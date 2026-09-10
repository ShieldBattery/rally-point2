//! On-demand load-state attestation: the coordinator asks a session's serving
//! relays, right now, what they hold for it, and waits for their answers.
//!
//! # Why an exchange rather than a stamp
//!
//! Every relay already restates its retained load state on every heartbeat, and
//! those restatements are the durable record the coordinator serves. What they
//! cannot supply is an *ordering* guarantee. A beat is snapshotted on the relay and
//! received some unknown interval later, so a fact the relay learned after taking
//! the snapshot arrives only in the next beat — and no stamp the coordinator writes
//! on receipt can say which side of a caller's deadline that fact fell on. Worse,
//! any such comparison spans two hosts' wall clocks.
//!
//! This module replaces the stamp with a causal barrier. The coordinator sends each
//! serving relay a request carrying a fresh correlation id; the relay snapshots what
//! it holds and answers with the id echoed back. Because the relay builds the
//! snapshot after the request arrived, everything it had observed before the caller
//! sent its read is necessarily in the answer. When *every* serving relay answers,
//! the union of their snapshots is complete as of the caller's own request — with no
//! clock on either side involved.
//!
//! A relay that does not answer — no live control connection, a build that predates
//! the request, a connection that dies mid-exchange, or one simply too slow —
//! contributes nothing but is not treated as an empty answer. The distinction
//! between "attests it holds nothing" and "did not attest" is the entire point:
//! only the first licenses reading an absent slot as a player who never arrived.
//!
//! # Bounding the fanout
//!
//! One read fans a question out to every relay serving the session, so the cost of
//! the exchange is bounded on two sides. The per-relay question channel is
//! **bounded** ([`LOAD_STATE_ASK_CAPACITY`]): a relay whose writer is behind sheds
//! the question rather than accumulating a backlog of reads nobody is waiting on
//! any more, and a full channel reads exactly like a silent relay — it did not
//! attest. And concurrent reads of the *same* session **share one round**
//! ([`LoadStateAttest::begin_round`]), so a tenant polling a session hard cannot
//! multiply the fleet-wide traffic by the number of requests in flight.
//!
//! Sharing a round is sound only because a joining read checks *when* the round it
//! joined put its questions out: a round that began asking before the joiner even
//! asked covers less than the joiner needs, so such a joiner waits for that round
//! to finish and then runs (or joins) the next one, which necessarily begins after
//! it asked. That costs at most one extra wait and never weakens the ordering claim
//! the answer carries.
//!
//! The instant a round is judged by is taken **before its first question goes out**,
//! not after its last. A relay asked early can snapshot and answer while the round
//! is still putting questions to the rest of the fleet, so an instant stamped at the
//! end of that fan-out can postdate a read that arrived after the earliest snapshot
//! was already taken — and that read would then accept a round missing exactly the
//! interval it asked about. Stamping before the first question makes the instant a
//! lower bound on every snapshot the round collects, which is what the joiner's
//! comparison needs it to be.
//!
//! # Shape
//!
//! One per-relay channel, drained by that relay's control-connection writer, plus a
//! map of outstanding requests keyed by correlation id and a map of in-flight rounds
//! keyed by session. All live behind a plain (non-async) mutex: every critical
//! section is a short, await-free lookup or insert, matching the descriptor and reap
//! outboxes next door. Clone the broker cheaply (state is behind one `Arc`) to share
//! it between the HTTP handler that asks and the control connections that answer.
//!
//! Nothing here is replayed on reconnect, unlike a reap directive: a request is only
//! meaningful to the caller still waiting on it, and that caller's own deadline
//! outlives no reconnect worth speaking of.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{SessionPresence, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

/// How long a load-state read waits for the serving relays' snapshots before
/// answering with whatever arrived.
///
/// The exchange is one small frame each way on a connection the relay is already
/// holding open, so a healthy fleet answers in well under a round-trip's worth of
/// scheduling. This is sized for a relay that is momentarily busy rather than for
/// one that is gone: past it, the caller is better served by an honest "not every
/// relay attested" than by a longer block, since it can simply read again. It also
/// bounds how long a tenant's HTTP request may occupy the coordinator.
pub const LOAD_STATE_ATTEST_TIMEOUT: Duration = Duration::from_millis(2500);

/// Depth of one relay's question channel.
///
/// Bounded so a relay whose control-connection writer is behind cannot accumulate
/// questions whose callers have long since stopped waiting. A full channel is a
/// non-answer, never a block: the read counts that relay as not having attested and
/// asks the rest, which is the same reading a disconnected or slow relay gets.
/// Sized well above the reads one session can have in flight under the endpoint's
/// own rate limit, so reaching it means the writer is genuinely stuck.
pub const LOAD_STATE_ASK_CAPACITY: usize = 64;

/// One relay's pending load-state question, handed to its control-connection
/// writer. The writer answers it by snapshotting the session on the relay and
/// sending a [`CoordinatorToRelay::LoadStateRequest`](rally_point_proto::control::CoordinatorToRelay::LoadStateRequest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadStateAsk {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session to ask about.
    pub session: SessionId,
    /// The correlation id the relay echoes back on its snapshot.
    pub request_id: u64,
}

/// The coordinator's load-state attestation broker.
#[derive(Clone, Default)]
pub struct LoadStateAttest {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Mints correlation ids, strictly increasing for the coordinator's lifetime so
    /// an id is never reused and a late answer can never match a later request.
    next_request_id: AtomicU64,
    state: Mutex<AttestState>,
}

#[derive(Default)]
struct AttestState {
    /// Each relay's live control-connection sender, replaced on every subscribe (so
    /// a reconnect owns the live receiver) and cleared when the connection's
    /// receiver is gone. Absent while the relay holds no connection, which makes it
    /// a non-answerer.
    senders: HashMap<RelayId, mpsc::Sender<LoadStateAsk>>,
    /// The requests still waiting for an answer, keyed by correlation id. An entry
    /// is removed when its answer arrives or when the waiter gives up (see
    /// [`PendingSnapshot`]'s `Drop`), so the map is bounded by the reads in flight.
    pending: HashMap<u64, PendingRequest>,
    /// The attestation rounds in flight, keyed by session, so concurrent reads of
    /// one session share a round instead of each fanning out. An entry is removed
    /// when its round's leader finishes or gives up (see [`RoundLeader`]'s `Drop`),
    /// so the map is bounded by the sessions being read right now.
    rounds: HashMap<RoundKey, watch::Receiver<Option<AttestRound>>>,
}

/// The key of one in-flight attestation round: which session, for which tenant.
type RoundKey = (TenantId, SessionId);

/// One outstanding request: who was asked, about what, and where the answer goes.
struct PendingRequest {
    /// The relay the request was sent to. An answer from anyone else is discarded —
    /// a correlation id is a handle to *this* relay's answer, and every relay in a
    /// session's serving set can see the others' ids only by guessing.
    relay: RelayId,
    tenant: TenantId,
    session: SessionId,
    answer: oneshot::Sender<AttestedSnapshot>,
}

/// One relay's answer to a load-state question: what it holds, and whether it
/// could rule out a slot's report still queued in that slot's client.
///
/// The two travel together because the coordinator's completeness claim needs
/// both. A snapshot's *facts* stand on their own; reading a slot's **absence**
/// from it as proof that player never got there additionally requires that the
/// relay fenced the session against its own clients when it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedSnapshot {
    /// What the relay holds for the session.
    pub state: SessionPresence,
    /// Whether the relay fenced every slot that could have been holding a report
    /// back. False is not a refusal — it only means this answer's absences may
    /// not be read as proof.
    pub fenced: bool,
}

/// One attestation round's outcome, shared by every read that joined it.
///
/// Cheap to clone: the relay sets live behind `Arc`s, since a round with several
/// joiners hands the same two sets to each.
#[derive(Debug, Clone)]
pub struct AttestRound {
    /// The instant the round was taken **before** it asked its first relay
    /// anything. Every answer it collects is snapshotted after this, so a read that
    /// arrived before it is fully covered — and one that arrived after it must not
    /// use this round, because a fact from the interval between could be missing
    /// from the snapshot of a relay that answered early.
    pub started_before_any_request: Instant,
    /// The relays that answered inside the round's deadline.
    pub attested: Arc<HashSet<RelayId>>,
    /// The relays whose answer was fenced — a subset of `attested`.
    pub fenced: Arc<HashSet<RelayId>>,
}

/// A request in flight, held by the caller waiting on its answer.
///
/// Dropping it retires the request: an answer that arrives afterwards finds no
/// entry and is discarded, exactly as a stale one is. That is what keeps the
/// pending map bounded by live reads rather than by every read ever made, however
/// the waiter leaves — answered, timed out, or cancelled with the HTTP request.
pub struct PendingSnapshot {
    request_id: u64,
    inner: Arc<Inner>,
    answer: oneshot::Receiver<AttestedSnapshot>,
}

impl PendingSnapshot {
    /// Waits for this relay's snapshot. `None` when the answer can no longer come —
    /// the control connection ended, or the coordinator dropped the request — which
    /// the caller reads as this relay not having attested, never as an empty
    /// snapshot. Bound the wait with a deadline: nothing here times out on its own.
    pub async fn recv(&mut self) -> Option<AttestedSnapshot> {
        (&mut self.answer).await.ok()
    }
}

impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        self.inner.state.lock().pending.remove(&self.request_id);
    }
}

impl LoadStateAttest {
    /// Creates a broker with no connections and nothing outstanding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes `relay`'s control connection to the load-state questions addressed
    /// to it, replacing any prior sender so a reconnect owns the live receiver.
    /// Returns the receiver the connection's writer drains.
    pub fn subscribe(&self, relay: RelayId) -> mpsc::Receiver<LoadStateAsk> {
        let (tx, rx) = mpsc::channel(LOAD_STATE_ASK_CAPACITY);
        self.inner.state.lock().senders.insert(relay, tx);
        rx
    }

    /// Asks `relay` what it holds for `(tenant, session)`, returning the handle to
    /// wait on its answer.
    ///
    /// `None` when the question could not even be put to the relay — it holds no
    /// control connection, the one it held has just died, or its queue is full
    /// because its writer is behind. That is a non-answer like any other: the caller
    /// counts it against completeness and asks the rest. Never blocks: a stuck
    /// connection must cost this read its claim, not the coordinator's thread.
    pub fn request(
        &self,
        relay: RelayId,
        tenant: &TenantId,
        session: SessionId,
    ) -> Option<PendingSnapshot> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (answer_tx, answer_rx) = oneshot::channel();
        let mut state = self.inner.state.lock();
        let sender = state.senders.get(&relay)?;
        match sender.try_send(LoadStateAsk {
            tenant: tenant.clone(),
            session,
            request_id,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The writer is behind. Keep the sender — the connection is alive
                // and will drain — but this read gets no answer from this relay.
                return None;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The connection's writer is gone, so nothing will ever read this
                // question. Clear the dead sender so the next request skips it
                // outright.
                state.senders.remove(&relay);
                return None;
            }
        }
        state.pending.insert(
            request_id,
            PendingRequest {
                relay,
                tenant: tenant.clone(),
                session,
                answer: answer_tx,
            },
        );
        drop(state);
        Some(PendingSnapshot {
            request_id,
            inner: self.inner.clone(),
            answer: answer_rx,
        })
    }

    /// Delivers a relay's snapshot to whoever asked for it, returning whether it
    /// matched an outstanding request.
    ///
    /// A snapshot is accepted only when its correlation id names a request that is
    /// still outstanding **and** that request went to this relay for this exact
    /// session. Anything else — an id already answered, an id from a prior read, an
    /// id another relay's request owns, or a session other than the one asked about
    /// — is discarded rather than folded in: a caller's completeness claim rests on
    /// having heard from each serving relay individually, so one relay must never be
    /// able to answer in another's name.
    pub fn resolve(
        &self,
        request_id: u64,
        relay: RelayId,
        snapshot: AttestedSnapshot,
    ) -> Result<(), StaleSnapshot> {
        let mut state = self.inner.state.lock();
        let matches = state.pending.get(&request_id).is_some_and(|pending| {
            pending.relay == relay
                && pending.tenant == snapshot.state.tenant
                && pending.session == snapshot.state.session
        });
        if !matches {
            return Err(StaleSnapshot);
        }
        let pending = state
            .pending
            .remove(&request_id)
            .expect("the entry was just matched under this lock");
        drop(state);
        // A dropped receiver means the waiter already gave up; the snapshot is
        // simply not needed, which is not an error to report.
        let _ = pending.answer.send(snapshot);
        Ok(())
    }

    /// Drops `relay`'s question channel, for a relay id that has been
    /// **permanently** retired — the same narrow contract
    /// [`RelayReaps::forget`](crate::descriptors::RelayReaps::forget) documents.
    /// Idempotent. Outstanding requests to the relay are untouched: their waiters
    /// still hold them and retire them on their own deadline.
    pub fn forget(&self, relay: RelayId) {
        self.inner.state.lock().senders.remove(&relay);
    }

    /// Whether `request_id` still names an outstanding request.
    ///
    /// The control connection's writer checks this just before it puts a queued
    /// question on the wire: a read that timed out (or whose HTTP request was
    /// cancelled) retires its request the moment it leaves, and asking a relay a
    /// question nobody is waiting for spends a frame and a relay's fence for
    /// nothing.
    pub fn is_pending(&self, request_id: u64) -> bool {
        self.inner.state.lock().pending.contains_key(&request_id)
    }

    /// Claims or joins the in-flight attestation round for `(tenant, session)`.
    ///
    /// The first caller becomes the round's leader and receives the handle it
    /// publishes the outcome through; every caller that arrives while that handle
    /// lives joins instead and receives a watch on the outcome. The entry is removed
    /// when the leader's handle drops — published or not — so a leader that is
    /// cancelled mid-round leaves the next caller free to lead rather than wedging
    /// the session.
    ///
    /// A joiner must still check the round's `started_before_any_request` against its
    /// own arrival (see the module docs): a round that had begun asking before it
    /// joined answers a question older than the one it asked. [`shared_round`] is
    /// that whole protocol; prefer it to driving this by hand.
    pub fn begin_round(&self, tenant: &TenantId, session: SessionId) -> RoundEntry {
        let key = (tenant.clone(), session);
        let mut state = self.inner.state.lock();
        if let Some(rx) = state.rounds.get(&key) {
            return RoundEntry::Joined(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        state.rounds.insert(key.clone(), rx);
        RoundEntry::Leader(RoundLeader {
            key,
            inner: self.inner.clone(),
            publish: tx,
        })
    }

    /// How many requests are outstanding. Exists so the pending map's bound — live
    /// reads, not reads ever made — is actually asserted rather than assumed.
    pub fn pending_count(&self) -> usize {
        self.inner.state.lock().pending.len()
    }

    /// How many rounds are in flight. Exists so the round map's bound — sessions
    /// being read right now — is actually asserted rather than assumed.
    pub fn round_count(&self) -> usize {
        self.inner.state.lock().rounds.len()
    }
}

/// What [`LoadStateAttest::begin_round`] hands back: leadership of a fresh round, or
/// a watch on one already running.
pub enum RoundEntry {
    /// This caller runs the round and publishes its outcome.
    Leader(RoundLeader),
    /// A round was already running; await its outcome here.
    Joined(watch::Receiver<Option<AttestRound>>),
}

/// The leader's handle on an in-flight round: publish the outcome through it, and
/// drop it when the round is over.
///
/// Dropping retires the round whether or not it published, so the session is never
/// left with an entry no one will ever fill — a leader whose HTTP request was
/// cancelled simply frees the next caller to lead. Joiners watching a retired,
/// unpublished round see the sender close and lead the next one themselves.
pub struct RoundLeader {
    key: RoundKey,
    inner: Arc<Inner>,
    publish: watch::Sender<Option<AttestRound>>,
}

impl RoundLeader {
    /// Publishes the finished round to every caller that joined it, and retires the
    /// entry.
    ///
    /// The entry goes **before** the value is sent, so a caller woken by the publish
    /// finds no round to join and leads the next one instead of re-reading an
    /// outcome it has already rejected. Without that order a joiner whose arrival
    /// the round predates could re-join the same finished round indefinitely.
    pub fn publish(&self, round: AttestRound) {
        self.inner.state.lock().rounds.remove(&self.key);
        // A send with no receivers left is not an error here: every joiner may
        // simply have given up, and the leader has its own copy regardless.
        let _ = self.publish.send(Some(round));
    }
}

impl Drop for RoundLeader {
    /// Retires the round if [`publish`](RoundLeader::publish) has not already —
    /// a leader whose HTTP request was cancelled mid-round must not leave the
    /// session with an entry nobody will ever fill. Idempotent with `publish`.
    fn drop(&mut self) {
        self.inner.state.lock().rounds.remove(&self.key);
    }
}

/// Obtains an attestation round that covers a read arriving now: leads a fresh one
/// by calling `run_round`, or shares the round already running for the session.
///
/// Sharing is what keeps a tenant polling one session from multiplying the
/// fleet-wide fanout by its requests in flight. It is sound only with the arrival
/// check here: a round that had already begun asking when this read arrived answers
/// an *older* question than this one, and everything the relays learned in between
/// could be missing from it — so such a joiner waits that round out and takes the
/// next one, which necessarily begins after it asked. That costs at most one extra
/// wait: the next round starts after the one just finished, and therefore after this
/// read arrived.
///
/// `run_round` must stamp the round it returns with the instant taken before it
/// asked its first relay anything; the comparison here is only as sound as that
/// stamp.
pub async fn shared_round<F, Fut>(
    attest: &LoadStateAttest,
    tenant: &TenantId,
    session: SessionId,
    run_round: F,
) -> AttestRound
where
    F: Fn() -> Fut,
    Fut: Future<Output = AttestRound>,
{
    let asked_at = Instant::now();
    loop {
        match attest.begin_round(tenant, session) {
            RoundEntry::Leader(leader) => {
                let round = run_round().await;
                leader.publish(round.clone());
                return round;
            }
            RoundEntry::Joined(watch) => {
                if let Some(round) = joined_round(watch).await
                    && round_answers_read(round.started_before_any_request, asked_at)
                {
                    return round;
                }
                // Either the leader left without an outcome, or the round it ran
                // began before this read arrived. Round again: the entry is gone by
                // now, so this read leads or joins a round that starts after it
                // asked.
            }
        }
    }
}

/// Whether a shared round that began at `round_started` can answer a read that
/// arrived at `asked_at`: only if it began strictly after. The clock is monotonic
/// but not strictly increasing, so two causally ordered samples can read equal —
/// and an equal stamp cannot tell a round that began before this read from one
/// that began after it. Equality is therefore treated as the older case and the
/// read waits for the next round; the cost is one extra round in a window a
/// high-resolution clock almost never produces, against a claim that must hold
/// always.
fn round_answers_read(round_started: Instant, asked_at: Instant) -> bool {
    round_started > asked_at
}

/// Awaits the outcome of a round this caller joined, or `None` if its leader left
/// without publishing one.
pub async fn joined_round(mut watch: watch::Receiver<Option<AttestRound>>) -> Option<AttestRound> {
    loop {
        if let Some(round) = watch.borrow_and_update().clone() {
            return Some(round);
        }
        if watch.changed().await.is_err() {
            // The leader dropped its handle. It may have published on the way out,
            // in which case the value is still readable here.
            return watch.borrow().clone();
        }
    }
}

/// A snapshot that matched no outstanding request: a stale answer, a repeat, or one
/// whose correlation id belongs to a different relay or session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleSnapshot;

#[cfg(test)]
mod tests;
