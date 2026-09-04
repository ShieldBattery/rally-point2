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
//! # Shape
//!
//! One per-relay channel, drained by that relay's control-connection writer, plus a
//! map of outstanding requests keyed by correlation id. Both live behind a plain
//! (non-async) mutex: every critical section is a short, await-free lookup or
//! insert, matching the descriptor and reap outboxes next door. Clone the broker
//! cheaply (state is behind one `Arc`) to share it between the HTTP handler that
//! asks and the control connections that answer.
//!
//! Nothing here is replayed on reconnect, unlike a reap directive: a request is only
//! meaningful to the caller still waiting on it, and that caller's own deadline
//! outlives no reconnect worth speaking of.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{SessionPresence, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};
use tokio::sync::{mpsc, oneshot};

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
    /// a reconnect owns the live receiver) and cleared when a send fails. Absent
    /// while the relay holds no connection, which makes it a non-answerer.
    senders: HashMap<RelayId, mpsc::UnboundedSender<LoadStateAsk>>,
    /// The requests still waiting for an answer, keyed by correlation id. An entry
    /// is removed when its answer arrives or when the waiter gives up (see
    /// [`PendingSnapshot`]'s `Drop`), so the map is bounded by the reads in flight.
    pending: HashMap<u64, PendingRequest>,
}

/// One outstanding request: who was asked, about what, and where the answer goes.
struct PendingRequest {
    /// The relay the request was sent to. An answer from anyone else is discarded —
    /// a correlation id is a handle to *this* relay's answer, and every relay in a
    /// session's serving set can see the others' ids only by guessing.
    relay: RelayId,
    tenant: TenantId,
    session: SessionId,
    answer: oneshot::Sender<SessionPresence>,
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
    answer: oneshot::Receiver<SessionPresence>,
}

impl PendingSnapshot {
    /// Waits for this relay's snapshot. `None` when the answer can no longer come —
    /// the control connection ended, or the coordinator dropped the request — which
    /// the caller reads as this relay not having attested, never as an empty
    /// snapshot. Bound the wait with a deadline: nothing here times out on its own.
    pub async fn recv(&mut self) -> Option<SessionPresence> {
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
    pub fn subscribe(&self, relay: RelayId) -> mpsc::UnboundedReceiver<LoadStateAsk> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.state.lock().senders.insert(relay, tx);
        rx
    }

    /// Asks `relay` what it holds for `(tenant, session)`, returning the handle to
    /// wait on its answer.
    ///
    /// `None` when the question could not even be put to the relay — it holds no
    /// control connection, or the one it held has just died. That is a non-answer
    /// like any other: the caller counts it against completeness and asks the rest.
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
        if sender
            .send(LoadStateAsk {
                tenant: tenant.clone(),
                session,
                request_id,
            })
            .is_err()
        {
            // The connection's writer is gone, so nothing will ever read this
            // question. Clear the dead sender so the next request skips it outright.
            state.senders.remove(&relay);
            return None;
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
        snapshot: SessionPresence,
    ) -> Result<(), StaleSnapshot> {
        let mut state = self.inner.state.lock();
        let matches = state.pending.get(&request_id).is_some_and(|pending| {
            pending.relay == relay
                && pending.tenant == snapshot.tenant
                && pending.session == snapshot.session
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

    /// How many requests are outstanding. Exists so the pending map's bound — live
    /// reads, not reads ever made — is actually asserted rather than assumed.
    pub fn pending_count(&self) -> usize {
        self.inner.state.lock().pending.len()
    }
}

/// A snapshot that matched no outstanding request: a stale answer, a repeat, or one
/// whose correlation id belongs to a different relay or session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleSnapshot;

#[cfg(test)]
mod tests {
    use rally_point_proto::ids::SlotId;

    use super::*;

    fn tid() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    fn snapshot(session: SessionId, ever_connected: &[u8]) -> SessionPresence {
        SessionPresence {
            tenant: tid(),
            session,
            slots: vec![],
            ever_connected: ever_connected.iter().map(|&s| SlotId(s)).collect(),
            started: vec![],
            started_at_ms: None,
        }
    }

    #[tokio::test]
    async fn a_request_reaches_the_relay_and_its_answer_reaches_the_waiter() {
        let attest = LoadStateAttest::new();
        let mut asks = attest.subscribe(RelayId(1));
        let mut pending = attest
            .request(RelayId(1), &tid(), SessionId(5))
            .expect("the relay is connected");
        let ask = asks.recv().await.expect("the question was queued");
        assert_eq!(ask.tenant, tid());
        assert_eq!(ask.session, SessionId(5));

        attest
            .resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[0, 2]))
            .expect("the id is outstanding for this relay");
        assert_eq!(
            pending.recv().await.map(|s| s.ever_connected),
            Some(vec![SlotId(0), SlotId(2)]),
        );
    }

    #[tokio::test]
    async fn a_relay_with_no_connection_cannot_be_asked() {
        let attest = LoadStateAttest::new();
        assert!(attest.request(RelayId(9), &tid(), SessionId(5)).is_none());
        assert_eq!(attest.pending_count(), 0);
    }

    #[tokio::test]
    async fn a_dead_connection_is_dropped_rather_than_asked_again() {
        // The writer's receiver going away means nothing will read the question, so
        // the request fails outright instead of parking a waiter nothing can answer.
        let attest = LoadStateAttest::new();
        let asks = attest.subscribe(RelayId(1));
        drop(asks);
        assert!(attest.request(RelayId(1), &tid(), SessionId(5)).is_none());
        assert!(attest.request(RelayId(1), &tid(), SessionId(5)).is_none());
        assert_eq!(attest.pending_count(), 0);
    }

    #[tokio::test]
    async fn ids_do_not_cross_match_between_relays_sessions_or_reads() {
        let attest = LoadStateAttest::new();
        let mut asks_one = attest.subscribe(RelayId(1));
        let _asks_two = attest.subscribe(RelayId(2));
        let mut pending = attest
            .request(RelayId(1), &tid(), SessionId(5))
            .expect("connected");
        let ask = asks_one.recv().await.expect("queued");

        // Another relay answering in relay 1's name.
        assert_eq!(
            attest.resolve(ask.request_id, RelayId(2), snapshot(SessionId(5), &[0])),
            Err(StaleSnapshot),
        );
        // The right relay, the wrong session.
        assert_eq!(
            attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(6), &[0])),
            Err(StaleSnapshot),
        );
        // An id nobody is waiting on.
        assert_eq!(
            attest.resolve(
                ask.request_id.wrapping_add(1),
                RelayId(1),
                snapshot(SessionId(5), &[0]),
            ),
            Err(StaleSnapshot),
        );
        // None of that consumed the request, and the real answer still lands.
        attest
            .resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[1]))
            .expect("outstanding");
        assert_eq!(
            pending.recv().await.map(|s| s.ever_connected),
            Some(vec![SlotId(1)]),
        );
        // A second answer for the same id is stale: the request is consumed.
        assert_eq!(
            attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[1])),
            Err(StaleSnapshot),
        );
    }

    #[tokio::test]
    async fn a_waiter_that_gives_up_retires_its_request() {
        let attest = LoadStateAttest::new();
        let mut asks = attest.subscribe(RelayId(1));
        let pending = attest
            .request(RelayId(1), &tid(), SessionId(5))
            .expect("connected");
        let ask = asks.recv().await.expect("queued");
        assert_eq!(attest.pending_count(), 1);

        drop(pending);
        assert_eq!(attest.pending_count(), 0, "the map tracks live reads only");
        assert_eq!(
            attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[0])),
            Err(StaleSnapshot),
            "an answer for an abandoned read is discarded",
        );
    }

    #[tokio::test]
    async fn a_reconnect_replaces_the_question_channel() {
        // A relay's fresh control connection owns the live receiver; the prior one's
        // is dropped, so a question can never be delivered to a dead writer.
        let attest = LoadStateAttest::new();
        let mut old = attest.subscribe(RelayId(1));
        let mut new = attest.subscribe(RelayId(1));
        let _pending = attest
            .request(RelayId(1), &tid(), SessionId(5))
            .expect("connected");
        assert!(new.recv().await.is_some());
        assert!(old.recv().await.is_none(), "the old channel is closed");
    }
}
