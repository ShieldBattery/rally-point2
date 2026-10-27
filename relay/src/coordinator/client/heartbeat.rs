//! What the relay tells the coordinator about the sessions it holds: the periodic
//! heartbeat's roster and the answer to a one-session load-state question.
//!
//! Both use the live routing roster and per-session decision-makers. Heartbeats
//! restate every session's roster and progress facts, plus a rotating byte-bounded
//! subset of paired observations not yet sent on this control connection. Requested snapshots carry all observations for
//! one session. Selection happens before opaque bodies are cloned. The
//! load-state side adds the fence: probe every slot that could still be holding
//! a report back, wait for the acks, and only then snapshot.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rally_point_proto::control::{
    ClosedSlot, MAX_PERIODIC_EVIDENCE_SLOTS, RegionRttReport, SessionPresence, SlotEvidenceHistory,
};
use rally_point_proto::ids::SlotId;
use tokio::sync::mpsc::Sender;
use tokio::time::Instant;

use crate::consensus::{PeriodicEvidencePair, RetainedLoadState};
use crate::coordinator::region_ping::RegionRttCache;
use crate::key::SessionKey;
use crate::routing::Sessions;

use super::HeartbeatSources;

/// A coordinator's [`CoordinatorToRelay::LoadStateRequest`](rally_point_proto::control::CoordinatorToRelay::LoadStateRequest), routed from the read
/// half to the write half (answering it is a send, and only the writer sends).
///
/// The whole point of the exchange is ordering: the answer must be built from what
/// this relay holds *after* the request arrived, so the routed ask carries only the
/// question and the writer's fence task snapshots the state itself, after its
/// probes are answered.
pub(super) struct LoadStateAsk {
    /// The coordinator's correlation id, echoed back on the snapshot.
    pub(super) request_id: u64,
    /// The session to snapshot.
    pub(super) key: SessionKey,
    /// Whether this request asks the relay to close its setup lobby epoch.
    pub(super) settle_lobby: bool,
}

/// Snapshots what this relay holds for each session into the [`SessionPresence`]
/// entries a heartbeat carries: its currently-connected slots and the load state
/// it has retained, tenant/session/slot only (the relay holds no user identity to
/// leak).
///
/// An entry goes up for **every session this relay holds a decision-maker for**,
/// not only the occupied ones. A maker outlives the links that fed it, while the
/// live roster drops a session the moment its last local slot leaves — so keying
/// the beat on the roster alone would silently stop restating the load state of a
/// session whose slots have all disconnected, exactly when the coordinator most
/// needs it (that relay learned who arrived, and the game is still running
/// elsewhere). Such an entry names no connected slot, which the coordinator reads
/// exactly as it reads an omission: no presence, and complete-roster proof that
/// the relay holds nobody for the session. A session with connected slots but no
/// maker (a provisional admission no descriptor ever claimed) still gets its
/// entry, with the load fields empty.
///
/// The roster and progress sets are complete every time, so a lost beat is
/// corrected by the next one. A byte-bounded rotating subset of periodic samples
/// carries its matching admission for recovery without growing the complete roster
/// beyond the control-message limit. Requested load state retains every observation.
#[cfg(test)]
pub(super) fn heartbeat_presence(sources: &HeartbeatSources) -> Vec<SessionPresence> {
    heartbeat_presence_with_evidence(sources, &mut 0, &[], &mut HashSet::new())
}

pub(super) fn heartbeat_presence_with_evidence(
    sources: &HeartbeatSources,
    cursor: &mut usize,
    region_rtts: &[RegionRttReport],
    sent: &mut HashSet<(SessionKey, SlotId, u64)>,
) -> Vec<SessionPresence> {
    // Retained state before the live roster, for the reason `session_load_snapshot`
    // gives: a slot is registered before it activates, so a slot ever-connected here
    // without a live link really had gone by the time the roster was read.
    let retained = sources.decision_makers.retained_load_states();
    let mut live: HashMap<SessionKey, _> = crate::routing::live_slots(&sources.sessions)
        .into_iter()
        .collect();
    let mut roster: Vec<SessionPresence> = retained
        .into_iter()
        .map(|(key, load)| {
            let slots = live.remove(&key).unwrap_or_default();
            presence_entry(key, slots, load)
        })
        .collect();
    roster.extend(
        live.into_iter()
            .map(|(key, slots)| presence_entry(key, slots, RetainedLoadState::default())),
    );
    let candidates = unsent_periodic_candidates(sources, sent);
    attach_heartbeat_evidence(
        &mut roster,
        cursor,
        region_rtts,
        candidates,
        |key, slot, sequence, remaining| {
            sources
                .decision_makers
                .periodic_evidence_pair(key, slot, sequence, remaining)
        },
    );
    roster
}

pub(super) fn unsent_periodic_candidates(
    sources: &HeartbeatSources,
    sent: &mut HashSet<(SessionKey, SlotId, u64)>,
) -> Vec<(SessionKey, SlotId, u64)> {
    let current: HashSet<_> = sources
        .decision_makers
        .periodic_evidence_candidates()
        .into_iter()
        .collect();
    sent.retain(|entry| current.contains(entry));
    current
        .into_iter()
        .filter(|entry| !sent.contains(entry))
        .collect()
}

const HEARTBEAT_EVIDENCE_BYTES: usize = 512 * 1024;

/// A complete roster with a rotating bounded subset of paired observations.
/// Candidate enumeration holds only identities; the callback clones only pairs
/// that fit. A stale identity is skipped without stopping later candidates.
pub(super) fn attach_heartbeat_evidence(
    roster: &mut [SessionPresence],
    cursor: &mut usize,
    region_rtts: &[RegionRttReport],
    mut candidates: Vec<(SessionKey, SlotId, u64)>,
    mut pair: impl FnMut(
        &SessionKey,
        SlotId,
        u64,
        &mut usize,
    ) -> Result<Option<PeriodicEvidencePair>, ()>,
) {
    roster.sort_by(|a, b| (&a.tenant.0, a.session).cmp(&(&b.tenant.0, b.session)));
    candidates.sort_by(|(a, sa, qa), (b, sb, qb)| {
        (&a.tenant.0, a.session, sa, qa).cmp(&(&b.tenant.0, b.session, sb, qb))
    });
    if candidates.is_empty() {
        *cursor = 0;
        return;
    }
    // The complete base roster and RTTs count against the coordinator's 2 MiB
    // frame cap too. Leave extra framing headroom rather than assuming the roster
    // is small because the opaque attachment budget is bounded.
    let base = serde_json::to_vec(&(&roster, region_rtts))
        .expect("heartbeat fields serialize")
        .len();
    let mut remaining =
        HEARTBEAT_EVIDENCE_BYTES.min((2usize * 1024 * 1024).saturating_sub(base + 1024));
    let start = *cursor % candidates.len();
    for offset in 0..candidates.len() {
        let index = (start + offset) % candidates.len();
        let (key, slot, sequence) = &candidates[index];
        let Ok(session) = roster.binary_search_by(|entry| {
            (&entry.tenant.0, entry.session).cmp(&(&key.tenant.0, key.session))
        }) else {
            continue;
        };
        if roster[session].periodic_evidence.len() + roster[session].evidence_history.len()
            >= MAX_PERIODIC_EVIDENCE_SLOTS
        {
            continue;
        }
        match pair(key, *slot, *sequence, &mut remaining) {
            Ok(Some(pair)) => {
                if let Some(history) = pair.history {
                    roster[session].evidence_history.push(SlotEvidenceHistory {
                        slot: pair.sample.slot,
                        history: *history,
                    });
                } else {
                    roster[session].evidence.push(pair.admission);
                    roster[session].periodic_evidence.push(pair.sample);
                }
            }
            // A candidate may disappear or be replaced between enumeration and
            // lookup. It did not spend the budget and must not stop this beat.
            Ok(None) => {}
            Err(()) => {
                // A pair that exhausted this beat's budget gets first chance next
                // time. A pair too large even when first must not pin the rotation.
                *cursor = if offset == 0 {
                    (index + 1) % candidates.len()
                } else {
                    index
                };
                break;
            }
        }
        *cursor = (index + 1) % candidates.len();
    }
    for session in roster {
        session.evidence.sort_by_key(|entry| entry.slot);
        session.periodic_evidence.sort_by_key(|entry| entry.slot);
        session.evidence_history.sort_by_key(|entry| entry.slot);
    }
}

/// Snapshots what this relay holds for **one** session, in the same
/// [`SessionPresence`] shape a heartbeat's roster entry carries — the answer to a
/// [`CoordinatorToRelay::LoadStateRequest`](rally_point_proto::control::CoordinatorToRelay::LoadStateRequest).
///
/// Reads the same roster and progress facts as a heartbeat, plus the session's
/// retained connection observations, including ones outside the current heartbeat
/// attachment budget.
/// A session this relay holds nothing for — no maker, no live slot — snapshots to
/// empty lists, which is this relay attesting that it knows of no arrival rather
/// than declining to answer.
///
/// Also hands back the connection epoch behind each connected slot, read under the
/// same roster lock as the slot list itself, so a caller comparing two snapshots
/// sees one consistent membership per read rather than a slot list from one instant
/// and epochs from another.
///
/// Takes the two handles it reads rather than the whole heartbeat sources, so the
/// fence task — which outlives any borrow of the connection's sources — can take
/// the same snapshot from its own clones.
///
/// The retained state is read **before** the live roster, and the order is what
/// keeps a slot that is not there from being taken for one that left. The two
/// reads take different locks, so a link can come or go between them, and a slot
/// registers on the roster before it activates into `ever_connected`. Read in this
/// order, a slot in `ever_connected` without a live link had activated before the
/// first read and was off the roster by the second: it really is gone. A slot that
/// activates in between shows up live but not yet ever-connected, which a fence
/// reads as a live link it never probed — unfenced, and asked again — rather than
/// as a departed one. A slot that leaves in between shows up as departed, which it
/// is.
///
/// `between_reads` runs after the retained state is read and before the live
/// roster is. Every caller passes a no-op except a test landing a link change
/// exactly in that window.
pub(super) fn session_load_snapshot(
    sessions: &Sessions,
    decision_makers: &crate::consensus::DecisionMakers,
    key: SessionKey,
    between_reads: impl FnOnce(),
) -> SessionLoadSnapshot {
    let mut load = decision_makers.retained_load_state(&key);
    let last_link_epochs = std::mem::take(&mut load.last_link_epochs);
    between_reads();
    let links = crate::routing::live_session_slot_epochs(sessions, &key);
    SessionLoadSnapshot {
        state: presence_entry(key, links.iter().map(|(slot, _)| *slot).collect(), load),
        links,
        last_link_epochs,
    }
}

/// One [`session_load_snapshot`]: the session as a heartbeat would describe it,
/// plus what a fence judges it against.
pub(super) struct SessionLoadSnapshot {
    /// What this relay holds for the session.
    pub(super) state: SessionPresence,
    /// The connection epoch behind each slot in `state.slots`, read under the same
    /// roster lock as the slot list itself.
    pub(super) links: Vec<(SlotId, u64)>,
    /// Each slot's latest activated link epoch, read with the retained state
    /// (before the roster), ascending by slot.
    pub(super) last_link_epochs: Vec<(SlotId, u64)>,
}

/// A finished load-state answer, handed from a fence task back to the write half
/// that sends it.
pub(super) struct LoadStateAnswer {
    /// The coordinator's correlation id, echoed back on the snapshot.
    pub(super) request_id: u64,
    /// The snapshot and the fence verdict over it.
    pub(super) load: FencedLoadState,
    /// Whether this request made a final home-lobby ingress cut.
    pub(super) setup_settled: bool,
}

/// One session's snapshot, taken after its fence resolved, with the fence's
/// verdict beside it. The two travel together because they are one claim: the
/// sets say what this relay saw, and the verdict says which of its slots it could
/// rule out still holding a report in their client (see
/// [`fenced_load_state_snapshot`]).
#[derive(Debug)]
pub(super) struct FencedLoadState {
    /// What this relay holds for the session, read after the fence resolved.
    pub(super) state: SessionPresence,
    /// Whether every probe was acked in time and every live, unstarted slot at
    /// the end acked on the connection epoch it still holds — the verdict over
    /// every slot except those in `closed_slots`.
    pub(super) fenced_live: bool,
    /// The slots this relay has seen connect that are neither live nor started in
    /// `state`, ascending: the ones no probe can reach, each with the link whose
    /// closure left it disconnected.
    pub(super) closed_slots: Vec<ClosedSlot>,
}

impl FencedLoadState {
    /// Whether the whole session was fenced: the live verdict holds and no slot
    /// sits beyond the fence's reach.
    pub(super) fn fenced(&self) -> bool {
        self.fenced_live && self.closed_slots.is_empty()
    }
}

/// Starts one routed load-state ask's fence, or sheds it when this relay is already
/// running its cap of fences.
///
/// The seat is what bounds the probing. The ask channel cannot: it is drained the
/// instant a question arrives, so its depth caps questions *queued*, and the answer
/// channel bounds answers already finished. A fence, by contrast, occupies a task
/// for as long as its clients take to reply, and nothing upstream throttles that —
/// so a permit is taken before the task exists and held until it ends. An ask that
/// finds every seat taken costs nothing at all: no task, no probe, no answer, which
/// the coordinator reads as this relay not having attested, the same reading a slow
/// or disconnected relay gets.
pub(super) fn start_load_state_answer(
    sources: &HeartbeatSources,
    ask: LoadStateAsk,
    answers: &Sender<LoadStateAnswer>,
) {
    let Some(permit) = sources.load_fence.try_start() else {
        tracing::debug!(
            request_id = ask.request_id,
            "shedding a load-state ask: every fence seat on this relay is taken",
        );
        return;
    };
    spawn_load_state_answer(sources, ask, answers.clone(), permit);
}

/// Runs one load-state answer's fence off the control connection's write half and
/// hands the finished answer back over `answers`.
///
/// Spawned rather than awaited inline because fencing waits on acknowledgements
/// from game clients: parking the connection's only sender on a client round-trip
/// would stall heartbeats and webhook-bearing notices behind an unrelated tenant's
/// read. An answer that cannot be queued back — the writer gone, or already holding
/// as many answers as questions were admitted — is dropped, which the coordinator
/// reads as this relay not having attested.
///
/// `permit` is this fence's seat under the relay's active-fence cap, taken by the
/// caller before the task exists and released only when the task ends. The task can
/// outlive anyone's interest in it — the coordinator stops waiting on its own
/// deadline, and a request it has already retired can still be in flight here — so
/// the permit, not the asker, is what bounds the probing this relay does at once.
fn spawn_load_state_answer(
    sources: &HeartbeatSources,
    ask: LoadStateAsk,
    answers: Sender<LoadStateAnswer>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let sessions = Arc::clone(&sources.sessions);
    let decision_makers = Arc::clone(&sources.decision_makers);
    let gates = sources.session_gates.clone();
    let provisional_turns = sources.provisional_turns.clone();
    let fence = sources.load_fence.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let setup_settled = ask.settle_lobby
            && gates
                .with_exclusive(&ask.key, || {
                    !provisional_turns.is_unresolved(&ask.key)
                        && decision_makers.settle_lobby(&ask.key)
                })
                .unwrap_or(false);
        let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, ask.key).await;
        if answers
            .try_send(LoadStateAnswer {
                request_id: ask.request_id,
                load,
                setup_settled,
            })
            .is_err()
        {
            tracing::debug!(
                request_id = ask.request_id,
                "dropping a load-state answer: the control connection's writer is behind or gone",
            );
        }
    });
}

/// Fences the session against its own clients, then snapshots it — the answer to a
/// coordinator load-state question, plus whether that answer's *absences* may be
/// trusted.
///
/// A slot's `GameStarted` travels its own ordered control stream, independently of
/// the coordinator's question, so what this relay has observed is not by itself
/// what has happened. Every slot this relay homes that has connected and not yet
/// started is therefore probed on that stream and waited for: the client writes any
/// report it owes ahead of its ack, so an ack proves nothing of that slot's is
/// still behind it. The snapshot is taken **after** the acks, since a probe may
/// have delivered a report in the meantime.
///
/// A probe answers for one *link*, not one seat: it is issued against the
/// connection epoch the slot held when the roster was read, delivered only to that
/// connection, and acked only by it. That is what lets a membership change during
/// the wait be detected rather than papered over — a client that (re)connects
/// mid-fence would otherwise show up in the final snapshot as live, unstarted and
/// unprobed, with a report of its own possibly still queued.
///
/// The verdict comes in two halves. `fenced_live` holds only when both of these
/// do:
///
/// - every probe issued was acked within the fence's timeout
///   ([`LOAD_STATE_FENCE_TIMEOUT`](super::LOAD_STATE_FENCE_TIMEOUT)) — a probe no
///   stream would take, or one that went unanswered, leaves that slot unfenced;
///   and
/// - every slot live at the *end* that has not started acked a probe issued
///   against the epoch it still holds, so a slot that arrived mid-fence (never
///   probed) and one whose link was replaced after acking (probed on the epoch
///   before) both spoil the verdict.
///
/// `closed_slots` is every slot this relay has ever seen connect that is now
/// disconnected without having started. Such a slot has no stream to probe and its
/// client may be holding a report for the stream it opens next, so it can never be
/// fenced; naming it lets a reader trust everything else the answer vouches for
/// while knowing exactly which slots it cannot. The whole session is fenced
/// ([`FencedLoadState::fenced`]) only when `fenced_live` holds and no slot is
/// closed.
///
/// So any membership change across the fence withholds the live verdict and the
/// tenant's next read simply asks again — the answer's facts are unaffected, only
/// the licence to read its absences as proof.
///
/// A slot that never connected here is not probed and does not spoil the verdict:
/// no client ever held a stream to this relay for it, so there is nothing of its to
/// be queued anywhere and its absence is attestable as it stands.
pub(super) async fn fenced_load_state_snapshot(
    sessions: &Sessions,
    decision_makers: &crate::consensus::DecisionMakers,
    fence: &crate::coordinator::load_fence::LoadStateFence,
    key: SessionKey,
) -> FencedLoadState {
    fenced_load_state_snapshot_with(sessions, decision_makers, fence, key, || {}).await
}

/// [`fenced_load_state_snapshot`], running `between_reads` inside its final
/// snapshot, between the retained-state read and the live-roster read (see
/// [`session_load_snapshot`]).
pub(super) async fn fenced_load_state_snapshot_with(
    sessions: &Sessions,
    decision_makers: &crate::consensus::DecisionMakers,
    fence: &crate::coordinator::load_fence::LoadStateFence,
    key: SessionKey,
    between_reads: impl FnOnce(),
) -> FencedLoadState {
    let started: HashSet<SlotId> = decision_makers
        .retained_load_state(&key)
        .started
        .into_iter()
        .collect();
    let mut probes = Vec::new();
    let mut every_probe_acked = true;
    for (slot, connection_epoch) in crate::routing::live_session_slot_epochs(sessions, &key) {
        if started.contains(&slot) {
            continue;
        }
        let pending = fence.probe(&key, slot, connection_epoch);
        if crate::routing::deliver_load_state_probe_to_slot(
            sessions,
            &key,
            slot,
            connection_epoch,
            pending.probe_id(),
        ) {
            probes.push((slot, connection_epoch, pending));
        } else {
            // Nothing carried the probe — the link ended under us, a reconnect
            // took the seat, or the push queue is full — so no ack can ever come
            // for it.
            every_probe_acked = false;
        }
    }
    // Every probe goes out before any ack is waited on, and all of them share one
    // absolute deadline, so the fence costs at most one timeout however many slots
    // this relay homes and however many of them are slow.
    let deadline = Instant::now() + fence.timeout();
    let mut acked: HashMap<SlotId, u64> = HashMap::new();
    for (slot, connection_epoch, probe) in &mut probes {
        if matches!(
            tokio::time::timeout_at(deadline, probe.recv()).await,
            Ok(true)
        ) {
            acked.insert(*slot, *connection_epoch);
        } else {
            every_probe_acked = false;
        }
    }

    // Re-read: an acked probe may have delivered a `GameStarted` ahead of its ack,
    // and that is precisely the fact the fence exists to capture. The epochs come
    // back with it, so the roster this is judged against is the one that exists
    // now, not the one the probes went out to.
    let SessionLoadSnapshot {
        state,
        links,
        last_link_epochs,
    } = session_load_snapshot(sessions, decision_makers, key.clone(), between_reads);
    let every_live_link_fenced = links
        .iter()
        .all(|(slot, epoch)| state.started.contains(slot) || acked.get(slot) == Some(epoch));
    // `ever_connected` is ascending, so the filtered set is too.
    let closed_slots: Vec<ClosedSlot> = state
        .ever_connected
        .iter()
        .copied()
        .filter(|slot| !state.slots.contains(slot) && !state.started.contains(slot))
        .map(|slot| ClosedSlot {
            slot,
            link_epoch: link_epoch_of(&last_link_epochs, slot),
        })
        .collect();
    // A closed slot's epoch was read before the roster, so a link of its that
    // activated and closed again between the two reads would leave the epoch
    // naming the earlier closure. The roster read is the one that found the slot
    // gone; no epoch moving between the first read and this one means no link of
    // the slot activated across it, so the epoch read first is still the latest
    // and names the closure the roster saw. A moved epoch is a membership change
    // like any other across the fence, and withholds the live verdict.
    let epochs_after = decision_makers.last_link_epochs(&key);
    let closed_epochs_settled = closed_slots
        .iter()
        .all(|closed| link_epoch_of(&epochs_after, closed.slot) == closed.link_epoch);
    FencedLoadState {
        state,
        fenced_live: every_probe_acked && every_live_link_fenced && closed_epochs_settled,
        closed_slots,
    }
}

/// The epoch recorded for `slot` in an ascending `(slot, epoch)` list.
fn link_epoch_of(epochs: &[(SlotId, u64)], slot: SlotId) -> Option<u64> {
    epochs
        .binary_search_by_key(&slot, |(entry, _)| *entry)
        .ok()
        .map(|index| epochs[index].1)
}

/// Assembles one [`SessionPresence`] from a session's key, its connected slots, and
/// the retained state selected for that report. Heartbeats attach bounded paired
/// observations after assembling progress; requested snapshots carry every observation.
fn presence_entry(key: SessionKey, slots: Vec<SlotId>, load: RetainedLoadState) -> SessionPresence {
    SessionPresence {
        evidence_history: load.evidence_history,
        periodic_evidence: load.periodic_evidence,
        tenant: key.tenant,
        session: key.session,
        slots,
        ever_connected: load.ever_connected,
        started: load.started,
        forwarded: load.forwarded,
        lobby_violations: load.lobby_violations,
        evidence: load.evidence,
        started_at_ms: load.started_at_ms,
    }
}

/// Snapshots the region-ping cache into the [`RegionRttReport`] entries a heartbeat
/// carries — one per region the relay currently has a measured median for, sorted
/// by region id so the beat's wire output is deterministic. Empty until the relay
/// has measured anything, and empty entries are omitted from the wire.
pub(super) fn heartbeat_region_rtts(cache: &RegionRttCache) -> Vec<RegionRttReport> {
    let mut reports: Vec<RegionRttReport> = cache
        .snapshot()
        .into_iter()
        .map(|(region, rtt_ms)| RegionRttReport { region, rtt_ms })
        .collect();
    reports.sort_by(|a, b| a.region.0.cmp(&b.region.0));
    reports
}
