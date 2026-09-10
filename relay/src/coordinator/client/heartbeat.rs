//! What the relay tells the coordinator about the sessions it holds: the periodic
//! heartbeat's roster and the answer to a one-session load-state question.
//!
//! Both are built from the same two sources — the live routing roster and the
//! per-session decision-makers — through one shared presence builder, so a beat's
//! entry and an attested snapshot can never drift apart. The load-state side adds
//! the fence: probe every slot that could still be holding a report back, wait for
//! the acks off the connection's write half, and only then snapshot.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rally_point_proto::control::{RegionRttReport, SessionPresence};
use rally_point_proto::ids::SlotId;
use tokio::sync::mpsc::Sender;
use tokio::time::Instant;

use crate::consensus::RetainedLoadState;
use crate::coordinator::region_ping::RegionRttCache;
use crate::routing::{SessionKey, Sessions};

use super::{HeartbeatSources, LOAD_STATE_FENCE_TIMEOUT};

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
/// The roster is the whole current truth every time, load state included: a beat
/// restates every session's full sets rather than reporting what changed, so a
/// lost or reordered beat is corrected by the next one.
pub(super) fn heartbeat_presence(sources: &HeartbeatSources) -> Vec<SessionPresence> {
    let mut live: HashMap<SessionKey, _> = crate::routing::live_slots(&sources.sessions)
        .into_iter()
        .collect();
    let mut roster: Vec<SessionPresence> =
        crate::consensus::retained_load_states(&sources.decision_makers)
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
    roster
}

/// Snapshots what this relay holds for **one** session, in the same
/// [`SessionPresence`] shape a heartbeat's roster entry carries — the answer to a
/// [`CoordinatorToRelay::LoadStateRequest`](rally_point_proto::control::CoordinatorToRelay::LoadStateRequest).
///
/// Reads exactly the two sources a beat reads, so an attested snapshot and a
/// restated one describe the session identically: the session's currently-connected
/// slots from the live roster, and its retained load state from its decision-maker.
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
pub(super) fn session_load_snapshot(
    sessions: &Sessions,
    decision_makers: &crate::consensus::DecisionMakers,
    key: SessionKey,
) -> (SessionPresence, Vec<(SlotId, u64)>) {
    let links = crate::routing::live_session_slot_epochs(sessions, &key);
    let load = crate::consensus::retained_load_state(decision_makers, &key);
    (
        presence_entry(key, links.iter().map(|(slot, _)| *slot).collect(), load),
        links,
    )
}

/// A finished load-state answer, handed from a fence task back to the write half
/// that sends it. Carries the fence verdict beside the snapshot because the two are
/// one claim: the sets say what this relay saw, and `fenced` says whether it could
/// rule out a slot's report still sitting in that slot's client.
pub(super) struct LoadStateAnswer {
    /// The coordinator's correlation id, echoed back on the snapshot.
    pub(super) request_id: u64,
    /// What this relay holds for the session, read after the fence resolved.
    pub(super) state: SessionPresence,
    /// Whether every slot that could be holding something back was proven not to
    /// be (see [`fenced_load_state_snapshot`]).
    pub(super) fenced: bool,
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
    let fence = sources.load_fence.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let (state, fenced) =
            fenced_load_state_snapshot(&sessions, &decision_makers, &fence, ask.key).await;
        if answers
            .try_send(LoadStateAnswer {
                request_id: ask.request_id,
                state,
                fenced,
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
/// The verdict is `true` only when all of these hold:
///
/// - every probe issued was acked within [`LOAD_STATE_FENCE_TIMEOUT`] — a probe no
///   stream would take, or one that went unanswered, leaves that slot unfenced;
/// - every slot live at the *end* that has not started acked a probe issued
///   against the epoch it still holds, so a slot that arrived mid-fence (never
///   probed) and one whose link was replaced after acking (probed on the epoch
///   before) both spoil the verdict; and
/// - no slot this relay has ever seen connect is now disconnected without having
///   started. Such a slot has no stream to probe and its client may be holding a
///   report for the stream it opens next, so it can never be fenced.
///
/// So any membership change across the fence yields `false` and the tenant's next
/// read simply asks again — the answer's facts are unaffected, only the licence to
/// read its absences as proof.
///
/// A slot that never connected here is not probed and does not spoil the verdict:
/// no client ever held a stream to this relay for it, so there is nothing of its to
/// be queued anywhere and its absence is attestable as it stands.
pub(super) async fn fenced_load_state_snapshot(
    sessions: &Sessions,
    decision_makers: &crate::consensus::DecisionMakers,
    fence: &crate::coordinator::load_fence::LoadStateFence,
    key: SessionKey,
) -> (SessionPresence, bool) {
    let started: HashSet<SlotId> = crate::consensus::retained_load_state(decision_makers, &key)
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
    let deadline = Instant::now() + LOAD_STATE_FENCE_TIMEOUT;
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
    let (state, links) = session_load_snapshot(sessions, decision_makers, key);
    let every_live_link_fenced = links
        .iter()
        .all(|(slot, epoch)| state.started.contains(slot) || acked.get(slot) == Some(epoch));
    let unfenceable = state
        .ever_connected
        .iter()
        .any(|slot| !state.slots.contains(slot) && !state.started.contains(slot));
    (
        state,
        every_probe_acked && every_live_link_fenced && !unfenceable,
    )
}

/// Assembles one [`SessionPresence`] from a session's key, its connected slots, and
/// the load state its decision-maker retained — the single place the wire shape is
/// built, so a heartbeat's roster entry and an attested snapshot can never drift
/// apart in what they report.
fn presence_entry(key: SessionKey, slots: Vec<SlotId>, load: RetainedLoadState) -> SessionPresence {
    SessionPresence {
        tenant: key.tenant,
        session: key.session,
        slots,
        ever_connected: load.ever_connected,
        started: load.started,
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
