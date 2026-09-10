//! What a freshly registered link replays to converge: the leave, slot,
//! started-report and resume-cursor re-sends a Join enqueues, the presence
//! push that carries a session's live-player count, and the batch
//! session-id collision guard.

use std::collections::HashMap;

use rally_point_proto::ids::{SessionId, SlotId};

use crate::routing::{self, SessionKey};

use super::conditions::ConditionsRegistry;
use super::frames::*;
use super::links::{MeshControlTx, MeshLinks};
use super::seen::{SeenRegistries, has_resumable_state, resume_cursor_snapshot};

/// Re-sends this relay's known leave state for `key` down a freshly registered
/// link's control channel, so a link that died and redialed converges. Every
/// recorded departure goes out as a `SlotDeparted` and every cached directive as
/// a `LeaveDirective`, unconditionally — a leave is pushed once at decision time
/// and re-pushed on every link re-join (and on an authority promotion); the relay
/// has no sound way to tell "every survivor applied it" from "every survivor is
/// still stalled waiting for it", so it never tries. All idempotent (dedup by
/// slot on receipt) and cheap — a session has <=12 slots and leaves are rare.
pub(super) fn reconcile_leaves_on_join(
    decision_makers: &crate::consensus::DecisionMakers,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let (departures, directives) = crate::consensus::leave_reconcile(decision_makers, key);
    // Unbounded send only fails on a closed channel; the driver we are
    // registering into is alive here, so these always enqueue.
    for (slot, stamps, reason, connection_epoch) in departures {
        let _ = control_tx.send(slot_departed_frame(
            key.session,
            slot,
            &stamps,
            reason,
            connection_epoch,
        ));
    }
    for leave in directives {
        let _ = control_tx.send(leave_directive_frame(key.session, leave));
    }
    // If the session already started, re-send the directive down the fresh link
    // too: a peer relay that dialed in (or redialed) after the authority fired
    // would otherwise never hear it, stranding its local slots. Idempotent — a
    // relay that already started latches it again and re-fans to its own locals.
    // Carries this relay's stored initial buffer depth, which is `None` on a
    // resumed relay (it never sized one), so a re-push into a running game never
    // resizes a live buffer.
    if crate::consensus::session_started(decision_makers, key) {
        let initial_buffer_turns =
            crate::consensus::session_initial_buffer_turns(decision_makers, key);
        let _ = control_tx.send(session_start_frame(key.session, initial_buffer_turns));
    }
}

/// Replays every active home-client slot and connection generation to a mesh
/// peer after Join, or after that peer proves its own Join via initial presence.
///
/// The conditions registry is the linearization point deliberately: a slot is
/// activated there immediately before its live `SlotPresent`, and retired there
/// before its terminal departure is announced. Holding its lock through these
/// synchronous enqueues means a concurrent slot transition falls wholly before
/// or after the replay, never departure-then-stale-present. A slot whose setup
/// has not activated yet will announce normally after this link registration.
/// Duplicate replays are harmless because peer slot presence is set-valued.
pub(super) fn reconcile_local_slots_on_join(
    conditions: &ConditionsRegistry,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let roster = conditions.lock();
    let mut slots: Vec<(SlotId, Option<u64>)> = roster
        .get(key)
        .into_iter()
        .flat_map(|slots| slots.iter())
        .map(|(&slot, conditions)| (slot, conditions.connection_epoch))
        .collect();
    slots.sort_by_key(|(slot, _)| *slot);
    for (slot, epoch) in slots {
        let _ = control_tx.send(slot_present_frame(key.session, slot));
        if let Some(epoch) = epoch {
            let _ = control_tx.send(slot_connectivity_frame(
                key.session,
                slot,
                true,
                Some(epoch),
            ));
        }
    }
}

/// Re-shares every game-started report this relay's own home clients made for
/// `key` down a freshly registered link's control channel, so a peer that joined
/// the mesh after those reports — or a relay that replaced one — converges on the
/// full set instead of treating those slots as still loading forever. First-hand
/// reports only: a relay never re-shares a peer's, so nothing loops the mesh.
/// Idempotent on receipt (the accumulated set is a set) and cheap — a session has
/// <=12 slots.
pub(super) fn reconcile_started_slots_on_join(
    decision_makers: &crate::consensus::DecisionMakers,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    for slot in crate::consensus::started_home_slots(decision_makers, key) {
        let _ = control_tx.send(slot_started_frame(key.session, slot));
    }
}

/// Sends this relay's resume cursors for `key` down a freshly registered
/// link's control channel — the mesh counterpart of
/// [`reconcile_leaves_on_join`], closing the gap a redialed link's fresh
/// transport state otherwise leaves: turns in flight or queued at the moment
/// the old link died are gone from that link's own state, but this session's
/// forward-gate cursors survive it (see [`resume_cursor_snapshot`]), so the
/// fresh link can still ask for exactly what's missing. Every Join sends one.
///
/// The frame's `resuming` flag ([`has_resumable_state`]) is what keeps a
/// first join and a real mid-game recovery from being confused with each
/// other even though both can produce the exact same (empty) cursor list: a
/// first join has no forward-gate entry at all, so `resuming` is `false` and
/// the empty cursors ask for nothing; a session recovering from a death whose
/// every slot happens to be gapped or never-seen also has an empty cursor
/// list, but its forward-gate entry exists (`resuming` true), so the SAME
/// empty list instead asks the peer to replay every slot it can, from the
/// start.
pub(super) fn reconcile_resume_cursors_on_join(
    seen: &SeenRegistries,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let cursors = resume_cursor_snapshot(seen, key);
    let resuming = has_resumable_state(seen, key);
    let _ = control_tx.send(resume_cursors_frame(key.session, cursors, resuming));
}

/// Reads one joined session's authoritative local-player count. Kept separate
/// from the reliable-stream write so the short roster lock is never held over
/// an await.
pub(super) fn local_live_players(sessions: &routing::Sessions, key: &SessionKey) -> u32 {
    let roster = sessions.lock();
    roster.get(key).map_or(0, |slots| slots.len() as u32)
}

/// Pushes the presence changes a link-wide maintenance pass collected, the
/// initial report a Join produced, or a one-shot Join-rendezvous reply. Regular
/// maintenance is push-on-change over a reliable stream, so a stable roster
/// writes nothing; the rendezvous deliberately repeats the current value after
/// the peer proves it has joined. `presence_sent` advances only after its frame
/// was written successfully.
///
/// An `Err` means the stream (and so the connection) is gone; the caller exits
/// with `ConnectionFailed` like any other send failure.
pub(super) async fn push_presence_updates(
    presence_tx: &mut rally_point_transport::noq::SendStream,
    presence_sent: &mut HashMap<SessionId, u32>,
    updates: &[(SessionId, u32)],
) -> Result<(), rally_point_transport::noq::WriteError> {
    for &(session_id, live) in updates {
        let frame = rally_point_proto::mesh::MeshPresence {
            session: session_id,
            live_players: live,
        }
        .encode();
        presence_tx.write_all(&frame).await?;
        presence_sent.insert(session_id, live);
    }
    Ok(())
}

/// Validates a list of sessions for a mesh link, refusing if two tenants share
/// the same session id — the wire's bare `session: u64` can't disambiguate them,
/// so the second is refused rather than overwriting the first.
///
/// A batch pre-validation helper: a caller that collected a session list before
/// driving the link can refuse the whole batch at once. `run_mesh_link` runs the
/// same check on every `Join`, so a caller that sends sessions one at a time —
/// or skips this helper — still can't silently cross-wire tenants.
pub fn join_sessions(links: &MeshLinks, keys: &[SessionKey]) -> Result<(), SessionIdCollision> {
    let mut roster = links.lock();
    let mut seen: HashMap<
        rally_point_proto::ids::SessionId,
        &rally_point_proto::control::TenantId,
    > = HashMap::new();
    for key in keys {
        if let Some(existing_tenant) = seen.get(&key.session)
            && **existing_tenant != key.tenant
        {
            return Err(SessionIdCollision {
                session: key.session,
                existing_tenant: (*existing_tenant).clone(),
                new_tenant: key.tenant.clone(),
            });
        }
        seen.insert(key.session, &key.tenant);
        roster.entry(key.clone()).or_default();
    }
    Ok(())
}

/// A session id collision: the wire's bare `session: u64` can't disambiguate
/// two tenants that both assigned the same number. The second join is refused.
#[derive(Debug, thiserror::Error)]
#[error(
    "session id {session} collision: already joined by tenant {existing_tenant:?}, refused for {new_tenant:?}"
)]
pub struct SessionIdCollision {
    pub session: rally_point_proto::ids::SessionId,
    pub existing_tenant: rally_point_proto::control::TenantId,
    pub new_tenant: rally_point_proto::control::TenantId,
}
