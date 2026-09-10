//! Shared fixtures for the routing tests: the session key and payloads every
//! topic builds on, the drop-hold and abandoned-session harnesses that stand up
//! a single-relay authority, and the timing knobs that make the hold and abandon
//! windows drivable without real waits.

use super::*;

use std::sync::atomic::Ordering;

use rally_point_transport::Received;

use crate::consensus;
use crate::consensus::{LEAVE_REASON_DROPPED, LEAVE_REASON_LEFT, MAX_GAME_RESULT_PAYLOAD_LEN};

use super::departure::{decide_and_broadcast_abandoned, report_own_presence};
use super::drops::handle_drop_request;
use super::forward::game_result_admissible;
use super::registry::deregister;
use super::slot_link::{end_slot_link, should_sample_active_conditions};

mod abandoned;
mod drop_holds;
mod finalized_drops;
mod forward_queue;
mod phase;
mod reconnect_races;
mod roster;
mod session_close;

pub(super) fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(1),
    }
}

pub(super) fn payload() -> Payload {
    Payload {
        seq: 0,
        slot: 0,
        commands: Vec::new().into(),
        ..Default::default()
    }
}

/// A payload carrying `len` command bytes, for exercising the forward queue's
/// resident-byte budget (the only field the budget measures).
pub(super) fn payload_of(len: usize) -> Payload {
    Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; len].into(),
        ..Default::default()
    }
}

// -- drop holds, manual drop requests, and connectivity fan-out --

use crate::session::drop_hold::DropHolds;

/// A drop-unlock floor a test can never reach by waiting, so a `RequestDrop`
/// before it is provably refused.
pub(super) const UNREACHABLE_UNLOCK: Duration = Duration::from_secs(3600);

/// A zero unlock floor, so a held drop is "past the floor" from the first
/// instant and a `RequestDrop` is honored without any wait.
pub(super) const IMMEDIATE_UNLOCK: Duration = Duration::ZERO;
/// Stands up a single-relay authority maker for `key` with a frame basis, plus
/// a survivor slot registered so a decided leave has somewhere to fan out. The
/// departing slot is given an observed frame too, so `decide_leave` schedules
/// against it. Returns the shared registries and the survivor's inbox.
/// Like [`drop_hold_harness`], but the session runs the finalized-drop
/// handshake and this relay strictly homes `homed`.
pub(super) fn finalized_drop_harness(
    key: &SessionKey,
    survivor: SlotId,
    departing: SlotId,
    homed: &[u8],
) -> (
    Sessions,
    crate::mesh::MeshLinks,
    Arc<crate::consensus::DecisionMakers>,
    crate::mesh::SeenRegistries,
    SlotInbox,
) {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let seen = crate::mesh::new_seen_registries();
    let _ = consensus::sync_maker(
        &makers,
        key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        homed.iter().map(|&s| SlotId(s)).collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    consensus::observe_frame(
        &makers,
        key,
        survivor,
        rally_point_proto::ids::GameFrameCount(40),
    );
    consensus::observe_frame(
        &makers,
        key,
        departing,
        rally_point_proto::ids::GameFrameCount(50),
    );
    let (mut guard, inbox) = register(&sessions, key, survivor, 1).expect("survivor registers");
    guard.disarm();
    (sessions, mesh_links, makers, seen, inbox)
}
pub(super) fn drop_hold_harness(
    key: &SessionKey,
    survivor: SlotId,
    departing: SlotId,
) -> (
    Sessions,
    crate::mesh::MeshLinks,
    Arc<crate::consensus::DecisionMakers>,
    SlotInbox,
) {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let _ = consensus::sync_maker(
        &makers,
        key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    // Both slots have framed history: the survivor pins a session frame and the
    // departing slot gives the leave its apply-frame basis.
    consensus::observe_frame(
        &makers,
        key,
        survivor,
        rally_point_proto::ids::GameFrameCount(40),
    );
    consensus::observe_frame(
        &makers,
        key,
        departing,
        rally_point_proto::ids::GameFrameCount(50),
    );

    let (mut guard, inbox) = register(&sessions, key, survivor, 1).expect("survivor registers");
    guard.disarm();
    (sessions, mesh_links, makers, inbox)
}
// -- fully-abandoned session teardown --

/// A short abandoned-session window for tests, so the timer path can be driven
/// with a real (tiny) sleep rather than the production 45 seconds.
pub(super) const TINY_ABANDON: Duration = Duration::from_millis(80);

/// Bundles individually-constructed registries into the `MeshState` that
/// `report_own_presence` / `reconcile_abandon` take, leaving the registries a
/// test doesn't drive at their empty defaults. Every field is a shared
/// handle, so the test's own bindings and the bundle observe the same state.
pub(super) fn mesh_with(
    holds: &DropHolds,
    makers: &Arc<crate::consensus::DecisionMakers>,
    mesh_links: &crate::mesh::MeshLinks,
    presence: &Arc<crate::session::presence::PresenceRegistry>,
) -> crate::mesh::MeshState {
    crate::mesh::MeshState {
        drop_holds: holds.clone(),
        decision_makers: Arc::clone(makers),
        links: mesh_links.clone(),
        presence: Arc::clone(presence),
        ..crate::mesh::new_mesh_state()
    }
}

/// A started, single-relay authority session over slots {0, 1} with a frame
/// basis for each and this relay's presence order set to itself. No departures
/// are recorded — each test records exactly the ones it needs and drives the
/// own-roster presence count. Returns the registries the abandoned-session tests
/// reconcile against.
pub(super) fn abandoned_harness() -> (
    Arc<crate::session::presence::PresenceRegistry>,
    Sessions,
    crate::mesh::MeshLinks,
    Arc<crate::consensus::DecisionMakers>,
    SessionKey,
) {
    use crate::consensus::{self, Authority};
    use crate::session::presence::Candidate;
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let presence = Arc::new(crate::session::presence::new_presence_registry());
    let _ = consensus::sync_maker(
        &makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&makers, &k);
    consensus::observe_frame(&makers, &k, SlotId(0), GameFrameCount(50));
    consensus::observe_frame(&makers, &k, SlotId(1), GameFrameCount(50));
    crate::session::presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);
    crate::session::presence::record_own(&presence, &k, 1);
    (presence, sessions, mesh_links, makers, k)
}

/// Records `slot` as a dropped departure and marks its hold — the maker/hold
/// state `announce_departure` leaves behind for a disconnected slot.
pub(super) fn drop_slot(
    makers: &Arc<crate::consensus::DecisionMakers>,
    holds: &DropHolds,
    k: &SessionKey,
    slot: SlotId,
) {
    crate::consensus::record_departure(
        makers,
        k,
        slot,
        crate::consensus::DepartureStamps {
            last_frame: Some(rally_point_proto::ids::GameFrameCount(50)),
            ..Default::default()
        },
        LEAVE_REASON_DROPPED,
    );
    holds.hold(k.clone(), slot);
}

/// Leaves `slot` departed with its hold already gone: undecided, so it arms
/// the abandoned-session timer, but promising no reconnect, so the
/// session-emptied close runs instead of deferring — the state a departure
/// whose hold has been released leaves behind.
pub(super) fn depart_slot_unheld(
    makers: &Arc<crate::consensus::DecisionMakers>,
    holds: &DropHolds,
    k: &SessionKey,
    slot: SlotId,
) {
    drop_slot(makers, holds, k, slot);
    assert!(holds.release(k, slot), "the departure's hold is released");
}

/// Drains `rx` and counts the session-closed notices in it.
pub(super) fn closes_reported(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::consensus::RelayNotice>,
) -> usize {
    let mut closes = 0;
    while let Ok(notice) = rx.try_recv() {
        if matches!(notice, crate::consensus::RelayNotice::SessionClosed { .. }) {
            closes += 1;
        }
    }
    closes
}
