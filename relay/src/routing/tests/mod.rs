//! Shared fixtures for the routing tests: the session key and payloads every
//! topic builds on, the drop-hold and abandoned-session harnesses that stand up
//! a single-relay authority, and the timing knobs that make the hold and abandon
//! windows drivable without real waits.

use super::*;

use rally_point_proto::control::TenantId;
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
mod silence;

pub(super) use crate::test_support::{seed_maker, session_key};

pub(super) fn key() -> SessionKey {
    session_key(1)
}

/// Registers `slot` for `key` and hands back its inbox with the registration
/// guard disarmed — the shape of every test that just wants a slot on the
/// roster, the guard's own free-on-drop behavior having its own tests in
/// `roster.rs`.
pub(super) fn registered(sessions: &Sessions, key: &SessionKey, slot: SlotId) -> SlotInbox {
    let (mut guard, inbox) = register(sessions, key, slot, 1).expect("the slot registers");
    guard.disarm();
    inbox
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
use crate::session::{SessionState, Tunables};

/// A drop-unlock floor a test can never reach by waiting, so a `RequestDrop`
/// before it is provably refused.
pub(super) const UNREACHABLE_UNLOCK: Duration = Duration::from_secs(3600);

/// A zero unlock floor, so a held drop is "past the floor" from the first
/// instant and a `RequestDrop` is honored without any wait.
pub(super) const IMMEDIATE_UNLOCK: Duration = Duration::ZERO;
/// A stood-up single-relay session for the departure and drop-request tests:
/// the shared registries the drop paths read, plus the survivor slot's inbox,
/// where a decided leave lands.
pub(super) struct DropHarness {
    pub(super) sessions: Sessions,
    pub(super) mesh_links: crate::mesh::MeshLinks,
    pub(super) makers: Arc<crate::consensus::DecisionMakers>,
    pub(super) seen: crate::mesh::SeenRegistries,
    pub(super) inbox: SlotInbox,
}

impl DropHarness {
    /// The `MeshState` the drop paths take, carrying this harness's registries
    /// plus the caller's holds and leaving every registry the test doesn't
    /// drive at its empty default. Every field is a shared handle, so the
    /// test's own bindings and the bundle observe the same state.
    pub(super) fn mesh(&self, holds: &DropHolds) -> crate::mesh::MeshState {
        crate::mesh::MeshState {
            links: self.mesh_links.clone(),
            seen: self.seen.clone(),
            session: SessionState {
                drop_holds: holds.clone(),
                decision_makers: Arc::clone(&self.makers),
                ..SessionState::default()
            },
            ..crate::mesh::MeshState::default()
        }
    }
}

/// Stands up a single-relay authority maker for `key` with a frame basis, plus
/// a survivor slot registered so a decided leave has somewhere to fan out. The
/// departing slot is given an observed frame too, so `decide_leave` schedules
/// against it.
///
/// `finalized_homes` is `None` for an ordinary session and `Some(slots)` for
/// one running the home-side finalization handshake, where this relay strictly
/// homes exactly `slots` — the only axis the two shapes differ on.
pub(super) fn drop_hold_harness(
    key: &SessionKey,
    survivor: SlotId,
    departing: SlotId,
    finalized_homes: Option<&[u8]>,
) -> DropHarness {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let seen = crate::mesh::new_seen_registries();
    let _ = consensus::sync_maker(
        &makers,
        key,
        consensus::MakerSync {
            homed_slots: finalized_homes
                .unwrap_or(&[])
                .iter()
                .map(|&s| SlotId(s))
                .collect(),
            finalized_drops: finalized_homes.is_some(),
            ..consensus::MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
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
    DropHarness {
        sessions,
        mesh_links,
        makers,
        seen,
        inbox,
    }
}

// -- fully-abandoned session teardown --

/// A short abandoned-session window for tests, so a timer's own sleep is the
/// first deadline a paused clock advances to rather than the production 45
/// seconds' worth of virtual time.
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
        links: mesh_links.clone(),
        session: SessionState {
            drop_holds: holds.clone(),
            decision_makers: Arc::clone(makers),
            presence: Arc::clone(presence),
            ..SessionState::default()
        },
        ..crate::mesh::MeshState::default()
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
    use rally_point_proto::ids::GameFrameCount;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let presence = Arc::new(crate::session::presence::new_presence_registry());
    seed_maker(&makers, &k, Authority::SelfRelay, &[0, 1], &[]);
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
