//! Shared fixtures for the mesh tests, plus the per-topic test modules.
//!
//! Each child starts with `use super::*;`, which picks up this module's glob of
//! the mesh crate module along with the explicit imports below and the
//! fixtures here.

use super::*;

use std::collections::BTreeSet;

use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{
    FinalizeDrop, FinalizeDropResult, GameChat, LeaveDirective, LinkConditions, LobbyCommand,
    MeshControlFrame, Payload, PlayerSkin, RequestDrop, SlotConditions, SlotConnectivity,
    SlotDeparted, SlotStarted, mesh_control_frame,
};
use tokio::sync::{Notify, mpsc};

use crate::routing::{self};

use super::dispatch::dispatch_mesh_control;
use super::fan_out::{apply_ack_cursors, fold_oversize_into_link, reconcile_ack_cursors};
use super::forward::{
    deliver_turn_to_locals, resume_replay_for_frame, send_resume_replay, send_turn_over_link,
};
use super::frames::*;
use super::join::{
    reconcile_leaves_on_join, reconcile_local_slots_on_join, reconcile_resume_cursors_on_join,
    reconcile_started_slots_on_join,
};
use super::link_run::{MeshMaintenanceTimer, defer_flush_after_send};
use super::links::{
    LeaseAwait, MESH_RTT_CACHE_TTL, MESH_UNACKED_WINDOW_CAP, MeshLinkRegistration, MeshRttCache,
    SessionState, await_while_current, mesh_window_exhausted, next_mesh_link_id,
};
use super::seen::{SPARSE_SEEN_CAP, SlotSeen};

mod delivery;
mod dispatch_frames;
mod dispatch_local;
mod drop_request;
mod fan_out_links;
mod finalize_drop;
mod gating;
mod join_reconcile;
mod leases;
mod leave_flow;
mod link_state;
mod registries;
mod seen_gate;

pub(super) fn control_key() -> SessionKey {
    SessionKey {
        tenant: rally_point_proto::control::TenantId("t".to_owned()),
        session: SessionId(1),
    }
}

/// Registers one link's `(forward, control)` pair into the mesh-links registry
/// and returns the receivers a test drains to observe what the link was told.
pub(super) fn register_link_channels(
    links: &MeshLinks,
    key: &SessionKey,
) -> (
    mpsc::Receiver<(SessionId, Payload)>,
    mpsc::UnboundedReceiver<MeshControlFrame>,
) {
    let (forward, forward_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    let (control, control_rx) = mpsc::unbounded_channel();
    links
        .lock()
        .entry(key.clone())
        .or_default()
        .push(MeshLinkTx {
            id: next_mesh_link_id(),
            forward,
            control,
            // Unobserved by every caller of this helper (none of them test
            // the reset signal); a fresh, otherwise-untouched `Notify` per
            // registration keeps them independent regardless.
            shutdown: Arc::new(Notify::new()),
        });
    (forward_rx, control_rx)
}

/// Bundles the registries a `dispatch_mesh_control` test already built
/// (so it can register members and observe echoes against them) into the
/// `MeshState` its signature now takes. `conditions` and `presence` are not
/// under test here, so fresh empty ones are enough.
pub(super) fn test_mesh_state(
    mesh_links: &MeshLinks,
    seen: &SeenRegistries,
    makers: &Arc<crate::consensus::DecisionMakers>,
    lobby: &crate::session::lobby::LobbyRegistry,
    chat: &crate::session::chat::ChatRegistry,
    skins: &crate::session::skin::SkinRegistry,
) -> MeshState {
    MeshState {
        links: mesh_links.clone(),
        current_links: Arc::new(Mutex::new(HashMap::new())),
        seen: seen.clone(),
        conditions: new_conditions_registry(),
        decision_makers: makers.clone(),
        presence: Arc::new(crate::session::presence::new_presence_registry()),
        lobby: lobby.clone(),
        chat: chat.clone(),
        skins: skins.clone(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
        // A zero unlock floor so a held drop is "past the floor" from the first
        // instant, letting a `RequestDrop` dispatch test drive the honor path
        // without a real wait. Tests that only hold and release a drop are
        // unaffected by the floor. The abandoned-session window keeps its
        // production value — no dispatch test drives that path.
        drop_holds: crate::session::drop_hold::DropHolds::new(
            std::time::Duration::ZERO,
            crate::session::drop_hold::ABANDONED_SESSION_TIMEOUT,
        ),
        turn_ring: crate::session::turn_ring::TurnRing::new(),
        provisional: crate::session::provisional::ProvisionalSessions::new(
            crate::session::provisional::PROVISIONAL_WINDOW,
        ),
        gates: crate::session::gate::SessionGates::default(),
        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
    }
}

/// Registers a single joined-session state for a mesh dispatch test, resolving
/// the frame's bare session id to `key` exactly as a post-`Join` driver would.
pub(super) fn joined_state(
    mesh_links: &MeshLinks,
    key: &SessionKey,
) -> HashMap<SessionId, SessionState> {
    let mut joined = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    joined
}
