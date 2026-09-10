//! The relay mesh: peer-relay links and a session-level forward-once gate.
//!
//! A relay's client edge ([`crate::routing`]) fans each validated turn out to the
//! session's local slots. The mesh adds a second fan-out path: to connected peer
//! relays, so a turn one relay receives from a local client reaches every other
//! relay's local clients too. Each relay↔relay link is a
//! [`MeshLink`](rally_point_transport::MeshLink) — one QUIC
//! connection shared across every game both relays jointly serve, with per-session
//! transport state.
//!
//! A locally originated turn is sent directly to every peer relay serving the
//! session. A receiving relay delivers it to local clients and stops it there;
//! turns are never re-forwarded relay-to-relay. [`MeshSeen`] is the defensive
//! session-level dedup across ingress instances — link replacement, resume replay,
//! and slot re-home overlap can still present the same `(slot, seq)` more than
//! once. It is distinct from the per-link `Dedup`, which drops redundant copies
//! within one connection.
//!
//! Mesh-link establishment uses a lower-id-dials-higher tie-break
//! ([`should_dial_mesh`](rally_point_transport::should_dial_mesh)): each relay
//! compares its own id to the peer's configured id and dials only when it is the
//! lower, so exactly one side connects and there is no two-way race to resolve
//! on the wire. Authenticated relay tokens and tenant binding land with the
//! coordinator (Phase 3); this increment has no auth token.

pub mod control;
pub mod dialer;
pub mod edge;

mod conditions;
mod dispatch;
mod dispatch_finalize;
mod fan_out;
mod forward;
mod frames;
mod join;
mod link_arms;
mod link_commands;
mod link_run;
mod links;
mod seen;

pub use conditions::{
    ConditionsRegistry, activate_conditions, new_conditions_registry, publish_conditions,
    snapshot_conditions, unpublish_conditions,
};
pub use fan_out::fan_out_to_mesh;
pub(crate) use fan_out::{
    broadcast_leaves, fan_out_chat, fan_out_delivery_cursors, fan_out_finalize_drop,
    fan_out_finalize_drop_result, fan_out_leave_directive, fan_out_lobby_command,
    fan_out_request_drop, fan_out_session_start, fan_out_skin, fan_out_slot_connectivity,
    fan_out_slot_departed, fan_out_slot_present, fan_out_slot_started,
};
pub(crate) use forward::deliver_mesh_turn;
pub use forward::forward_client_turn;
pub(crate) use frames::{
    FINALIZE_OUTCOME_FINALIZED, FINALIZE_OUTCOME_REJECTED_LIVE, FINALIZE_OUTCOME_REJECTED_NO_CURSOR,
};
pub use join::{SessionIdCollision, join_sessions};
pub use link_run::{MeshCommand, MeshControlIo, MeshLinkHandle, MeshLinkIo, run_mesh_link};
pub(crate) use links::{CurrentMeshLinks, command_channel, register_mesh_link, rtt_us};
pub use links::{
    IDLE_TIMEOUT, MeshLinkAdmission, MeshLinkAttempt, MeshLinkExit, MeshLinkLease, MeshLinkTx,
    MeshLinks, claim_mesh_link, claim_verified_mesh_link, new_mesh_link_attempt, new_mesh_links,
};
pub use seen::{
    Forwarded, MeshSeen, Seen, SeenRegistries, SlotReceipts, deregister_seen, forwarded_count,
    has_resumable_state, mark_seen, new_seen_registries, resume_cursor_snapshot, slot_receipts,
};

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_transport::MeshSessionKey;

use crate::routing::SessionKey;

/// Converts a relay-local [`SessionKey`] into the transport layer's
/// [`MeshSessionKey`] — the lightweight `(session, tenant)` pair `MeshLink`
/// keys its per-session transport state by. The relay always knows its own
/// session's tenant, so every mesh-link call this relay originates is
/// tenant-scoped; `MeshLink`'s own tenant-less path only ever arises from a
/// peer's wire packet that didn't stamp one (see `MeshSessionKey`'s own doc).
fn mesh_session_key(key: &SessionKey) -> MeshSessionKey {
    MeshSessionKey::new(key.session, key.tenant.as_ref())
}

/// The three mesh-related registries a relay thread needs: the live mesh links
/// (fan-out to peer relays), the session-level forward-once gate,
/// and the per-client conditions the mesh attaches to outgoing datagrams.
///
/// These are always created together, passed together, and used together, so
/// bundling them keeps the `serve` and `run_slot_link` signatures within the
/// argument-count the codebase holds elsewhere — no `#[allow(clippy::too_many_arguments)]`
/// needed. Clone the struct cheaply (each field is an `Arc`) to hand a copy to a
/// spawned task.
#[derive(Clone)]
pub struct MeshState {
    /// Channels to peer-relay mesh-link tasks, keyed by session.
    pub links: MeshLinks,
    /// Current process-local physical-link generation per peer relay.
    pub(crate) current_links: CurrentMeshLinks,
    /// Session-level duplicate gate across client and mesh ingress instances.
    pub seen: SeenRegistries,
    /// Per-slot link conditions the mesh attaches to outgoing datagrams.
    pub conditions: ConditionsRegistry,
    /// Per-session latency-buffer decision-makers. The slot-link and mesh-link
    /// tasks feed conditions in (home-client stats directly, peer-relay stats off
    /// the mesh sidecar) and stamp the authority's buffer changes onto the turns
    /// they forward. `MeshControl` creates and destroys the makers as descriptors
    /// arrive and sessions end; sharing the registry here is what lets the turn
    /// path reach them. Bundled with the mesh registries because it has the same
    /// per-session lifecycle and is threaded through the same tasks.
    pub decision_makers: Arc<crate::consensus::DecisionMakers>,
    /// Per-session presence (the authority order plus who still serves live
    /// players), driving the buffer-authority verdict. The slot-link tasks
    /// report the local roster into it, the mesh-link drivers deliver peers'
    /// reports, and `MeshControl` sets the order from each descriptor. Same
    /// per-session lifecycle and task-threading as the registries above.
    pub presence: Arc<crate::session::presence::PresenceRegistry>,
    /// Per-session lobby-command fan-out and its ordered replay log. The
    /// slot-link tasks deliver their clients' lobby commands into it (and register
    /// each member for replay), and the mesh-link drivers deliver peers' lobby
    /// commands into it. Bundled here, not because it is a mesh concern, but
    /// because it has the same per-session lifecycle and is threaded through the
    /// same two tasks as the registries above. See [`crate::session::lobby`].
    pub lobby: crate::session::lobby::LobbyRegistry,
    /// Per-session game-chat fan-out. The mid-game counterpart to `lobby`: the
    /// slot-link tasks deliver their clients' chat messages into it (and
    /// register each member to receive others'), and the mesh-link drivers
    /// deliver peers' messages into it. No replay log — chat is ephemeral —
    /// but the same per-session lifecycle and task-threading as `lobby`. See
    /// [`crate::session::chat`].
    pub chat: crate::session::chat::ChatRegistry,
    /// Per-session cosmetic-skin fan-out and its latest-blob-per-slot replay map.
    /// The slot-link tasks deliver their clients' skin blobs into it (and register
    /// each member to receive others' and replay the stored map), and the
    /// mesh-link drivers deliver peers' blobs into it. Bundled here for the same
    /// reason as `lobby` and `chat` — the same per-session lifecycle and
    /// task-threading, not because it is a mesh concern. See [`crate::session::skin`].
    pub skins: crate::session::skin::SkinRegistry,
    /// Per-relay holds on dropped slots' synced-leave decisions, plus the
    /// per-requester rate cap on the manual drop requests that resolve them. A slot
    /// that dropped (its link died) has its departure recorded and announced
    /// immediately, but the decision to remove it from lockstep is held here
    /// indefinitely — made only when a surviving member's `RequestDrop` is honored
    /// past the unlock floor, never on a timer; a clean leave bypasses the hold.
    /// Local and ephemeral — not replicated — so it lives beside the other
    /// registries only because it shares their per-session task-threading, not
    /// because it is a mesh concern. See [`crate::session::drop_hold`].
    pub drop_holds: crate::session::drop_hold::DropHolds,
    /// Per-session bounded record of the turns this relay has forwarded, so a
    /// client that dropped and re-dialed while its drop was undecided can be replayed
    /// the turns it missed and catch its sim up. Local and ephemeral like `drop_holds`, and
    /// threaded through the same per-session tasks (the turn forward path records
    /// into it; a re-register reads from it). See [`crate::session::turn_ring`].
    pub turn_ring: crate::session::turn_ring::TurnRing,
    /// Provisional-admission deadlines: a session a client admitted with no
    /// applied descriptor yet is marked here, and the relay's periodic sweep
    /// tears it down if no descriptor claims it in time. Local and ephemeral
    /// like `drop_holds`, and threaded through the same admission and
    /// descriptor-apply paths. See [`crate::session::provisional`].
    pub provisional: crate::session::provisional::ProvisionalSessions,
    /// The per-session terminal ingress boundary: client admission, the turn
    /// funnel, and mesh dispatch all run their critical sections through it,
    /// and descriptor retirement marks a session retired under its write side
    /// before sweeping any state — so no ingress can resurrect what a
    /// retirement removed. Shared with `MeshControl` (which retires and
    /// reopens) and the flight recorder (whose create-on-first-touch consults
    /// it). See [`crate::session::gate`].
    pub gates: crate::session::gate::SessionGates,
    /// The holding pen for pre-descriptor client turns: while a session has
    /// no decision-maker, the turn funnel deposits turns here instead of
    /// fanning them out, and descriptor application drains them through the
    /// ordinary forward path — where freshly seeded decided leaves fence a
    /// departed slot's turns. Armed only on a coordinator-managed relay
    /// (`main.rs`); disarmed (every test constructor), the funnel behaves
    /// exactly as before. See [`crate::session::provisional_turns`].
    pub provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen,
    /// The load-state fence broker: the outstanding stream-position probes this
    /// relay has sent its local slots while answering a coordinator load-state
    /// question. Bundled here because the slot-link tasks are where the clients'
    /// acks land and this is the bundle those tasks already receive — it has no
    /// per-session lifecycle of its own and is not a mesh concern. See
    /// [`crate::coordinator::load_fence`].
    pub load_fence: crate::coordinator::load_fence::LoadStateFence,
}

/// Creates a `MeshState` with empty registries for a relay that has no peer-relay
/// links, no sessions, and no local clients yet.
pub fn new_mesh_state() -> MeshState {
    new_mesh_state_with_timings(
        crate::session::drop_hold::DROP_UNLOCK,
        crate::session::drop_hold::ABANDONED_SESSION_TIMEOUT,
    )
}

/// [`new_mesh_state`] with an explicit drop-unlock floor, so a test can inject a
/// tiny floor and drive the honor-a-drop-request path without waiting out the
/// production 30-second window. The abandoned-session window keeps its production
/// value.
pub fn new_mesh_state_with_drop_unlock(unlock: std::time::Duration) -> MeshState {
    new_mesh_state_with_timings(unlock, crate::session::drop_hold::ABANDONED_SESSION_TIMEOUT)
}

/// [`new_mesh_state`] with an explicit provisional-admission window, so a test
/// can drive a client-admitted, undescribed session to its deadline without
/// waiting out the production 10-second window. Every other timing keeps its
/// production value.
pub fn new_mesh_state_with_provisional_window(window: std::time::Duration) -> MeshState {
    MeshState {
        provisional: crate::session::provisional::ProvisionalSessions::new(window),
        ..new_mesh_state()
    }
}

/// [`new_mesh_state`] with an explicit provisional-journal session ceiling,
/// so a test can drive the admission-time capacity refusal without four
/// thousand fixture sessions. The pen is NOT armed — arm it explicitly, as
/// production wiring does. Every other setting keeps its production value.
pub fn new_mesh_state_with_journal_ceiling(max_sessions: usize) -> MeshState {
    MeshState {
        provisional_turns:
            crate::session::provisional_turns::ProvisionalTurnPen::with_session_ceiling(
                max_sessions,
            ),
        ..new_mesh_state()
    }
}

/// [`new_mesh_state`] with an explicit region-label release delay, so a test can
/// drive the release path without waiting out the production
/// [`crate::consensus::REGION_LABEL_RELEASE_DELAY`]. Every other timing keeps its
/// production value.
pub fn new_mesh_state_with_region_release_delay(delay: std::time::Duration) -> MeshState {
    MeshState {
        decision_makers: Arc::new(crate::consensus::new_decision_makers_with_region_delay(
            delay,
        )),
        ..new_mesh_state()
    }
}

/// [`new_mesh_state`] with both drop-decision windows injected — the manual-drop
/// unlock floor and the fully-abandoned-session timeout — so a test can drive
/// either auto-decision path on a tiny window rather than the production waits.
/// Production builds it through [`new_mesh_state`] with the real constants.
pub fn new_mesh_state_with_timings(
    unlock: std::time::Duration,
    abandon_timeout: std::time::Duration,
) -> MeshState {
    MeshState {
        links: new_mesh_links(),
        current_links: Arc::new(Mutex::new(HashMap::new())),
        seen: new_seen_registries(),
        conditions: new_conditions_registry(),
        decision_makers: Arc::new(crate::consensus::new_decision_makers()),
        presence: Arc::new(crate::session::presence::new_presence_registry()),
        lobby: crate::session::lobby::new_lobby_registry(),
        chat: crate::session::chat::new_chat_registry(),
        skins: crate::session::skin::new_skin_registry(),
        drop_holds: crate::session::drop_hold::DropHolds::new(unlock, abandon_timeout),
        turn_ring: crate::session::turn_ring::TurnRing::new(),
        provisional: crate::session::provisional::ProvisionalSessions::new(
            crate::session::provisional::PROVISIONAL_WINDOW,
        ),
        gates: crate::session::gate::SessionGates::default(),
        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    }
}

#[cfg(test)]
mod tests;
