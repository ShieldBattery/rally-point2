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
//! on the wire. An accepted peer's claimed id is then pinned against the leaf
//! certificate the coordinator's fleet-peer push recorded for it (see
//! `edge::verify_mesh_peer_identity`), so a relay cannot join the mesh as an id
//! it does not hold the key for. The dev/loopback static mesh receives no such
//! push and stays unauthenticated unless `--require-mesh-peer-auth` forces the
//! check to fail closed.

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

use crate::key::SessionKey;
use crate::session::SessionState;

/// Converts a relay-local [`SessionKey`] into the transport layer's
/// [`MeshSessionKey`] — the lightweight `(session, tenant)` pair `MeshLink`
/// keys its per-session transport state by. The relay always knows its own
/// session's tenant, so every mesh-link call this relay originates is
/// tenant-scoped; `MeshLink`'s own tenant-less path only ever arises from a
/// peer's wire packet that didn't stamp one (see `MeshSessionKey`'s own doc).
fn mesh_session_key(key: &SessionKey) -> MeshSessionKey {
    MeshSessionKey::new(key.session, key.tenant.as_ref())
}

/// The mesh's own per-session registries, plus the session state the tasks that
/// carry them also need.
///
/// The first four fields are the mesh proper — the live peer-relay links, the
/// session-level forward-once gate, the link conditions the mesh attaches to
/// outgoing datagrams, and the peer-generation map behind them. `session` is
/// everything else a session needs ([`SessionState`]), held here because
/// `run_slot_link` and `run_mesh_link` each need both halves and would
/// otherwise take them apart argument by argument. A function that needs only
/// the session half takes `&SessionState` and is called with `&mesh.session`.
///
/// Clone the struct cheaply (each field is an `Arc` or a handle around one) to
/// hand a copy to a spawned task.
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
    /// Everything this relay holds for a session that is not a mesh concern.
    pub session: SessionState,
}

impl Default for MeshState {
    /// Empty mesh registries beside a production [`SessionState`] — a relay
    /// with no peer-relay links, no sessions, and no local clients yet.
    fn default() -> Self {
        MeshState::new(SessionState::default())
    }
}

impl MeshState {
    /// Empty mesh registries beside `session`. Production builds `session` from
    /// [`Tunables::default`](crate::session::Tunables::default); a test shrinks
    /// the one window it drives.
    pub fn new(session: SessionState) -> MeshState {
        MeshState {
            links: new_mesh_links(),
            current_links: Arc::new(Mutex::new(HashMap::new())),
            seen: new_seen_registries(),
            conditions: new_conditions_registry(),
            session,
        }
    }
}

#[cfg(test)]
mod tests;
