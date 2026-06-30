//! Relay registry: the coordinator's view of which relays have phoned home
//! and are available to serve sessions.
//!
//! A relay phones home once at startup with a [`RelayHello`]. The coordinator
//! records it here and uses the registry to pick home + backup relays for
//! session requests and to build mesh topology (the [`RelayPeer`] list in a
//! session descriptor).
//!
//! Phone-home authentication (a coordinator-injected bootstrap secret so a
//! rogue relay cannot register and MITM) is not yet enforced — the enroll
//! endpoint is open for dev/loopback today. It lands alongside the relay
//! enrollment flow.
//!
//! The registry is a plain `parking_lot::Mutex<HashMap<...>>` — every critical
//! section is a short, await-free insert or lookup, mirroring the relay's
//! `routing::Sessions` and `mesh::MeshLinks`. It is the coordinator's
//! in-memory state: a coordinator restart loses the registry, and relays
//! re-phone-home to repopulate it. Persistence (coordinator HA) is open.
//!
//! # Tenant isolation
//!
//! Prod runs its own isolated coordinator + fleet; staging + developers
//! share one. A relay entry is not tenant-scoped — a relay serves any tenant
//! the coordinator it phones home to is responsible for. Tenant isolation is
//! enforced at the token layer (per-tenant signing keys), not at the relay
//! layer: two tenants on the same shared coordinator can land on the same
//! relay, but their sessions are isolated by `SessionKey` (tenant + session)
//! throughout the relay's routing and mesh layers.

use std::collections::HashMap;

use parking_lot::Mutex;
use rally_point_proto::control::{RelayEntry, RelayHello, RelayPeer};
use rally_point_proto::ids::RelayId;

/// The coordinator's relay registry: `RelayId` → the relay's entry.
///
/// A plain (non-async) mutex is deliberate: every critical section is a short,
/// await-free insert or lookup, so the lock is never held across I/O or an
/// await point — mirroring `routing::Sessions` and `mesh::MeshLinks` on the
/// relay. Clone the registry cheaply (each clone shares the same `Arc`) to
/// hand a copy to a session-setup task.
#[derive(Clone, Default)]
pub struct RelayRegistry {
    relays: Arc<Mutex<HashMap<RelayId, RelayEntry>>>,
}

use std::sync::Arc;

/// Registers a relay that has phoned home.
///
/// Re-registering the same `relay_id` replaces the prior entry (a relay that
/// restarted with a new address). Returns the entry the coordinator now holds
/// for this relay.
pub fn enroll(registry: &RelayRegistry, hello: RelayHello) -> RelayEntry {
    let entry = RelayEntry {
        relay_id: hello.relay_id,
        relay_addr: hello.relay_addr,
        protocol: hello.protocol,
    };
    registry.relays.lock().insert(entry.relay_id, entry.clone());
    entry
}

/// Looks up a relay by id, returning a [`RelayPeer`] (the id + address a
/// session descriptor carries).
pub fn peer(registry: &RelayRegistry, id: RelayId) -> Option<RelayPeer> {
    registry.relays.lock().get(&id).map(RelayPeer::from)
}

/// Looks up a relay's full entry by id.
pub fn entry(registry: &RelayRegistry, id: RelayId) -> Option<RelayEntry> {
    registry.relays.lock().get(&id).cloned()
}

/// All registered relays as [`RelayPeer`] entries, in an unspecified order.
/// Used to pick home + backup relays for a session.
pub fn all_peers(registry: &RelayRegistry) -> Vec<RelayPeer> {
    registry
        .relays
        .lock()
        .values()
        .map(RelayPeer::from)
        .collect()
}

/// The number of registered relays. Zero means no relay has phoned home — a
/// session request will fail with [`NoRelaysAvailable`].
pub fn len(registry: &RelayRegistry) -> usize {
    registry.relays.lock().len()
}

/// Whether the registry has no relays.
pub fn is_empty(registry: &RelayRegistry) -> bool {
    registry.relays.lock().is_empty()
}

/// Removes a relay (it has gone away). Idempotent.
pub fn remove(registry: &RelayRegistry, id: RelayId) {
    registry.relays.lock().remove(&id);
}

/// Creates an empty relay registry for a coordinator with no relays phoned
/// home yet.
pub fn new_registry() -> RelayRegistry {
    RelayRegistry::default()
}

/// Why a session request could not be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionSetupError {
    /// No relays have phoned home, so there is no relay to assign.
    #[error("no relays available in the registry")]
    NoRelaysAvailable,
    /// Not enough relays for a distinct backup. The session can still proceed
    /// with `backup == home` (degraded single-relay), but the caller asked for
    /// a distinct backup and there is only one relay.
    #[error("only {available} relay(s) available; need {needed} for a distinct backup")]
    NotEnoughRelays { available: usize, needed: usize },
    /// A player's slot index is out of range (max 7 for an 8-player game).
    #[error("slot {0} is out of range (max 7)")]
    SlotOutOfRange(u16),
    /// The tenant is not enrolled (no signing key registered for it).
    #[error("tenant {0:?} is not enrolled")]
    TenantNotFound(rally_point_proto::control::TenantId),
    /// The player list is empty.
    #[error("session request has no players")]
    NoPlayers,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::RelayHello;
    use rally_point_proto::ids::RelayId;
    use rally_point_proto::version::ProtocolVersion;

    fn hello(id: u64, port: u16) -> RelayHello {
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ProtocolVersion::CURRENT,
        )
    }

    #[test]
    fn enroll_then_peer_roundtrips() {
        let reg = new_registry();
        assert!(is_empty(&reg));

        let entry = enroll(&reg, hello(1, 14900));
        assert_eq!(entry.relay_id, RelayId(1));
        assert!(!is_empty(&reg));

        let p = peer(&reg, RelayId(1)).unwrap();
        assert_eq!(p.relay_id, RelayId(1));
        assert_eq!(p.relay_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)));
    }

    #[test]
    fn re_enroll_replaces_address() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        enroll(&reg, hello(1, 14999)); // same id, new address

        let p = peer(&reg, RelayId(1)).unwrap();
        assert_eq!(p.relay_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 14999)));
        assert_eq!(len(&reg), 1);
    }

    #[test]
    fn peer_for_unknown_returns_none() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        assert!(peer(&reg, RelayId(99)).is_none());
    }

    #[test]
    fn all_peers_lists_everyone() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        enroll(&reg, hello(2, 14901));
        let peers = all_peers(&reg);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn remove_clears_an_entry() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        remove(&reg, RelayId(1));
        assert!(is_empty(&reg));
        assert!(peer(&reg, RelayId(1)).is_none());
    }
}
