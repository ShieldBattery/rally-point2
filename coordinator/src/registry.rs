//! Relay registry: the coordinator's view of which relays have enrolled
//! and are available to serve sessions.
//!
//! A relay enrolls when it opens its control connection, sending a [`RelayHello`]
//! as its first frame. The coordinator records it here and uses the registry to
//! pick home + backup relays for session requests and to build mesh topology
//! (the [`RelayPeer`] list in a session descriptor).
//!
//! The control connection that carries enrollment is authenticated by a
//! coordinator-issued bootstrap secret (fail-closed). Binding the connection to a
//! specific relay *identity* (so a secret-holder cannot enroll as an arbitrary id)
//! is deferred to the relay-identity / mTLS work.
//!
//! The registry is a plain `parking_lot::Mutex<HashMap<...>>` — every critical
//! section is a short, await-free insert or lookup, mirroring the relay's
//! `routing::Sessions` and `mesh::MeshLinks`. It is the coordinator's
//! in-memory state: a coordinator restart loses the registry, and relays
//! re-enroll (their control connections redial) to repopulate it. Persistence
//! (coordinator HA) is open.
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rally_point_proto::control::{RelayEntry, RelayHello, RelayPeer};
use rally_point_proto::ids::RelayId;

/// A registered relay, paired with the generation of the control connection that
/// last enrolled it.
///
/// The generation is a fencing token. Each new control connection enrolls with a
/// strictly greater generation, so when a connection drops it can deregister the
/// relay *only if it is still the current one* — a relay that has already
/// reconnected (a later connection re-enrolled it with a higher generation) is not
/// evicted by the stale drop. See [`enroll`] and [`remove_if_current`].
struct Registered {
    entry: RelayEntry,
    generation: u64,
}

/// The coordinator's relay registry: `RelayId` → the relay's entry.
///
/// A plain (non-async) mutex is deliberate: every critical section is a short,
/// await-free insert or lookup, so the lock is never held across I/O or an
/// await point — mirroring `routing::Sessions` and `mesh::MeshLinks` on the
/// relay. Clone the registry cheaply (each clone shares the same `Arc`) to
/// hand a copy to a session-setup task.
#[derive(Clone, Default)]
pub struct RelayRegistry {
    relays: Arc<Mutex<HashMap<RelayId, Registered>>>,
    /// Hands out a fresh, strictly-increasing generation per enroll. Monotonic
    /// for the coordinator's lifetime, so two connections (even for the same
    /// relay id) never share one.
    next_generation: Arc<AtomicU64>,
}

/// Registers a relay that has enrolled (sent its `Hello` on its control
/// connection), returning the **connection generation** the coordinator now holds
/// for it.
///
/// Re-registering the same `relay_id` replaces the prior entry (a relay that
/// restarted, or reconnected, with a new address) and assigns a strictly greater
/// generation. The caller — a control-connection task — keeps the returned
/// generation and passes it to [`remove_if_current`] when its connection drops, so
/// a drop only deregisters the relay when no newer connection has since taken over.
pub fn enroll(registry: &RelayRegistry, hello: RelayHello) -> u64 {
    let entry = RelayEntry {
        relay_id: hello.relay_id,
        relay_addr: hello.relay_addr,
        protocol: hello.protocol,
        cert_der: hello.cert_der,
    };
    let generation = registry.next_generation.fetch_add(1, Ordering::Relaxed);
    registry
        .relays
        .lock()
        .insert(entry.relay_id, Registered { entry, generation });
    generation
}

/// Looks up a relay by id, returning a [`RelayPeer`] (the id, address, and
/// pinned cert a session descriptor carries — the cert the relay reported at
/// enrollment, so a peer relay dialing it pins exactly what clients pin).
pub fn peer(registry: &RelayRegistry, id: RelayId) -> Option<RelayPeer> {
    registry
        .relays
        .lock()
        .get(&id)
        .map(|r| RelayPeer::from(&r.entry))
}

/// Looks up a relay's full entry by id.
pub fn entry(registry: &RelayRegistry, id: RelayId) -> Option<RelayEntry> {
    registry.relays.lock().get(&id).map(|r| r.entry.clone())
}

/// All registered relays' full entries, in an unspecified order. Used to pick
/// home + backup relays for a session — the session response needs the full
/// enrollment record (protocol version and all), not just the peer view.
pub fn all_entries(registry: &RelayRegistry) -> Vec<RelayEntry> {
    registry
        .relays
        .lock()
        .values()
        .map(|r| r.entry.clone())
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

/// Removes a relay (it has gone away), regardless of which connection enrolled
/// it. Idempotent. Prefer [`remove_if_current`] from a control-connection task,
/// which is safe against a relay that reconnected while this connection was
/// dropping.
pub fn remove(registry: &RelayRegistry, id: RelayId) {
    registry.relays.lock().remove(&id);
}

/// Deregisters a relay when its control connection drops, but **only if that
/// connection is still the current one** — its `generation` matches the one held
/// for the relay. Returns whether the relay was removed.
///
/// This is the safe deregister for a control-connection task. If the relay
/// reconnected while this connection was dropping, the later connection re-enrolled
/// it with a higher generation, so the match fails and the stale drop leaves the
/// live entry untouched — closing the reconnect race that an unconditional
/// [`remove`] would lose.
pub fn remove_if_current(registry: &RelayRegistry, id: RelayId, generation: u64) -> bool {
    let mut relays = registry.relays.lock();
    match relays.get(&id) {
        Some(registered) if registered.generation == generation => {
            relays.remove(&id);
            true
        }
        _ => false,
    }
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
    /// A player's slot index is out of range (max 11: 8 players + 4
    /// observers, BW's 12 network participants).
    #[error("slot {0} is out of range (max 11)")]
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
            vec![id as u8; 4],
        )
    }

    #[test]
    fn enroll_then_peer_roundtrips() {
        let reg = new_registry();
        assert!(is_empty(&reg));

        enroll(&reg, hello(1, 14900));
        assert!(!is_empty(&reg));

        let e = entry(&reg, RelayId(1)).unwrap();
        assert_eq!(e.relay_id, RelayId(1));

        let p = peer(&reg, RelayId(1)).unwrap();
        assert_eq!(p.relay_id, RelayId(1));
        assert_eq!(p.relay_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)));
        assert_eq!(
            p.cert_der,
            vec![1u8; 4],
            "the peer carries the cert the relay enrolled with, for the mesh dial to pin",
        );
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
    fn enroll_hands_out_strictly_increasing_generations() {
        let reg = new_registry();
        let g0 = enroll(&reg, hello(1, 14900));
        let g1 = enroll(&reg, hello(1, 14999)); // same relay reconnecting
        let g2 = enroll(&reg, hello(2, 14901)); // a different relay
        assert!(g1 > g0, "a re-enroll gets a later generation");
        assert!(g2 > g1, "every enroll gets a distinct, later generation");
    }

    #[test]
    fn remove_if_current_removes_on_a_matching_generation() {
        let reg = new_registry();
        let generation = enroll(&reg, hello(1, 14900));
        assert!(remove_if_current(&reg, RelayId(1), generation));
        assert!(is_empty(&reg));
        // A second drop of the same connection is a no-op (already gone).
        assert!(!remove_if_current(&reg, RelayId(1), generation));
    }

    #[test]
    fn remove_if_current_keeps_a_relay_that_already_reconnected() {
        // The reconnect race: connection #1 enrolls, connection #2 re-enrolls the
        // same relay (a reconnect), then connection #1's drop fires. The stale
        // generation must not evict the live entry connection #2 installed.
        let reg = new_registry();
        let stale = enroll(&reg, hello(1, 14900));
        let current = enroll(&reg, hello(1, 14999));
        assert_ne!(stale, current);

        assert!(
            !remove_if_current(&reg, RelayId(1), stale),
            "a stale connection must not deregister a reconnected relay",
        );
        assert!(!is_empty(&reg), "the relay stays registered");
        // The current connection's own later drop still deregisters it.
        assert!(remove_if_current(&reg, RelayId(1), current));
        assert!(is_empty(&reg));
    }

    #[test]
    fn peer_for_unknown_returns_none() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        assert!(peer(&reg, RelayId(99)).is_none());
    }

    #[test]
    fn all_entries_lists_everyone() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900));
        enroll(&reg, hello(2, 14901));
        let entries = all_entries(&reg);
        assert_eq!(entries.len(), 2);
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
