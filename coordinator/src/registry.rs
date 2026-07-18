//! Relay registry: the coordinator's view of which relays have enrolled
//! and are available to serve sessions.
//!
//! A relay enrolls when it opens its control connection, sending a [`RelayHello`]
//! as its first frame. The coordinator records it here and uses the registry to
//! pick each player's home relay for session requests and to build mesh topology
//! (the [`RelayPeer`] list in a session descriptor).
//!
//! The control connection that carries enrollment is authenticated by a
//! coordinator-issued bootstrap secret (fail-closed), which proves fleet
//! membership, not identity. Identity is bound at enroll time: the connection
//! handler challenges the relay to prove possession of the private key behind
//! its `Hello`'s certificate (see [`crate::identity`]), and [`try_enroll`]
//! refuses to re-enroll a live id under a different certificate.
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
use rally_point_proto::control::{MeshPeerIdentity, RelayEntry, RelayHello, RelayPeer};
use rally_point_proto::ids::RelayId;
use tokio::sync::watch;

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
    /// The SHA-256 fingerprint of `entry.cert_der`, computed once at enroll and
    /// kept alongside it — the duplicate-id check and the fleet-set publish
    /// both need it, and neither has to re-hash the certificate to get it.
    cert_fingerprint: [u8; 32],
    /// Whether this relay has asked to drain — it received its shutdown signal and
    /// requested that the coordinator stop assigning it new sessions (see
    /// [`mark_draining`]). A draining relay stays enrolled and keeps serving its
    /// existing sessions; it is only excluded from *new* assignments
    /// ([`is_available`], [`available_entries`]). Reset to `false` on every enroll,
    /// so a relay that restarted or reconnected is fresh — which is why a relay that
    /// reconnects mid-drain must re-send its `Draining` frame.
    draining: bool,
}

/// The coordinator's relay registry: `RelayId` → the relay's entry.
///
/// A plain (non-async) mutex is deliberate: every critical section is a short,
/// await-free insert or lookup, so the lock is never held across I/O or an
/// await point — mirroring `routing::Sessions` and `mesh::MeshLinks` on the
/// relay. Clone the registry cheaply (each clone shares the same `Arc`) to
/// hand a copy to a session-setup task.
#[derive(Clone)]
pub struct RelayRegistry {
    relays: Arc<Mutex<HashMap<RelayId, Registered>>>,
    /// Hands out a fresh, strictly-increasing generation per enroll. Monotonic
    /// for the coordinator's lifetime, so two connections (even for the same
    /// relay id) never share one.
    next_generation: Arc<AtomicU64>,
    /// Broadcast of the fleet's current mesh-peer set — every enrolled relay's id
    /// paired with the SHA-256 fingerprint of the certificate it enrolled with
    /// ([`MeshPeerIdentity`]). Rebuilt and published under the registry lock on
    /// every membership change (enroll, remove), so a relay's control connection
    /// re-syncs the whole set on connect and receives each change. Every enrolled
    /// relay is included, draining ones too: the set governs new mesh-link
    /// admission, not liveness, and a draining relay still serves live links.
    mesh_peers: Arc<watch::Sender<Vec<MeshPeerIdentity>>>,
}

impl Default for RelayRegistry {
    fn default() -> Self {
        Self {
            relays: Arc::default(),
            next_generation: Arc::default(),
            mesh_peers: Arc::new(watch::channel(Vec::new()).0),
        }
    }
}

/// The SHA-256 fingerprint of a relay's DER-encoded certificate — the compact
/// form used to record which certificate a relay enrolled with (and which a
/// session's clients pinned to it), rather than carrying the full DER bytes
/// through every comparison. Shared so the registry and session setup hash the
/// certificate one way.
///
/// A relay's mesh acceptor computes the same digest (SHA-256 over the raw DER
/// bytes) over a dialing peer's presented certificate and compares it
/// byte-for-byte against the fingerprints distributed from here in the
/// fleet-peer set — any change to this digest must land on both sides at once.
pub(crate) fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, cert_der).as_ref());
    out
}

/// Rebuilds the fleet mesh-peer set from the current relay map and publishes it
/// on the broadcast channel, waking every subscribed control connection only when
/// the set actually changed. Called under the registry lock, so the published set
/// is a consistent snapshot of the mutation that produced it. Every enrolled relay
/// is included — draining ones too — since the set governs new mesh-link admission,
/// not liveness. Sorted by relay id for a stable wire order and a cheap equality
/// check against the last-published set.
fn publish_mesh_peers(
    relays: &HashMap<RelayId, Registered>,
    mesh_peers: &watch::Sender<Vec<MeshPeerIdentity>>,
) {
    let mut peers: Vec<MeshPeerIdentity> = relays
        .values()
        .map(|r| MeshPeerIdentity {
            relay_id: r.entry.relay_id,
            cert_sha256: r.cert_fingerprint,
        })
        .collect();
    peers.sort_by_key(|p| p.relay_id.0);
    mesh_peers.send_if_modified(|current| {
        if *current == peers {
            false
        } else {
            *current = peers.clone();
            true
        }
    });
}

/// Registers a relay that has enrolled (sent its `Hello` on its control
/// connection), returning the **connection generation** the coordinator now holds
/// for it.
///
/// Re-registering the same `relay_id` replaces the prior entry (a relay that
/// restarted, or reconnected, with a new address) and assigns a strictly greater
/// generation — **unconditionally**, whatever certificate the hello carries.
/// This is the raw replace primitive and performs no identity check, so it must
/// not be reached for a hello whose certificate possession was not proven: the
/// live control handler always enrolls through [`try_enroll`] (after proving
/// possession), which refuses an id conflict instead of displacing. This
/// unconditional form seeds registry state directly in tests. The caller — a
/// control-connection task — keeps the returned generation and passes it to
/// [`remove_if_current`] when its connection drops, so a drop only deregisters
/// the relay when no newer connection has since taken over.
pub fn enroll(registry: &RelayRegistry, hello: RelayHello) -> u64 {
    let cert_fingerprint = cert_fingerprint(&hello.cert_der);
    let mut relays = registry.relays.lock();
    insert_locked(registry, &mut relays, hello, cert_fingerprint)
}

/// Refusal from [`try_enroll`]: the id is already enrolled by a live control
/// connection bound to a different certificate — a second relay process
/// colliding on the id, not the same relay reconnecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollConflict;

/// Registers a relay like [`enroll`], but refuses — instead of replacing —
/// when a live entry already holds the id under a **different** certificate
/// fingerprint. The same fingerprint still replaces: that is this relay's own
/// control connection redialing (its certificate is stable across reconnects
/// of one instance).
///
/// The conflict check and the insert are one atomic step under the registry
/// lock, deliberately: as two separate steps, two concurrent enrolls for the
/// same id could each pass the check and the later insert would silently
/// displace the earlier winner — the exact takeover the refusal exists to
/// block. Callers must have proof-of-possession-verified the hello's
/// certificate first; refusing on an unproven claim would let anyone squat an
/// id with a copied public certificate.
pub fn try_enroll(registry: &RelayRegistry, hello: RelayHello) -> Result<u64, EnrollConflict> {
    let cert_fingerprint = cert_fingerprint(&hello.cert_der);
    let mut relays = registry.relays.lock();
    if let Some(existing) = relays.get(&hello.relay_id)
        && existing.cert_fingerprint != cert_fingerprint
    {
        return Err(EnrollConflict);
    }
    Ok(insert_locked(
        registry,
        &mut relays,
        hello,
        cert_fingerprint,
    ))
}

/// The shared insert both enrollment paths end in: builds the [`Registered`]
/// entry, assigns a fresh generation, and publishes the updated fleet
/// mesh-peer set — all under the registry lock the caller already holds, so
/// the published snapshot is consistent with the mutation and a concurrent
/// enroll can neither interleave nor publish a stale set.
fn insert_locked(
    registry: &RelayRegistry,
    relays: &mut HashMap<RelayId, Registered>,
    hello: RelayHello,
    cert_fingerprint: [u8; 32],
) -> u64 {
    let entry = RelayEntry {
        relay_id: hello.relay_id,
        relay_addr: hello.relay_addr,
        protocol: hello.protocol,
        cert_der: hello.cert_der,
        relay_addrs: hello.relay_addrs,
        region: hello.region,
    };
    let generation = registry.next_generation.fetch_add(1, Ordering::Relaxed);
    relays.insert(
        entry.relay_id,
        Registered {
            entry,
            generation,
            cert_fingerprint,
            // A fresh enroll is never draining: a relay that reconnects mid-drain
            // re-sends its `Draining` frame to re-mark itself.
            draining: false,
        },
    );
    publish_mesh_peers(relays, &registry.mesh_peers);
    generation
}

/// Marks `id` as draining — it has asked the coordinator to stop assigning it new
/// sessions — **only if the entry's generation matches** `generation`. Returns
/// whether the mark applied.
///
/// The generation fence is what makes a racing reconnect safe: a stale connection's
/// `Draining` must not mark an entry a *newer* connection just re-enrolled (a
/// re-enroll clears the flag deliberately, so the live connection re-sends its own
/// `Draining`). A mismatched generation, or an unknown relay, is a no-op returning
/// `false`. Already-draining under the same generation counts as applied (`true`) —
/// the mark is idempotent, so a re-sent `Draining` still draws its ack.
pub fn mark_draining(registry: &RelayRegistry, id: RelayId, generation: u64) -> bool {
    let mut relays = registry.relays.lock();
    match relays.get_mut(&id) {
        Some(registered) if registered.generation == generation => {
            registered.draining = true;
            true
        }
        _ => false,
    }
}

/// Clears the draining mark on `id` — it may be assigned new sessions again —
/// **only if the entry's generation matches** `generation`. Returns whether the
/// clear applied.
///
/// The inverse of [`mark_draining`], under the same generation fence: a caller
/// that marked an entry draining and then decides to spare it (a scale-down that
/// found the relay picked up a session after the mark) re-admits exactly the
/// entry it marked, never a newer connection a reconnect installed. A mismatched
/// generation, or an unknown relay, is a no-op returning `false`. Idempotent —
/// clearing an entry that is not draining still reports applied (`true`) under a
/// matching generation.
pub fn clear_draining(registry: &RelayRegistry, id: RelayId, generation: u64) -> bool {
    let mut relays = registry.relays.lock();
    match relays.get_mut(&id) {
        Some(registered) if registered.generation == generation => {
            registered.draining = false;
            true
        }
        _ => false,
    }
}

/// Whether `id` is enrolled and available for a *new* session assignment — present
/// in the registry and not draining. A draining relay reads as unavailable here
/// even though it stays enrolled and keeps serving its existing sessions.
pub fn is_available(registry: &RelayRegistry, id: RelayId) -> bool {
    registry.relays.lock().get(&id).is_some_and(|r| !r.draining)
}

/// Whether `id` is currently enrolled at all — draining or not. Distinct from
/// [`is_available`], which excludes a draining relay: the reconcile sweeps ask
/// only whether a relay is present (a bound ledger id whose relay is still
/// enrolled has not vanished), so a draining-but-present relay must read as
/// enrolled here.
pub fn is_enrolled(registry: &RelayRegistry, id: RelayId) -> bool {
    registry.relays.lock().contains_key(&id)
}

/// A snapshot of one enrolled relay for the reconcile loop: its id, the region
/// it enrolled with, the generation of its current control connection (the fence
/// token a drain mark must present), and whether it is already draining.
///
/// Carries only what per-region reconcile needs, so a tick reads the whole fleet
/// once — a live count per region, and the drain candidates with the generation
/// each mark must match — without cloning every relay's certificate and address
/// set the way [`all_entries`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledRelay {
    /// The enrolled relay's id.
    pub relay_id: RelayId,
    /// The region the relay enrolled with, or `None` for an untagged relay.
    pub region: Option<rally_point_proto::control::RegionId>,
    /// The generation of the relay's current control connection — what a
    /// [`mark_draining`] / [`clear_draining`] for this relay must present.
    pub generation: u64,
    /// Whether the relay has already been marked draining.
    pub draining: bool,
}

/// A snapshot of every enrolled relay, in an unspecified order. One lock
/// acquisition yields the reconcile loop its whole per-region view: live counts
/// (all enrolled relays, draining included) and drain candidates (the
/// non-draining ones), each carrying the generation a drain mark must fence
/// against.
pub fn enrolled_relays(registry: &RelayRegistry) -> Vec<EnrolledRelay> {
    registry
        .relays
        .lock()
        .values()
        .map(|r| EnrolledRelay {
            relay_id: r.entry.relay_id,
            region: r.entry.region.clone(),
            generation: r.generation,
            draining: r.draining,
        })
        .collect()
}

/// Whether `generation` is still the generation enrolled for `id` — i.e. the
/// control connection that enrolled under it is the relay's *current* one, not a
/// stale predecessor a reconnect has since replaced. The gate a heartbeat's
/// presence roster passes before it is applied: state reported over a superseded
/// connection must not overwrite what the live connection reports.
pub fn generation_is_current(registry: &RelayRegistry, id: RelayId, generation: u64) -> bool {
    registry
        .relays
        .lock()
        .get(&id)
        .is_some_and(|r| r.generation == generation)
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

/// The certificate fingerprint of the *live* entry for `id`, if the registry
/// holds one — the enroll-time duplicate-id check's comparison point. `None`
/// when no relay is currently registered under `id` (a fresh id, or one whose
/// prior entry already aged out), which the caller treats as nothing to
/// compare against: any (proof-of-possession-verified) `Hello` may enroll.
pub fn live_cert_fingerprint(registry: &RelayRegistry, id: RelayId) -> Option<[u8; 32]> {
    registry.relays.lock().get(&id).map(|r| r.cert_fingerprint)
}

/// All registered relays' full entries, in an unspecified order — draining ones
/// included. Callers that must reach *every* enrolled relay (e.g. a re-home
/// last-resort fallback picking any live relay) use this; assignment of a *new*
/// session uses [`available_entries`] instead.
pub fn all_entries(registry: &RelayRegistry) -> Vec<RelayEntry> {
    registry
        .relays
        .lock()
        .values()
        .map(|r| r.entry.clone())
        .collect()
}

/// The registered relays available for a *new* session assignment — every enrolled
/// relay that is not draining — in an unspecified order. This is what session setup
/// and the re-home replacement pick read, so a relay that has asked to drain is
/// never handed a fresh session even while it keeps serving its existing ones.
pub fn available_entries(registry: &RelayRegistry) -> Vec<RelayEntry> {
    registry
        .relays
        .lock()
        .values()
        .filter(|r| !r.draining)
        .map(|r| r.entry.clone())
        .collect()
}

/// The number of registered relays. Zero means no relay has phoned home — a
/// session request will fail with [`SessionSetupError::NoRelaysAvailable`].
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
    let mut relays = registry.relays.lock();
    if relays.remove(&id).is_some() {
        // The relay left the fleet: re-publish the shrunk mesh-peer set.
        publish_mesh_peers(&relays, &registry.mesh_peers);
    }
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
            // The relay left the fleet: re-publish the shrunk mesh-peer set.
            publish_mesh_peers(&relays, &registry.mesh_peers);
            true
        }
        _ => false,
    }
}

/// Subscribes a control connection to the fleet mesh-peer set. The returned
/// receiver's current value is the whole set as it stands now — so a freshly
/// connected relay re-syncs the complete set before it waits for changes — and it
/// wakes on every fleet-membership change ([`enroll`], [`remove`],
/// [`remove_if_current`]). The relay applies each set wholesale, so re-delivery of
/// an unchanged set is a harmless no-op.
pub fn subscribe_mesh_peers(registry: &RelayRegistry) -> watch::Receiver<Vec<MeshPeerIdentity>> {
    registry.mesh_peers.subscribe()
}

/// The current fleet mesh-peer set — every enrolled relay's id and cert
/// fingerprint, sorted by relay id. Non-consuming; a one-shot read for tests and
/// callers that do not need to observe changes.
pub fn mesh_peers(registry: &RelayRegistry) -> Vec<MeshPeerIdentity> {
    registry.mesh_peers.borrow().clone()
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
    /// The coordinator's global live-session ceiling is reached, so a fresh
    /// create is refused until sessions close. Idempotent replays of a
    /// still-live session are unaffected — they mint nothing.
    #[error("the coordinator's live-session ceiling is reached")]
    SessionCeilingReached,
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
    /// Two players in the request name the same slot — the coordinator has no
    /// way to tell which one actually occupies it.
    #[error("duplicate slot {0} in the player list")]
    DuplicateSlot(u16),
    /// The request's `external_id` exceeds the coordinator's length cap.
    #[error("external_id exceeds the maximum length")]
    ExternalIdTooLong,
    /// A player's `external_ref` exceeds the coordinator's length cap.
    #[error("external_ref for slot {0} exceeds the maximum length")]
    ExternalRefTooLong(u16),
    /// The request's `external_id` is already bound to a still-live session, but
    /// the roster it names (slots, pubkeys, observer flags, or correlation refs)
    /// differs from the one that created that session. The coordinator neither
    /// hands back the original roster's tokens nor overwrites the live session's
    /// accounting, so the conflicting create is refused: the tenant must close
    /// the existing session, or use a distinct `external_id`, before binding this
    /// id to a new roster.
    #[error("external_id is already bound to a live session with a different roster")]
    IdempotentCreateMismatch,
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

    #[test]
    fn mark_draining_applies_under_the_current_generation() {
        let reg = new_registry();
        let generation = enroll(&reg, hello(1, 14900));
        assert!(is_available(&reg, RelayId(1)));

        assert!(mark_draining(&reg, RelayId(1), generation));
        assert!(
            !is_available(&reg, RelayId(1)),
            "a marked relay is unavailable"
        );
        // Idempotent: re-marking under the same generation still reports applied.
        assert!(mark_draining(&reg, RelayId(1), generation));
        // Still enrolled — draining excludes only new assignments, not the entry.
        assert!(entry(&reg, RelayId(1)).is_some());
    }

    #[test]
    fn mark_draining_ignores_a_stale_generation() {
        // A stale connection's Draining must not mark an entry a newer connection
        // re-enrolled (whose fresh enroll cleared the flag deliberately).
        let reg = new_registry();
        let stale = enroll(&reg, hello(1, 14900));
        let current = enroll(&reg, hello(1, 14999));
        assert_ne!(stale, current);

        assert!(
            !mark_draining(&reg, RelayId(1), stale),
            "a stale generation must not mark the reconnected relay draining",
        );
        assert!(
            is_available(&reg, RelayId(1)),
            "the reconnected relay stays available",
        );
        // The live connection's own Draining applies.
        assert!(mark_draining(&reg, RelayId(1), current));
        assert!(!is_available(&reg, RelayId(1)));
    }

    #[test]
    fn generation_is_current_tracks_re_enrollment() {
        let reg = new_registry();
        let stale = enroll(&reg, hello(1, 14900));
        assert!(generation_is_current(&reg, RelayId(1), stale));

        // A reconnect re-enrolls with a newer generation: the old one is stale.
        let current = enroll(&reg, hello(1, 14999));
        assert!(!generation_is_current(&reg, RelayId(1), stale));
        assert!(generation_is_current(&reg, RelayId(1), current));

        // An unknown relay has no current generation at all.
        assert!(!generation_is_current(&reg, RelayId(9), current));
    }

    #[test]
    fn mark_draining_on_an_unknown_relay_is_a_no_op() {
        let reg = new_registry();
        assert!(!mark_draining(&reg, RelayId(7), 0));
    }

    #[test]
    fn re_enroll_clears_the_draining_flag() {
        // A relay that reconnects mid-drain is fresh: its enroll clears the flag, so
        // it must re-send Draining to re-mark itself.
        let reg = new_registry();
        let g0 = enroll(&reg, hello(1, 14900));
        assert!(mark_draining(&reg, RelayId(1), g0));
        assert!(!is_available(&reg, RelayId(1)));

        enroll(&reg, hello(1, 14999)); // reconnect
        assert!(
            is_available(&reg, RelayId(1)),
            "a re-enroll clears draining — the relay is fresh again",
        );
    }

    #[test]
    fn clear_draining_re_admits_under_the_current_generation() {
        let reg = new_registry();
        let generation = enroll(&reg, hello(1, 14900));
        assert!(mark_draining(&reg, RelayId(1), generation));
        assert!(!is_available(&reg, RelayId(1)));

        // Clearing under the same generation re-admits the relay.
        assert!(clear_draining(&reg, RelayId(1), generation));
        assert!(
            is_available(&reg, RelayId(1)),
            "a cleared relay is available for new assignments again",
        );
        // Idempotent: clearing an already-cleared entry still reports applied.
        assert!(clear_draining(&reg, RelayId(1), generation));
        assert!(is_available(&reg, RelayId(1)));
    }

    #[test]
    fn clear_draining_ignores_a_stale_generation() {
        // A stale connection's clear must not re-admit an entry a newer connection
        // re-enrolled — the same fence mark_draining honors, in the other direction.
        let reg = new_registry();
        let stale = enroll(&reg, hello(1, 14900));
        let current = enroll(&reg, hello(1, 14999));
        assert!(mark_draining(&reg, RelayId(1), current));
        assert!(!is_available(&reg, RelayId(1)));

        assert!(
            !clear_draining(&reg, RelayId(1), stale),
            "a stale generation must not clear the reconnected relay's mark",
        );
        assert!(
            !is_available(&reg, RelayId(1)),
            "the relay stays draining under the stale clear",
        );
        // The live generation's own clear applies.
        assert!(clear_draining(&reg, RelayId(1), current));
        assert!(is_available(&reg, RelayId(1)));
    }

    #[test]
    fn clear_draining_on_an_unknown_relay_is_a_no_op() {
        let reg = new_registry();
        assert!(!clear_draining(&reg, RelayId(7), 0));
    }

    #[test]
    fn is_enrolled_tracks_presence_including_draining() {
        let reg = new_registry();
        assert!(!is_enrolled(&reg, RelayId(1)));
        let generation = enroll(&reg, hello(1, 14900));
        assert!(is_enrolled(&reg, RelayId(1)));

        // A draining relay is still enrolled (present), even though unavailable.
        mark_draining(&reg, RelayId(1), generation);
        assert!(is_enrolled(&reg, RelayId(1)));
        assert!(!is_available(&reg, RelayId(1)));

        remove(&reg, RelayId(1));
        assert!(!is_enrolled(&reg, RelayId(1)));
    }

    #[test]
    fn enrolled_relays_snapshots_id_region_generation_and_draining() {
        let reg = new_registry();
        let region = rally_point_proto::control::RegionId("us-east".to_owned());
        let g1 = enroll(&reg, hello(1, 14900).with_region(region.clone()));
        enroll(&reg, hello(2, 14901)); // untagged
        mark_draining(&reg, RelayId(1), g1);

        let mut snapshot = enrolled_relays(&reg);
        snapshot.sort_by_key(|r| r.relay_id.0);
        assert_eq!(snapshot.len(), 2);

        assert_eq!(snapshot[0].relay_id, RelayId(1));
        assert_eq!(snapshot[0].region.as_ref(), Some(&region));
        assert_eq!(snapshot[0].generation, g1);
        assert!(snapshot[0].draining, "relay 1 was marked draining");

        assert_eq!(snapshot[1].relay_id, RelayId(2));
        assert_eq!(snapshot[1].region, None, "relay 2 enrolled untagged");
        assert!(!snapshot[1].draining);
    }

    #[test]
    fn available_entries_excludes_a_draining_relay() {
        let reg = new_registry();
        let g1 = enroll(&reg, hello(1, 14900));
        enroll(&reg, hello(2, 14901));

        // Both enrolled: both available.
        assert_eq!(available_entries(&reg).len(), 2);
        assert_eq!(all_entries(&reg).len(), 2);

        mark_draining(&reg, RelayId(1), g1);
        // available_entries drops the draining relay; all_entries keeps it.
        let available: Vec<_> = available_entries(&reg)
            .into_iter()
            .map(|e| e.relay_id)
            .collect();
        assert_eq!(available, vec![RelayId(2)]);
        assert_eq!(
            all_entries(&reg).len(),
            2,
            "the draining relay stays enrolled"
        );
    }

    #[test]
    fn enroll_publishes_a_fingerprinted_mesh_peer_set() {
        let reg = new_registry();
        assert!(mesh_peers(&reg).is_empty(), "no relays enrolled, no peers");

        enroll(&reg, hello(2, 14902));
        enroll(&reg, hello(1, 14901));

        // Sorted by relay id, each peer carrying the SHA-256 of the cert it
        // enrolled with (`hello` enrolls with `vec![id; 4]`).
        let peers = mesh_peers(&reg);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].relay_id, RelayId(1));
        assert_eq!(peers[0].cert_sha256, cert_fingerprint(&[1u8; 4]));
        assert_eq!(peers[1].relay_id, RelayId(2));
        assert_eq!(peers[1].cert_sha256, cert_fingerprint(&[2u8; 4]));
    }

    #[test]
    fn a_subscriber_re_syncs_the_current_set_and_wakes_on_membership_change() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14901));

        // A fresh subscriber re-syncs the current set as its initial value.
        let mut rx = subscribe_mesh_peers(&reg);
        let initial = rx.borrow_and_update().clone();
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].relay_id, RelayId(1));

        // A later enroll wakes the subscriber and grows the set.
        enroll(&reg, hello(2, 14902));
        assert!(rx.has_changed().unwrap());
        let grown = rx.borrow_and_update().clone();
        assert_eq!(grown.len(), 2);

        // Re-enrolling the same relay with the same cert (only its address
        // differs) leaves the mesh-peer set unchanged, so it must not wake the
        // subscriber — the set keys on id + cert fingerprint, nothing else.
        enroll(&reg, hello(2, 14999));
        assert!(
            !rx.has_changed().unwrap(),
            "an unchanged mesh-peer set must not wake a subscriber",
        );
    }

    #[test]
    fn live_cert_fingerprint_tracks_the_current_entry() {
        let reg = new_registry();
        assert_eq!(
            live_cert_fingerprint(&reg, RelayId(1)),
            None,
            "an unenrolled id has nothing to compare against",
        );

        enroll(&reg, hello(1, 14900));
        assert_eq!(
            live_cert_fingerprint(&reg, RelayId(1)),
            Some(cert_fingerprint(&[1u8; 4])),
        );

        // Deregistering clears it.
        remove(&reg, RelayId(1));
        assert_eq!(live_cert_fingerprint(&reg, RelayId(1)), None);
    }

    /// Builds a hello like [`hello`] but with an explicit certificate, for
    /// exercising same-id/different-cert enrollment conflicts.
    fn hello_with_cert(id: u64, port: u16, cert_der: Vec<u8>) -> RelayHello {
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ProtocolVersion::CURRENT,
            cert_der,
        )
    }

    #[test]
    fn try_enroll_refuses_a_live_id_bound_to_a_different_certificate() {
        let reg = new_registry();
        enroll(&reg, hello(1, 14900)); // cert [1u8; 4]

        // A different certificate claiming the live id is refused, and the
        // refusal leaves everything untouched: the entry, its fingerprint, and
        // the published mesh-peer set.
        let before_peers = mesh_peers(&reg);
        let refused = try_enroll(&reg, hello_with_cert(1, 15000, vec![0xAA; 4]));
        assert_eq!(refused, Err(EnrollConflict));
        assert_eq!(
            live_cert_fingerprint(&reg, RelayId(1)),
            Some(cert_fingerprint(&[1u8; 4])),
            "the refused enroll must not displace the live entry",
        );
        assert_eq!(
            entry(&reg, RelayId(1)).unwrap().relay_addr.port(),
            14900,
            "the refused enroll must not touch the live entry's address",
        );
        assert_eq!(mesh_peers(&reg), before_peers);
    }

    #[test]
    fn try_enroll_replaces_on_the_same_certificate_and_enrolls_fresh_ids() {
        let reg = new_registry();
        let g1 = try_enroll(&reg, hello(1, 14900)).expect("a fresh id enrolls");

        // The same certificate re-enrolling is this relay's own reconnect: it
        // replaces the entry (new address) under a strictly greater generation.
        let g2 = try_enroll(&reg, hello_with_cert(1, 15000, vec![1u8; 4]))
            .expect("the same certificate reconnecting replaces");
        assert!(g2 > g1);
        assert_eq!(entry(&reg, RelayId(1)).unwrap().relay_addr.port(), 15000);
    }

    #[test]
    fn deregistration_shrinks_the_mesh_peer_set() {
        let reg = new_registry();
        let g1 = enroll(&reg, hello(1, 14901));
        enroll(&reg, hello(2, 14902));
        assert_eq!(mesh_peers(&reg).len(), 2);

        // A generation-fenced deregister drops the relay and shrinks the set.
        assert!(remove_if_current(&reg, RelayId(1), g1));
        let peers = mesh_peers(&reg);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].relay_id, RelayId(2));

        // An unconditional remove shrinks it too.
        remove(&reg, RelayId(2));
        assert!(mesh_peers(&reg).is_empty());
    }
}
