//! Session setup: take an app-server session request, assign home + backup
//! relays, mint one connection-bound token per player, and return the
//! session response the app server hands to the game DLLs at launch.
//!
//! This is the coordinator's primary production action. The app server has
//! already formed the lobby (matchmaking stays in the app server); the
//! coordinator finds relays and mints tokens. The response carries:
//!
//! - The session id (coordinator-assigned, unique within the tenant).
//! - The home relay (where clients connect) and a backup relay (failover
//!   target — may equal home if only one relay is available).
//! - One token per player, each binding the player's client pubkey to its
//!   slot and session.
//! - The latency-buffer bounds the relay's decision-maker clamps to.
//!
//! The coordinator also builds a [`SessionDescriptor`] per relay — what drives
//! `MeshCommand::Join` in production. `create_session` records which relays
//! serve which session; `descriptor_for` reads that membership to build the
//! per-relay mesh-peer list. `create_session` both returns the response for the
//! app server *and* stages each relay's descriptor in the
//! [outbox](crate::descriptors), which the relay's descriptor-fetch endpoint
//! delivers to the running relay.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rally_point_proto::control::{
    PlayerToken, RelayPeer, SessionDescriptor, SessionRequest, SessionResponse,
};
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_proto::token::ExpiresAt;

use crate::descriptors::RelayDescriptors;
use crate::registry::{self, RelayRegistry, SessionSetupError};
use crate::tenant::{self, TenantStore};

/// The relay ids serving one session, keyed by `(tenant, session)`.
///
/// This is the session→relay membership the coordinator records at
/// `create_session` time and `descriptor_for` reads. Without it, the
/// coordinator couldn't distinguish "peers in this session" from "all
/// registered relays" — a multi-relay fleet would tell a relay to mesh with
/// peers outside its session.
type SessionRelays =
    Arc<Mutex<HashMap<(rally_point_proto::control::TenantId, SessionId), Vec<RelayId>>>>;

use std::sync::Arc;

/// The inputs to session setup: the registries the coordinator holds.
#[derive(Clone)]
pub struct SessionSetup {
    /// The relay registry — which relays have phoned home.
    registry: RelayRegistry,
    /// The tenant store — per-tenant signing keys + policy.
    tenants: TenantStore,
    /// Which relays serve which session. Populated by `create_session`,
    /// read by `descriptor_for`.
    session_relays: SessionRelays,
    /// Per-relay descriptor outbox — what each relay should currently apply on
    /// its mesh links. Populated by `create_session`; read by the relay's
    /// descriptor-fetch endpoint.
    descriptors: RelayDescriptors,
    /// The session-id counter, seeded from wall-clock time at construction.
    /// Monotonic within this coordinator's lifetime; scoped per `SessionSetup`
    /// instance. Session ids are unique within a tenant but not globally (two
    /// tenants can both share a session id) — the relay keys its routing
    /// groups on `SessionKey` (tenant + session) for exactly this reason.
    next_session: Arc<AtomicU64>,
}

impl SessionSetup {
    /// Creates a session-setup context from the coordinator's registries.
    pub fn new(registry: RelayRegistry, tenants: TenantStore) -> Self {
        Self {
            registry,
            tenants,
            session_relays: Arc::new(Mutex::new(HashMap::new())),
            descriptors: RelayDescriptors::new(),
            next_session: Arc::new(AtomicU64::new(first_session_id())),
        }
    }

    /// Exposes the relay registry (the coordinator's API needs it to build
    /// the `CoordinatorState`).
    pub fn registry(&self) -> &RelayRegistry {
        &self.registry
    }

    /// Exposes the tenant store (the coordinator's API needs it to build
    /// the `CoordinatorState`).
    pub fn tenants(&self) -> &TenantStore {
        &self.tenants
    }

    /// Exposes the per-relay descriptor outbox (the descriptor-fetch endpoint
    /// reads the current set a relay should apply).
    pub fn descriptors(&self) -> &RelayDescriptors {
        &self.descriptors
    }
}

/// The first session id for a freshly constructed coordinator: the wall clock
/// in microseconds since the Unix epoch. Relays hold per-session state keyed
/// on `(tenant, session)` — routing groups, dedup sets, decision-makers — and
/// deliberately keep it through a coordinator outage so running games survive
/// one. A restarted coordinator that counted from 1 again could hand a new
/// game a key a relay still holds the old game's state under; a time seed
/// makes ids from different coordinator lifetimes disjoint (the process would
/// have to mint a session per microsecond of downtime to catch up to the next
/// seed). Never 0, so an id is always distinguishable from an unset field.
fn first_session_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_micros() as u64)
        .unwrap_or(1)
        .max(1)
}

/// Assigns the next session id. Monotonic within this coordinator's lifetime,
/// starting from the time-seeded counter so ids never repeat across restarts.
fn next_session_id(setup: &SessionSetup) -> SessionId {
    SessionId(setup.next_session.fetch_add(1, Ordering::Relaxed))
}

/// Creates a game session from an app-server request: assigns relays, mints
/// tokens, and returns the response the app server hands to its clients.
///
/// The home relay is the lowest-id registered relay (deterministic for a given
/// fleet state); the backup is the next one (or the same relay if only one is
/// available). Each player gets a token signed by its tenant's key, binding
/// the client pubkey to the slot and session. The bounds come from the
/// tenant's enrolled policy.
///
/// Records the session's relay membership (home + backup) so
/// [`descriptor_for`] can list only the relays actually serving this session.
///
/// Token expiry is set to `expires_at` — the caller decides the lifetime
/// (typically game session duration plus margin).
pub fn create_session(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
) -> Result<SessionResponse, SessionSetupError> {
    validate_request(&request)?;

    let (home, backup) = assign_relays(&setup.registry)?;

    if !tenant::is_enrolled(&setup.tenants, &request.tenant) {
        return Err(SessionSetupError::TenantNotFound(request.tenant));
    }

    let session = next_session_id(setup);
    let bounds = tenant::bounds(&setup.tenants, &request.tenant).expect("checked enrollment above");

    // Record which relays serve this session. The home + backup are the
    // session's relay set; `descriptor_for` reads this to build per-relay
    // mesh-peer lists.
    let relay_ids: Vec<RelayId> = {
        let mut ids = vec![home.relay_id];
        if backup.relay_id != home.relay_id {
            ids.push(backup.relay_id);
        }
        ids
    };
    setup
        .session_relays
        .lock()
        .insert((request.tenant.clone(), session), relay_ids.clone());

    // Stage each relay's descriptor in the outbox so the relay's descriptor
    // fetch delivers it. Built after membership is recorded, since
    // `descriptor_for` reads that membership to list a relay's mesh peers.
    for &relay_id in &relay_ids {
        if let Some(descriptor) = descriptor_for(setup, &request.tenant, session, relay_id) {
            setup.descriptors.record(relay_id, descriptor);
        }
    }

    let mut tokens = Vec::with_capacity(request.players.len());
    for player in &request.players {
        let token = tenant::mint_token(
            &setup.tenants,
            &request.tenant,
            session,
            player.slot,
            player.client_pubkey,
            expires_at,
        )
        .map_err(|_| SessionSetupError::TenantNotFound(request.tenant.clone()))?;

        let encoded = token
            .encode()
            .map_err(|_| SessionSetupError::TenantNotFound(request.tenant.clone()))?;

        tokens.push(PlayerToken {
            slot: player.slot,
            token: encoded,
        });
    }

    Ok(SessionResponse {
        session,
        home_relay: home,
        backup_relay: backup,
        tokens,
        bounds,
    })
}

/// Builds the [`SessionDescriptor`] the coordinator pushes to a relay serving
/// `session`, so the relay can join the session on its mesh links.
///
/// `peers` is the list of *other* relays serving the same session — the
/// relay's mesh peers, read from the session→relay membership `create_session`
/// recorded. For a single-relay session (no mesh), this is empty. For a
/// multi-relay session, it's every relay in the session except the one the
/// descriptor is being built for.
///
/// Returns `None` if the session has no recorded relay membership (the
/// session doesn't exist or wasn't created through `create_session`), or if
/// the tenant's bounds are no longer enrolled (the tenant was removed).
pub fn descriptor_for(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> Option<SessionDescriptor> {
    let bounds = tenant::bounds(&setup.tenants, tenant)?;

    let relay_ids = setup
        .session_relays
        .lock()
        .get(&(tenant.clone(), session))?
        .clone();

    // The peers are the session's relays except the one this descriptor is
    // for — each relay meshes with the others serving the same session.
    let peers: Vec<RelayPeer> = relay_ids
        .iter()
        .filter(|&&id| id != relay_id)
        .filter_map(|&id| registry::peer(&setup.registry, id))
        .collect();

    Some(SessionDescriptor {
        tenant: tenant.clone(),
        session,
        peers,
        bounds,
        // The recorded membership is already the authority priority order:
        // `create_session` lists the home relay first, then the backup. The
        // home relay was chosen for the session's latency profile, so it
        // decides the buffer while its players are present, and authority
        // falls down this list as relays' players leave.
        authority_order: relay_ids,
    })
}

/// Validates a session request before any work is done.
fn validate_request(request: &SessionRequest) -> Result<(), SessionSetupError> {
    if request.players.is_empty() {
        return Err(SessionSetupError::NoPlayers);
    }
    for player in &request.players {
        if player.slot.0 > MAX_SLOT {
            return Err(SessionSetupError::SlotOutOfRange(player.slot.0 as u16));
        }
    }
    Ok(())
}

/// Picks the home and backup relays from the registry.
///
/// The home relay is the lowest-id registered relay (deterministic for a
/// given fleet state); the backup is the next one. If only one relay is
/// available, the backup equals the home (degraded single-relay operation).
fn assign_relays(registry: &RelayRegistry) -> Result<(RelayPeer, RelayPeer), SessionSetupError> {
    let mut peers = registry::all_peers(registry);
    if peers.is_empty() {
        return Err(SessionSetupError::NoRelaysAvailable);
    }

    // Sort by relay_id for deterministic assignment.
    peers.sort_by_key(|p| p.relay_id);

    let home = peers[0].clone();
    let backup = peers.get(1).cloned().unwrap_or_else(|| home.clone());
    Ok((home, backup))
}

/// The maximum slot id (7 for an 8-player SC:R game).
const MAX_SLOT: u8 = 7;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId, SignedToken};
    use rally_point_proto::version::ProtocolVersion;
    use rally_point_relay::auth::Registry;

    fn enroll_relay(reg: &RelayRegistry, id: u64, port: u16) {
        registry::enroll(
            reg,
            RelayHello::new(
                RelayId(id),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                ProtocolVersion::CURRENT,
            ),
        );
    }

    fn setup_with_two_relays_and_tenant() -> SessionSetup {
        let reg = registry::new_registry();
        enroll_relay(&reg, 1, 14900);
        enroll_relay(&reg, 2, 14901);

        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();

        SessionSetup::new(reg, tenants)
    }

    fn two_players() -> Vec<PlayerHandoff> {
        vec![
            PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
            },
        ]
    }

    #[test]
    fn create_session_assigns_relays_and_mints_tokens() {
        let setup = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };

        let resp = create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap();

        // Home is the lowest-id relay; backup is the next.
        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert_eq!(resp.backup_relay.relay_id, RelayId(2));

        // One token per player.
        assert_eq!(resp.tokens.len(), 2);
        assert_eq!(resp.tokens[0].slot, SlotId(0));
        assert_eq!(resp.tokens[1].slot, SlotId(1));

        // Bounds come from the tenant's policy.
        assert_eq!(resp.bounds, BufferBounds::new(1, 6).unwrap());
    }

    #[test]
    fn issued_tokens_verify_on_the_relay() {
        let setup = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
        let resp = create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap();

        // Seed the relay registry with the tenant's verifying key.
        let (kid, pubkey) =
            tenant::verifying_key(&setup.tenants, &TenantId("sb-test".to_owned())).unwrap();
        let mut relay_registry = Registry::new();
        relay_registry.insert(kid, TenantId("sb-test".to_owned()), pubkey);

        // Each token the coordinator minted must verify on the relay.
        for player_token in &resp.tokens {
            let signed = SignedToken::decode(&player_token.token).unwrap();
            let authorized =
                rally_point_relay::auth::verify_token(&relay_registry, &signed, u64::MAX - 1)
                    .unwrap();
            assert_eq!(authorized.session, resp.session);
            assert_eq!(authorized.slot, player_token.slot);
        }
    }

    #[test]
    fn single_relay_session_has_backup_equal_to_home() {
        let reg = registry::new_registry();
        enroll_relay(&reg, 5, 14900);

        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();

        let setup = SessionSetup::new(reg, tenants);
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        assert_eq!(resp.home_relay, resp.backup_relay);
    }

    #[test]
    fn no_relays_available_fails() {
        let setup = SessionSetup::new(registry::new_registry(), tenant::new_store());
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::NoRelaysAvailable);
    }

    #[test]
    fn unenrolled_tenant_fails() {
        let reg = registry::new_registry();
        enroll_relay(&reg, 1, 14900);
        let setup = SessionSetup::new(reg, tenant::new_store());
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("not-enrolled".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionSetupError::TenantNotFound(TenantId("not-enrolled".to_owned()))
        );
    }

    #[test]
    fn empty_players_fails() {
        let setup = setup_with_two_relays_and_tenant();
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![],
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::NoPlayers);
    }

    #[test]
    fn descriptor_for_lists_other_session_relays_as_peers() {
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // Relay 1's peers are the other relays serving this session → relay 2.
        let desc = descriptor_for(
            &setup,
            &TenantId("sb-test".to_owned()),
            resp.session,
            RelayId(1),
        )
        .unwrap();
        assert_eq!(desc.peers.len(), 1);
        assert_eq!(desc.peers[0].relay_id, RelayId(2));
        assert_eq!(desc.bounds, BufferBounds::new(1, 6).unwrap());

        // Relay 2's peers → relay 1.
        let desc2 = descriptor_for(
            &setup,
            &TenantId("sb-test".to_owned()),
            resp.session,
            RelayId(2),
        )
        .unwrap();
        assert_eq!(desc2.peers.len(), 1);
        assert_eq!(desc2.peers[0].relay_id, RelayId(1));

        // Both descriptors carry the same buffer-authority order, home relay
        // (relay 1) first — every relay must rank the candidates identically
        // or the presence-driven handoff would crown different authorities.
        assert_eq!(desc.authority_order, vec![RelayId(1), RelayId(2)]);
        assert_eq!(desc2.authority_order, desc.authority_order);
    }

    #[test]
    fn descriptor_for_single_relay_session_has_no_peers() {
        let reg = registry::new_registry();
        enroll_relay(&reg, 1, 14900);
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);

        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        let desc = descriptor_for(
            &setup,
            &TenantId("sb-test".to_owned()),
            resp.session,
            RelayId(1),
        )
        .unwrap();
        assert!(desc.peers.is_empty());
    }

    #[test]
    fn descriptor_for_unknown_session_returns_none() {
        let setup = setup_with_two_relays_and_tenant();
        // No session was created → no membership recorded.
        assert!(
            descriptor_for(
                &setup,
                &TenantId("sb-test".to_owned()),
                SessionId(999),
                RelayId(1),
            )
            .is_none()
        );
    }

    #[test]
    fn descriptor_for_excludes_relays_not_in_session() {
        // Three relays registered, but a session only uses two (home + backup).
        // The third relay must NOT appear in the descriptor's peer list.
        let reg = registry::new_registry();
        enroll_relay(&reg, 1, 14900);
        enroll_relay(&reg, 2, 14901);
        enroll_relay(&reg, 3, 14902); // not in the session

        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);

        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // Home=1, backup=2. Relay 3 is registered but not in the session.
        let desc = descriptor_for(
            &setup,
            &TenantId("sb-test".to_owned()),
            resp.session,
            RelayId(1),
        )
        .unwrap();
        // Only relay 2 is a peer — relay 3 is excluded.
        assert_eq!(desc.peers.len(), 1);
        assert_eq!(desc.peers[0].relay_id, RelayId(2));
    }

    #[test]
    fn create_session_stages_descriptors_for_each_relay() {
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // Both relays serving the session have a descriptor staged in the outbox,
        // each naming the other as its mesh peer.
        let for_home = setup.descriptors().current_for(resp.home_relay.relay_id);
        assert_eq!(for_home.len(), 1);
        assert_eq!(for_home[0].session, resp.session);
        assert_eq!(for_home[0].peers.len(), 1);
        assert_eq!(for_home[0].peers[0].relay_id, resp.backup_relay.relay_id);

        let for_backup = setup.descriptors().current_for(resp.backup_relay.relay_id);
        assert_eq!(for_backup.len(), 1);
        assert_eq!(for_backup[0].peers[0].relay_id, resp.home_relay.relay_id);
    }

    #[test]
    fn create_session_single_relay_stages_a_peerless_descriptor() {
        // A single-relay session still stages a descriptor (with no peers) so the
        // relay learns the session and its bounds, even with no mesh.
        let reg = registry::new_registry();
        enroll_relay(&reg, 5, 14900);
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);

        create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        let staged = setup.descriptors().current_for(RelayId(5));
        assert_eq!(staged.len(), 1);
        assert!(staged[0].peers.is_empty());
    }

    #[test]
    fn session_ids_are_unique_per_session() {
        let setup = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
        let r1 = create_session(&setup, req.clone(), ExpiresAt(u64::MAX)).unwrap();
        let r2 = create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap();
        assert_ne!(r1.session, r2.session);
    }

    #[test]
    fn a_restarted_coordinator_does_not_reuse_session_ids() {
        // Relays keep per-session state through a coordinator outage, so ids
        // from different coordinator lifetimes must be disjoint. The counter
        // is seeded from the wall clock in microseconds: a restarted process
        // seeds later than any id the previous lifetime minted (a lifetime
        // would have to mint a session per microsecond of its whole runtime
        // to catch up to the next seed). Guard the seed's scale — a
        // regression to counting from 1 is the failure this test exists for.
        assert!(
            first_session_id() > 1_600_000_000_000_000,
            "the seed is wall-clock microseconds, not a small counter",
        );

        let before = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
        let old = create_session(&before, req.clone(), ExpiresAt(u64::MAX)).unwrap();

        let after = setup_with_two_relays_and_tenant();
        let new = create_session(&after, req, ExpiresAt(u64::MAX)).unwrap();
        assert!(
            new.session.0 >= old.session.0,
            "a fresh coordinator's ids never start below the old one's",
        );
    }
}
