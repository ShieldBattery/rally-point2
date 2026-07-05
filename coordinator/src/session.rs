//! Session setup: take an app-server session request, assign each player a home
//! relay, mint one connection-bound token per player, and return the session
//! response the app server hands to the game DLLs at launch.
//!
//! This is the coordinator's primary production action. The app server has
//! already formed the lobby (matchmaking stays in the app server); the
//! coordinator finds relays and mints tokens. The response carries:
//!
//! - The session id (coordinator-assigned, unique within the tenant).
//! - The home relay (where clients connect). A session is single-relay by
//!   default — every slot homes there — but a dev-forced cross-relay split can
//!   move individual slots onto a secondary relay, listed per slot in
//!   `slot_homes`. Multi-relay redundancy is per-player home relays plus the
//!   mesh: a relay that serves a session always homes at least one of its slots.
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
    PlayerToken, RelayEndpoint, RelayPeer, SessionDescriptor, SessionRequest, SessionResponse,
    SlotExternalRef, SlotHome,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::ExpiresAt;

use crate::descriptors::{RelayDescriptors, RelayReaps};
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

/// The tenant's own correlation ids for a session and its players, keyed by
/// `(tenant, session)`. Recorded at `create_session` from the request and read
/// when a departure notice arrives, so the webhook names the game + player in
/// the tenant's own terms without the coordinator (or the tenant) keeping any
/// other session map.
type SessionRefsStore =
    Arc<Mutex<HashMap<(rally_point_proto::control::TenantId, SessionId), SessionRefs>>>;

/// The correlation ids a tenant attached to one session: the session's own id
/// and the per-slot player ids. Both are optional — a request from an app server
/// that predates the fields carries neither, and the webhook simply omits them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionRefs {
    /// The tenant's own id for the session (ShieldBattery's `gameId`).
    pub external_id: Option<String>,
    /// The tenant's own id for the player in each slot (a stringified
    /// `SbUserId`). Only slots whose handoff carried an `external_ref` appear.
    pub slots: HashMap<SlotId, String>,
    /// The slots the request flagged as observers. Carried into every relay's
    /// [`SessionDescriptor::observer_slots`] so the relay's desync comparator
    /// excludes them. Recorded here, alongside the correlation ids, so it
    /// survives the same restart/persistence paths those do.
    pub observers: Vec<SlotId>,
}

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
    /// The tenant's correlation ids per session. Populated by `create_session`,
    /// read by [`session_refs`] when a departure webhook is built.
    session_refs: SessionRefsStore,
    /// Per-relay descriptor outbox — what each relay should currently apply on
    /// its mesh links. Populated by `create_session`; read by the relay's
    /// descriptor-fetch endpoint.
    descriptors: RelayDescriptors,
    /// Per-relay reap outbox — the one-shot `CloseSlot` directives the reap
    /// policies arm. Drained by the relay's control connection alongside the
    /// descriptor set.
    reaps: RelayReaps,
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
            session_refs: Arc::new(Mutex::new(HashMap::new())),
            descriptors: RelayDescriptors::new(),
            reaps: RelayReaps::new(),
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

    /// Exposes the per-relay reap outbox (the control connection drains it, and
    /// the reap policies push `CloseSlot` directives into it).
    pub fn reaps(&self) -> &RelayReaps {
        &self.reaps
    }

    /// The relays serving `session`, as recorded at `create_session` — the
    /// distinct home relays of its slots — or empty if the session was never
    /// created here. The reap policies fan a `CloseSlot` out to all of these; a
    /// relay that does not hold a named slot ignores it.
    pub fn serving_relays(
        &self,
        tenant: &rally_point_proto::control::TenantId,
        session: SessionId,
    ) -> Vec<RelayId> {
        self.session_relays
            .lock()
            .get(&(tenant.clone(), session))
            .cloned()
            .unwrap_or_default()
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
/// Every slot homes on the primary relay — the lowest-id registered relay
/// (deterministic for a given fleet state) — except any listed in the request's
/// dev-only [`dev_relay_split`](SessionRequest::dev_relay_split), which home on
/// the secondary (next-lowest) relay instead, to force a cross-relay meshed
/// session in testing. Each player gets a token signed by its tenant's key,
/// binding the client pubkey to the slot and session. The bounds come from the
/// tenant's enrolled policy.
///
/// Records the session's relay membership — the distinct home relays of its
/// slots — so [`descriptor_for`] can list only the relays actually serving this
/// session, and so every serving relay homes at least one slot.
///
/// Token expiry is set to `expires_at` — the caller decides the lifetime
/// (typically game session duration plus margin).
pub fn create_session(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
) -> Result<SessionResponse, SessionSetupError> {
    validate_request(&request)?;

    let (home, secondary) = assign_relays(&setup.registry)?;

    if !tenant::is_enrolled(&setup.tenants, &request.tenant) {
        return Err(SessionSetupError::TenantNotFound(request.tenant));
    }

    let session = next_session_id(setup);
    let bounds = tenant::bounds(&setup.tenants, &request.tenant).expect("checked enrollment above");

    // The dev cross-relay split: slots the request flagged home on the secondary
    // relay instead of the primary. Honored only when a second relay is enrolled;
    // otherwise the split collapses and every slot homes on the primary.
    let slot_homes: Vec<SlotHome> = match &secondary {
        Some(secondary) => request
            .players
            .iter()
            .filter(|p| request.dev_relay_split.contains(&p.slot))
            .map(|p| SlotHome {
                slot: p.slot,
                relay: secondary.clone(),
            })
            .collect(),
        None => Vec::new(),
    };

    // Record which relays serve this session: the distinct home relays of its
    // slots. That is the primary, plus the secondary when at least one slot homes
    // there — a serving relay always homes at least one slot. `descriptor_for`
    // reads this to build per-relay mesh-peer lists.
    let relay_ids: Vec<RelayId> = {
        let mut ids = vec![home.relay_id];
        if let Some(secondary) = &secondary
            && !slot_homes.is_empty()
            && secondary.relay_id != home.relay_id
        {
            ids.push(secondary.relay_id);
        }
        ids
    };
    setup
        .session_relays
        .lock()
        .insert((request.tenant.clone(), session), relay_ids.clone());

    // Record the tenant's correlation ids so a later departure webhook can echo
    // them — the notification is then self-describing (the coordinator keeps no
    // other session→game map, and the tenant needs none either).
    let refs = SessionRefs {
        external_id: request.external_id.clone(),
        slots: request
            .players
            .iter()
            .filter_map(|p| p.external_ref.clone().map(|r| (p.slot, r)))
            .collect(),
        observers: request
            .players
            .iter()
            .filter(|p| p.observer)
            .map(|p| p.slot)
            .collect(),
    };
    setup
        .session_refs
        .lock()
        .insert((request.tenant.clone(), session), refs);

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
        slot_homes,
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
/// Every descriptor also carries the tenant's stored correlation ids
/// ([`session_refs`]) — the session's `external_id` and each slot's
/// `external_ref` — so every relay serving the session can stamp them into a
/// departure notice itself, rather than the notification depending on the
/// coordinator's in-memory session-refs store surviving to notice time (it
/// doesn't survive a coordinator restart; the descriptor-carried copy is what
/// does, since a relay holds what it last received independently of the
/// coordinator's process lifetime). It carries the session's observer slots the
/// same way, so a relay's desync comparator can exclude them.
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

    let refs = session_refs(setup, tenant, session).unwrap_or_default();

    Some(SessionDescriptor {
        tenant: tenant.clone(),
        session,
        peers,
        bounds,
        // The recorded membership is already the authority priority order:
        // `create_session` lists the primary home relay first, then any
        // secondary home. The primary was chosen for the session's latency
        // profile, so it decides the buffer while its players are present, and
        // authority falls down this list as relays' players leave.
        authority_order: relay_ids,
        external_id: refs.external_id,
        slot_refs: refs
            .slots
            .into_iter()
            .map(|(slot, external_ref)| SlotExternalRef { slot, external_ref })
            .collect(),
        observer_slots: refs.observers,
    })
}

/// The tenant's correlation ids for `session`, recorded at `create_session`, or
/// `None` if the session was never created here (or predates this coordinator
/// lifetime). Read when a departure notice is enriched into a webhook.
pub fn session_refs(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
) -> Option<SessionRefs> {
    setup
        .session_refs
        .lock()
        .get(&(tenant.clone(), session))
        .cloned()
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

/// Picks the session's home relays from the registry, as the client-facing
/// endpoints (address + pinned cert) the session response carries: the primary
/// home every slot dials by default, and the secondary a dev cross-relay split
/// can move individual slots onto.
///
/// The primary is the lowest-id registered relay (deterministic for a given
/// fleet state); the secondary is the next one, or `None` when only one relay is
/// enrolled (a single-relay session, where the split silently collapses).
fn assign_relays(
    registry: &RelayRegistry,
) -> Result<(RelayEndpoint, Option<RelayEndpoint>), SessionSetupError> {
    let mut entries = registry::all_entries(registry);
    if entries.is_empty() {
        return Err(SessionSetupError::NoRelaysAvailable);
    }

    // Sort by relay_id for deterministic assignment.
    entries.sort_by_key(|e| e.relay_id);

    let home = RelayEndpoint::from(&entries[0]);
    let secondary = entries.get(1).map(RelayEndpoint::from);
    Ok((home, secondary))
}

/// The maximum slot id (11: BW supports 12 network participants — 8 players
/// plus 4 observers).
const MAX_SLOT: u8 = 11;

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

    /// A fake per-relay cert DER, derived from the id so a test can check the
    /// response carries the right relay's cert.
    fn fake_cert(id: u64) -> Vec<u8> {
        vec![id as u8; 4]
    }

    fn enroll_relay(reg: &RelayRegistry, id: u64, port: u16) {
        registry::enroll(
            reg,
            RelayHello::new(
                RelayId(id),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                ProtocolVersion::CURRENT,
                fake_cert(id),
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
                external_ref: None,
                observer: false,
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
                external_ref: None,
                observer: false,
            },
        ]
    }

    #[test]
    fn create_session_assigns_relays_and_mints_tokens() {
        let setup = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            dev_relay_split: Vec::new(),
        };

        let resp = create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap();

        // Home is the lowest-id relay, carrying the cert it reported at enrollment
        // so clients can pin it. Without a dev split every slot homes there, so the
        // response carries no per-slot overrides even with a second relay enrolled.
        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert_eq!(resp.home_relay.cert_der, fake_cert(1));
        assert!(
            resp.slot_homes.is_empty(),
            "a session with no dev split homes every slot on the primary",
        );

        // One token per player.
        assert_eq!(resp.tokens.len(), 2);
        assert_eq!(resp.tokens[0].slot, SlotId(0));
        assert_eq!(resp.tokens[1].slot, SlotId(1));

        // Bounds come from the tenant's policy.
        assert_eq!(resp.bounds, BufferBounds::new(1, 6).unwrap());
    }

    #[test]
    fn dev_split_homes_listed_slots_on_the_secondary_relay() {
        // The dev cross-relay knob: the listed slot homes on the secondary relay,
        // the others on the primary, so both relays serve one meshed session.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert_eq!(
            resp.slot_homes,
            vec![SlotHome {
                slot: SlotId(1),
                relay: RelayEndpoint {
                    relay_id: RelayId(2),
                    relay_addr: resp.slot_homes[0].relay.relay_addr,
                    cert_der: fake_cert(2),
                },
            }],
            "only the split slot homes on the secondary relay, with its pinned cert",
        );

        // The session serves exactly the distinct home relays of its slots.
        let serving = setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session);
        assert_eq!(
            serving
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([RelayId(1), RelayId(2)]),
        );
    }

    #[test]
    fn serving_relays_are_the_distinct_homes_and_a_lone_relay_needs_no_split() {
        // With no split (and even with a second relay enrolled) the session serves
        // only the primary home — a serving relay always homes at least one slot,
        // so an unused relay is never in the set.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        assert_eq!(
            setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session),
            vec![RelayId(1)],
        );

        // A split naming slots on a single-relay fleet collapses: no secondary
        // exists, so every slot still homes on the primary and no override rides.
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
        let lone = SessionSetup::new(reg, tenants);
        let resp = create_session(
            &lone,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        assert!(
            resp.slot_homes.is_empty(),
            "a split with no second relay collapses to a single-relay session",
        );
        assert_eq!(
            lone.serving_relays(&TenantId("sb-test".to_owned()), resp.session),
            vec![RelayId(5)],
        );
    }

    #[test]
    fn issued_tokens_verify_on_the_relay() {
        let setup = setup_with_two_relays_and_tenant();
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            dev_relay_split: Vec::new(),
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
    fn no_relays_available_fails() {
        let setup = SessionSetup::new(registry::new_registry(), tenant::new_store());
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: Vec::new(),
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
                external_id: None,
                dev_relay_split: Vec::new(),
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
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::NoPlayers);
    }

    #[test]
    fn slot_11_is_accepted_and_slot_12_is_rejected() {
        // BW supports 12 network participants (8 players + 4 observers), so
        // slots 0..=11 are valid and 12 is out of range.
        let setup = setup_with_two_relays_and_tenant();
        let player = |slot: u8| PlayerHandoff {
            slot: SlotId(slot),
            client_pubkey: ClientPublicKey([slot; 32]),
            external_ref: None,
            observer: false,
        };

        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: (0..=11).map(player).collect(),
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        assert_eq!(resp.tokens.len(), 12);

        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![player(12)],
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::SlotOutOfRange(12));
    }

    #[test]
    fn descriptor_for_lists_other_session_relays_as_peers() {
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                // Split slot 1 onto the secondary relay so both relays serve and
                // mesh — the only way a session spans two relays.
                dev_relay_split: vec![SlotId(1)],
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
        assert_eq!(
            desc.peers[0].cert_der,
            fake_cert(2),
            "the peer carries relay 2's enrolled cert, so relay 1's mesh dial pins it",
        );
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
        assert_eq!(desc2.peers[0].cert_der, fake_cert(1));

        // Both descriptors carry the same buffer-authority order, home relay
        // (relay 1) first — every relay must rank the candidates identically
        // or the presence-driven handoff would crown different authorities.
        assert_eq!(desc.authority_order, vec![RelayId(1), RelayId(2)]);
        assert_eq!(desc2.authority_order, desc.authority_order);
    }

    #[test]
    fn descriptor_for_includes_the_stored_session_refs() {
        // The correlation ids the app server sent at create_session must ride
        // in every descriptor built for the session, so a relay can stamp them
        // into a departure notice itself rather than depending on the
        // coordinator's in-memory session-refs store surviving to notice time.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![
                    PlayerHandoff {
                        slot: SlotId(0),
                        client_pubkey: ClientPublicKey([0xAA; 32]),
                        external_ref: Some("sb-user-7".to_owned()),
                        observer: false,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([0xBB; 32]),
                        external_ref: None,
                        // An observer: it must show up in the descriptor's
                        // observer_slots so relays exclude it from desync checks.
                        observer: true,
                    },
                ],
                external_id: Some("game-99".to_owned()),
                dev_relay_split: Vec::new(),
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
        assert_eq!(desc.external_id, Some("game-99".to_owned()));
        assert_eq!(desc.slot_refs.len(), 1, "only the slot with a ref appears");
        assert_eq!(desc.slot_refs[0].slot, SlotId(0));
        assert_eq!(desc.slot_refs[0].external_ref, "sb-user-7");
        assert_eq!(
            desc.observer_slots,
            vec![SlotId(1)],
            "the observer-flagged slot is carried into the descriptor",
        );
    }

    #[test]
    fn descriptor_for_without_stored_refs_has_none_and_empty() {
        // A session created with no correlation ids at all still builds a
        // descriptor — just with the fields empty, not an error.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: Vec::new(),
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
        assert!(desc.external_id.is_none());
        assert!(desc.slot_refs.is_empty());
        assert!(
            desc.observer_slots.is_empty(),
            "no observer-flagged players -> empty observer_slots",
        );
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
                external_id: None,
                dev_relay_split: Vec::new(),
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
        // Three relays registered, but a session only uses two (the dev split
        // homes slot 1 on the secondary). The third relay must NOT appear in the
        // descriptor's peer list.
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
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // Home=1, secondary=2. Relay 3 is registered but not in the session.
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
                external_id: None,
                // Split so slot 1 homes on the secondary, giving both relays a slot.
                dev_relay_split: vec![SlotId(1)],
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // The split's secondary home is the relay slot 1 was moved onto.
        let secondary_relay = resp.slot_homes[0].relay.relay_id;

        // Both relays serving the session have a descriptor staged in the outbox,
        // each naming the other as its mesh peer.
        let for_home = setup.descriptors().current_for(resp.home_relay.relay_id);
        assert_eq!(for_home.len(), 1);
        assert_eq!(for_home[0].session, resp.session);
        assert_eq!(for_home[0].peers.len(), 1);
        assert_eq!(for_home[0].peers[0].relay_id, secondary_relay);

        let for_secondary = setup.descriptors().current_for(secondary_relay);
        assert_eq!(for_secondary.len(), 1);
        assert_eq!(for_secondary[0].peers[0].relay_id, resp.home_relay.relay_id);
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
                external_id: None,
                dev_relay_split: Vec::new(),
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
            external_id: None,
            dev_relay_split: Vec::new(),
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
            external_id: None,
            dev_relay_split: Vec::new(),
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
