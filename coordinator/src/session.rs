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
    DepartedSlot, PlayerToken, RegionId, RelayEndpoint, RelayEntry, RelayPeer, SessionDescriptor,
    SessionRequest, SessionResponse, SlotExternalRef, SlotHome, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};

use crate::descriptors::{RelayDescriptors, RelayReaps};
use crate::presence::PresenceStore;
use crate::registry::{self, RelayRegistry, SessionSetupError};
use crate::rehome::RehomeLimiter;
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
    /// Every slot the request listed — players and observers alike. Carried into
    /// every relay's [`SessionDescriptor::expected_slots`] so the session's
    /// authority relay knows the full set that must connect before it fires the
    /// session-start directive. Recorded here, alongside the other correlation
    /// state, so it survives the same restart/persistence paths.
    pub expected: Vec<SlotId>,
    /// Every slot's assigned home relay — the per-relay-per-slot data
    /// [`SessionDescriptor::homed_slots`] is filtered from
    /// ([`build_descriptor`] keeps only the entries matching the relay a
    /// descriptor is being built for). A `BTreeMap`, not a `HashMap`, so the
    /// filtered `homed_slots` a descriptor carries is in a deterministic
    /// (ascending slot) order rather than hash order — descriptors are
    /// compared in tests, and a relay's admission check reads the set
    /// unordered anyway, but nothing is served by leaving the order to chance.
    /// [`rehome`] reassigns the dead relay's entries onto the replacement
    /// before rebuilding descriptors, so this always reflects current
    /// membership, not just the session's original assignment.
    pub homes: std::collections::BTreeMap<SlotId, RelayId>,
    /// The SHA-256 fingerprint of the DER certificate each serving relay's
    /// clients currently pin, keyed by relay id. Recorded at session creation
    /// for the primary home and any dev-split secondary, and updated for the
    /// replacement relay on every re-home (including a same-id restart, where
    /// it captures the relay's fresh cert under its unchanged id). A relay
    /// restart mints a new cert under the same id, so this — not the relay's
    /// enroll generation, which also bumps on a benign reconnect of an
    /// unchanged cert — is what tells a stay-or-move decision apart from a
    /// false alarm: the id being enrolled is not enough, the cert its clients
    /// hold must still be the one currently live.
    pub relay_certs: std::collections::BTreeMap<RelayId, [u8; 32]>,
    /// Each serving relay's region at the time it was picked, keyed by relay id
    /// (`None` for an untagged relay). Recorded at session creation and updated
    /// for the replacement relay on every re-home, alongside `relay_certs`, so a
    /// re-home can prefer a live relay in the *dead* relay's region for the
    /// replacement — keeping a re-homed slot near where it was placed — before
    /// falling back to a region-blind pick. A `BTreeMap` for the same
    /// deterministic-order reason as `homes`.
    pub relay_regions: std::collections::BTreeMap<RelayId, Option<RegionId>>,
}

/// A create request reduced to the fields that shape the session it mints,
/// normalized so two requests that would produce the same session compare
/// equal. This is the canonical form the create-idempotency cache checks an
/// incoming replay against: a retry of the same logical create reproduces an
/// identical fingerprint, whereas a second create that reuses the same
/// `external_id` for a *different* game does not, and is refused rather than
/// silently handed the first game's tokens (see
/// [`SessionSetupError::IdempotentCreateMismatch`]).
///
/// The idempotency key is `(tenant, external_id)`, so those two are equal by
/// construction on any cache hit and are deliberately **excluded** here. Every
/// other field of the [`SessionRequest`] that changes the minted response or
/// the session state the coordinator records is included:
///
/// - each player's `slot` and `client_pubkey` — the token minted for a slot
///   binds that pubkey, so a differing roster mints non-interchangeable tokens.
/// - each player's `observer` flag — it selects the slot into the session's
///   observer set ([`SessionDescriptor::observer_slots`]) and the lifecycle's
///   player/observer split, shaping recorded state even though it alters no
///   token.
/// - each player's `external_ref` — stored per slot and echoed into
///   departure/result webhooks, so replaying the first roster's refs for a
///   different roster would mislabel the players.
/// - each player's `region` — selects the slot's home relay, so the same
///   `external_id` retried with different per-slot regions reads as a genuine
///   roster mismatch (a `409`), not a replay.
/// - `dev_relay_split` — decides which slots home on the secondary relay,
///   shaping the response's `slot_homes` and the session's serving-relay set.
///
/// Equality is plain struct equality ([`PartialEq`]), never a hash: a hash
/// collision must not be able to bind two genuinely different rosters to one
/// cached response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CreateFingerprint {
    /// The request's players, sorted by slot so request order does not matter.
    /// A request cannot name a slot twice (`validate_request` rejects a
    /// duplicate), so the slot totally orders this list.
    players: Vec<FingerprintPlayer>,
    /// The dev cross-relay split, sorted so the same set in a different order
    /// still matches.
    dev_relay_split: Vec<SlotId>,
}

/// One player's contribution to a [`CreateFingerprint`]: the fields of a
/// [`PlayerHandoff`](rally_point_proto::control::PlayerHandoff) that shape the
/// session (its slot, the pubkey its token binds, whether it is an observer,
/// its tenant correlation ref, and its requested region).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FingerprintPlayer {
    slot: SlotId,
    client_pubkey: ClientPublicKey,
    observer: bool,
    external_ref: Option<String>,
    region: Option<RegionId>,
}

impl CreateFingerprint {
    /// Reduces a request to its canonical fingerprint, sorting the players by
    /// slot and the dev split so two semantically identical requests that
    /// differ only in ordering still compare equal.
    fn from_request(request: &SessionRequest) -> Self {
        let mut players: Vec<FingerprintPlayer> = request
            .players
            .iter()
            .map(|p| FingerprintPlayer {
                slot: p.slot,
                client_pubkey: p.client_pubkey,
                observer: p.observer,
                external_ref: p.external_ref.clone(),
                region: p.region.clone(),
            })
            .collect();
        players.sort_by_key(|p| p.slot);
        let mut dev_relay_split = request.dev_relay_split.clone();
        dev_relay_split.sort_unstable();
        Self {
            players,
            dev_relay_split,
        }
    }
}

/// A recorded create-idempotency entry: the response a matching replay returns,
/// and the [`CreateFingerprint`] of the request that produced it. The
/// fingerprint is what distinguishes an honest retry (same roster → replay the
/// response) from an `external_id` collision (different roster → refuse).
#[derive(Debug, Clone)]
struct CachedCreate {
    /// The fingerprint of the request that created the cached session.
    fingerprint: CreateFingerprint,
    /// The exact response a matching replay returns.
    response: SessionResponse,
}

/// The outcome of [`create_session`]: the response to hand the app server, and
/// whether it was replayed from the create-idempotency cache rather than freshly
/// minted.
///
/// `replayed` lets the api handler tell a fresh create from an idempotent retry:
/// a fresh create arms the session's lifecycle accounting, while a replay must
/// **not** — the original create already registered it, and re-registering would
/// reset the live session's never-started clock and overwrite its serving-relay
/// set with a possibly-stale one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// The session response the app server hands to its clients.
    pub response: SessionResponse,
    /// Whether `response` was replayed from the idempotency cache (a retry of a
    /// create for an `external_id` already bound to a live session) rather than
    /// freshly minted.
    pub replayed: bool,
}

/// The SHA-256 fingerprint of a relay's DER-encoded certificate — the compact
/// form a session records to remember which cert its clients pinned to a
/// relay, rather than carrying the full DER bytes through every session's
/// state for a plain byte comparison.
fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, cert_der).as_ref());
    out
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
    /// Per-relay reap outbox — the pending `CloseSlot` directives the reap
    /// policies arm, held as declarative per-relay state and re-synced on
    /// reconnect. Drained by the relay's control connection alongside the
    /// descriptor set.
    reaps: RelayReaps,
    /// Active-player presence — the connected slots relays report on their
    /// heartbeats. Fed by the relay control connections, read by the tenant's
    /// `POST /presence/query`. Held here alongside the registry it is fenced
    /// against (both are the coordinator's live view of the fleet).
    presence: PresenceStore,
    /// The session-id counter, seeded from wall-clock time at construction.
    /// Monotonic within this coordinator's lifetime; scoped per `SessionSetup`
    /// instance. Session ids are unique within a tenant but not globally (two
    /// tenants can both share a session id) — the relay keys its routing
    /// groups on `SessionKey` (tenant + session) for exactly this reason.
    next_session: Arc<AtomicU64>,
    /// Idempotency record for coordinator-mediated re-homes: maps a
    /// `(tenant, session, dead_relay)` to the replacement relay chosen for it, so
    /// a concurrent or repeated `rehome` naming the same dead relay returns the
    /// same target without re-mutating the session's relay set. Retired with the
    /// session's other state (see [`forget_rehomes`]).
    rehomes: Arc<Mutex<HashMap<RehomeKey, RelayId>>>,
    /// The per-session rate limiter for the tenant-authenticated re-home endpoint
    /// (`POST /session/rehome`). Held here — rather than only in the api-level
    /// `CoordinatorState` — so the lifecycle can drop a closed session's bucket at
    /// the same point it retires the session's other per-session state, keeping the
    /// bucket map bounded by live re-homing sessions.
    rehome_limiter: RehomeLimiter,
    /// Linearizes an assignment's registry-read→commit span against a relay's drain
    /// mark, closing the coordinated-drain race. The window is: [`create_session`]
    /// (and [`rehome`]) reads the registry to pick a relay, then commits — records
    /// `session_relays` membership and stages the descriptors that name it. If a
    /// relay's drain mark landed *between* the pick and the commit, the session
    /// would name a relay about to exit, and a never-started session on a gone relay
    /// is unrecoverable client-side. So the pick→commit span and the drain mark
    /// each hold this one lock and are therefore mutually exclusive: after the mark,
    /// every session that will ever name the relay has already staged its descriptor
    /// in the relay's outbox, and any create still mid-flight re-reads the registry
    /// under the lock and sees the relay draining.
    ///
    /// **Outermost lock.** The fine-grained locks (`session_relays`, the registry
    /// mutex, the descriptor outbox, `rehomes`) nest *under* this one; nothing
    /// acquires this while already holding one of them. It guards only await-free
    /// sync bodies, so the guard never crosses an await point.
    assignment_lock: Arc<Mutex<()>>,
    /// Idempotency record for `POST /session/create`: a tenant-scoped
    /// `external_id` already bound to a still-live session replies with that
    /// exact original response rather than minting a duplicate — an ordinary
    /// tenant HTTP retry inside the signed-request's replay window must not
    /// create a second session for the same game. Each entry caches the
    /// original response *and* the [`CreateFingerprint`] of the request that
    /// produced it, so a replay is honored only when the incoming request's
    /// fingerprint matches: a second create that reuses the `external_id` for a
    /// different roster is a conflict, not a retry, and must not be handed the
    /// first roster's tokens. Checked and (on a fresh create) recorded under
    /// [`assignment_lock`](Self::assignment_lock), so two near-simultaneous
    /// requests for the same `external_id` can't both race past the check and
    /// each mint their own session. Entries are removed at the same point
    /// session membership is retired
    /// ([`take_session_membership`](Self::take_session_membership)), so a
    /// tenant may legitimately reuse an `external_id` once the prior session
    /// is actually gone (a rematch, say). A request with no `external_id` is
    /// never recorded here and is therefore never idempotent — see
    /// [`SessionRequest::external_id`]'s own doc.
    create_idempotency: Arc<Mutex<HashMap<(TenantId, String), CachedCreate>>>,
}

/// The key of a recorded rehome decision: which dead relay, for which session.
type RehomeKey = (rally_point_proto::control::TenantId, SessionId, RelayId);

impl SessionSetup {
    /// Creates a session-setup context from the coordinator's registries, with the
    /// production re-home rate limiter ([`RehomeLimiter::default`]).
    pub fn new(registry: RelayRegistry, tenants: TenantStore) -> Self {
        Self::with_rehome_limiter(registry, tenants, RehomeLimiter::default())
    }

    /// Like [`new`](Self::new) but with an explicit re-home rate limiter, so a test
    /// can inject one with a shorter refill or smaller burst than production's.
    pub fn with_rehome_limiter(
        registry: RelayRegistry,
        tenants: TenantStore,
        rehome_limiter: RehomeLimiter,
    ) -> Self {
        Self {
            registry,
            tenants,
            session_relays: Arc::new(Mutex::new(HashMap::new())),
            session_refs: Arc::new(Mutex::new(HashMap::new())),
            descriptors: RelayDescriptors::new(),
            reaps: RelayReaps::new(),
            presence: crate::presence::new_store(),
            next_session: Arc::new(AtomicU64::new(first_session_id())),
            rehomes: Arc::new(Mutex::new(HashMap::new())),
            rehome_limiter,
            assignment_lock: Arc::new(Mutex::new(())),
            create_idempotency: Arc::new(Mutex::new(HashMap::new())),
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

    /// Exposes the active-player presence store (the control connection applies
    /// heartbeat rosters into it; the presence-query endpoint reads it).
    pub fn presence(&self) -> &PresenceStore {
        &self.presence
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

    /// Forgets any recorded rehome decisions for `session` — called when the
    /// session's lifecycle state is removed, so the idempotency record stays
    /// bounded by the coordinator's live sessions (the sibling of
    /// [`RelayReaps::retire`](crate::descriptors::RelayReaps::retire)).
    pub fn forget_rehomes(&self, tenant: &TenantId, session: SessionId) {
        self.rehomes
            .lock()
            .retain(|(t, s, _), _| !(t == tenant && *s == session));
    }

    /// Takes — removes and returns — a closing session's relay membership: its
    /// `session_relays` entry for `(tenant, session)`, or an empty vec if none is
    /// recorded. The `session_refs` entry is dropped in the same call.
    ///
    /// The removal-and-return of `session_relays` happens under a **single** lock
    /// acquisition, which is what makes the close path's clean-up race-free. A
    /// concurrent [`rehome`] re-validates membership under this same lock before it
    /// mutates, so relative to this take it lands wholly before or wholly after:
    ///
    /// - A rehome that observes the membership **gone** (it ran after this take)
    ///   fails its under-lock re-validation and returns `Unavailable` — it neither
    ///   pushes a descriptor nor records a rehome, so there is nothing left to clean.
    /// - A rehome that completed **before** this take had already added its target
    ///   relay to the membership, so that relay is in the vec this take returns — the
    ///   close's descriptor removal over the returned set therefore covers the
    ///   resumed descriptor that rehome pushed, and the close's
    ///   [`forget_rehomes`](Self::forget_rehomes) (run after the take) clears the
    ///   idempotency entry it recorded.
    ///
    /// Retiring `session_relays` is also what refuses a *later* re-home for the
    /// closed session: with no serving relays recorded, [`rehome`]'s
    /// `serving.is_empty() → Unavailable` guard fires, so a straggler whose token has
    /// not yet expired can no longer pick a replacement relay and resurrect a dead
    /// game. No separate liveness flag is needed — the empty membership *is* the
    /// terminal state. The `session_refs` clear takes its own lock afterward; only
    /// the take-and-clear of `session_relays` needs to be atomic (it is the map the
    /// racing rehome re-validates against), so nothing hinges on the two being
    /// retired under one lock.
    ///
    /// Also frees the session's `external_id` for reuse: if the taken refs
    /// carried one, its `create_idempotency` entry is removed too — but only
    /// if that entry still points at *this* session, so a concurrent create
    /// that already reused the freed `external_id` for a fresh session (a
    /// legitimate rematch racing this close) is never evicted by a close that
    /// started before it.
    pub fn take_session_membership(&self, tenant: &TenantId, session: SessionId) -> Vec<RelayId> {
        let key = (tenant.clone(), session);
        let taken = self.session_relays.lock().remove(&key).unwrap_or_default();
        if let Some(refs) = self.session_refs.lock().remove(&key)
            && let Some(external_id) = refs.external_id
        {
            let idem_key = (tenant.clone(), external_id);
            let mut idempotency = self.create_idempotency.lock();
            if idempotency
                .get(&idem_key)
                .is_some_and(|cached| cached.response.session == session)
            {
                idempotency.remove(&idem_key);
            }
        }
        taken
    }

    /// Retires a closed session's membership maps, discarding the taken serving set
    /// — the value-free form of [`take_session_membership`](Self::take_session_membership)
    /// for callers that only need the retirement, not the snapshot (the close paths
    /// use the take so they can remove each serving relay's descriptor).
    pub fn forget_session_membership(&self, tenant: &TenantId, session: SessionId) {
        self.take_session_membership(tenant, session);
    }

    /// The per-session re-home rate limiter, so the api handler can charge a token
    /// and the lifecycle can drop a closed session's bucket.
    pub fn rehome_limiter(&self) -> &RehomeLimiter {
        &self.rehome_limiter
    }

    /// Locks the assignment lock — the outermost lock that linearizes an
    /// assignment's pick→commit span against a relay's drain mark (see the field
    /// docs). The coordinator's control connection acquires it around
    /// [`registry::mark_draining`] so a drain mark
    /// lands wholly before or wholly after any in-flight `create_session`/`rehome`.
    /// Returns a guard held only across await-free sync work.
    pub fn lock_assignment(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.assignment_lock.lock()
    }
}

/// The outcome of a coordinator-mediated re-home request (`POST /session/rehome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehomeOutcome {
    /// The named relay is still live in the registry — the client should keep
    /// dialing it rather than move, resuming its same-relay reconnect backoff.
    Stay,
    /// No live relay could take the session over (none registered, or the session
    /// is unknown to this coordinator lifetime). The client keeps its same-relay
    /// backoff and re-asks later.
    Unavailable,
    /// The relay the whole homed group should move to, with the cert the client
    /// pins to reach it. The client keeps its token and re-dials this endpoint.
    NewTarget(RelayEndpoint),
}

/// The replacement relay a prior [`rehome`] already recorded for
/// `(tenant, session, dead_relay)`, if one exists and its target is still live.
///
/// This is the idempotent fast path the re-home handler consults *before*
/// charging a rate-limit token: a straggler re-asking about a relay this session
/// already re-homed off must get the recorded answer without spending a token a
/// real survivor may need for the same session's bucket. Returns `None` when no
/// rehome was recorded (the caller then falls through to the rate-limited
/// [`rehome`] path) or when the recorded target has since left the registry.
///
/// A fully-closed session never matches: its recorded rehomes are cleared by
/// [`forget_rehomes`](SessionSetup::forget_rehomes) at close, at the same moment its membership is retired. This
/// is the lock-free sibling of the identical lookup inside [`rehome`], which runs
/// there under the rehomes lock so the read-and-mutate stays atomic; a shared
/// helper cannot be reused there without re-entering that lock.
pub fn recorded_rehome(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
) -> Option<RelayEndpoint> {
    let existing = *setup
        .rehomes
        .lock()
        .get(&(tenant.clone(), session, dead_relay))?;
    let entry = registry::entry(&setup.registry, existing)?;
    Some(RelayEndpoint::from(&entry))
}

/// Coordinator-mediated failover: the client believes `dead_relay` has died and
/// asks where its session should move. Returns [`RehomeOutcome::Stay`] when the
/// relay is in fact still enrolled (a false alarm the coordinator authoritatively
/// overrules from the registry), [`RehomeOutcome::Unavailable`] when the session
/// is unknown or no live relay can take it over, and otherwise moves the whole
/// homed group to a replacement relay and returns its [`RelayEndpoint`].
///
/// The replacement `R_new` is chosen as a live relay **already serving** the
/// session if one exists (earliest in the authority order, which the serving set
/// records home-first), else the lowest-id available relay in the **dead relay's
/// recorded region**, else the lowest-id available relay overall. The dead relay
/// is replaced **in place** in the serving set — which is also the descriptors'
/// authority order — so `R_new` inherits its rank, and every serving relay's
/// descriptor is rebuilt as a `resumed` (rehome) descriptor seeding
/// `departed_slots`. The push to `R_new` is recorded first, so it is staged for
/// its control connection before this returns.
///
/// Idempotent per `(tenant, session, dead_relay)`: a concurrent or repeated call
/// naming the same dead relay returns the same `R_new` without re-mutating the
/// session's relay set, as long as that target is still live.
pub fn rehome(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
    departed_slots: Vec<DepartedSlot>,
) -> RehomeOutcome {
    rehome_inner(setup, tenant, session, dead_relay, departed_slots, || {})
}

/// Whether `relay`'s currently-presented cert (`current_der`) still matches the
/// cert `session`'s clients pinned to it, per the fingerprint recorded in
/// [`SessionRefs::relay_certs`]. A session with no recorded cert for `relay` (a
/// gap no caller in this module is expected to leave) reads as matching, so an
/// incomplete record cannot itself force a spurious move off a healthy relay.
fn cert_matches_pin(
    setup: &SessionSetup,
    key: &(TenantId, SessionId),
    relay: RelayId,
    current_der: &[u8],
) -> bool {
    let refs = setup.session_refs.lock();
    match refs.get(key).and_then(|refs| refs.relay_certs.get(&relay)) {
        Some(&recorded) => recorded == cert_fingerprint(current_der),
        None => true,
    }
}

/// [`rehome`]'s body, with a test seam `before_mutation` invoked after the
/// replacement relay is chosen but before the `session_relays` mutation — the exact
/// window in which a concurrent full close can land. Production passes a no-op; a
/// test passes a close to prove the mutation section re-validates and bails.
///
/// # Locking
///
/// Holds the outermost `assignment_lock` across its whole (await-free) body — so
/// the replacement pick (a registry read) and the descriptor re-staging are atomic
/// against a relay's drain mark, exactly as [`create_session`]'s pick→commit is —
/// then the `rehomes` lock across the middle section, and the `session_relays` lock
/// *nested* inside that for the mutation. A full close ([`Lifecycle::on_session_closed`])
/// touches `forget_rehomes` (the `rehomes` lock) and `forget_session_membership`
/// (the `session_relays` lock) as two separate, non-nested acquisitions that take
/// neither the assignment lock nor both fine locks at once, so it cannot deadlock
/// against this nesting order.
fn rehome_inner(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
    departed_slots: Vec<DepartedSlot>,
    before_mutation: impl FnOnce(),
) -> RehomeOutcome {
    // The outermost assignment lock: this re-home's pick→re-stage span linearizes
    // against a relay's drain mark the same way `create_session` does.
    let _assign = setup.lock_assignment();

    let key = (tenant.clone(), session);
    let serving = setup.serving_relays(tenant, session);
    // Unknown session (never created here, or a coordinator restart wiped its
    // membership): there is nothing to re-home.
    if serving.is_empty() {
        return RehomeOutcome::Unavailable;
    }

    let mut rehomes = setup.rehomes.lock();

    // Idempotent / already-re-homed: a prior rehome for this dead relay already
    // chose a target. Return it verbatim as long as that target is still live,
    // without re-mutating. This lookup runs *before* the registry-liveness Stay
    // check below on purpose: a dead relay can restart and re-enroll under a fresh
    // cert, but a straggler client still pinned to its OLD cert (which this session
    // already re-homed off) can never accept that new cert, so telling it to Stay
    // would wedge it dialing a cert it can never pass. The recorded replacement is
    // the honest answer for it. (The handler runs the same lookup lock-free first —
    // see [`recorded_rehome`] — to answer a recorded re-ask without a rate-limit
    // token; this copy stays here so the read-and-mutate below is atomic.)
    if let Some(&existing) = rehomes.get(&(tenant.clone(), session, dead_relay))
        && let Some(entry) = registry::entry(&setup.registry, existing)
    {
        return RehomeOutcome::NewTarget(RelayEndpoint::from(&entry));
    }

    // The named relay is still enrolled, still serving this session, and the cert
    // its clients pinned still matches what it currently presents: a genuine false
    // alarm, so the coordinator authoritatively overrules the client's belief and
    // tells it to stay. The serving-set guard is what distinguishes this from the
    // already-re-homed straggler above: a relay that is enrolled but no longer in
    // the serving set was moved off in a prior re-home (handled by the idempotency
    // lookup), not a false alarm — falling into Stay there would pin the straggler
    // to a relay this session no longer uses.
    //
    // Enrolled-under-this-id is not, by itself, enough: a relay that restarted in
    // place re-enrolls under the same id with a fresh self-signed cert, and every
    // client still holding the old pin can never accept it — answering Stay would
    // wedge them dialing a cert they can never pass. The cert comparison catches
    // that case and falls through to a replacement pick instead. The relay's
    // enroll *generation* is deliberately not the signal: it also bumps on a
    // benign control-WS reconnect that keeps the same cert, where Stay remains the
    // right answer, so generation alone cannot tell the two apart.
    if serving.contains(&dead_relay)
        && let Some(entry) = registry::entry(&setup.registry, dead_relay)
        && cert_matches_pin(setup, &key, dead_relay, &entry.cert_der)
    {
        return RehomeOutcome::Stay;
    }

    // The named dead relay must actually be serving this session. It is not both
    // enrolled and serving (the stay-guard above ruled that out) and — checked here
    // — it has no recorded rehome yet (the idempotency block above returned if it
    // did), so if it is also not a member of the serving set, the client named a
    // relay unrelated to its session. The in-place `retain`/reassign over the serving set below would
    // then be a silent no-op, yet the function would still pick an `r_new`, re-push
    // `resumed` descriptors to the untouched (healthy) serving set, and record a
    // bogus idempotency entry. Refuse before any of that: the coordinator cannot
    // re-home a session off a relay that does not serve it. `Unavailable` (not
    // `Stay`) is the honest answer — the relay is genuinely gone, so "keep dialing
    // it" would be wrong; the client keeps its same-relay backoff and re-asks, and a
    // correctly-named later request (its real home relay) re-homes normally.
    if !serving.contains(&dead_relay) {
        return RehomeOutcome::Unavailable;
    }

    // The dead relay's recorded region, so the replacement can prefer a live relay
    // in the same region — keeping a re-homed slot near where it was placed. `None`
    // for an untagged dead relay (or a session with no recorded region), which
    // simply skips straight to the region-blind fallback.
    let dead_region: Option<RegionId> = setup
        .session_refs
        .lock()
        .get(&key)
        .and_then(|refs| refs.relay_regions.get(&dead_relay).cloned())
        .flatten();

    // Pick the replacement: prefer a live *available* relay already serving the
    // session (earliest in the authority order), else the lowest-id available relay
    // in the dead relay's region, else the lowest-id available relay overall. A
    // draining relay is never chosen — it asked to stop taking new work, and
    // re-homing a whole group onto it would be exactly that.
    //
    // The dead relay's own id is a legal candidate here: reaching this point means
    // it either is not enrolled at all (genuinely gone, so `is_available` below
    // already excludes it) or is enrolled under a cert that no longer matches the
    // pin (the stay-check above ruled out a match) — the restart-in-place case,
    // where the relay is live, enrolled, available, and its own fresh cert is
    // exactly the valid target every serving client needs to move onto.
    let r_new = serving
        .iter()
        .copied()
        .find(|&id| registry::is_available(&setup.registry, id))
        .or_else(|| {
            let mut entries = registry::available_entries(&setup.registry);
            entries.sort_by_key(|e| e.relay_id);
            dead_region
                .as_ref()
                .and_then(|region| entries.iter().find(|e| e.region.as_ref() == Some(region)))
                .or_else(|| entries.first())
                .map(|e| e.relay_id)
        });
    let Some(r_new) = r_new else {
        return RehomeOutcome::Unavailable;
    };
    let Some(new_entry) = registry::entry(&setup.registry, r_new) else {
        return RehomeOutcome::Unavailable;
    };

    // Test seam: a full close landing between the serving-set snapshot above and
    // the mutation below (in production this is a no-op).
    before_mutation();

    // Move every slot homed on the dead relay onto R_new: replace the dead relay
    // in place in the serving set (which is also the authority order), so the
    // rebuilt descriptors rank R_new where the dead relay stood. If R_new was
    // already serving under a *different* id, drop the dead entry rather than
    // list it twice. A same-id replacement (the relay restarted in place) needs
    // neither move: its id already occupies its slot in the set, so membership
    // is left exactly as it is — only its recorded cert and descriptor, updated
    // below, actually change.
    //
    // Re-validate under the `session_relays` lock we are about to mutate: our
    // `serving` snapshot was taken before this lock, so a full close could have
    // cleared the membership (or a racing rehome moved the dead relay off) in the
    // meantime. If the entry is gone, or no longer names the dead relay, bail with
    // `Unavailable` here — before recording any rehome or pushing any descriptor —
    // so a close that lands mid-rehome can never leave a post-close recorded rehome
    // (which `recorded_rehome` would then serve token-free) or a re-staged
    // descriptor that resurrects the dead session on a live relay.
    {
        let mut relays = setup.session_relays.lock();
        let Some(members) = relays.get_mut(&key) else {
            return RehomeOutcome::Unavailable;
        };
        if !members.contains(&dead_relay) {
            return RehomeOutcome::Unavailable;
        }
        if dead_relay == r_new {
            // Same id, membership unchanged.
        } else if members.contains(&r_new) {
            members.retain(|&id| id != dead_relay);
        } else {
            for id in members.iter_mut() {
                if *id == dead_relay {
                    *id = r_new;
                }
            }
        }
    }

    // The dead relay's descriptor outbox entry for this session is stale — for a
    // different-id replacement it is no longer a member at all; for a same-id
    // restart its old descriptor predates the cert change and slot moves this
    // re-home is about to apply. Drop it now so that a relay reconnecting with
    // stale outbox state is not re-synced the pre-rehome descriptor before the
    // rebuild below re-records the current one. Safe even if the relay is
    // disconnected — the outbox is latest-wins current state.
    setup.descriptors.remove(dead_relay, tenant, session);

    // Move every slot's home-relay assignment from the dead relay onto R_new (a
    // same-id replacement reassigns each entry to its own unchanged id, a
    // harmless no-op), so the rebuilt descriptors below bind those slots to
    // their new home instead of a relay that no longer serves them — otherwise
    // R_new's descriptor would omit them from `homed_slots` and the client's own
    // reconnect to R_new would be refused as misrouted. Record R_new's cert here
    // too, replacing whatever this session had on file for the dead relay's id,
    // so the next Stay-check for R_new's id compares against the cert it
    // presents now rather than the one this re-home just moved off. A separate
    // lock acquisition from the `session_relays` mutation above, following
    // `take_session_membership`'s established precedent (see its doc): only
    // `session_relays` needs to be atomic with a racing close's re-validation,
    // and that already passed by this point, so a close landing exactly here
    // would simply retire this whole `session_refs` entry afterward regardless
    // of what this leaves in `homes`/`relay_certs`. Must still run before the
    // descriptor-rebuild loop below, which is what this position guarantees.
    if let Some(refs) = setup.session_refs.lock().get_mut(&key) {
        for home_relay in refs.homes.values_mut() {
            if *home_relay == dead_relay {
                *home_relay = r_new;
            }
        }
        refs.relay_certs.remove(&dead_relay);
        refs.relay_certs
            .insert(r_new, cert_fingerprint(&new_entry.cert_der));
        // Record R_new's region the same way, so a later re-home off R_new
        // prefers *its* region, and the dead relay's stale entry does not linger.
        refs.relay_regions.remove(&dead_relay);
        refs.relay_regions.insert(r_new, new_entry.region.clone());
    }

    // Rebuild every serving relay's descriptor as a resumed (rehome) descriptor,
    // seeding the departed slots, and push each. Record R_new's first so it is
    // staged for its control connection before this returns, shrinking the
    // descriptor/dial race the client's backoff otherwise absorbs.
    let mut serving_now = setup.serving_relays(tenant, session);
    serving_now.sort_by_key(|&id| if id == r_new { 0 } else { 1 });
    for relay_id in serving_now {
        if let Some(descriptor) = build_descriptor(
            setup,
            tenant,
            session,
            relay_id,
            true,
            departed_slots.clone(),
        ) {
            setup.descriptors.record(relay_id, descriptor);
        }
    }

    rehomes.insert((tenant.clone(), session, dead_relay), r_new);
    tracing::info!(
        tenant = tenant.as_ref(),
        session = session.0,
        dead_relay = dead_relay.0,
        new_relay = r_new.0,
        "session re-homed onto a replacement relay",
    );
    RehomeOutcome::NewTarget(RelayEndpoint::from(&new_entry))
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
/// Each slot homes on a live relay in the region it requested
/// ([`PlayerHandoff::region`](rally_point_proto::control::PlayerHandoff::region)),
/// falling back to the lowest-id available relay when it named no region or its
/// region has no live relay. A request that carries no region at all instead runs
/// the region-blind dev path, where every slot homes on the lowest-id relay
/// except those the dev-only
/// [`dev_relay_split`](SessionRequest::dev_relay_split) moves onto the secondary
/// to force a cross-relay meshed session in testing. Each player gets a token
/// signed by its tenant's key, binding the client pubkey to the slot and session.
/// The bounds come from the tenant's enrolled policy.
///
/// Records the session's relay membership — the distinct home relays of its
/// slots — so [`descriptor_for`] can list only the relays actually serving this
/// session, and so every serving relay homes at least one slot.
///
/// Token expiry is set to `expires_at` — the caller decides the lifetime
/// (typically game session duration plus margin).
///
/// Returns a [`CreatedSession`] whose `replayed` flag tells a fresh mint from
/// an idempotent retry: a create naming an `external_id` already bound to a
/// still-live session replays that session's original response (with `replayed
/// == true`) rather than minting a duplicate, and the caller must then skip
/// arming the session's lifecycle a second time. A replay is honored only when
/// the request matches the original roster's `CreateFingerprint`; the same
/// `external_id` presented with a different roster is refused with
/// [`SessionSetupError::IdempotentCreateMismatch`].
///
/// The whole body runs under the assignment lock (see
/// [`SessionSetup::lock_assignment`]), so the registry read that picks relays and
/// the commit that records membership and stages descriptors are atomic against a
/// concurrent relay drain mark — the mark lands wholly before this create (and this
/// create then sees the relay draining) or wholly after it (and the descriptor is
/// already staged in the relay's outbox).
pub fn create_session(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
) -> Result<CreatedSession, SessionSetupError> {
    create_session_inner(setup, request, expires_at, || {})
}

/// [`create_session`]'s body, with a test seam `before_commit` invoked after the
/// relays are picked but before any membership is recorded or descriptor staged —
/// the exact window in which a racing drain mark must be linearized out. Production
/// passes a no-op; a test passes a closure that pauses A mid-span so it can prove a
/// concurrent drain mark blocks on the assignment lock until A commits.
fn create_session_inner(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
    before_commit: impl FnOnce(),
) -> Result<CreatedSession, SessionSetupError> {
    // Hold the outermost assignment lock across this entire (await-free) body, so
    // the registry read below and the commit that follows cannot interleave with a
    // relay's drain mark. See `SessionSetup::assignment_lock`.
    let _assign = setup.lock_assignment();

    // Idempotent replay: a request naming an `external_id` already bound to a
    // still-live session gets that session's exact original response instead
    // of a fresh one — an ordinary tenant HTTP retry inside the
    // signed-request replay window must not mint a duplicate session for the
    // same game. "Still live" is read the same way `rehome` reads it: a
    // non-empty serving set (an empty one means the session already closed
    // and retired its membership, at which point the tenant may legitimately
    // reuse the `external_id`). Checked under the same assignment lock the
    // rest of this body holds, so two near-simultaneous requests for the same
    // `external_id` can't both race past this and each mint their own
    // session — whichever acquires the lock second either replays the
    // first's freshly recorded response or, if the first request failed
    // before recording one, proceeds to mint its own.
    //
    // A replay is honored only when the incoming request's fingerprint matches
    // the one that created the live session. An `external_id` still bound to a
    // live session but presented with a *different* roster is a collision, not
    // a retry: replaying would hand the caller the first roster's tokens, and
    // proceeding to mint would overwrite the live session's lifecycle
    // accounting — so the mismatch is refused outright and the cached entry is
    // left untouched.
    if let Some(external_id) = &request.external_id {
        let key = (request.tenant.clone(), external_id.clone());
        let cached = setup.create_idempotency.lock().get(&key).cloned();
        if let Some(cached) = cached
            && !setup
                .serving_relays(&request.tenant, cached.response.session)
                .is_empty()
        {
            if cached.fingerprint == CreateFingerprint::from_request(&request) {
                return Ok(CreatedSession {
                    response: cached.response,
                    replayed: true,
                });
            }
            return Err(SessionSetupError::IdempotentCreateMismatch);
        }
    }

    validate_request(&request)?;

    // Placement: each slot homes on a relay in the region it requested when one
    // is live, else the region-blind fallback (the lowest-id available relay). A
    // request that carries any per-slot region is placed by region and ignores
    // `dev_relay_split` — regions are the production placement mechanism, the
    // split a region-less dev escape hatch — while a request with no region at all
    // runs the dev-split path unchanged, so today's behavior is byte-for-byte
    // preserved.
    let any_region = request.players.iter().any(|p| p.region.is_some());
    let placement = if any_region {
        place_by_region(&setup.registry, &request)?
    } else {
        place_dev_split(&setup.registry, &request)?
    };

    if !tenant::is_enrolled(&setup.tenants, &request.tenant) {
        return Err(SessionSetupError::TenantNotFound(request.tenant));
    }

    let session = next_session_id(setup);
    let bounds = tenant::bounds(&setup.tenants, &request.tenant).expect("checked enrollment above");

    let Placement {
        home,
        slot_homes,
        relay_ids,
        homes,
        relay_certs,
        relay_regions,
    } = placement;

    // Test seam: a drain mark racing this create lands wholly before or after,
    // because it contends on the assignment lock this body holds (production no-op).
    before_commit();

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
        expected: request.players.iter().map(|p| p.slot).collect(),
        // The per-slot home assignment, each serving relay's client-cert
        // fingerprint (so a later re-home tells a restart-in-place apart from a
        // false alarm), and each serving relay's region (so a re-home can prefer
        // the dead relay's region) — all produced together by the placement so
        // they stay in lockstep with the tokens minted and the response returned.
        homes,
        relay_certs,
        relay_regions,
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

    let response = SessionResponse {
        session,
        home_relay: home,
        slot_homes,
        tokens,
        bounds,
    };
    // Record the exact response a duplicate create for this `external_id`
    // will replay, alongside the fingerprint a replay must match, still under
    // the assignment lock this whole body holds — see the idempotency check
    // above for why that matters. A request with no `external_id` is never
    // recorded (nothing to key a replay on).
    if let Some(external_id) = &request.external_id {
        setup.create_idempotency.lock().insert(
            (request.tenant.clone(), external_id.clone()),
            CachedCreate {
                fingerprint: CreateFingerprint::from_request(&request),
                response: response.clone(),
            },
        );
    }
    Ok(CreatedSession {
        response,
        replayed: false,
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
    build_descriptor(setup, tenant, session, relay_id, false, Vec::new())
}

/// Builds the [`SessionDescriptor`] for a relay serving `session`, with the
/// rehome-specific fields controlled by the caller.
///
/// `resumed` marks a descriptor that re-homes an already-running session onto a
/// relay (the coordinator-mediated failover path), and `departed_slots` seeds the
/// slots the coordinator already knows departed so a fresh relay with no mesh peer
/// to replay them still treats their leaves as decided. `create_session` and the
/// public [`descriptor_for`] pass `false`/empty (the ordinary start-on-coverage
/// path); [`rehome`] passes `true` plus the session's departed accounting.
pub fn build_descriptor(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    relay_id: RelayId,
    resumed: bool,
    departed_slots: Vec<DepartedSlot>,
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
        expected_slots: refs.expected,
        // Only the slots homed on THIS relay — `refs.homes` covers every slot
        // in the session, so filter to this descriptor's `relay_id`. Iterating
        // a `BTreeMap` yields ascending slot order, so this is deterministic
        // without an explicit sort.
        homed_slots: refs
            .homes
            .into_iter()
            .filter(|&(_, home_relay)| home_relay == relay_id)
            .map(|(slot, _)| slot)
            .collect(),
        resumed,
        departed_slots,
        latency_estimate_ms: None,
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

/// The largest `external_id`/`external_ref` the coordinator accepts. ShieldBattery's
/// own correlation ids (a stringified `gameId`/`SbUserId`) are short fixed-shape
/// strings — well under a hundred bytes — so this is generous headroom, not a tight
/// fit; a request naming something longer is either a caller bug or abuse, and the
/// tenant is already authenticated, so this is cheap defense, not a real limit on
/// legitimate use.
const MAX_EXTERNAL_STRING_LEN: usize = 256;

/// The largest `dev_relay_split` the coordinator accepts: no more entries than a
/// session can possibly have slots for ([`MAX_SLOT`] + 1). A dev-only field
/// (production requests always send it empty), but the tenant-authenticated cheap
/// defense applies here too — nothing legitimate ever needs more.
const MAX_DEV_RELAY_SPLIT_LEN: usize = MAX_SLOT as usize + 1;

/// Validates a session request before any work is done.
fn validate_request(request: &SessionRequest) -> Result<(), SessionSetupError> {
    if request.players.is_empty() {
        return Err(SessionSetupError::NoPlayers);
    }
    let mut seen_slots = std::collections::HashSet::with_capacity(request.players.len());
    for player in &request.players {
        if player.slot.0 > MAX_SLOT {
            return Err(SessionSetupError::SlotOutOfRange(player.slot.0 as u16));
        }
        if !seen_slots.insert(player.slot.0) {
            return Err(SessionSetupError::DuplicateSlot(player.slot.0 as u16));
        }
        if let Some(external_ref) = &player.external_ref
            && external_ref.len() > MAX_EXTERNAL_STRING_LEN
        {
            return Err(SessionSetupError::ExternalRefTooLong(player.slot.0 as u16));
        }
    }
    if let Some(external_id) = &request.external_id
        && external_id.len() > MAX_EXTERNAL_STRING_LEN
    {
        return Err(SessionSetupError::ExternalIdTooLong);
    }
    if request.dev_relay_split.len() > MAX_DEV_RELAY_SPLIT_LEN {
        return Err(SessionSetupError::DevRelaySplitTooLong(
            request.dev_relay_split.len(),
        ));
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
///
/// Only *available* relays are candidates — a relay that has asked to drain is
/// excluded from new assignments (it keeps serving its existing sessions). If every
/// relay is draining (or none is enrolled), there is nothing to assign and this is
/// [`NoRelaysAvailable`](SessionSetupError::NoRelaysAvailable).
fn assign_relays(
    registry: &RelayRegistry,
) -> Result<(RelayEndpoint, Option<RelayEndpoint>), SessionSetupError> {
    let mut entries = registry::available_entries(registry);
    if entries.is_empty() {
        return Err(SessionSetupError::NoRelaysAvailable);
    }

    // NOTE(version-aware placement): each entry carries the relay's advertised
    // `protocol` (negotiated against at enroll — an incompatible relay never gets
    // this far), so a placement policy that keeps one session's relays on a single
    // protocol version — needed once a wire bump rolls through a mixed fleet —
    // would filter the candidates here. Nothing consumes it yet; assignment stays
    // version-blind.

    // Sort by relay_id for deterministic assignment.
    entries.sort_by_key(|e| e.relay_id);

    let home = RelayEndpoint::from(&entries[0]);
    let secondary = entries.get(1).map(RelayEndpoint::from);
    Ok((home, secondary))
}

/// A session's relay placement, distilled into the response shape and the
/// coordinator-side records the descriptors and a later re-home read. Both the
/// region-aware and the dev-split paths produce one, so the rest of
/// [`create_session`] is placement-agnostic.
struct Placement {
    /// The session's primary home relay — the response's `home_relay`, where the
    /// most slots home (ties broken by lowest relay id).
    home: RelayEndpoint,
    /// Per-slot overrides for the slots homing on a relay other than `home`.
    slot_homes: Vec<SlotHome>,
    /// The session's serving relays in authority order — `home` first, then the
    /// rest by ascending id. The distinct assigned homes, so every serving relay
    /// homes at least one slot.
    relay_ids: Vec<RelayId>,
    /// Every slot's assigned home relay id.
    homes: std::collections::BTreeMap<SlotId, RelayId>,
    /// Each serving relay's client-cert fingerprint, for a later re-home's
    /// restart-in-place detection.
    relay_certs: std::collections::BTreeMap<RelayId, [u8; 32]>,
    /// Each serving relay's region at pick time, so a re-home can prefer the dead
    /// relay's region for the replacement.
    relay_regions: std::collections::BTreeMap<RelayId, Option<RegionId>>,
}

/// Region-aware placement: home each slot on a live relay in the region it
/// requested, falling back to the region-blind pick (the lowest-id available
/// relay overall) for a slot that named no region, or whose region has no live
/// relay. Slots sharing a region share that region's relay, so a same-region
/// game stays single-relay while a cross-region game produces the meshed
/// `slot_homes` shape.
///
/// The response's `home_relay` is the relay assigned the most slots (ties broken
/// by lowest relay id); `slot_homes` overrides every slot assigned elsewhere. By
/// construction the serving set is exactly the distinct assigned homes and every
/// serving relay homes at least one slot.
fn place_by_region(
    registry: &RelayRegistry,
    request: &SessionRequest,
) -> Result<Placement, SessionSetupError> {
    let mut entries = registry::available_entries(registry);
    if entries.is_empty() {
        return Err(SessionSetupError::NoRelaysAvailable);
    }
    // Ascending id, so "first in a region" and "first overall" are both the
    // deterministic lowest-id pick.
    entries.sort_by_key(|e| e.relay_id);
    let fallback = &entries[0];

    // Assign each slot: the lowest-id available relay in its requested region if
    // one exists, else the region-blind fallback.
    let slot_relay: Vec<(SlotId, &RelayEntry)> = request
        .players
        .iter()
        .map(|player| {
            let entry = player
                .region
                .as_ref()
                .and_then(|region| entries.iter().find(|e| e.region.as_ref() == Some(region)))
                .unwrap_or(fallback);
            (player.slot, entry)
        })
        .collect();

    // The home relay is the one assigned the most slots; a lowest-id tie-break
    // keeps the pick deterministic. Counting through a `BTreeMap` iterates ids
    // ascending, so `Reverse(id)` in the key makes the smallest id win a tie.
    let mut counts: std::collections::BTreeMap<RelayId, usize> = std::collections::BTreeMap::new();
    for (_, entry) in &slot_relay {
        *counts.entry(entry.relay_id).or_insert(0) += 1;
    }
    let home_id = *counts
        .iter()
        .max_by_key(|(id, count)| (**count, std::cmp::Reverse(**id)))
        .map(|(id, _)| id)
        .expect("a non-empty player list always assigns at least one slot");

    // Serving relays in authority order: home first, then the rest ascending
    // (`counts` keys are already ascending).
    let mut relay_ids = vec![home_id];
    relay_ids.extend(counts.keys().copied().filter(|&id| id != home_id));

    let entry_for = |id: RelayId| -> &RelayEntry {
        entries
            .iter()
            .find(|e| e.relay_id == id)
            .expect("a serving relay is always one of the assigned entries")
    };

    let home = RelayEndpoint::from(entry_for(home_id));
    let slot_homes: Vec<SlotHome> = slot_relay
        .iter()
        .filter(|(_, entry)| entry.relay_id != home_id)
        .map(|(slot, entry)| SlotHome {
            slot: *slot,
            relay: RelayEndpoint::from(*entry),
        })
        .collect();
    let homes = slot_relay
        .iter()
        .map(|(slot, entry)| (*slot, entry.relay_id))
        .collect();
    let relay_certs = relay_ids
        .iter()
        .map(|&id| (id, cert_fingerprint(&entry_for(id).cert_der)))
        .collect();
    let relay_regions = relay_ids
        .iter()
        .map(|&id| (id, entry_for(id).region.clone()))
        .collect();

    Ok(Placement {
        home,
        slot_homes,
        relay_ids,
        homes,
        relay_certs,
        relay_regions,
    })
}

/// The region-blind (dev / loopback) placement: every slot homes on the primary
/// relay (lowest-id available), except those the request's
/// [`dev_relay_split`](SessionRequest::dev_relay_split) moves onto the secondary
/// (next-lowest) to force a cross-relay meshed session in testing. This is the
/// pre-region behavior verbatim, run only when no player named a region.
fn place_dev_split(
    registry: &RelayRegistry,
    request: &SessionRequest,
) -> Result<Placement, SessionSetupError> {
    let (home, secondary) = assign_relays(registry)?;

    // Slots the split flagged home on the secondary — honored only when a second
    // relay is enrolled; otherwise the split collapses and every slot homes on
    // the primary.
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

    // The distinct home relays: the primary (serving unless the split moved every
    // slot off it), plus the secondary when at least one slot homes there. A
    // serving relay always homes at least one slot.
    let relay_ids: Vec<RelayId> = {
        let mut ids = Vec::new();
        if slot_homes.len() < request.players.len() {
            ids.push(home.relay_id);
        }
        if let Some(secondary) = &secondary
            && !slot_homes.is_empty()
            && secondary.relay_id != home.relay_id
        {
            ids.push(secondary.relay_id);
        }
        ids
    };

    // Every slot not in `slot_homes` homes on the primary; reusing that set keeps
    // `homes` in lockstep with the overrides by construction.
    let homes = request
        .players
        .iter()
        .map(|p| {
            let relay_id = slot_homes
                .iter()
                .find(|split| split.slot == p.slot)
                .map_or(home.relay_id, |split| split.relay.relay_id);
            (p.slot, relay_id)
        })
        .collect();

    // Each serving relay's cert, looked up from the `home`/`secondary` endpoints
    // rather than the registry again, so it reflects exactly the cert the tokens
    // just minted (and the response about to be returned) commit the clients to.
    let relay_certs = relay_ids
        .iter()
        .filter_map(|&id| {
            if id == home.relay_id {
                Some((id, cert_fingerprint(&home.cert_der)))
            } else {
                secondary
                    .as_ref()
                    .filter(|s| s.relay_id == id)
                    .map(|s| (id, cert_fingerprint(&s.cert_der)))
            }
        })
        .collect();

    // Each serving relay's region, from its current registry entry — the endpoints
    // above don't carry it (region is coordinator-side placement state, never sent
    // to clients or peers), so it is read back here at pick time.
    let relay_regions = relay_ids
        .iter()
        .map(|&id| (id, registry::entry(registry, id).and_then(|e| e.region)))
        .collect();

    Ok(Placement {
        home,
        slot_homes,
        relay_ids,
        homes,
        relay_certs,
        relay_regions,
    })
}

/// The maximum slot id (11: BW supports 12 network participants — 8 players
/// plus 4 observers).
const MAX_SLOT: u8 = 11;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, DepartureKind, PlayerHandoff, RelayHello, SessionRequest, TenantId,
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
        enroll_relay_with_cert(reg, id, port, fake_cert(id));
    }

    /// Enrolls (or re-enrolls) a relay under an explicit cert, so a test can
    /// simulate a same-id restart under a fresh one.
    fn enroll_relay_with_cert(reg: &RelayRegistry, id: u64, port: u16, cert_der: Vec<u8>) {
        registry::enroll(
            reg,
            RelayHello::new(
                RelayId(id),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                ProtocolVersion::CURRENT,
                cert_der,
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
                region: None,
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
                external_ref: None,
                observer: false,
                region: None,
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
            latency_estimate_ms: None,
        };

        let resp = create_session(&setup, req, ExpiresAt(u64::MAX))
            .unwrap()
            .response;

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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert_eq!(
            resp.slot_homes,
            vec![SlotHome {
                slot: SlotId(1),
                relay: RelayEndpoint {
                    relay_id: RelayId(2),
                    relay_addr: resp.slot_homes[0].relay.relay_addr,
                    cert_der: fake_cert(2),
                    relay_addrs: vec![],
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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
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
    fn dev_split_covering_every_slot_does_not_serve_the_slotless_home() {
        // A degenerate dev split naming every player slot moves them all onto the
        // secondary relay; the primary then homes no slot. It must not be recorded
        // as serving — a slotless serving relay would never register a slot, never
        // report `SessionClosed`, and the session's lifecycle would never close.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(0), SlotId(1)],
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

        // Every slot moved to the secondary (relay 2); only it serves.
        assert_eq!(
            setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session),
            vec![RelayId(2)],
            "the slotless primary is not recorded as serving",
        );
        assert_eq!(resp.slot_homes.len(), 2, "both slots home on the secondary");
        assert!(
            resp.slot_homes
                .iter()
                .all(|h| h.relay.relay_id == RelayId(2)),
        );

        // The descriptor built for the sole serving relay ranks only itself in the
        // authority order — the empty home never appears.
        let desc = descriptor_for(
            &setup,
            &TenantId("sb-test".to_owned()),
            resp.session,
            RelayId(2),
        )
        .unwrap();
        assert_eq!(desc.authority_order, vec![RelayId(2)]);
        assert!(
            desc.peers.is_empty(),
            "the slotless home is not a mesh peer"
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
            latency_estimate_ms: None,
        };
        let resp = create_session(&setup, req, ExpiresAt(u64::MAX))
            .unwrap()
            .response;

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
                latency_estimate_ms: None,
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
                latency_estimate_ms: None,
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
                latency_estimate_ms: None,
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
            region: None,
        };

        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: (0..=11).map(player).collect(),
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert_eq!(resp.tokens.len(), 12);

        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![player(12)],
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::SlotOutOfRange(12));
    }

    #[test]
    fn two_players_naming_the_same_slot_is_rejected() {
        let setup = setup_with_two_relays_and_tenant();
        let player = |slot: u8| PlayerHandoff {
            slot: SlotId(slot),
            client_pubkey: ClientPublicKey([slot; 32]),
            external_ref: None,
            observer: false,
            region: None,
        };

        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![player(0), player(1), player(0)],
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::DuplicateSlot(0));
    }

    #[test]
    fn an_oversized_external_id_is_rejected() {
        let setup = setup_with_two_relays_and_tenant();
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(result.unwrap_err(), SessionSetupError::ExternalIdTooLong);

        // Exactly at the cap is fine.
        let ok = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN)),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn an_oversized_external_ref_is_rejected() {
        let setup = setup_with_two_relays_and_tenant();
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![
                    PlayerHandoff {
                        slot: SlotId(0),
                        client_pubkey: ClientPublicKey([0; 32]),
                        external_ref: None,
                        observer: false,
                        region: None,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([1; 32]),
                        external_ref: Some("y".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
                        observer: false,
                        region: None,
                    },
                ],
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionSetupError::ExternalRefTooLong(1)
        );
    }

    #[test]
    fn an_oversized_dev_relay_split_is_rejected() {
        let setup = setup_with_two_relays_and_tenant();
        // More entries than any session could have slots for.
        let oversized_split: Vec<SlotId> = (0..(MAX_DEV_RELAY_SPLIT_LEN + 1) as u8)
            .map(SlotId)
            .collect();
        let result = create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: two_players(),
                external_id: None,
                dev_relay_split: oversized_split,
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        );
        assert_eq!(
            result.unwrap_err(),
            SessionSetupError::DevRelaySplitTooLong(MAX_DEV_RELAY_SPLIT_LEN + 1),
        );
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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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

        // Each relay's descriptor names only the slots the coordinator
        // actually assigned to it, not the whole session's slot set -- a relay
        // uses this to refuse a client whose token authorizes a slot homed
        // elsewhere. Slot 0 stayed on the primary (relay 1); slot 1 split onto
        // the secondary (relay 2).
        assert_eq!(desc.homed_slots, vec![SlotId(0)]);
        assert_eq!(desc2.homed_slots, vec![SlotId(1)]);
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
                        region: None,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([0xBB; 32]),
                        external_ref: None,
                        // An observer: it must show up in the descriptor's
                        // observer_slots so relays exclude it from desync checks.
                        observer: true,
                        region: None,
                    },
                ],
                external_id: Some("game-99".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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
        // Every slot the request listed — the competitor and the observer alike —
        // is carried as an expected slot so the authority relay knows the full set
        // that must connect before it fires the session-start directive.
        let mut expected = desc.expected_slots.clone();
        expected.sort_by_key(|s| s.0);
        assert_eq!(expected, vec![SlotId(0), SlotId(1)]);
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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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
        // Expected slots track the request's players even when no correlation ids
        // were sent: the two competitors must both connect before start.
        let mut expected = desc.expected_slots.clone();
        expected.sort_by_key(|s| s.0);
        assert_eq!(expected, vec![SlotId(0), SlotId(1)]);
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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

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
                latency_estimate_ms: None,
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
            latency_estimate_ms: None,
        };
        let r1 = create_session(&setup, req.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        let r2 = create_session(&setup, req, ExpiresAt(u64::MAX))
            .unwrap()
            .response;
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
            latency_estimate_ms: None,
        };
        let old = create_session(&before, req.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;

        let after = setup_with_two_relays_and_tenant();
        let new = create_session(&after, req, ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        assert!(
            new.session.0 >= old.session.0,
            "a fresh coordinator's ids never start below the old one's",
        );
    }

    // --- Coordinator-mediated re-home ---

    fn tid() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    /// Creates a plain two-player session on `setup`, returning the response.
    fn create_default_session(setup: &SessionSetup) -> SessionResponse {
        create_session(
            setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response
    }

    #[test]
    fn a_duplicate_create_within_the_window_replays_the_original_response() {
        let setup = setup_with_two_relays_and_tenant();
        let request = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        let second = create_session(&setup, request, ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        assert_eq!(
            first, second,
            "a retried create for the same (tenant, external_id) gets the exact original response back",
        );
    }

    #[test]
    fn a_duplicate_create_mints_no_new_session() {
        let setup = setup_with_two_relays_and_tenant();
        let request = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        let _ = create_session(&setup, request, ExpiresAt(u64::MAX))
            .unwrap()
            .response;

        // An unrelated fresh create still gets the very next id in sequence --
        // proof the duplicate above never advanced the session-id counter, so
        // no session was actually minted for it.
        let unrelated = create_default_session(&setup);
        assert_eq!(
            unrelated.session.0,
            first.session.0 + 1,
            "the duplicate consumed no session id of its own",
        );
    }

    #[test]
    fn a_different_external_id_creates_a_genuinely_fresh_session() {
        let setup = setup_with_two_relays_and_tenant();
        let first = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        let second = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: Some("game-2".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert_ne!(first.session, second.session);
        assert_ne!(first.tokens, second.tokens);
    }

    #[test]
    fn a_different_tenants_matching_external_id_is_not_a_duplicate() {
        // Tenant-scoped key: two tenants using the same external_id (plausible
        // if each mints its own game ids independently) must never collide.
        let setup = setup_with_two_relays_and_tenant();
        let other_tenant = TenantId("sb-other".to_owned());
        tenant::enroll(
            setup.tenants(),
            KeyId("test-key-2".to_owned()),
            other_tenant.clone(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();

        let first = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: Some("shared-id".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        let second = create_session(
            &setup,
            SessionRequest {
                tenant: other_tenant,
                players: two_players(),
                external_id: Some("shared-id".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert_ne!(first.session, second.session);
    }

    #[test]
    fn a_closed_sessions_external_id_can_be_reused() {
        let setup = setup_with_two_relays_and_tenant();
        let request = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;

        // The same retirement path a full close uses: membership (and, with
        // it, the idempotency entry) is taken.
        setup.forget_session_membership(&tid(), first.session);
        assert!(
            !setup
                .create_idempotency
                .lock()
                .contains_key(&(tid(), "game-1".to_owned())),
            "retirement must remove the map entry outright, not just leave a stale one \
             that happens to fail the liveness check -- otherwise a tenant that never \
             reuses an external_id leaks one entry per closed session forever",
        );

        let second = create_session(&setup, request, ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        assert_ne!(
            second.session, first.session,
            "the external_id mints a genuinely new session once the old one is gone",
        );
        assert_ne!(second.tokens, first.tokens);

        // The rematch's own external_id is now the one an idempotent retry
        // would replay -- the entry was replaced, not just vacated.
        let retried = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert_eq!(retried, second);
    }

    #[test]
    fn no_external_id_is_never_idempotent() {
        let setup = setup_with_two_relays_and_tenant();
        let request = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: None,
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        let second = create_session(&setup, request, ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        assert_ne!(
            first.session, second.session,
            "a request naming no external_id is never replayed, even back to back",
        );
    }

    #[test]
    fn a_matching_replay_reports_replayed_while_the_first_create_does_not() {
        let setup = setup_with_two_relays_and_tenant();
        let request = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX)).unwrap();
        assert!(
            !first.replayed,
            "the create that actually minted the session is a fresh mint, not a replay",
        );
        let second = create_session(&setup, request, ExpiresAt(u64::MAX)).unwrap();
        assert!(
            second.replayed,
            "a retry with the identical roster is served from the idempotency cache",
        );
        assert_eq!(
            first.response, second.response,
            "the replay hands back the exact original response",
        );
    }

    #[test]
    fn a_replay_matches_regardless_of_player_order() {
        // The fingerprint sorts players by slot, so a retry that lists the same
        // roster in a different order is still an idempotent replay, not a
        // conflict -- request order carries no meaning.
        let setup = setup_with_two_relays_and_tenant();
        let players = two_players();
        let mut reversed = players.clone();
        reversed.reverse();

        let first = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players,
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        let second = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: reversed,
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        assert!(
            second.replayed,
            "the same roster in a different order is the same request, so it replays",
        );
        assert_eq!(first.response, second.response);
    }

    #[test]
    fn a_conflicting_create_reusing_a_live_external_id_for_a_different_roster_is_refused() {
        let setup = setup_with_two_relays_and_tenant();
        let original = SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let first = create_session(&setup, original.clone(), ExpiresAt(u64::MAX)).unwrap();

        // The same external_id, still bound to the live session, but a different
        // roster: slot 1's client pubkey differs, so the tokens the first create
        // minted authorize different clients than this roster asks for. Handing
        // them back, or overwriting the live session's accounting, would both be
        // wrong -- so the create is refused.
        let conflicting = SessionRequest {
            tenant: tid(),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xCC; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
            ],
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        let err = create_session(&setup, conflicting, ExpiresAt(u64::MAX)).unwrap_err();
        assert_eq!(err, SessionSetupError::IdempotentCreateMismatch);

        // The refused conflict minted nothing: an unrelated fresh create still
        // gets the very next id in sequence, so the conflict advanced no counter.
        let unrelated = create_default_session(&setup);
        assert_eq!(
            unrelated.session.0,
            first.response.session.0 + 1,
            "the refused conflict consumed no session id of its own",
        );

        // It also left the cached entry untouched: a retry with the ORIGINAL
        // roster still replays the first response.
        let replay = create_session(&setup, original, ExpiresAt(u64::MAX)).unwrap();
        assert!(
            replay.replayed,
            "the conflict must not have evicted or overwritten the original cache entry",
        );
        assert_eq!(replay.response, first.response);
    }

    #[test]
    fn a_conflicting_create_differing_only_in_the_observer_flag_is_refused() {
        // The observer flag shapes recorded state (the session's observer set and
        // its lifecycle player/observer split) even though it alters no token, so a
        // roster that flips it is a distinct request, not a retry.
        let setup = setup_with_two_relays_and_tenant();
        let players = two_players();
        let mut with_observer = players.clone();
        with_observer[1].observer = true;

        create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players,
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        let err = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: with_observer,
                external_id: Some("game-1".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap_err();
        assert_eq!(err, SessionSetupError::IdempotentCreateMismatch);
    }

    #[test]
    fn rehome_stays_when_the_named_relay_is_still_live() {
        // The coordinator authoritatively knows the relay's liveness from its
        // registry: a client that believes a still-enrolled relay is dead is told to
        // stay rather than move.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);
        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Stay,
        );
    }

    #[test]
    fn rehome_moves_the_group_to_a_live_relay_when_the_home_died() {
        // The home relay (1) drops out of the registry; the session's whole group
        // moves to the lowest-id live relay (2), and the rebuilt descriptor is a
        // resumed one carrying the seeded departure and ranking the new relay in the
        // dead one's place.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);
        registry::remove(setup.registry(), RelayId(1));

        let departed = vec![DepartedSlot {
            slot: SlotId(0),
            kind: DepartureKind::Dropped,
        }];
        let RehomeOutcome::NewTarget(endpoint) =
            rehome(&setup, &tid(), resp.session, RelayId(1), departed.clone())
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(
            endpoint.relay_id,
            RelayId(2),
            "the lowest-id live relay takes over"
        );
        assert_eq!(
            setup.serving_relays(&tid(), resp.session),
            vec![RelayId(2)],
            "the dead relay is replaced in place in the serving set",
        );

        let staged = setup.descriptors().current_for(RelayId(2));
        assert_eq!(staged.len(), 1);
        assert!(staged[0].resumed, "a rehome descriptor resumes the session");
        assert_eq!(
            staged[0].departed_slots, departed,
            "the seeded departure rides it"
        );
        assert_eq!(staged[0].authority_order, vec![RelayId(2)]);
        assert_eq!(
            staged[0].homed_slots,
            vec![SlotId(0), SlotId(1)],
            "both slots homed on the dead relay move onto R_new's descriptor",
        );
    }

    #[test]
    fn rehome_prefers_a_relay_already_serving_the_session() {
        // Relays 1 (home), 2 (dev-split secondary), and 3 (live but idle). The home
        // dies; the replacement must be relay 2 — already serving the session — not
        // the idle relay 3, even though 3 is a lower id than any non-serving pick
        // would otherwise use.
        let reg = registry::new_registry();
        enroll_relay(&reg, 1, 14900);
        enroll_relay(&reg, 2, 14901);
        enroll_relay(&reg, 3, 14902);
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        // serving == {1, 2}; kill the home relay 1.
        registry::remove(setup.registry(), RelayId(1));

        let RehomeOutcome::NewTarget(endpoint) =
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(
            endpoint.relay_id,
            RelayId(2),
            "a live relay already serving the session is preferred over an idle one",
        );

        // Relay 2's rebuilt descriptor gains slot 0 (moved off the dead relay
        // 1) in addition to its own original slot 1 -- the homed-slot set must
        // follow a rehome, not just freeze at a session's original
        // assignment, or R_new's own admission check would refuse the very
        // slot it was just handed.
        let staged = setup.descriptors().current_for(RelayId(2));
        assert_eq!(staged.len(), 1);
        assert_eq!(
            staged[0].homed_slots,
            vec![SlotId(0), SlotId(1)],
            "the moved slot (0) and R_new's original slot (1) are both homed there now",
        );
    }

    #[test]
    fn rehome_is_idempotent_for_the_same_dead_relay() {
        // A concurrent/repeated re-home naming the same dead relay returns the same
        // target and does not re-mutate the serving set.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);
        registry::remove(setup.registry(), RelayId(1));

        let first = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
        let second = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
        assert_eq!(first, second, "a repeat rehome returns the same target");
        assert!(matches!(first, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2)));
        assert_eq!(
            setup.serving_relays(&tid(), resp.session),
            vec![RelayId(2)],
            "a repeat rehome did not further mutate the serving set",
        );
    }

    #[test]
    fn rehome_returns_the_recorded_target_after_the_dead_relay_re_enrolls() {
        // A dead relay can restart and re-enroll under a fresh cert after a session
        // has already re-homed off it. A straggler client still pinned to the OLD
        // cert then asks to re-home the same dead relay id. It must get the recorded
        // replacement (relay 2), not `Stay` — a `Stay` would pin it to relay 1's new
        // cert, which its old pin can never accept, wedging it forever.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);

        // The home relay 1 dies; the first client re-homes the group onto relay 2.
        registry::remove(setup.registry(), RelayId(1));
        let first = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
        assert!(
            matches!(first, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2)),
            "the first re-home moves the group to relay 2",
        );
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);

        // Relay 1 restarts and re-enrolls under a fresh cert.
        enroll_relay(setup.registry(), 1, 14900);

        // The straggler names the same dead relay 1. Even though relay 1 is enrolled
        // again, the recorded re-home wins: it gets relay 2, not Stay.
        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(RelayEndpoint::from(
                &registry::entry(setup.registry(), RelayId(2)).unwrap()
            )),
            "the recorded replacement overrules the re-enrolled dead relay's liveness",
        );
    }

    #[test]
    fn rehome_replaces_a_same_id_relay_that_restarted_with_a_new_cert() {
        // The home relay restarts in place: same id, but a fresh self-signed cert
        // from the new process. Every client's pin was to the old cert, which it
        // can never match, so even though the id is still enrolled and still
        // serving, the coordinator must treat this as a mismatch and hand back the
        // same id under its new cert rather than Stay.
        // Relays 5 and 6 (rather than the usual 1 and 2) so a lower-id relay can
        // enroll later without becoming the session's original home -- proving the
        // replacement pick reaches for the restarted relay's own id rather than
        // drifting to whichever live relay happens to sort lowest.
        let reg = registry::new_registry();
        enroll_relay(&reg, 5, 14900);
        enroll_relay(&reg, 6, 14901);
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);
        let resp = create_default_session(&setup);
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(5)]);

        // A new, lower-id relay enrolls after the session was created. It must not
        // steal the replacement pick away from the restarted relay's own id.
        enroll_relay(setup.registry(), 1, 14899);
        enroll_relay_with_cert(setup.registry(), 5, 14900, vec![0xEE; 4]);

        let departed = vec![DepartedSlot {
            slot: SlotId(0),
            kind: DepartureKind::Dropped,
        }];
        let RehomeOutcome::NewTarget(endpoint) =
            rehome(&setup, &tid(), resp.session, RelayId(5), departed.clone())
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(
            endpoint.relay_id,
            RelayId(5),
            "the restarted relay is its own valid replacement, not the newly-idle lower-id relay 1"
        );
        assert_eq!(
            endpoint.cert_der,
            vec![0xEE; 4],
            "the response carries the relay's fresh cert"
        );
        assert_eq!(
            setup.serving_relays(&tid(), resp.session),
            vec![RelayId(5)],
            "membership is unchanged -- the id never left the serving set",
        );

        let staged = setup.descriptors().current_for(RelayId(5));
        assert_eq!(staged.len(), 1);
        assert!(
            staged[0].resumed,
            "a resumed descriptor is re-pushed to the restarted relay"
        );
        assert_eq!(staged[0].departed_slots, departed);
        assert_eq!(
            staged[0].homed_slots,
            vec![SlotId(0), SlotId(1)],
            "both slots stay homed on the relay under its unchanged id",
        );

        let refs = session_refs(&setup, &tid(), resp.session).unwrap();
        assert_eq!(
            refs.relay_certs.get(&RelayId(5)),
            Some(&cert_fingerprint(&[0xEE; 4])),
            "the recorded pin is updated to the relay's fresh cert",
        );
    }

    #[test]
    fn rehome_stays_when_a_relay_reconnects_under_an_unchanged_cert() {
        // A benign control-WS reconnect re-enrolls the same id under a NEW
        // generation but the SAME cert -- a connection blip, not a restart. The
        // enroll generation is deliberately not the signal for a cert change, so
        // this must still answer Stay.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);

        enroll_relay(setup.registry(), 1, 14900); // same id, same fake_cert(1)

        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Stay,
        );
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
    }

    #[test]
    fn create_session_records_each_serving_relays_cert_for_a_split_session() {
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

        let refs = session_refs(&setup, &tid(), resp.session).unwrap();
        assert_eq!(
            refs.relay_certs.get(&RelayId(1)),
            Some(&cert_fingerprint(&fake_cert(1))),
            "the primary home's cert is recorded",
        );
        assert_eq!(
            refs.relay_certs.get(&RelayId(2)),
            Some(&cert_fingerprint(&fake_cert(2))),
            "the split secondary's cert is recorded too",
        );
    }

    #[test]
    fn rehome_unavailable_for_an_unknown_session() {
        // The dead relay is gone (else the stay-guard short-circuits); an unknown
        // session has no serving set to move.
        let setup = setup_with_two_relays_and_tenant();
        registry::remove(setup.registry(), RelayId(1));
        assert_eq!(
            rehome(&setup, &tid(), SessionId(999_999), RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
        );
    }

    #[test]
    fn rehome_unavailable_when_no_relay_can_take_over() {
        // Every relay has left the registry, so there is nobody to move the session
        // to.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);
        registry::remove(setup.registry(), RelayId(1));
        registry::remove(setup.registry(), RelayId(2));
        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
        );
    }

    #[test]
    fn rehome_unavailable_when_the_named_relay_does_not_serve_the_session() {
        // `dead_relay` comes from the request body. A client that names a relay that
        // is neither still enrolled (so the stay-guard doesn't fire) nor a member of
        // the session's serving set must get Unavailable — with no mutation, no
        // resumed-descriptor push, and no idempotency entry recorded, so a bogus name
        // can't disturb an otherwise-healthy session.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup);

        // The session serves only its home relay 1. Relay 99 was never enrolled and
        // never served it, so it passes the stay-guard yet is not a serving member.
        let before_serving = setup.serving_relays(&tid(), resp.session);
        assert_eq!(before_serving, vec![RelayId(1)]);
        let baseline_descriptor = setup.descriptors().current_for(RelayId(1));

        assert_eq!(
            rehome(
                &setup,
                &tid(),
                resp.session,
                RelayId(99),
                vec![DepartedSlot {
                    slot: SlotId(0),
                    kind: DepartureKind::Dropped,
                }],
            ),
            RehomeOutcome::Unavailable,
        );

        // The serving set is untouched, and no resumed descriptor was pushed to the
        // healthy relay (its outbox still holds exactly the create_session baseline).
        assert_eq!(setup.serving_relays(&tid(), resp.session), before_serving);
        assert_eq!(
            setup.descriptors().current_for(RelayId(1)),
            baseline_descriptor,
            "a non-serving dead-relay name must not re-push descriptors",
        );

        // Re-asking about the same unrelated relay is still Unavailable — no
        // idempotency entry was recorded that would echo a spurious target.
        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(99), vec![]),
            RehomeOutcome::Unavailable,
        );

        // And the session is otherwise unharmed: when its real home relay dies, a
        // correctly-named rehome still moves the group to the live relay 2.
        registry::remove(setup.registry(), RelayId(1));
        assert!(matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
        ));
    }

    #[test]
    fn forget_session_membership_retires_maps_and_refuses_rehome() {
        // Retiring a closed session's membership must empty both `session_relays`
        // and `session_refs`, and — with no serving set left — turn any further
        // re-home ask into `Unavailable`, so a straggler cannot resurrect the game.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: Some("game-42".to_owned()),
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert!(!setup.serving_relays(&tid(), resp.session).is_empty());
        assert!(session_refs(&setup, &tid(), resp.session).is_some());

        // Record a rehome first, so we can also prove the recorded fast path stops
        // matching once membership is retired (its rehomes are cleared elsewhere,
        // but even the standalone lookup must not resurrect a closed session).
        registry::remove(setup.registry(), RelayId(1));
        assert!(matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(_),
        ));

        setup.forget_session_membership(&tid(), resp.session);
        setup.forget_rehomes(&tid(), resp.session);

        assert!(
            setup.serving_relays(&tid(), resp.session).is_empty(),
            "membership retirement empties the serving set",
        );
        assert!(
            session_refs(&setup, &tid(), resp.session).is_none(),
            "membership retirement drops the correlation ids",
        );
        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
            "a session with no membership refuses re-home",
        );
        assert!(
            recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
            "no recorded target survives to resurrect the closed session",
        );
    }

    #[test]
    fn rehome_removes_the_dead_relays_descriptor_so_a_re_enroll_is_not_re_synced() {
        // When the group moves off a dead relay, that relay's descriptor outbox entry
        // for the session must be removed — else a re-enrolling dead relay would be
        // re-synced a descriptor for a session it no longer serves and rejoin it.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                // Split slot 1 onto the secondary so both relays serve (and each has
                // a descriptor staged).
                dev_relay_split: vec![SlotId(1)],
                external_id: None,
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(1))
                .iter()
                .any(|d| d.session == resp.session),
            "the home relay has a descriptor before it dies",
        );

        // The home relay 1 dies; the group re-homes onto the already-serving relay 2.
        registry::remove(setup.registry(), RelayId(1));
        assert!(matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
        ));

        // The dead relay's outbox no longer carries the moved-off session, so a
        // re-enrolling relay 1 subscribing afresh is not told to serve it.
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(1))
                .iter()
                .all(|d| d.session != resp.session),
            "the dead relay's descriptor for the moved-off session was removed",
        );
        let rx = setup.descriptors().subscribe(RelayId(1));
        assert!(!rx.borrow().iter().any(|d| d.session == resp.session));
    }

    #[test]
    fn a_rehome_racing_a_full_close_bails_without_recording_or_pushing() {
        // A rehome that has already passed the early serving-set snapshot, then has a
        // full close land before its mutation, must re-validate under the mutation
        // lock and return Unavailable — recording no rehome (which recorded_rehome
        // would otherwise serve token-free) and pushing no descriptor (which could
        // resurrect the dead session on a live relay). The `before_mutation` seam
        // simulates the close landing in exactly that window.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup); // serving == {1}
        registry::remove(setup.registry(), RelayId(1)); // the home died, so not Stay

        let baseline_relay2 = setup.descriptors().current_for(RelayId(2));

        let outcome = rehome_inner(&setup, &tid(), resp.session, RelayId(1), vec![], || {
            // The concurrent full close clears the session's membership between the
            // snapshot and the mutation (its forget_rehomes would block on the
            // rehomes lock this rehome holds, so only membership is cleared here —
            // faithfully modeling the race window).
            setup.forget_session_membership(&tid(), resp.session);
        });

        assert_eq!(
            outcome,
            RehomeOutcome::Unavailable,
            "a rehome that raced a close bails instead of resurrecting the session",
        );
        assert!(
            recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
            "the raced rehome recorded no idempotency entry to serve token-free",
        );
        assert_eq!(
            setup.descriptors().current_for(RelayId(2)),
            baseline_relay2,
            "the raced rehome pushed no resumed descriptor to a live relay",
        );
    }

    #[test]
    fn a_full_close_after_a_completed_rehome_clears_the_new_relays_descriptor_and_record() {
        // The complement of the racing-rehome test: when a rehome completes FULLY —
        // recording its idempotency entry and pushing a resumed descriptor to the new
        // relay — BEFORE a full close, the close must still clean up after it. The
        // close takes the session's membership atomically, and that snapshot now
        // includes the new relay the completed rehome added, so the close removes the
        // new relay's descriptor too and its forget_rehomes clears the recorded entry.
        let setup = setup_with_two_relays_and_tenant();
        let resp = create_default_session(&setup); // serving == {1}
        registry::remove(setup.registry(), RelayId(1)); // the home died, so not Stay

        // A full rehome moves the group onto relay 2: it records the idempotency entry
        // and pushes a resumed descriptor to relay 2.
        assert!(matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
        ));
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(2))
                .iter()
                .any(|d| d.session == resp.session),
            "the completed rehome staged a resumed descriptor on the new relay",
        );
        assert!(
            recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_some(),
            "the completed rehome recorded an idempotency entry",
        );

        // A full close, in the coordinator's take-first order: take the membership
        // snapshot (it now includes relay 2), remove each taken relay's descriptor,
        // then forget the recorded rehomes.
        let taken = setup.take_session_membership(&tid(), resp.session);
        assert_eq!(
            taken,
            vec![RelayId(2)],
            "the taken snapshot includes the relay the completed rehome added",
        );
        for relay_id in taken {
            setup.descriptors().remove(relay_id, &tid(), resp.session);
        }
        setup.forget_rehomes(&tid(), resp.session);

        // The new relay's descriptor for the closed session is gone from its outbox,
        // and a relay resubscribing after the close is not re-synced it.
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(2))
                .iter()
                .all(|d| d.session != resp.session),
            "the close removed the new relay's descriptor for the closed session",
        );
        let rx = setup.descriptors().subscribe(RelayId(2));
        assert!(
            !rx.borrow().iter().any(|d| d.session == resp.session),
            "a fresh subscribe for the new relay lacks the closed session",
        );

        // No recorded rehome survives to be served token-free after the close.
        assert!(
            recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
            "the close cleared the recorded rehome",
        );
    }

    // --- Dual-stack advertise ---

    #[test]
    fn a_dual_stack_enrollment_flows_through_response_descriptor_and_rehome() {
        // Two dual-stack relays enroll with complete v4+v6 sets. The set must
        // survive every consumer-facing path unchanged — session response,
        // descriptor peers, and a rehome's NewTarget — with the primary intact.
        let v4_1: SocketAddr = "203.0.113.1:14900".parse().unwrap();
        let v6_1: SocketAddr = "[2001:db8::1]:14900".parse().unwrap();
        let v4_2: SocketAddr = "203.0.113.2:14900".parse().unwrap();
        let v6_2: SocketAddr = "[2001:db8::2]:14900".parse().unwrap();

        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(RelayId(1), v4_1, ProtocolVersion::CURRENT, fake_cert(1))
                .with_relay_addrs(vec![v4_1, v6_1]),
        );
        registry::enroll(
            &reg,
            RelayHello::new(RelayId(2), v4_2, ProtocolVersion::CURRENT, fake_cert(2))
                .with_relay_addrs(vec![v4_2, v6_2]),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);

        // A cross-relay session so both relays serve (and each descriptor names
        // the other as a peer).
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

        // The session response's endpoints carry the set, primary unchanged.
        assert_eq!(resp.home_relay.relay_addr, v4_1);
        assert_eq!(resp.home_relay.relay_addrs, vec![v4_1, v6_1]);
        assert_eq!(resp.home_relay.addr_for_family(true), Some(v6_1));
        assert_eq!(resp.slot_homes[0].relay.relay_addrs, vec![v4_2, v6_2]);

        // The descriptor's peer carries the other relay's full set.
        let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
        assert_eq!(desc.peers[0].relay_id, RelayId(2));
        assert_eq!(desc.peers[0].relay_addr, v4_2);
        assert_eq!(desc.peers[0].relay_addrs, vec![v4_2, v6_2]);
        assert_eq!(desc.peers[0].addrs(), vec![v4_2, v6_2]);

        // The home relay dies; the rehome's NewTarget carries the survivor's set.
        registry::remove(setup.registry(), RelayId(1));
        let RehomeOutcome::NewTarget(endpoint) =
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(endpoint.relay_id, RelayId(2));
        assert_eq!(endpoint.relay_addr, v4_2);
        assert_eq!(endpoint.relay_addrs, vec![v4_2, v6_2]);
    }

    // --- Coordinated drain: assignment eligibility + the linearization ---

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// A one-relay setup returning the relay's enroll generation (needed to mark it
    /// draining under the generation fence).
    fn one_relay_setup() -> (SessionSetup, u64) {
        let reg = registry::new_registry();
        let generation = registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                addr(14900),
                ProtocolVersion::CURRENT,
                fake_cert(1),
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        (SessionSetup::new(reg, tenants), generation)
    }

    /// A two-relay setup returning each relay's enroll generation.
    fn two_relay_setup() -> (SessionSetup, u64, u64) {
        let reg = registry::new_registry();
        let g1 = registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                addr(14900),
                ProtocolVersion::CURRENT,
                fake_cert(1),
            ),
        );
        let g2 = registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(2),
                addr(14901),
                ProtocolVersion::CURRENT,
                fake_cert(2),
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        (SessionSetup::new(reg, tenants), g1, g2)
    }

    #[test]
    fn create_session_skips_a_draining_relay() {
        // Relay 1 (the default primary) drains; a create homes on the still-available
        // relay 2 and never names relay 1 in its outbox.
        let (setup, g1, _g2) = two_relay_setup();
        assert!(registry::mark_draining(setup.registry(), RelayId(1), g1));

        let resp = create_default_session(&setup);
        assert_eq!(
            resp.home_relay.relay_id,
            RelayId(2),
            "a create skips the draining relay and homes on the available one",
        );
        assert!(
            setup.descriptors().current_for(RelayId(1)).is_empty(),
            "the drained relay's outbox gains no session from a post-mark create",
        );
    }

    #[test]
    fn all_relays_draining_yields_no_relays_available() {
        let (setup, g1) = one_relay_setup();
        registry::mark_draining(setup.registry(), RelayId(1), g1);

        let err = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap_err();
        assert_eq!(err, SessionSetupError::NoRelaysAvailable);
    }

    #[test]
    fn rehome_replacement_pick_never_selects_a_draining_relay() {
        // Home relay 1 dies; the only other live relay (2) is draining, so the
        // replacement pick refuses it (there is no other live relay) — Unavailable
        // rather than re-homing the whole group onto a relay that asked to stop.
        let (setup, _g1, g2) = two_relay_setup();
        let resp = create_default_session(&setup); // serving == {1}
        registry::remove(setup.registry(), RelayId(1));
        registry::mark_draining(setup.registry(), RelayId(2), g2);

        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
            "a draining relay is never chosen as a re-home target",
        );
    }

    #[test]
    fn rehome_for_a_serving_but_draining_relay_returns_stay() {
        // The dead-named relay is enrolled AND still serving, only draining. Drain
        // blocks NEW assignments; a draining relay still serving is alive, so the
        // stay-check (unchanged — it reads registry liveness, not availability)
        // correctly overrules the client's belief that it died.
        let (setup, g1, _g2) = two_relay_setup();
        let resp = create_default_session(&setup); // serving == {1}
        registry::mark_draining(setup.registry(), RelayId(1), g1);

        assert_eq!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Stay,
            "a draining relay still serving its session is alive: Stay, not a move",
        );
    }

    #[test]
    fn a_drain_mark_racing_create_session_is_linearized_after_the_commit() {
        // The deterministic interleaving: thread A enters create_session's critical
        // section and pauses at the seam (holding the assignment lock); thread B's
        // drain mark must block on that lock until A commits, so B's post-mark view of
        // the relay's descriptor outbox already includes A's just-created session.
        let (setup, g1) = one_relay_setup();

        let (seam_tx, seam_rx) = std::sync::mpsc::channel();
        let setup_a = setup.clone();
        let a = std::thread::spawn(move || {
            create_session_inner(
                &setup_a,
                SessionRequest {
                    tenant: tid(),
                    players: two_players(),
                    external_id: None,
                    dev_relay_split: Vec::new(),
                    latency_estimate_ms: None,
                },
                ExpiresAt(u64::MAX),
                || {
                    // Reached the seam (past the pick, before the commit). Signal, then
                    // linger so B has time to contend on the assignment lock A holds.
                    seam_tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(50));
                },
            )
            .unwrap()
        });

        seam_rx.recv().unwrap(); // A is in its critical section, holding the lock
        {
            // B's drain mark blocks on the assignment lock until A commits and releases.
            let _assign = setup.lock_assignment();
            assert!(registry::mark_draining(setup.registry(), RelayId(1), g1));
        }
        let resp = a.join().unwrap();

        assert!(
            setup
                .descriptors()
                .current_for(RelayId(1))
                .iter()
                .any(|d| d.session == resp.response.session),
            "A committed before B could mark, so A's session is staged in the outbox",
        );
        assert!(
            !registry::is_available(setup.registry(), RelayId(1)),
            "the relay is now draining",
        );
    }

    #[test]
    fn concurrent_creates_and_a_drain_never_name_the_relay_without_staging_it() {
        // The stochastic form of the invariant: N threads hammer create_session on a
        // single relay while one thread marks it draining. Every session a create
        // returned Ok for necessarily committed before the mark (a post-mark create
        // sees the relay draining and fails NoRelaysAvailable), so it must be staged in
        // the relay's descriptor outbox as observed at the mark point — "set before
        // ack: an empty set at ack means provably unassigned", proven at coordinator
        // state level with no sockets.
        let (setup, g1) = one_relay_setup();

        let created: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let setup = setup.clone();
            let created = Arc::clone(&created);
            handles.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    if let Ok(resp) = create_session(
                        &setup,
                        SessionRequest {
                            tenant: tid(),
                            players: two_players(),
                            external_id: None,
                            dev_relay_split: Vec::new(),
                            latency_estimate_ms: None,
                        },
                        ExpiresAt(u64::MAX),
                    ) {
                        created.lock().push(resp.response.session);
                    }
                }
            }));
        }

        // Mark the relay draining partway through, then snapshot its outbox — the
        // coordinator-side ack point. After the mark, no further create can stage a
        // descriptor for the relay, so this snapshot is the complete set of sessions
        // that will ever name it.
        std::thread::sleep(std::time::Duration::from_millis(2));
        {
            let _assign = setup.lock_assignment();
            registry::mark_draining(setup.registry(), RelayId(1), g1);
        }
        let staged: std::collections::HashSet<SessionId> = setup
            .descriptors()
            .current_for(RelayId(1))
            .into_iter()
            .map(|d| d.session)
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let created = created.lock();
        assert!(
            !created.is_empty(),
            "some creates committed before the drain"
        );
        for session in created.iter() {
            assert!(
                staged.contains(session),
                "every Ok session is staged in the relay's outbox at the drain point",
            );
        }
    }

    // --- Region-aware placement ---

    /// Enrolls a relay tagged with `region` (or untagged when `None`), under the
    /// id-derived fake cert.
    fn enroll_relay_in_region(reg: &RelayRegistry, id: u64, port: u16, region: Option<&str>) {
        let mut hello = RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ProtocolVersion::CURRENT,
            fake_cert(id),
        );
        if let Some(region) = region {
            hello = hello.with_region(RegionId(region.to_owned()));
        }
        registry::enroll(reg, hello);
    }

    /// A player in `slot` requesting `region` (or none), with an id-derived pubkey.
    fn player_in_region(slot: u8, region: Option<&str>) -> PlayerHandoff {
        PlayerHandoff {
            slot: SlotId(slot),
            client_pubkey: ClientPublicKey([slot; 32]),
            external_ref: None,
            observer: false,
            region: region.map(|r| RegionId(r.to_owned())),
        }
    }

    /// A tenant-enrolled setup with the given region-tagged relays.
    fn setup_with_region_relays(relays: &[(u64, u16, Option<&str>)]) -> SessionSetup {
        let reg = registry::new_registry();
        for &(id, port, region) in relays {
            enroll_relay_in_region(&reg, id, port, region);
        }
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        SessionSetup::new(reg, tenants)
    }

    /// Creates a session from `players` (region-tagged), returning the response.
    fn create_region_session(setup: &SessionSetup, players: Vec<PlayerHandoff>) -> SessionResponse {
        create_session(
            setup,
            SessionRequest {
                tenant: tid(),
                players,
                external_id: None,
                dev_relay_split: Vec::new(),
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response
    }

    #[test]
    fn region_placement_homes_each_slot_in_its_region() {
        // Two relays in two regions, one slot each: each slot homes on its region's
        // relay, producing the meshed cross-region shape.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let resp = create_region_session(
            &setup,
            vec![
                player_in_region(0, Some("region-a")),
                player_in_region(1, Some("region-b")),
            ],
        );

        // One slot each is a tie, so the home is the lowest-id relay (region-a's 1).
        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        // Slot 1 (region-b) is overridden onto relay 2, with its pinned cert.
        assert_eq!(resp.slot_homes.len(), 1);
        assert_eq!(resp.slot_homes[0].slot, SlotId(1));
        assert_eq!(resp.slot_homes[0].relay.relay_id, RelayId(2));
        assert_eq!(resp.slot_homes[0].relay.cert_der, fake_cert(2));
        // Both relays serve the meshed session.
        let serving: std::collections::HashSet<_> = setup
            .serving_relays(&tid(), resp.session)
            .into_iter()
            .collect();
        assert_eq!(
            serving,
            std::collections::HashSet::from([RelayId(1), RelayId(2)]),
        );
    }

    #[test]
    fn a_slot_whose_region_has_no_relay_falls_back_to_the_global_pick() {
        // Only region-a has relays; a slot asking for region-b falls back to the
        // lowest-id available relay overall — today's region-blind pick.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-a"))]);
        let resp = create_region_session(
            &setup,
            vec![
                player_in_region(0, Some("region-a")),
                player_in_region(1, Some("region-b")),
            ],
        );

        // region-a's lowest-id relay is 1; the unlit region-b slot falls back to the
        // global lowest-id pick, which is also relay 1 — so a single-relay session.
        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert!(
            resp.slot_homes.is_empty(),
            "both slots land on relay 1, so there are no overrides",
        );
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
    }

    #[test]
    fn the_home_relay_is_the_plurality_pick_not_merely_the_lowest_id() {
        // relay 2 (region-b) is assigned two slots, relay 1 (region-a) one: the home
        // is the plurality relay 2, even though relay 1 has the lower id.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let resp = create_region_session(
            &setup,
            vec![
                player_in_region(0, Some("region-b")),
                player_in_region(1, Some("region-b")),
                player_in_region(2, Some("region-a")),
            ],
        );

        assert_eq!(
            resp.home_relay.relay_id,
            RelayId(2),
            "the plurality relay is the home even though it is not the lowest id",
        );
        // Only the region-a slot (2) is overridden, onto relay 1.
        assert_eq!(resp.slot_homes.len(), 1);
        assert_eq!(resp.slot_homes[0].slot, SlotId(2));
        assert_eq!(resp.slot_homes[0].relay.relay_id, RelayId(1));
    }

    #[test]
    fn dev_relay_split_is_ignored_when_any_player_names_a_region() {
        // Slot 0 asks for region-a; slot 1 names no region but is in dev_relay_split.
        // Because a region is present anywhere in the request, the split is ignored
        // entirely: slot 1 falls back to the global pick (relay 1), not relay 2.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let resp = create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: vec![
                    player_in_region(0, Some("region-a")),
                    player_in_region(1, None),
                ],
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;

        assert_eq!(resp.home_relay.relay_id, RelayId(1));
        assert!(
            resp.slot_homes.is_empty(),
            "the dev split is ignored, so slot 1 stays on the global pick (relay 1)",
        );
        assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
    }

    #[test]
    fn placement_records_each_serving_relays_region() {
        // The serving relays' regions are recorded so a later re-home can prefer the
        // dead relay's region.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let resp = create_region_session(
            &setup,
            vec![
                player_in_region(0, Some("region-a")),
                player_in_region(1, Some("region-b")),
            ],
        );
        let refs = session_refs(&setup, &tid(), resp.session).unwrap();
        assert_eq!(
            refs.relay_regions.get(&RelayId(1)),
            Some(&Some(RegionId("region-a".to_owned()))),
        );
        assert_eq!(
            refs.relay_regions.get(&RelayId(2)),
            Some(&Some(RegionId("region-b".to_owned()))),
        );
    }

    #[test]
    fn a_conflicting_create_differing_only_in_a_players_region_is_refused() {
        // Region selects a slot's home relay, so the same external_id reused with a
        // different per-slot region is a genuine roster mismatch (409), not a replay.
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let original = SessionRequest {
            tenant: tid(),
            players: vec![
                player_in_region(0, Some("region-a")),
                player_in_region(1, Some("region-a")),
            ],
            external_id: Some("game-1".to_owned()),
            dev_relay_split: Vec::new(),
            latency_estimate_ms: None,
        };
        create_session(&setup, original.clone(), ExpiresAt(u64::MAX)).unwrap();

        let mut changed = original.clone();
        changed.players[1].region = Some(RegionId("region-b".to_owned()));
        assert_eq!(
            create_session(&setup, changed, ExpiresAt(u64::MAX)).unwrap_err(),
            SessionSetupError::IdempotentCreateMismatch,
        );

        // The original roster still replays, so the conflict left the cache intact.
        assert!(
            create_session(&setup, original, ExpiresAt(u64::MAX))
                .unwrap()
                .replayed,
        );
    }

    #[test]
    fn rehome_prefers_a_replacement_in_the_dead_relays_region() {
        // relay 2 (region-b) homes the single-slot session; the spares are relay 1
        // (region-a) and relay 3 (region-b). When relay 2 dies and no serving relay
        // is left to take over, the replacement is the region-b spare (relay 3), not
        // the lower-id region-a relay 1.
        let setup = setup_with_region_relays(&[
            (1, 14900, Some("region-a")),
            (2, 14901, Some("region-b")),
            (3, 14902, Some("region-b")),
        ]);
        let resp = create_region_session(&setup, vec![player_in_region(0, Some("region-b"))]);
        assert_eq!(resp.home_relay.relay_id, RelayId(2));

        registry::remove(setup.registry(), RelayId(2));
        match rehome(&setup, &tid(), resp.session, RelayId(2), vec![]) {
            RehomeOutcome::NewTarget(ep) => assert_eq!(
                ep.relay_id,
                RelayId(3),
                "the replacement is the region-b spare, not the lower-id region-a relay",
            ),
            other => panic!("expected NewTarget(relay 3), got {other:?}"),
        }
    }

    #[test]
    fn rehome_falls_back_to_any_relay_when_the_dead_region_has_no_live_relay() {
        // relay 2 (region-b) homes the session; the only spare is relay 1 (region-a).
        // When relay 2 dies, region-b has no live relay, so the replacement is the
        // region-blind fallback (relay 1).
        let setup =
            setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
        let resp = create_region_session(&setup, vec![player_in_region(0, Some("region-b"))]);
        assert_eq!(resp.home_relay.relay_id, RelayId(2));

        registry::remove(setup.registry(), RelayId(2));
        match rehome(&setup, &tid(), resp.session, RelayId(2), vec![]) {
            RehomeOutcome::NewTarget(ep) => assert_eq!(
                ep.relay_id,
                RelayId(1),
                "with no live relay in the dead region, any available relay takes over",
            ),
            other => panic!("expected NewTarget(relay 1), got {other:?}"),
        }
    }
}
