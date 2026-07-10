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
    DepartedSlot, PlayerToken, RelayEndpoint, RelayPeer, SessionDescriptor, SessionRequest,
    SessionResponse, SlotExternalRef, SlotHome, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::ExpiresAt;

use crate::descriptors::{RelayDescriptors, RelayReaps};
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
            next_session: Arc::new(AtomicU64::new(first_session_id())),
            rehomes: Arc::new(Mutex::new(HashMap::new())),
            rehome_limiter,
            assignment_lock: Arc::new(Mutex::new(())),
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
    ///   resumed descriptor that rehome pushed, and the close's [`forget_rehomes`]
    ///   (run after the take) clears the idempotency entry it recorded.
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
    pub fn take_session_membership(&self, tenant: &TenantId, session: SessionId) -> Vec<RelayId> {
        let key = (tenant.clone(), session);
        let taken = self.session_relays.lock().remove(&key).unwrap_or_default();
        self.session_refs.lock().remove(&key);
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
    /// [`registry::mark_draining`](crate::registry::mark_draining) so a drain mark
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
/// [`forget_rehomes`] at close, at the same moment its membership is retired. This
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
/// records home-first), else the lowest-id live registered relay. The dead relay
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

    // The named relay is still enrolled *and* still serving this session: a genuine
    // false alarm, so the coordinator authoritatively overrules the client's belief
    // and tells it to stay. The serving-set guard is what distinguishes this from
    // the already-re-homed straggler above: a relay that is enrolled but no longer
    // in the serving set was moved off in a prior re-home (handled by the
    // idempotency lookup), not a false alarm — falling into Stay there would pin the
    // straggler to a relay this session no longer uses.
    if serving.contains(&dead_relay) && registry::entry(&setup.registry, dead_relay).is_some() {
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

    // Pick the replacement: prefer a live *available* relay already serving the
    // session (earliest in the authority order), else the lowest-id live available
    // registered relay. A draining relay is never chosen — it asked to stop taking
    // new work, and re-homing a whole group onto it would be exactly that.
    let r_new = serving
        .iter()
        .copied()
        .find(|&id| id != dead_relay && registry::is_available(&setup.registry, id))
        .or_else(|| {
            let mut entries = registry::available_entries(&setup.registry);
            entries.sort_by_key(|e| e.relay_id);
            entries.first().map(|e| e.relay_id)
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
    // already serving, drop the dead entry rather than list it twice.
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
        if members.contains(&r_new) {
            members.retain(|&id| id != dead_relay);
        } else {
            for id in members.iter_mut() {
                if *id == dead_relay {
                    *id = r_new;
                }
            }
        }
    }

    // The dead relay is no longer a member. Drop its descriptor outbox entry for
    // this session so that if it re-enrolls later it is not re-synced a descriptor
    // for a session it no longer serves (the surviving relays get the resumed push
    // below). Safe even if the dead relay is disconnected — the outbox is
    // latest-wins current state, and a session it left must not remain in its set.
    setup.descriptors.remove(dead_relay, tenant, session);

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
) -> Result<SessionResponse, SessionSetupError> {
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
) -> Result<SessionResponse, SessionSetupError> {
    // Hold the outermost assignment lock across this entire (await-free) body, so
    // the registry read below and the commit that follows cannot interleave with a
    // relay's drain mark. See `SessionSetup::assignment_lock`.
    let _assign = setup.lock_assignment();

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
    //
    // Every slot not moved to the secondary homes on the primary, so the primary
    // is serving unless the split moved *every* slot off it (a degenerate dev
    // split naming all slots). Recording a relay that homes no slot would break
    // the "every serving relay homes a slot" invariant: it would never register a
    // slot, so never report `SessionClosed`, and the session's lifecycle would
    // never close.
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
        resumed,
        departed_slots,
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
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();

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
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
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
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
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
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
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
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
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
            RelayHello::new(RelayId(1), addr(14900), ProtocolVersion::CURRENT, fake_cert(1)),
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
            RelayHello::new(RelayId(1), addr(14900), ProtocolVersion::CURRENT, fake_cert(1)),
        );
        let g2 = registry::enroll(
            &reg,
            RelayHello::new(RelayId(2), addr(14901), ProtocolVersion::CURRENT, fake_cert(2)),
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
                .any(|d| d.session == resp.session),
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
                        },
                        ExpiresAt(u64::MAX),
                    ) {
                        created.lock().push(resp.session);
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
        assert!(!created.is_empty(), "some creates committed before the drain");
        for session in created.iter() {
            assert!(
                staged.contains(session),
                "every Ok session is staged in the relay's outbox at the drain point",
            );
        }
    }
}
