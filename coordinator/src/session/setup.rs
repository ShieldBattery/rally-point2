//! [`SessionSetup`] — the registries and per-session maps every session
//! operation reads and mutates — plus the accessors and membership-retirement
//! methods that guard them. Grouped here because the locking discipline these
//! methods establish (the outermost assignment lock, the single-acquisition
//! membership take) is what create, rehome, and close all build on.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};

use crate::attest::LoadStateAttest;
use crate::descriptors::{RelayDescriptors, RelayReaps};
use crate::presence::PresenceStore;
use crate::registry::RelayRegistry;
use crate::rehome::{LoadStateLimiter, RehomeLimiter};
use crate::tenant::TenantStore;

use super::create::first_session_id;
use super::gate::{CachedCreate, ProvisionGate};
use super::{SessionRefsStore, SessionRelays};

/// The inputs to session setup: the registries the coordinator holds.
#[derive(Clone)]
pub struct SessionSetup {
    /// The relay registry — which relays have phoned home.
    pub(super) registry: RelayRegistry,
    /// The tenant store — per-tenant signing keys + policy.
    pub(super) tenants: TenantStore,
    /// Which relays serve which session. Populated by `create_session`,
    /// read by `descriptor_for`.
    pub(super) session_relays: SessionRelays,
    /// The tenant's correlation ids per session. Populated by `create_session`,
    /// read by [`session_refs`] when a departure webhook is built.
    pub(super) session_refs: SessionRefsStore,
    /// Per-relay descriptor outbox — what each relay should currently apply on
    /// its mesh links. Populated by `create_session`; read by the relay's
    /// descriptor-fetch endpoint.
    pub(super) descriptors: RelayDescriptors,
    /// Per-relay reap outbox — the pending `CloseSlot` directives the reap
    /// policies arm, held as declarative per-relay state and re-synced on
    /// reconnect. Drained by the relay's control connection alongside the
    /// descriptor set.
    reaps: RelayReaps,
    /// The load-state attestation broker — the per-relay question channel the
    /// control connections drain and the correlation map the load-state read waits
    /// on. Held here alongside the other per-relay outboxes it is shaped after.
    attest: LoadStateAttest,
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
    pub(super) next_session: Arc<AtomicU64>,
    /// Idempotency record for coordinator-mediated re-homes: maps a
    /// `(tenant, session, dead_relay)` to the replacement relay chosen for it, so
    /// a concurrent or repeated `rehome` naming the same dead relay returns the
    /// same target without re-mutating the session's relay set. Retired with the
    /// session's other state (see [`forget_rehomes`]).
    pub(super) rehomes: Arc<Mutex<HashMap<RehomeKey, RelayId>>>,
    /// The per-session rate limiter for the tenant-authenticated re-home endpoint
    /// (`POST /session/rehome`). Held here — rather than only in the api-level
    /// `CoordinatorState` — so the lifecycle can drop a closed session's bucket at
    /// the same point it retires the session's other per-session state, keeping the
    /// bucket map bounded by live re-homing sessions.
    rehome_limiter: RehomeLimiter,
    /// The per-tenant rate limiter for the tenant-authenticated load-state read
    /// (`POST /session/load-state`). Keyed on the tenant rather than the session
    /// because the cost it bounds is fleet-wide — each read questions every relay
    /// serving the named session — so a caller reading a thousand different
    /// sessions is exactly the load worth capping. Nothing retires its buckets at
    /// session close: they are per-tenant and pruned by their own idle sweep.
    load_state_limiter: LoadStateLimiter,
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
    pub(super) create_idempotency: Arc<Mutex<HashMap<(TenantId, String), CachedCreate>>>,
    /// The provisioning gate: the shared warm-demand store, its TTL, and (when a
    /// provisioning loop is running) the per-create hold cap. Consulted by
    /// hold-until-ready create and by `POST /regions/warm`. Dormant — an orphan
    /// warm store and no hold — on a coordinator with no provisioning loop, which
    /// keeps every hold-until-ready behavior off.
    pub(super) provision: ProvisionGate,
    /// First-hold timestamps (Unix seconds) for creates currently held for a cold
    /// region, keyed `(tenant, external_id)`. Stamped when a create is first held
    /// and consulted on every retry to enforce the hold cap; dropped when the
    /// create finally places (in-region or via fallback), when the cap elapses, or
    /// by a lazy prune of abandoned anchors. Empty and unused on a coordinator with
    /// no provisioning loop.
    pub(super) pending_creates: Arc<Mutex<HashMap<(TenantId, String), u64>>>,
    /// The global cap on concurrently live sessions across every tenant, or
    /// `None` for uncapped. An emergency brake for the coordinator as a whole:
    /// at the cap a fresh create is refused
    /// ([`SessionSetupError::SessionCeilingReached`]) until sessions close, so
    /// a runaway caller or an abuse burst degrades into refused creates
    /// instead of unbounded session/descriptor/lifecycle growth. Idempotent
    /// replays of a still-live session are exempt — they mint nothing.
    pub(super) session_ceiling: Option<usize>,
    /// Whether new sessions on capable cohorts enable the finalized-drop
    /// handshake. Cohort placement is unconditional; only the feature bit is
    /// gated. See [`with_finalized_drops`](Self::with_finalized_drops).
    pub(super) finalize_feature: bool,
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
            attest: LoadStateAttest::new(),
            presence: crate::presence::new_store(),
            next_session: Arc::new(AtomicU64::new(first_session_id())),
            rehomes: Arc::new(Mutex::new(HashMap::new())),
            rehome_limiter,
            load_state_limiter: LoadStateLimiter::default(),
            assignment_lock: Arc::new(Mutex::new(())),
            create_idempotency: Arc::new(Mutex::new(HashMap::new())),
            provision: ProvisionGate::dormant(),
            pending_creates: Arc::new(Mutex::new(HashMap::new())),
            session_ceiling: None,
            finalize_feature: true,
        }
    }

    /// Sets whether new sessions on capable cohorts run the finalized-drop
    /// handshake. Placement still keeps build-class cohorts apart either way;
    /// this only decides whether a capable cohort's sessions actually enable
    /// the feature. Production wires this from the coordinator's
    /// `--enable-finalized-drops` switch (default OFF until the coordinated
    /// rehome fence exists — see the flag's doc); the constructor default is
    /// ON so the feature's own tests exercise it without ceremony.
    #[must_use]
    pub fn with_finalized_drops(mut self, enabled: bool) -> Self {
        self.finalize_feature = enabled;
        self
    }

    /// Sets the global live-session ceiling (see the field docs). `None` — the
    /// default — is uncapped.
    pub fn with_session_ceiling(mut self, ceiling: Option<usize>) -> Self {
        self.session_ceiling = ceiling;
        self
    }

    /// Installs the provisioning gate, enabling hold-until-ready create and giving
    /// `POST /regions/warm` the warm store the reconcile loop shares. Called once
    /// at construction on a coordinator whose provisioning loop is running; a
    /// coordinator with no loop keeps the dormant gate and every hold-until-ready
    /// behavior stays off.
    pub fn with_provision_gate(mut self, gate: ProvisionGate) -> Self {
        self.provision = gate;
        self
    }

    /// The provisioning gate — the warm store, warm TTL, and create-hold cap the
    /// warm endpoint and hold-until-ready create consult.
    pub fn provision(&self) -> &ProvisionGate {
        &self.provision
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

    /// Exposes the load-state attestation broker (the control connection drains a
    /// relay's questions and resolves its answers; the load-state read asks).
    pub fn attest(&self) -> &LoadStateAttest {
        &self.attest
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

    /// Installs authoritative membership for lifecycle tests that intentionally
    /// bypass [`create_session`]. Keeping this seam test-only ensures production
    /// close handling never fabricates membership from its cached lifecycle view.
    #[cfg(test)]
    pub(crate) fn set_session_membership_for_test(
        &self,
        tenant: &TenantId,
        session: SessionId,
        relays: Vec<RelayId>,
    ) {
        self.session_relays
            .lock()
            .insert((tenant.clone(), session), relays);
    }

    /// The number of live sessions `relay` currently serves — how many recorded
    /// serving sets, across every tenant, name it. Zero means the relay homes no
    /// session's slots right now: a reconcile scale-down reads this to find a relay
    /// safe to drain, and re-reads it after marking the relay draining to catch a
    /// session that landed in the placement race. Counts a session once even if the
    /// relay were to appear in its set more than once (it never is — a serving set
    /// is the session's distinct home relays).
    pub fn session_count_for_relay(&self, relay: RelayId) -> usize {
        self.session_relays
            .lock()
            .values()
            .filter(|relays| relays.contains(&relay))
            .count()
    }

    /// How many sessions are currently live: recorded serving sets, across
    /// every tenant, that still name at least one relay. Read the same way the
    /// idempotent-replay liveness check reads a single session — a set that is
    /// empty (or gone) is a session that already closed.
    pub(super) fn live_session_count(&self) -> usize {
        self.session_relays
            .lock()
            .values()
            .filter(|relays| !relays.is_empty())
            .count()
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
    /// concurrent [`rehome`](fn@crate::session::rehome) re-validates membership under this same lock before it
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
    /// closed session: with no serving relays recorded, [`rehome`](fn@crate::session::rehome)'s
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

    /// The per-tenant load-state read rate limiter, so the api handler can charge a
    /// token and answer a refused read with the interval to retry after.
    pub fn load_state_limiter(&self) -> &LoadStateLimiter {
        &self.load_state_limiter
    }

    /// Replaces the load-state read limiter, so a test can inject a smaller burst or
    /// shorter refill than production's without waiting real seconds.
    #[must_use]
    pub fn with_load_state_limiter(mut self, limiter: LoadStateLimiter) -> Self {
        self.load_state_limiter = limiter;
        self
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
