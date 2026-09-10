//! The create path: session-id assignment, request validation, and the shared
//! body every create entry point runs — idempotent replay, the live-session
//! ceiling, the hold-until-ready consult, placement, and the commit that records
//! membership, stages descriptors, and mints tokens.

use std::sync::atomic::Ordering;

use rally_point_proto::control::{PlayerToken, SessionRequest, SessionResponse};
use rally_point_proto::ids::SessionId;
use rally_point_proto::token::ExpiresAt;

use crate::registry::SessionSetupError;
use crate::tenant;

use super::descriptor::{descriptor_for, relay_region_labels};
use super::gate::{CachedCreate, CreateFingerprint};
use super::placement::{
    Placement, hold_pending_create, now_unix_secs_fail_closed, place_by_region,
    unlit_requested_regions,
};
use super::setup::SessionSetup;
use super::{CreateOutcome, CreatePolicy, CreatedSession, MAX_SLOT, SessionRefs};

/// The first session id for a freshly constructed coordinator: the wall clock
/// in microseconds since the Unix epoch. Relays hold per-session state keyed
/// on `(tenant, session)` — routing groups, dedup sets, decision-makers — and
/// deliberately keep it through a coordinator outage so running games survive
/// one. A restarted coordinator that counted from 1 again could hand a new
/// game a key a relay still holds the old game's state under; a time seed
/// makes ids from different coordinator lifetimes disjoint (the process would
/// have to mint a session per microsecond of downtime to catch up to the next
/// seed). Never 0, so an id is always distinguishable from an unset field.
pub(super) fn first_session_id() -> u64 {
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

/// The id the next successful create will receive, without consuming it.
///
/// A create holds [`SessionSetup::lock_assignment`] while peeking and later
/// assigning the id, so another create cannot advance the counter between the
/// two operations. Placement uses this candidate to balance authority across
/// otherwise-equivalent home relays while still leaving the id available when
/// placement fails.
pub(super) fn candidate_session_id(setup: &SessionSetup) -> SessionId {
    SessionId(setup.next_session.load(Ordering::Relaxed))
}

/// Creates a game session from an app-server request: assigns relays, mints
/// tokens, and returns the response the app server hands to its clients.
///
/// Each slot homes on a live relay in the region it requested
/// ([`PlayerHandoff::region`](rally_point_proto::control::PlayerHandoff::region)),
/// falling back to the lowest-id available relay when it named no region or its
/// region has no live relay. A request with no per-slot regions at all falls back
/// for every slot, so it homes as a single-relay session on the lowest-id relay.
/// In a multi-relay session, the relay homing the most slots is primary; ties
/// rotate deterministically by session id so balanced sessions spread authority
/// work across their equally populated relays without changing any slot's home.
/// Each player gets a token signed by its tenant's key, binding the client pubkey
/// to the slot and session. The bounds come from the tenant's enrolled policy.
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

/// Hold-until-ready create: like [`create_session`], but on a provisioning-enabled
/// coordinator (one whose gate carries a create-hold cap) a request naming a region
/// with **no available relay** warms that region and returns
/// [`CreateOutcome::Provisioning`] instead of falling straight back to a
/// region-blind relay. The caller re-sends the byte-identical signed request until
/// the region's relay enrolls (the retry then places in-region) or the coordinator's
/// hold cap elapses (the retry then falls back exactly as [`create_session`] would),
/// at which point a session is minted and [`CreateOutcome::Created`] returned.
///
/// The hold is anchored across retries by the request's `external_id`: a create with
/// none has nothing to key the cap on, so it never holds and falls back immediately.
/// A held create mints nothing — no session, idempotency entry, descriptor, or
/// lifecycle state — so nothing needs undoing when it is finally placed, and the
/// idempotency fingerprint is undisturbed across the retries.
pub fn create_or_provision_session(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
) -> Result<CreateOutcome, SessionSetupError> {
    create_or_provision_session_at(setup, request, expires_at, now_unix_secs_fail_closed())
}

/// [`create_or_provision_session`] with the hold-cap clock supplied, so a test can
/// drive the cap deterministically. `now` is Unix seconds; `u64::MAX` marks an
/// unusable clock, on which a create never holds (it falls back immediately) so a
/// broken clock cannot wedge session creation.
pub fn create_or_provision_session_at(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
    now: u64,
) -> Result<CreateOutcome, SessionSetupError> {
    create_body(
        setup,
        request,
        expires_at,
        CreatePolicy::HoldUntilReady { now },
        || {},
    )
}

/// [`create_session`]'s body, with a test seam `before_commit` invoked after the
/// relays are picked but before any membership is recorded or descriptor staged —
/// the exact window in which a racing drain mark must be linearized out. Production
/// passes a no-op; a test passes a closure that pauses A mid-span so it can prove a
/// concurrent drain mark blocks on the assignment lock until A commits.
pub(super) fn create_session_inner(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
    before_commit: impl FnOnce(),
) -> Result<CreatedSession, SessionSetupError> {
    match create_body(
        setup,
        request,
        expires_at,
        CreatePolicy::Immediate,
        before_commit,
    )? {
        CreateOutcome::Created(created) => Ok(created),
        // Immediate placement never consults the warm gate, so it cannot warm or
        // hold — it only ever yields a created session.
        CreateOutcome::Provisioning { .. } => {
            unreachable!("immediate placement never returns a provisioning hold")
        }
    }
}

/// The shared body of every create path. `policy` selects immediate placement
/// (the behavior of [`create_session`]) or hold-until-ready (the behavior of
/// [`create_or_provision_session`], which may return [`CreateOutcome::Provisioning`]).
/// `before_commit` is the drain-race test seam (see [`create_session_inner`]).
fn create_body(
    setup: &SessionSetup,
    request: SessionRequest,
    expires_at: ExpiresAt,
    policy: CreatePolicy,
    before_commit: impl FnOnce(),
) -> Result<CreateOutcome, SessionSetupError> {
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
                return Ok(CreateOutcome::Created(CreatedSession {
                    response: cached.response,
                    replayed: true,
                }));
            }
            return Err(SessionSetupError::IdempotentCreateMismatch);
        }
    }

    validate_request(&request)?;

    // The global live-session ceiling: at the cap, a fresh create is refused
    // outright. Deliberately after the replay check above (an idempotent retry
    // of a live session mints nothing, so an ordinary HTTP retry must keep
    // succeeding at the cap) and before the hold-until-ready path below
    // (capacity, not region warmth, is the bottleneck at the cap — holding
    // could not succeed until sessions close, and the immediate refusal tells
    // the tenant so).
    if let Some(ceiling) = setup.session_ceiling
        && setup.live_session_count() >= ceiling
    {
        return Err(SessionSetupError::SessionCeilingReached);
    }

    // Hold-until-ready: on a provisioning-enabled coordinator, a request naming a
    // region with no available relay warms that region and holds — returning a
    // provisioning signal rather than falling straight back to a region-blind
    // relay — until the region's relay enrolls or a per-create hold cap elapses.
    // The hold is anchored across retries by `external_id`; a request with none has
    // nothing to key the cap on and falls straight through to region-blind
    // placement. A held create commits nothing (no placement runs), so a retry that
    // finally places does not double-place.
    if let CreatePolicy::HoldUntilReady { now } = policy
        && let Some(create_hold) = setup.provision.create_hold
        && let Some(external_id) = &request.external_id
    {
        let unlit = unlit_requested_regions(&setup.registry, &request);
        if !unlit.is_empty() {
            for region in &unlit {
                setup
                    .provision
                    .warm
                    .warm(region.clone(), setup.provision.warm_ttl);
            }
            let key = (request.tenant.clone(), external_id.clone());
            if hold_pending_create(&setup.pending_creates, &key, now, create_hold) {
                return Ok(CreateOutcome::Provisioning { regions: unlit });
            }
            // The cap elapsed (or the clock is unusable): the anchor was dropped and
            // the create falls through to placement below, whose region-blind
            // fallback fills the still-unlit slots — a game is never refused because
            // a region stayed cold.
        }
    }

    // Placement: each slot homes on a relay in the region it requested when one
    // is live, else the region-blind fallback (the lowest-id available relay). A
    // request with no per-slot regions at all falls back for every slot, landing
    // everyone on that single relay. Peek rather than consume the id: balanced
    // placements use it to rotate the primary home, but a placement failure must
    // leave the same id available to the next successful create.
    let candidate_session = candidate_session_id(setup);
    let placement = place_by_region(
        &setup.registry,
        &request,
        candidate_session,
        setup.finalize_feature,
    )?;

    if !tenant::is_enrolled(&setup.tenants, &request.tenant) {
        return Err(SessionSetupError::TenantNotFound(request.tenant));
    }

    let session = next_session_id(setup);
    debug_assert_eq!(
        session, candidate_session,
        "the assignment lock keeps the session-id candidate stable through placement",
    );
    let bounds = tenant::bounds(&setup.tenants, &request.tenant).expect("checked enrollment above");

    let Placement {
        home,
        slot_homes,
        relay_ids,
        homes,
        relay_certs,
        relay_regions,
        finalized_drops,
        capable_cohort,
    } = placement;

    // Test seam: a drain mark racing this create lands wholly before or after,
    // because it contends on the assignment lock this body holds (production no-op).
    before_commit();

    setup
        .session_relays
        .lock()
        .insert((request.tenant.clone(), session), relay_ids.clone());

    // Reduced to the response's wire shape before `relay_regions` moves into `refs`
    // below — the response and the recorded correlation state both need this
    // placement data, so it is captured once here rather than re-derived later.
    let response_relay_regions = relay_region_labels(&relay_regions);

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
        finalized_drops,
        capable_cohort,
        latency_estimate_ms: request.latency_estimate_ms,
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
        relay_regions: response_relay_regions,
    };
    // Record the exact response a duplicate create for this `external_id`
    // will replay, alongside the fingerprint a replay must match, still under
    // the assignment lock this whole body holds — see the idempotency check
    // above for why that matters. A request with no `external_id` is never
    // recorded (nothing to key a replay on).
    if let Some(external_id) = &request.external_id {
        let key = (request.tenant.clone(), external_id.clone());
        // The create committed: drop any hold anchored on this `external_id`. The
        // relay enrolled and the slot placed in-region, or the cap elapsed and it
        // placed via fallback — either way the hold is over.
        setup.pending_creates.lock().remove(&key);
        setup.create_idempotency.lock().insert(
            key,
            CachedCreate {
                fingerprint: CreateFingerprint::from_request(&request),
                response: response.clone(),
            },
        );
    }
    Ok(CreateOutcome::Created(CreatedSession {
        response,
        replayed: false,
    }))
}

/// The largest `external_id`/`external_ref` the coordinator accepts. ShieldBattery's
/// own correlation ids (a stringified `gameId`/`SbUserId`) are short fixed-shape
/// strings — well under a hundred bytes — so this is generous headroom, not a tight
/// fit; a request naming something longer is either a caller bug or abuse, and the
/// tenant is already authenticated, so this is cheap defense, not a real limit on
/// legitimate use.
pub(super) const MAX_EXTERNAL_STRING_LEN: usize = 256;

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
    Ok(())
}
