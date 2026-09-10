//! Session-lifecycle endpoints: create, re-home, and the batch liveness probe.
//!
//! These are the tenant-authenticated handlers that mint a session, move one off
//! a dead relay, and answer which of a tenant's sessions the coordinator still
//! holds live state for. Grouped because all three operate on the coordinator's
//! session assignment + lifecycle accounting rather than on read-only views.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rally_point_proto::control::{
    RegionId, RelayEndpoint, SessionRequest, SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId};
use serde::{Deserialize, Serialize};

use crate::registry;
use crate::session::{self, RehomeOutcome, SessionSetup};

use super::CoordinatorState;
use super::request_auth::{TenantAccess, verify_tenant_request};

/// Creates a game session: assigns relays, mints tokens.
///
/// Authenticated by the tenant's request signature (see the module docs): the
/// body is deserialized to learn the tenant, then the signature is verified
/// against that tenant's enrolled `client_pubkeys` before any work is done.
/// Reads the raw body (rather than a `Json` extractor) so the signature covers
/// exactly the bytes on the wire. A suspended or revoked tenant is refused `403`
/// after its signature verifies: creating a new game is exactly the operation
/// suspension halts.
///
/// Each player token is stamped with an expiry of the current Unix time plus
/// [`CoordinatorState::player_token_lifetime`] (saturating). A relay rejects an
/// expired token at handshake, so the lifetime must outlast every (re)connection
/// a client makes over a session's life — initial connect, same-relay reconnect,
/// re-home. The never-started reaper deliberately does NOT wait out this
/// lifetime: a session no client ever dialed is retired after the fixed
/// `lifecycle::NEVER_STARTED_REAP_GRACE`, token validity notwithstanding — see
/// that constant's doc for the rationale.
///
/// On a provisioning-enabled coordinator, a request naming a region with no
/// available relay does not immediately fall back: the coordinator warms that
/// region and answers `202 Accepted` with a [`ProvisioningResponse`]
/// (`{"status":"provisioning", ...}`) without minting anything. The caller
/// re-sends the byte-identical signed request; once the region's relay enrolls the
/// retry places in-region and returns `200`, and if the region stays cold past the
/// coordinator's hold cap the retry falls back to region-blind placement and also
/// returns `200`. The held request never changes, so idempotency is undisturbed.
pub(super) async fn create_session(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: SessionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::NewGame,
    )?;

    // Capture the tenant and the player/observer slot split before the request is
    // consumed, to register the session's lifecycle accounting after setup.
    let tenant = request.tenant.clone();
    let player_slots: std::collections::HashSet<_> = request
        .players
        .iter()
        .filter(|p| !p.observer)
        .map(|p| p.slot)
        .collect();
    let observer_slots: std::collections::HashSet<_> = request
        .players
        .iter()
        .filter(|p| p.observer)
        .map(|p| p.slot)
        .collect();

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = rally_point_proto::token::ExpiresAt(
        now_unix.saturating_add(state.player_token_lifetime.as_secs()),
    );
    let created = match session::create_or_provision_session(&state.setup, request, expires_at) {
        Ok(session::CreateOutcome::Created(created)) => created,
        Ok(session::CreateOutcome::Provisioning { regions }) => {
            // No session minted: a requested region has no relay yet. The
            // coordinator warmed it and is holding the create; the caller re-sends
            // the identical signed request until a relay enrolls or the hold cap
            // elapses. Not a failure, so this does not log like one.
            crate::metrics::session_held(&tenant);
            tracing::info!(
                regions = regions.len(),
                "session create held for a region with no relay yet",
            );
            return Ok((
                StatusCode::ACCEPTED,
                Json(ProvisioningResponse {
                    status: "provisioning",
                    regions,
                    retry_after_ms: PROVISIONING_RETRY_AFTER_MS,
                }),
            )
                .into_response());
        }
        Err(e) => {
            tracing::warn!(error = %e, "session setup failed");
            return Err(match e {
                registry::SessionSetupError::NoRelaysAvailable
                | registry::SessionSetupError::SessionCeilingReached => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                registry::SessionSetupError::IdempotentCreateMismatch => StatusCode::CONFLICT,
                registry::SessionSetupError::TenantNotFound(_)
                | registry::SessionSetupError::SlotOutOfRange(_)
                | registry::SessionSetupError::NoPlayers
                | registry::SessionSetupError::DuplicateSlot(_)
                | registry::SessionSetupError::ExternalIdTooLong
                | registry::SessionSetupError::ExternalRefTooLong(_) => StatusCode::BAD_REQUEST,
            });
        }
    };
    let resp: SessionResponse = created.response;
    let replayed = created.replayed;

    // Arm the session's lifecycle only on a fresh mint: its serving relay set
    // (the distinct home relays of its slots) and its player/observer slots
    // drive `sessionClosed` and the reap policies, including the fixed
    // never-started grace (see `lifecycle::NEVER_STARTED_REAP_GRACE` for why
    // that window is deliberately shorter than the tokens' lifetime).
    //
    // A replayed create must skip this: the original create already registered
    // this session, and re-registering would reset its never-started clock and
    // overwrite its serving-relay accounting with a freshly-read set, corrupting
    // the live session's lifecycle on nothing more than a duplicate retry.
    if !replayed {
        state.lifecycle.register_session(
            tenant.clone(),
            resp.session,
            state.setup.serving_relays(&tenant, resp.session),
            player_slots,
            observer_slots,
        );
        crate::metrics::session_created(&tenant);
    }

    tracing::info!(
        session = %resp.session,
        home_relay = %resp.home_relay.relay_id,
        players = resp.tokens.len(),
        "session created"
    );
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// How long (milliseconds) a `202 provisioning` response tells the caller to wait
/// before re-sending the identical create. Short enough that a relay enrolling
/// mid-hold is noticed promptly, long enough that a stream of retries does not
/// hammer the coordinator while a region warms.
const PROVISIONING_RETRY_AFTER_MS: u64 = 2000;

/// The `202 Accepted` body a hold-until-ready create returns while a requested
/// region is being warmed: `{"status":"provisioning","regions":[...],
/// "retryAfterMs":2000}`. camelCase (tenant-facing surface). `regions` are the
/// still-unlit requested regions the coordinator warmed; the caller re-sends the
/// byte-identical signed create after `retryAfterMs`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisioningResponse {
    /// Always `"provisioning"` — the discriminator that tells this body apart from
    /// a `200` [`SessionResponse`].
    status: &'static str,
    /// The still-unlit requested regions the coordinator is warming.
    regions: Vec<rally_point_proto::control::RegionId>,
    /// How long to wait before re-sending the identical create.
    retry_after_ms: u64,
}

/// Request body for `POST /session/rehome` (tenant-authenticated, snake_case —
/// this is control-plane surface, the same wire style as [`SessionRequest`]).
///
/// The tenant's app server asserts, on behalf of one of its game clients, that a
/// session's home relay has died and asks where the session should move. The
/// request is authenticated exactly like `POST /session/create` — a tenant
/// request signature over the raw body (see the module docs) — and `tenant` must
/// match the tenant that signature verifies under. `session` and `dead_relay_id`
/// are the app server's trusted assertion about one of its own sessions: the
/// tenant is fully trusted for its own sessions, and the coordinator's
/// session lookup is tenant-keyed, so a caller can only ever affect a session it
/// actually owns (a cross-tenant `session` finds no serving set and yields
/// `unavailable`).
#[derive(Debug, Deserialize)]
struct RehomeRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The session to re-home, in the coordinator's `(tenant, session)` id space.
    session: u64,
    /// The relay id the app server reports has died.
    dead_relay_id: u64,
}

/// Response body for `POST /session/rehome`. `decision` is `"stay"`,
/// `"unavailable"`, or `"newTarget"`; `relay` is present only for `"newTarget"`.
/// `relay` is the same proto [`RelayEndpoint`] shape `SessionResponse::home_relay`
/// uses (field names are snake_case to match the rest of the tenant-facing API,
/// and `cert_der` rides as a JSON byte array, not hex) — the app server already
/// parses that shape for `/session/create`, so the re-home response reuses it
/// verbatim rather than converting to a bespoke encoding.
#[derive(Debug, Serialize)]
pub(super) struct RehomeResponse {
    /// The re-home decision: `stay` (the relay is still live), `unavailable` (no
    /// live relay can take over), or `newTarget` (move to `relay`).
    decision: &'static str,
    /// The replacement relay, present only when `decision` is `newTarget`.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelayEndpoint>,
    /// `relay`'s region, present only when `decision` is `newTarget` and the
    /// coordinator has a recorded region for it. Mirrors
    /// [`SessionResponse::relay_regions`](rally_point_proto::control::SessionResponse::relay_regions)
    /// for the same tenant-only, operator-facing purpose — not carried on `relay`
    /// itself, which is the client-facing [`RelayEndpoint`] shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_region: Option<RegionId>,
}

impl RehomeResponse {
    /// Builds the response for `outcome`, looking up the replacement relay's
    /// recorded region (for a `newTarget` decision) from the session's own
    /// placement state.
    fn from_outcome(
        setup: &SessionSetup,
        tenant: &TenantId,
        session: SessionId,
        outcome: RehomeOutcome,
    ) -> Self {
        match outcome {
            RehomeOutcome::Stay => Self {
                decision: "stay",
                relay: None,
                relay_region: None,
            },
            RehomeOutcome::Unavailable => Self {
                decision: "unavailable",
                relay: None,
                relay_region: None,
            },
            RehomeOutcome::NewTarget(endpoint) => {
                let relay_region =
                    session::relay_region_for(setup, tenant, session, endpoint.relay_id);
                Self {
                    decision: "newTarget",
                    relay: Some(endpoint),
                    relay_region,
                }
            }
        }
    }
}

/// Coordinator-mediated failover: a tenant's app server, on behalf of an in-game
/// client whose home relay is unreachable, asks where the session should move.
///
/// **Authenticated exactly like `POST /session/create`** — a tenant request
/// signature over the raw body ([`verify_tenant_request`]) — because the caller
/// is the tenant's app server (the control plane), not the game client. Clients
/// never talk to the coordinator directly; the app server mediates the re-home.
/// The `tenant` in the body must match the tenant the signature verifies under,
/// and the `session` + `dead_relay_id` are the app server's trusted assertion
/// about one of its own sessions. A missing/invalid signature, a stale timestamp,
/// or an unenrolled tenant all map to `401` without revealing which failed. A
/// lenient per-`(tenant, session)` rate limit returns `429` when the caller
/// re-asks too fast. As live-game machinery this is refused (`403`) only for a
/// revoked tenant, not a suspended one — failover must not strand a running game.
///
/// The session lookup [`session::rehome`] performs is tenant-keyed, so a caller
/// can only ever affect a session it actually owns: a `session` that belongs to
/// another tenant (or to no one) finds no serving set and yields `unavailable`,
/// leaking nothing. The decision itself: `stay` when the named relay is in fact
/// still enrolled, `newTarget` when the coordinator moves the whole homed group
/// to a replacement relay (seeding the rebuilt descriptors with the session's
/// already-decided departures so a fresh relay resumes rather than waits), and
/// `unavailable` when the session is unknown or no live relay can take it over.
pub(super) async fn rehome_session(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RehomeResponse>, StatusCode> {
    let request: RehomeRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;

    let tenant = request.tenant;
    let session = SessionId(request.session);
    let dead_relay = RelayId(request.dead_relay_id);

    // Idempotent fast path, served WITHOUT spending a rate-limit token: a straggler
    // re-asking about a relay this session already re-homed off gets the recorded
    // replacement directly. Charging it a token would let already-answered re-asks
    // starve a real survivor's ask for the same session's bucket. A fully-closed
    // session records nothing here (its rehomes are cleared at close), so this can
    // never revive a dead session.
    if let Some(endpoint) = session::recorded_rehome(&state.setup, &tenant, session, dead_relay) {
        return Ok(Json(RehomeResponse::from_outcome(
            &state.setup,
            &tenant,
            session,
            RehomeOutcome::NewTarget(endpoint),
        )));
    }

    // Every non-recorded ask — a first-time survivor, a false-alarm `stay`, or an
    // unknown/garbage session — is rate-limited per authenticated (tenant, session).
    // A refused request is a 429 the caller backs off and re-asks after.
    if !state.setup.rehome_limiter().check(&tenant, session) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Cancel any globally-empty proof before the assignment mutation. Otherwise an
    // already-expired reap task could retire the replacement assignment in the
    // narrow interval before `on_rehome` updates the lifecycle's cached relay set.
    state.lifecycle.prepare_rehome(&tenant, session);
    // Commit lifecycle's cached serving set while `session::rehome` still holds
    // the assignment lock and before it publishes resumed descriptors. Terminal
    // notices take that same lock, so a replacement can never report closed in a
    // gap where authoritative membership is new but lifecycle membership is old.
    // The departed accounting is handed over as a reader, not a snapshot: the
    // rehome reads it at descriptor-build time under that same lock, so a
    // departure notice landing while this request is in flight still seeds the
    // resumed descriptors (see `rehome_inner`).
    let outcome = session::rehome_with_assignment_commit(
        &state.setup,
        &tenant,
        session,
        dead_relay,
        || state.lifecycle.departed_slots(&tenant, session),
        |replacement| {
            state
                .lifecycle
                .on_rehome(&tenant, session, dead_relay, replacement);
        },
    );
    // Let the descriptor push reach R_new's control task before responding, so the
    // relay is likelier to hold the resumed descriptor before a client dials it
    // (the client's reconnect backoff absorbs whatever race remains).
    tokio::task::yield_now().await;

    Ok(Json(RehomeResponse::from_outcome(
        &state.setup,
        &tenant,
        session,
        outcome,
    )))
}

/// The most session ids one liveness probe may ask about, so a caller cannot make
/// the coordinator scan an unbounded list. The probe set in steady state is only
/// the unreconciled v2 games that missed both push paths — near zero — so a few
/// hundred is ample headroom.
pub(super) const MAX_LIVENESS_SESSIONS: usize = 512;

/// Request body for `POST /sessions/alive`: a tenant and the session ids to probe.
#[derive(Debug, Deserialize)]
struct SessionsAliveRequest {
    tenant: TenantId,
    sessions: Vec<u64>,
}

/// Response body for `POST /sessions/alive`: the subset of the probed ids the
/// coordinator still holds live state for. Unknown, closed, and never-created ids
/// are simply omitted — the caller force-reconciles those.
#[derive(Debug, Serialize)]
pub(super) struct SessionsAliveResponse {
    alive: Vec<u64>,
}

/// Batch liveness probe: which of the given sessions the coordinator still holds
/// live state for (created this lifetime, serving set not fully closed). The 15-
/// minute sweep asks this for its unreconciled v2 games and force-reconciles the
/// omitted (gone/unknown) ones — the backstop against coordinator death, in place
/// of a blind per-session timer.
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs): the body is deserialized to learn the tenant, then verified against
/// that tenant's enrolled `client_pubkeys` before the probe. A running game's
/// liveness must survive suspension, so this is refused only for a revoked
/// tenant, not a suspended one. Rejects an over-cap list rather than scan it.
pub(super) async fn sessions_alive(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionsAliveResponse>, StatusCode> {
    let request: SessionsAliveRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;

    if request.sessions.len() > MAX_LIVENESS_SESSIONS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let alive = request
        .sessions
        .into_iter()
        .filter(|&session| {
            state
                .lifecycle
                .is_alive(&request.tenant, SessionId(session))
        })
        .collect();
    Ok(Json(SessionsAliveResponse { alive }))
}
