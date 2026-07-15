//! HTTP control-plane API: session setup + the relay control connection.
//!
//! Exposes a [`router`] function that builds the axum [`Router`] over the
//! coordinator's shared state. The binary binds a TCP listener and serves it;
//! the library owns the routing + handlers so they're testable without a
//! socket (via `tower::ServiceExt::oneshot`).
//!
//! # Endpoints
//!
//! - `POST /session/create` — an app server requests a session. Body:
//!   [`SessionRequest`]; response: [`SessionResponse`] with per-player tokens
//!   and the relay topology.
//! - `GET /tenant/:tenant/pubkey` — fetches a tenant's Ed25519 verifying key
//!   (`{"kid", "publicKey"}`, hex-encoded), so an app server can validate
//!   departure-webhook signatures without pinning the key in its own config.
//!   Public key material only, so — like `/session/create` handing out relay
//!   certs — it needs no auth; 404s for an unenrolled tenant.
//! - `GET /relay/control` — a relay opens its persistent control connection (a
//!   WebSocket). The relay's first frame is a [`RelayToCoordinator::Hello`] that
//!   **enrolls** it into the registry; the coordinator then pushes the relay's
//!   current session-descriptor set down the same connection — on connect
//!   (re-sync) and on every change — driving `MeshCommand::Join`/`Leave` on the
//!   running relay. So a relay registers and receives topology over one channel,
//!   not a separate phone-home plus a socket. The connection is authenticated by
//!   a coordinator-issued **bootstrap secret** the relay presents as
//!   `Authorization: Bearer <secret>` on the upgrade. Auth is [`ControlAuth`]:
//!   either a required secret or an explicit `Open` (no auth) — there is no
//!   implicit open default, and the binary refuses to start `Open` without an
//!   explicit opt-in. The relay also reports liveness up this same connection (a
//!   periodic heartbeat); a relay that goes silent past the liveness deadline, or
//!   whose connection drops, is deregistered — one channel, authenticated once, in
//!   both directions.
//!
//! `session/create` is JSON over HTTP/1.1; the control endpoint upgrades to a
//! WebSocket.
//!
//! # Inbound request authentication (tenant → coordinator)
//!
//! Every tenant-scoped endpoint that mutates or reads per-player state — `POST
//! /session/create`, `POST /sessions/alive`, and `POST /presence/query` —
//! requires an Ed25519 request signature from the tenant's
//! own client key, the mirror image of the coordinator→tenant webhook
//! signature. The app server signs each request with its client key
//! (`SB_RP2_CLIENT_KEY`); the coordinator verifies against one of the public
//! halves it holds for the tenant (its `client_pubkeys`, set at enrollment —
//! more than one only while a request key is being rotated, when a signature
//! from either is accepted). Headers: `x-rp2-timestamp`
//! (unix *seconds*) + `x-rp2-signature` (hex) over `rp2-request-v1:<ts>:<METHOD
//! uppercased>:<path as sent>:<raw body>`. Binding method + path stops a
//! signed body being replayed against a different endpoint. Verification is
//! **required** (fail closed): a missing/invalid signature, a stale timestamp
//! (outside a ±5 minute window), or a tenant with no enrolled client key all
//! 401 without revealing which check failed. There is deliberately **no
//! nonce** — a request captured inside the window can be replayed, but at worst
//! that mints a garbage session that is reaped, and the transport is HTTPS in
//! prod / loopback in dev, so a captured-in-window replay is not a meaningful
//! threat.
//!
//! Once a signature verifies, the tenant's operational state gates the endpoint:
//! a suspended tenant is refused `403` on the new-game operations (session
//! create, region warming) while its running games' endpoints keep working, and
//! a revoked tenant is refused `403` everywhere. The state check runs only after
//! the signature, so a tenant's state is disclosed to that authenticated tenant
//! alone, never to an unauthenticated caller (who always gets the same `401`).
//! `GET /tenant/:tenant/pubkey` stays unsigned (bootstrap: it hands out
//! public key material only, the same posture as `/session/create` returning
//! relay certs), but a revoked tenant's key reads as absent there — a `404`.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        ConnectInfo, FromRequestParts, Path, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Method, StatusCode, Uri, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rally_point_proto::control::{
    CoordinatorToRelay, MeshPeerIdentity, RegionBeaconTarget, RelayEndpoint, RelayHello,
    RelayToCoordinator, SessionDescriptor, SessionRequest, SessionResponse, TenantId,
    TenantVerifyingKey,
};
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_proto::version::{
    self, CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::descriptors::SlotClose;
use crate::identity;
use crate::ledger::RelayLedger;
use crate::lifecycle::Lifecycle;
use crate::notify::{self, NoticeDedup};
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session::{self, RehomeOutcome, SessionSetup};
use crate::tenant;

/// The connecting relay's transport-level peer address, when the server was
/// built to record it (`into_make_service_with_connect_info::<SocketAddr>`).
/// `None` when the serve path supplies none — the router-`oneshot` unit tests,
/// and any test harness that drives the endpoint without a real socket — in which
/// case a ledger's expected-address check reads the peer as unknown.
///
/// An infallible extractor: it never rejects a request, so wiring it onto the
/// control handler cannot change the dev / loopback path, which ignores the value
/// entirely (only a ledger-backed coordinator consults it).
struct OptionalPeerAddr(Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalPeerAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalPeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|connect_info| connect_info.0),
        ))
    }
}

/// How the relay control endpoint authenticates a connecting relay.
///
/// An explicit type rather than an `Option<String>`, so "no authentication" is a
/// deliberate choice the caller spells out ([`Open`](Self::Open)) rather than a
/// fall-through default — the coordinator binary refuses to construct `Open`
/// without an explicit insecure opt-in, so a misconfigured production deploy
/// fails to start instead of silently serving an open control endpoint.
#[derive(Clone)]
pub enum ControlAuth {
    /// Require this bootstrap secret, presented as `Authorization: Bearer
    /// <secret>` on the upgrade.
    Secret(String),
    /// No authentication — for trusted dev/loopback only, where the operator has
    /// explicitly accepted that any reachable caller can open a control
    /// connection.
    Open,
}

/// The coordinator was started with neither a bootstrap secret nor an explicit
/// insecure opt-in, so the relay control endpoint would be unauthenticated. The
/// binary turns this into a startup failure rather than serving an open endpoint.
#[derive(Debug, thiserror::Error)]
#[error(
    "the relay control endpoint would be unauthenticated: configure a bootstrap secret or explicitly allow insecure control"
)]
pub struct InsecureControlNotAllowed;

/// Resolves the control-auth posture from the configured secret and the explicit
/// insecure opt-in, **failing closed**: a secret yields [`ControlAuth::Secret`];
/// no secret yields [`ControlAuth::Open`] only when `allow_insecure` is set, and
/// otherwise is an error so the coordinator refuses to start rather than serve an
/// unauthenticated control endpoint by default.
pub fn resolve_control_auth(
    bootstrap_secret: Option<String>,
    allow_insecure: bool,
) -> Result<ControlAuth, InsecureControlNotAllowed> {
    match bootstrap_secret {
        Some(secret) => Ok(ControlAuth::Secret(secret)),
        None if allow_insecure => Ok(ControlAuth::Open),
        None => Err(InsecureControlNotAllowed),
    }
}

/// How long a control connection has, after the WebSocket upgrade, to send its
/// enroll `Hello` before the coordinator drops it. Bounds an authenticated (or,
/// in `Open` mode, any) connection that opens the socket but never enrolls, so it
/// cannot pin a task indefinitely — the symmetric counterpart to the relay's own
/// client-edge authorization timeout.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the coordinator waits to hear *anything* from an enrolled relay
/// before declaring its control connection dead. Reset on every inbound frame; a
/// relay sends a heartbeat well inside this window, so the deadline only lapses
/// when several heartbeats are missed — a crashed relay or a TCP connection that
/// died without a close. Comfortably larger than the relay's heartbeat interval
/// (a few times over) so ordinary jitter or a single dropped beat never trips it.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(30);

/// The shared state the HTTP handlers operate over: the coordinator's
/// session-setup context plus the relay control-connection auth posture.
/// Cloned cheaply (the setup's fields are `Arc`-backed), so axum's per-request
/// `State` clone shares one set of registries.
#[derive(Clone)]
pub struct CoordinatorState {
    /// The session-setup context — relay registry, tenant store, session→relay
    /// membership, and the per-relay descriptor outbox.
    pub setup: SessionSetup,
    /// Dedup sets for relay notices (departures + desyncs): redundant reports of
    /// one event collapse to a single webhook. Shared across all relay control
    /// connections.
    pub notices: NoticeDedup,
    /// Per-session lifecycle: ordered webhook dispatch, the `sessionClosed`
    /// signal, and the reap policies. Shared across all relay control connections
    /// and the session-create + liveness endpoints.
    pub lifecycle: Lifecycle,
    /// How a relay authenticates to open its control connection.
    pub control_auth: ControlAuth,
    /// How long a connection has to send its enroll `Hello` before it is dropped
    /// (see [`HELLO_TIMEOUT`]). A field so tests can shorten it.
    pub hello_timeout: Duration,
    /// How long an enrolled relay may go silent (no heartbeat or any other frame)
    /// before its connection is dropped and it is deregistered (see
    /// [`LIVENESS_TIMEOUT`]). A field so tests can shorten it.
    pub liveness_timeout: Duration,
    /// The configured placement regions (immutable after startup). Read by
    /// `GET /regions` to serve the client-facing list, and at relay enroll to
    /// refuse a relay tagged with a region not listed here. Empty (the default,
    /// when no `--regions` file is given) leaves every region behavior dormant.
    pub regions: RegionsConfig,
    /// How long each minted player token stays valid, measured from the mint
    /// instant. A client presents its token to a relay at every (re)connection,
    /// and the relay rejects an expired one at handshake, so this bounds the
    /// window in which a client can still (re)connect to its session. Set from
    /// `--player-token-lifetime-secs`.
    pub player_token_lifetime: Duration,
    /// The provisioned-relay ledger, when the coordinator was started with one
    /// (`--relay-ledger`). Present ⇒ **ledger mode**: a relay may enroll only
    /// under an id the ledger minted, presenting its one-time token at first
    /// enroll and its bound certificate on every reconnect; a token-less or
    /// otherwise unauthorized enroll is refused. Absent ⇒ the dev / loopback
    /// posture, where an enroll's id claim is accepted as presented and this whole
    /// path is untouched. Shared across all relay control connections.
    pub ledger: Option<Arc<RelayLedger>>,
}

/// Builds the coordinator's HTTP router over `state`.
pub fn router(state: CoordinatorState) -> Router {
    Router::new()
        .route("/session/create", post(create_session))
        .route("/session/rehome", post(rehome_session))
        .route("/sessions/alive", post(sessions_alive))
        .route("/presence/query", post(presence_query))
        .route("/regions/warm", post(warm_regions))
        .route("/tenant/{tenant}/pubkey", get(tenant_pubkey))
        .route("/regions", get(regions))
        .route("/relay/control", get(relay_control))
        .with_state(state)
}

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
/// re-home. That same expiry also sizes the never-started reaper's grace window
/// (see `lifecycle::never_started_grace`): a freshly created session is held at
/// least until its tokens can no longer be used to dial in, so the reaper never
/// retires a session a straggler could still legitimately connect to.
///
/// On a provisioning-enabled coordinator, a request naming a region with no
/// available relay does not immediately fall back: the coordinator warms that
/// region and answers `202 Accepted` with a [`ProvisioningResponse`]
/// (`{"status":"provisioning", ...}`) without minting anything. The caller
/// re-sends the byte-identical signed request; once the region's relay enrolls the
/// retry places in-region and returns `200`, and if the region stays cold past the
/// coordinator's hold cap the retry falls back to region-blind placement and also
/// returns `200`. The held request never changes, so idempotency is undisturbed.
async fn create_session(
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
                registry::SessionSetupError::NoRelaysAvailable => StatusCode::SERVICE_UNAVAILABLE,
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
    // drive `sessionClosed` and the reap policies. `expires_at` sizes the
    // never-started reap's grace window (see `lifecycle::never_started_grace`)
    // -- the same value the tokens above just carried, so the reaper never
    // gives up before a client's own token would have.
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
            expires_at,
        );
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
struct RehomeResponse {
    /// The re-home decision: `stay` (the relay is still live), `unavailable` (no
    /// live relay can take over), or `newTarget` (move to `relay`).
    decision: &'static str,
    /// The replacement relay, present only when `decision` is `newTarget`.
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<RelayEndpoint>,
}

impl From<RehomeOutcome> for RehomeResponse {
    fn from(outcome: RehomeOutcome) -> Self {
        match outcome {
            RehomeOutcome::Stay => Self {
                decision: "stay",
                relay: None,
            },
            RehomeOutcome::Unavailable => Self {
                decision: "unavailable",
                relay: None,
            },
            RehomeOutcome::NewTarget(endpoint) => Self {
                decision: "newTarget",
                relay: Some(endpoint),
            },
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
async fn rehome_session(
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
        return Ok(Json(RehomeResponse::from(RehomeOutcome::NewTarget(
            endpoint,
        ))));
    }

    // Every non-recorded ask — a first-time survivor, a false-alarm `stay`, or an
    // unknown/garbage session — is rate-limited per authenticated (tenant, session).
    // A refused request is a 429 the caller backs off and re-asks after.
    if !state.setup.rehome_limiter().check(&tenant, session) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let departed = state.lifecycle.departed_slots(&tenant, session);
    let outcome = session::rehome(&state.setup, &tenant, session, dead_relay, departed);
    // Keep the lifecycle's cached serving-relay set in step with the mutation
    // `session::rehome` just committed, so a later `SessionClosed` from the
    // replacement can still satisfy the all-relays-closed condition. Only the
    // ask that actually performed (or replayed, via `rehome`'s own idempotency
    // check) the mutation reaches here — the lock-free recorded-rehome fast path
    // above returns before this point and never calls in, matching that its
    // first application already applied the swap. `on_rehome` is itself
    // idempotent (a second call for an already-swapped id is a no-op), so a
    // repeat here from `rehome`'s internal idempotent branch is harmless.
    if let RehomeOutcome::NewTarget(ref endpoint) = outcome {
        state
            .lifecycle
            .on_rehome(&tenant, session, dead_relay, endpoint.relay_id);
    }
    // Let the descriptor push reach R_new's control task before responding, so the
    // relay is likelier to hold the resumed descriptor before a client dials it
    // (the client's reconnect backoff absorbs whatever race remains).
    tokio::task::yield_now().await;

    Ok(Json(RehomeResponse::from(outcome)))
}

/// The most session ids one liveness probe may ask about, so a caller cannot make
/// the coordinator scan an unbounded list. The probe set in steady state is only
/// the unreconciled v2 games that missed both push paths — near zero — so a few
/// hundred is ample headroom.
const MAX_LIVENESS_SESSIONS: usize = 512;

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
struct SessionsAliveResponse {
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
async fn sessions_alive(
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

/// The most user refs one presence query may ask about, so a caller cannot make
/// the coordinator resolve an unbounded list. A matchmaking check asks about one
/// user (or one party's few), so this is generous headroom — the same posture as
/// [`MAX_LIVENESS_SESSIONS`].
const MAX_PRESENCE_USERS: usize = 64;

/// Request body for `POST /presence/query`: a tenant and the user refs to probe —
/// the tenant's own player ids, the same `external_ref` values it attached to
/// each slot at session creation.
#[derive(Debug, Deserialize)]
struct PresenceQueryRequest {
    tenant: TenantId,
    users: Vec<String>,
}

/// Response body for `POST /presence/query`: one answer per queried user, in
/// request order.
#[derive(Debug, Serialize)]
struct PresenceQueryResponse {
    users: Vec<UserPresence>,
}

/// One queried user's presence verdict.
#[derive(Debug, Serialize)]
struct UserPresence {
    /// The queried ref, echoed back.
    user: String,
    /// Whether any relay currently reports a slot mapped to this user connected.
    in_game: bool,
    /// The sessions the user is present in (the coordinator's tenant-scoped ids,
    /// which this tenant already knows from its own session responses). Included
    /// for observability; empty when `in_game` is false.
    sessions: Vec<u64>,
}

/// Active-player presence query: which of the given users are connected to a
/// relay in a live game right now — what a tenant's matchmaker consults to block
/// an in-game player from re-queueing.
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. As live-game machinery this is refused (`403`) only for a revoked
/// tenant, not a suspended one. Rejects an over-cap user list rather than resolve
/// it.
///
/// **Fail-open, by design.** Absence of evidence answers `in_game: false`. The
/// presence store is in-memory truth fed by relay heartbeats: a coordinator
/// restart wipes it (the next round of beats repopulates it within one ~10s
/// interval), a relay's control-connection flap clears that relay's entries, and
/// an expired TTL reads as absent. In every one of those unavailable states the
/// endpoint must NOT lock players out of matchmaking — letting an in-game player
/// queue briefly is today's status quo, while locking out a legitimate player is
/// strictly worse. Callers should treat `true` as authoritative and `false` as
/// "no evidence".
///
/// **Semantics, honestly:** presence means "connected to a relay now". A
/// just-created session whose clients have not dialed yet is the tenant's own
/// knowledge (it created it); it does not read as presence here until the
/// clients connect.
///
/// Resolution is coordinator-side only: relays report tenant/session/slot, and
/// slots map to user refs through the session refs the tenant supplied at
/// creation — no user identity ever reaches a relay.
async fn presence_query(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PresenceQueryResponse>, StatusCode> {
    let request: PresenceQueryRequest =
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

    if request.users.len() > MAX_PRESENCE_USERS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Snapshot the tenant's fresh presence and resolve each (session, slot) to
    // the tenant's user ref through the stored session refs. A session with no
    // stored refs (created before a restart wiped them, or with no external_refs
    // supplied) resolves to no users — fail-open.
    let fresh = presence::fresh_slots(
        state.setup.presence(),
        &request.tenant,
        std::time::Instant::now(),
    );
    let mut sessions_by_user: std::collections::HashMap<String, std::collections::BTreeSet<u64>> =
        std::collections::HashMap::new();
    let mut refs_by_session: std::collections::HashMap<SessionId, Option<session::SessionRefs>> =
        std::collections::HashMap::new();
    for (session_id, slot) in fresh {
        let refs = refs_by_session
            .entry(session_id)
            .or_insert_with(|| session::session_refs(&state.setup, &request.tenant, session_id));
        if let Some(refs) = refs
            && let Some(user) = refs.slots.get(&slot)
        {
            sessions_by_user
                .entry(user.clone())
                .or_default()
                .insert(session_id.0);
        }
    }

    let users = request
        .users
        .into_iter()
        .map(|user| {
            let sessions: Vec<u64> = sessions_by_user
                .get(&user)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            UserPresence {
                in_game: !sessions.is_empty(),
                user,
                sessions,
            }
        })
        .collect();
    Ok(Json(PresenceQueryResponse { users }))
}

/// Request body for `POST /regions/warm`: a tenant and the regions it wants kept
/// warm. Tenant-authenticated (snake_case control-plane surface, like
/// [`SessionRequest`]); `tenant` must match the tenant the request signature
/// verifies under.
#[derive(Debug, Deserialize)]
struct WarmRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The regions to keep warm.
    regions: Vec<rally_point_proto::control::RegionId>,
}

/// Response body for `POST /regions/warm`: which requested regions were warmed and
/// which were not recognized. A region the coordinator does not configure lands in
/// `unknown` rather than failing the request, so a stale region list on the tenant
/// still warms the valid remainder.
#[derive(Debug, Serialize)]
struct WarmResponse {
    /// The requested regions the coordinator configures — warmed (their demand
    /// raised and TTL extended) when a provisioning loop is running.
    warmed: Vec<rally_point_proto::control::RegionId>,
    /// The requested regions the coordinator does not configure. Reported, not an
    /// error.
    unknown: Vec<rally_point_proto::control::RegionId>,
}

/// Keeps the named regions warm: raises each configured region's warm demand and
/// pushes its TTL out, so the reconcile loop provisions (or holds) a relay there
/// ahead of a create that needs it. Idempotent — the app server re-sends this on an
/// interval to hold a region warm, and stops simply by going quiet (the demand
/// lapses at its TTL).
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. A region the coordinator does not configure is reported in `unknown`
/// (and logged at debug) rather than failing the whole request, so a stale region
/// list still warms its valid regions. No rate limit: the only callers are
/// tenant-signed app servers.
///
/// On a coordinator with **no provisioning loop**, the gate is dormant: known
/// regions are still acknowledged in `warmed` and unknown ones still reported, but
/// nothing consumes warm demand, so no relay is actually held warm. The response
/// shape is the same, so a caller sees the known/unknown split either way.
async fn warm_regions(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WarmResponse>, StatusCode> {
    let request: WarmRequest =
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

    let gate = state.setup.provision();
    let mut warmed = Vec::new();
    let mut unknown = Vec::new();
    for region in request.regions {
        if state.regions.contains(&region) {
            gate.warm().warm(region.clone(), gate.warm_ttl());
            warmed.push(region);
        } else {
            tracing::debug!(
                region = region.as_ref(),
                "warm request named a region the coordinator does not configure",
            );
            unknown.push(region);
        }
    }
    Ok(Json(WarmResponse { warmed, unknown }))
}

/// Response body for `GET /tenant/:tenant/pubkey`.
///
/// camelCase (not the control plane's snake_case): this is tenant-facing
/// surface, like the departure webhook body, not coordinator↔relay wire.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantPubkeyResponse {
    /// The `kid` naming this key — the same value a departure webhook's
    /// signature was made under, so a consumer can key its own verifying-key
    /// cache by it.
    kid: String,
    /// The raw 32-byte Ed25519 verifying key, as 64 lowercase hex characters.
    public_key: String,
}

/// Fetches a tenant's Ed25519 verifying key, so an app server can validate
/// departure-webhook signatures ([`crate::tenant::sign_webhook`]'s
/// counterpart) without pinning the key in its own env config.
///
/// No auth: this hands out public key material only, the same trust posture
/// as `/session/create` handing out relay certs. 404s for a tenant that isn't
/// enrolled (never provisioned, or removed). A revoked tenant is treated as
/// absent — a `404` — since a revoked tenant delivers no webhooks, so there is
/// no signature for a consumer to validate against its key.
async fn tenant_pubkey(
    State(state): State<CoordinatorState>,
    Path(tenant): Path<String>,
) -> Result<Json<TenantPubkeyResponse>, StatusCode> {
    let tenant = TenantId(tenant);
    if matches!(
        tenant::tenant_state(state.setup.tenants(), &tenant),
        Some(tenant::TenantState::Revoked)
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    let (kid, public_key) =
        tenant::verifying_key(state.setup.tenants(), &tenant).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(TenantPubkeyResponse {
        kid: kid.0,
        public_key: hex::encode(public_key),
    }))
}

/// Serves the coordinator's configured region list as `{"regions": [...]}` (ids,
/// display names, and ping targets), in the file's display order.
///
/// **Unauthenticated GET**, following the `GET /tenant/:tenant/pubkey`
/// precedent: the request-signature scheme covers body-carrying mutations, and
/// this list is client-public by design — the SB server forwards it verbatim to
/// every game client. An empty body (`{"regions": []}`) is the honest answer for
/// a coordinator with no `--regions` config.
async fn regions(State(state): State<CoordinatorState>) -> Json<RegionsConfig> {
    Json(state.regions.clone())
}

/// Accepts a relay's persistent control connection (a WebSocket).
///
/// Authenticates against the bootstrap secret before the upgrade — a rejected
/// relay gets a `401` rather than an open socket — then upgrades and serves the
/// connection, which enrolls the relay (from its `Hello`) and pushes descriptors.
///
/// **The claimed relay id is bound to proof of holding its certificate's private
/// key**, not merely trusted from the shared bootstrap secret. After the `Hello`
/// and version negotiation, [`serve_relay_control`] challenges the connection
/// with a random nonce and verifies a signature over it made with the private
/// key matching `Hello.cert_der`, before enrolling — closing the gap where a
/// bootstrap-secret holder could otherwise copy a victim relay's public
/// certificate into its own `Hello` and enroll as it (see [`crate::identity`]).
/// The challenge is mandatory: negotiation refuses any relay advertising a
/// version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so there is no un-challenged enroll path. Proof of possession alone still
/// permits *any* id claim, though: a live registry entry under the claimed id
/// whose certificate differs from the newly-proven one is refused as a duplicate
/// rather than silently evicted (the same certificate replaces it, exactly as a
/// reconnect always has).
///
/// A coordinator started with a provisioned-relay ledger tightens this further:
/// after the proof-of-possession succeeds, the connection is authorized against
/// the ledger (see [`crate::ledger`]) — the id must have been minted, must not be
/// retired, and must present its one-time token (first enroll) or its bound
/// certificate (reconnect), else the connection is closed with
/// [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`] and never reaches the registry. A
/// coordinator with no ledger skips that step entirely (dev / loopback).
async fn relay_control(
    State(state): State<CoordinatorState>,
    headers: HeaderMap,
    OptionalPeerAddr(peer_addr): OptionalPeerAddr,
    ws: WebSocketUpgrade,
) -> Response {
    if !control_auth_ok(&headers, &state.control_auth) {
        tracing::warn!("relay control connection rejected: bad bootstrap secret");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let setup = state.setup.clone();
    let notices = state.notices.clone();
    let lifecycle = state.lifecycle.clone();
    let hello_timeout = state.hello_timeout;
    let liveness_timeout = state.liveness_timeout;
    let regions = state.regions.clone();
    let ledger = state.ledger.clone();
    let peer_ip = peer_addr.map(|addr| addr.ip());
    ws.on_upgrade(move |socket| {
        serve_relay_control(
            socket,
            setup,
            notices,
            lifecycle,
            hello_timeout,
            liveness_timeout,
            regions,
            ledger,
            peer_ip,
        )
    })
}

/// Serves one relay's control connection: enroll from its `Hello`, push
/// descriptors, watch the relay's liveness, and deregister it when the connection
/// drops.
///
/// The relay's first frame must be its [`RelayToCoordinator::Hello`], sent within
/// `hello_timeout`. After version negotiation and region validation succeed, the
/// connection must prove possession of its certificate's private key (see
/// [`crate::identity`]) and clear the duplicate-id check before
/// [`registry::try_enroll`] runs and yields the connection's generation —
/// negotiation already refused any relay advertising a version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so the challenge runs on every connection that reaches it. The connection
/// then serves descriptors and watches liveness ([`push_and_watch`]) until it
/// ends — the relay closes, the socket errors, the relay goes silent past
/// `liveness_timeout`, or the coordinator's outbox is dropped (shutdown).
///
/// When `ledger` is present, a step runs between the proof-of-possession and the
/// registry insert: the enroll is authorized against the provisioned-relay ledger
/// (see [`crate::ledger`]), refused with [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`] if
/// the id was not minted, is retired, or presents no valid token / bound
/// certificate. On a first enroll the ledger consumes the id's token and binds it
/// to this certificate; when the ledger recorded a coordinator-resolved advertise
/// set for the id, that set overrides the hello's self-reported addresses before
/// enrollment (coordinator-sourced addresses win, the hello is the fallback).
/// `peer_ip` is the connection's transport-level peer address, enforced against
/// the ledger's expected address for the id when one was recorded. Without a
/// ledger this step is skipped and the hello enrolls with its self-reported id
/// and addresses.
///
/// When the connection drops, the relay is deregistered — but only if this
/// connection is still the current one ([`registry::remove_if_current`]): a relay
/// that already reconnected (a newer connection re-enrolled it) keeps its live
/// entry, so a stale drop racing a reconnect does not evict a relay that is in fact
/// connected.
#[allow(clippy::too_many_arguments)]
async fn serve_relay_control(
    mut socket: WebSocket,
    setup: SessionSetup,
    notices: NoticeDedup,
    lifecycle: Lifecycle,
    hello_timeout: Duration,
    liveness_timeout: Duration,
    regions: RegionsConfig,
    ledger: Option<Arc<RelayLedger>>,
    peer_ip: Option<IpAddr>,
) {
    // The first frame enrolls the relay, and must arrive within the deadline — a
    // connection that opens the socket but never sends a Hello is dropped rather
    // than left to pin a task. A bad/absent first frame likewise just closes.
    let mut hello = match tokio::time::timeout(hello_timeout, read_hello(&mut socket)).await {
        Ok(Some(hello)) => hello,
        Ok(None) => return,
        Err(_elapsed) => {
            tracing::debug!("control connection sent no Hello within the deadline; closing");
            return;
        }
    };
    // Negotiate before enrolling: the Hello advertises the relay's
    // `[min_protocol, protocol]` window (a relay predating the field advertises
    // the single version in `protocol`). No overlap with this build's window means
    // this coordinator cannot drive the relay at any version — refuse with a close
    // frame naming both windows rather than register a relay every session
    // assignment would then mis-speak to. The relay recognizes the close code and
    // backs off until a deploy fixes the skew.
    let window_min = hello.min_protocol.unwrap_or(hello.protocol);
    let negotiated = match version::negotiate(window_min, hello.protocol) {
        Ok(negotiated) => negotiated,
        Err(error) => {
            tracing::warn!(
                relay_id = hello.relay_id.0,
                %error,
                "refusing relay control connection: no common protocol version",
            );
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: CONTROL_CLOSE_PROTOCOL_MISMATCH,
                    reason: error.to_string().into(),
                })))
                .await;
            return;
        }
    };
    // Validate the relay's advertised region before enrolling: a hello carrying a
    // region the coordinator's config does not list — including the case where no
    // regions are configured at all — is refused, since a typo'd region tag that
    // silently serves nobody is worse than a failed enroll. A hello with no region
    // always enrolls (dev / loopback, or a fleet with no region config). The relay
    // recognizes the close code and backs off long, treating it as a config fix
    // rather than a redial.
    if let Some(region) = &hello.region
        && !regions.contains(region)
    {
        tracing::warn!(
            relay_id = hello.relay_id.0,
            region = region.as_ref(),
            "refusing relay control connection: region not in the coordinator's config",
        );
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CONTROL_CLOSE_UNKNOWN_REGION,
                reason: format!("unknown region: {}", region.as_ref()).into(),
            })))
            .await;
        return;
    }

    let relay_id = hello.relay_id;
    let registry = setup.registry();

    // Every accepted control connection proves possession of its certificate's
    // key before enrolling: `hello.cert_der` alone is a claim the relay
    // presented, not proof it holds the matching private key — a
    // bootstrap-secret holder could otherwise copy a victim relay's public
    // certificate into its own Hello and enroll as it. Negotiation already
    // refused any relay advertising a version below the challenge threshold, so
    // there is no un-challenged enroll path to reach.
    if !challenge_and_verify(&mut socket, &hello, hello_timeout).await {
        return;
    }

    // A ledger-backed coordinator authorizes the enroll against its provisioned
    // record before touching the registry: the id must be one the ledger minted,
    // not retired, and either presenting its one-time token (first enroll, binding
    // this proof-of-possession-verified certificate) or re-presenting the bound
    // certificate (a reconnect). A refusal closes with a single generic reason so a
    // caller cannot probe which ids exist or whether a token was near-valid; the
    // specific class rides only the server-side log. A coordinator with no ledger
    // skips this entirely — the id claim is accepted as presented (dev / loopback).
    if let Some(ledger) = &ledger {
        let cert_fingerprint = registry::cert_fingerprint(&hello.cert_der);
        match ledger.authorize_enroll(
            relay_id,
            cert_fingerprint,
            hello.enroll_token.as_deref(),
            peer_ip,
        ) {
            Ok(_authorized) => {
                // Coordinator-sourced addresses win; the hello's self-report is the
                // fallback. When the ledger recorded an advertise set for this id,
                // override the hello's addresses with it (first entry is the
                // primary) before enrolling, so the registry advertises what the
                // coordinator resolved rather than what the relay claimed. An id
                // with no recorded set enrolls with its self-reported addresses.
                match ledger.advertised_addrs(relay_id) {
                    Ok(Some(addrs)) if !addrs.is_empty() => {
                        hello.relay_addr = addrs[0];
                        hello.relay_addrs = addrs;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            relay_id = relay_id.0,
                            %error,
                            "reading the ledger advertise set failed; enrolling with the hello's addresses",
                        );
                    }
                }
            }
            Err(refusal) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    %refusal,
                    "refusing relay control connection: ledger did not authorize the enroll",
                );
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
                        reason: "enrollment not authorized for this relay id".into(),
                    })))
                    .await;
                return;
            }
        }
    }

    // Enrollment goes through `registry::try_enroll`, whose duplicate-id refusal
    // is atomic with the insert: a live entry under this id bound to a
    // *different* certificate is a second relay process colliding on the id and
    // is refused, while the same fingerprint is this relay's own control
    // connection redialing (its cert is stable across restarts of one instance)
    // and replaces the entry exactly as it always has. Proof of possession above
    // is what makes the fingerprint trustworthy to compare against.
    let generation = match registry::try_enroll(registry, hello) {
        Ok(generation) => generation,
        Err(registry::EnrollConflict) => {
            tracing::warn!(
                relay_id = relay_id.0,
                "refusing relay control connection: relay id already enrolled under a different certificate",
            );
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: CONTROL_CLOSE_DUPLICATE_RELAY_ID,
                    reason: "relay id already enrolled under a different certificate".into(),
                })))
                .await;
            return;
        }
    };
    tracing::info!(
        relay_id = relay_id.0,
        negotiated = %negotiated,
        "relay enrolled over control connection"
    );

    push_and_watch(
        &mut socket,
        &setup,
        &regions,
        &notices,
        &lifecycle,
        relay_id,
        generation,
        liveness_timeout,
    )
    .await;

    // The connection ended: clear the presence this connection reported, so its
    // players read as queueable promptly rather than waiting out the TTL. Fenced
    // by this connection's exact generation — a stale drop racing a reconnect
    // removes only its own entries, never the fresh presence the reconnected
    // connection has already reported — the same race `remove_if_current` closes
    // for the registry entry itself.
    presence::clear_connection(setup.presence(), relay_id, generation);
    if registry::remove_if_current(registry, relay_id, generation) {
        tracing::info!(
            relay_id = relay_id.0,
            "relay deregistered on control disconnect"
        );
    }
    tracing::info!(relay_id = relay_id.0, "relay control connection closed");
}

/// Challenges a freshly-negotiated control connection to prove possession of the
/// private key matching its `Hello`'s certificate, returning whether it proved
/// it. A fresh random nonce goes down as an
/// [`CoordinatorToRelay::IdentityChallenge`]; the relay must answer within
/// `hello_timeout` with a [`RelayToCoordinator::IdentityProof`] whose signature
/// verifies against `hello.cert_der` (see [`crate::identity`]).
///
/// On a failed or absent proof this sends the [`CONTROL_CLOSE_IDENTITY_UNPROVEN`]
/// close itself and returns `false`; it also returns `false` (closing the socket
/// implicitly) when the nonce cannot be generated or the challenge cannot be
/// sent. A `false` return means the caller must stop serving the connection
/// without enrolling. Called unconditionally: negotiation already refused any
/// relay advertising a version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so there is no un-challenged enroll path.
async fn challenge_and_verify(
    socket: &mut WebSocket,
    hello: &RelayHello,
    hello_timeout: Duration,
) -> bool {
    let relay_id = hello.relay_id;
    let mut nonce = [0u8; 32];
    if let Err(error) = SystemRandom::new().fill(&mut nonce) {
        tracing::error!(
            relay_id = relay_id.0,
            %error,
            "generating the enroll challenge nonce failed; closing",
        );
        return false;
    }
    let challenge_json = serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce })
        .expect("an identity-challenge frame always serializes");
    if socket
        .send(Message::Text(challenge_json.into()))
        .await
        .is_err()
    {
        return false;
    }

    // Bounded by the same hello_timeout pattern as the initial enroll frame: a
    // relay silent past it, or one that answers with anything other than an
    // IdentityProof, is exactly as unwelcome here as one that never sent a Hello.
    let proof = tokio::time::timeout(hello_timeout, read_identity_proof(socket))
        .await
        .ok()
        .flatten();
    let proven = proof.is_some_and(|signature| {
        identity::verify_enroll_proof(&hello.cert_der, &nonce, &signature)
    });
    if !proven {
        tracing::warn!(
            relay_id = relay_id.0,
            "refusing relay control connection: enroll proof-of-possession failed",
        );
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CONTROL_CLOSE_IDENTITY_UNPROVEN,
                reason: "enroll proof-of-possession failed".into(),
            })))
            .await;
    }
    proven
}

/// Subscribes to `relay_id`'s descriptor set, re-syncs it on connect, then pushes
/// every change down the connection while watching the relay's liveness. Returns
/// when the connection ends: the relay closes, the socket errors, the liveness
/// deadline lapses (the relay went silent *or* a descriptor send stalled), or the
/// coordinator's outbox is dropped on shutdown.
///
/// Liveness is a single absolute deadline that every inbound frame pushes forward.
/// Crucially, the deadline also bounds the descriptor sends: a relay that stops
/// reading stalls the WebSocket send under backpressure, and if that send couldn't
/// be raced against the deadline it would block the loop from ever polling the
/// timer — leaving a wedged relay registered indefinitely, the exact degraded path
/// this watch exists to catch. So each send (including the initial re-sync) races
/// the same deadline, and a send that can't finish in time ends the connection.
#[allow(clippy::too_many_arguments)]
async fn push_and_watch(
    socket: &mut WebSocket,
    setup: &SessionSetup,
    regions: &RegionsConfig,
    notices: &NoticeDedup,
    lifecycle: &Lifecycle,
    relay_id: RelayId,
    generation: u64,
    liveness_timeout: Duration,
) {
    let mut rx = setup.descriptors().subscribe(relay_id);
    // The reap outbox for this relay: the reap policies push `CloseSlot`
    // directives here, and this loop forwards each down the connection. A fresh
    // subscribe replaces any prior sender, so a reconnect owns the live receiver.
    let mut reaps = setup.reaps().subscribe(relay_id);
    // The fleet mesh-peer set: shared across every relay's connection, re-synced
    // in full on connect and pushed again whenever fleet membership changes. The
    // relay pins a dialing peer's cert against it at mesh-accept time.
    let mut mesh_peers_rx = registry::subscribe_mesh_peers(setup.registry());

    // A relay silent past this deadline — or one whose send stalls past it — is
    // treated as dead. Every inbound frame pushes it forward; a heartbeat lands
    // well inside the window, so it only lapses when the relay stops making
    // progress (a crash, a half-open connection, or a peer that stopped reading).
    let mut deadline = tokio::time::Instant::now() + liveness_timeout;

    // The tenant verifying keys, pushed once on connect and strictly ahead of the
    // first descriptor: a descriptor must never reach a relay that cannot yet
    // verify its clients' tokens. Tenant config is immutable per process, so this
    // is a one-time connect-time push — a relay that reconnects re-receives it, and
    // a future dynamic registry would re-push from a watch arm in the loop below.
    let tenant_keys = tenant::all_verifying_keys(setup.tenants());
    if !send_tenant_keys_before_deadline(socket, &tenant_keys, relay_id, deadline).await {
        return;
    }

    // The region ping beacon targets, pushed once on connect ahead of the first
    // descriptor, alongside the tenant keys. The region registry is immutable per
    // process, so this is a one-time connect-time push — a relay that reconnects
    // re-receives it. A coordinator with no regions configured sends nothing here:
    // a region-blind fleet has no beacons to measure, so the frame stays off its
    // connections entirely.
    let beacon_targets = regions.beacon_targets();
    if !beacon_targets.is_empty()
        && !send_region_beacons_before_deadline(socket, &beacon_targets, relay_id, deadline).await
    {
        return;
    }

    // Initial re-sync, bounded by the deadline. Clone the set out of the watch
    // borrow before awaiting — a watch borrow must never be held across an await.
    let initial = rx.borrow_and_update().clone();
    if !send_before_deadline(socket, &initial, relay_id, deadline).await {
        return;
    }
    // The fleet mesh-peer set rides the same connect-time re-sync, alongside the
    // descriptor set: the relay learns every enrolled peer's cert fingerprint the
    // moment it connects.
    let initial_peers = mesh_peers_rx.borrow_and_update().clone();
    if !send_mesh_peers_before_deadline(socket, &initial_peers, relay_id, deadline).await {
        return;
    }

    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    break; // the outbox was dropped: coordinator shutting down
                }
                let set = rx.borrow_and_update().clone();
                if !send_before_deadline(socket, &set, relay_id, deadline).await {
                    break;
                }
            }
            changed = mesh_peers_rx.changed() => {
                if changed.is_err() {
                    break; // the registry's mesh-peer channel was dropped: shutting down
                }
                let peers = mesh_peers_rx.borrow_and_update().clone();
                if !send_mesh_peers_before_deadline(socket, &peers, relay_id, deadline).await {
                    break;
                }
            }
            close = reaps.recv() => {
                // The reap outbox never closes on its own (the sender lives in the
                // shared outbox), so `None` here would only mean a replaced
                // subscription — treat it as end-of-stream and stop selecting.
                let Some(close) = close else { break };
                if !send_reap_before_deadline(socket, close, relay_id, deadline).await {
                    break;
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(message)) => {
                        let action =
                            note_inbound(setup, notices, lifecycle, relay_id, generation, &message);
                        // Any frame proves the relay is alive — push the deadline out.
                        deadline = tokio::time::Instant::now() + liveness_timeout;
                        // A Draining frame additionally runs the drain exchange: mark
                        // the relay ineligible for new assignments, then push its
                        // current descriptor set followed by a DrainAck (set before
                        // ack, racing the refreshed deadline). A send that stalls or
                        // errors ends the connection like any other.
                        if action == InboundAction::DrainRequested
                            && !handle_drain_request(
                                socket, setup, relay_id, generation, &mut rx, deadline,
                            )
                            .await
                        {
                            break;
                        }
                    }
                    Some(Err(error)) => {
                        tracing::debug!(%error, relay_id = relay_id.0, "relay control connection error");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::info!(
                    relay_id = relay_id.0,
                    "relay control connection went silent past the liveness deadline; dropping",
                );
                break;
            }
        }
    }
}

/// Sends a `CloseSlot` reap directive down the connection, racing the same
/// liveness deadline as a descriptor push. Returns whether the connection should
/// keep running.
async fn send_reap_before_deadline(
    socket: &mut WebSocket,
    close: SlotClose,
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    let message = CoordinatorToRelay::CloseSlot {
        tenant: close.tenant,
        session: close.session,
        slots: close.slots,
    };
    let json = serde_json::to_string(&message).expect("a close-slot frame always serializes");
    tokio::select! {
        result = socket.send(Message::Text(json.into())) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "close-slot push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "close-slot push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// Pushes a descriptor set, but only up to the liveness `deadline`: if the send
/// can't complete before then — the relay stopped reading and backpressure stalled
/// the socket — the connection is treated as dead so it can't hold a registry entry
/// open while wedged. Returns whether the connection should keep running: `false`
/// on a send error or a stall past the deadline (the caller then ends it).
async fn send_before_deadline(
    socket: &mut WebSocket,
    set: &[SessionDescriptor],
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    tokio::select! {
        result = push_descriptors(socket, set) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "descriptor push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "descriptor push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// Sends the tenant verifying-key set down the connection, racing the same liveness
/// deadline as a descriptor push (a relay that stopped reading must not hold its
/// registry entry open while wedged). Returns whether the connection should keep
/// running: `false` on a send error or a stall past the deadline.
///
/// Pushed once on connect, ahead of the first descriptor, so the relay can verify a
/// session's client tokens by the time that session's descriptor arrives.
async fn send_tenant_keys_before_deadline(
    socket: &mut WebSocket,
    keys: &[TenantVerifyingKey],
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    let message = CoordinatorToRelay::TenantKeys {
        keys: keys.to_vec(),
    };
    let json = serde_json::to_string(&message).expect("a tenant-keys frame always serializes");
    tokio::select! {
        result = socket.send(Message::Text(json.into())) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "tenant-keys push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "tenant-keys push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// Sends the region ping-beacon set down the connection, racing the same liveness
/// deadline as a descriptor push (a relay that stopped reading must not hold its
/// registry entry open while wedged). Returns whether the connection should keep
/// running: `false` on a send error or a stall past the deadline.
///
/// Pushed once on connect, ahead of the first descriptor, so a relay learns the
/// regions it can measure backbone round-trips against as soon as it enrolls. The
/// caller omits it for a coordinator with no configured regions.
async fn send_region_beacons_before_deadline(
    socket: &mut WebSocket,
    beacons: &[RegionBeaconTarget],
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    let message = CoordinatorToRelay::RegionBeacons {
        beacons: beacons.to_vec(),
    };
    let json = serde_json::to_string(&message).expect("a region-beacons frame always serializes");
    tokio::select! {
        result = socket.send(Message::Text(json.into())) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "region-beacons push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "region-beacons push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// Sends the fleet mesh-peer set down the connection, racing the same liveness
/// deadline as a descriptor push (a relay that stopped reading must not hold its
/// registry entry open while wedged). Returns whether the connection should keep
/// running: `false` on a send error or a stall past the deadline.
async fn send_mesh_peers_before_deadline(
    socket: &mut WebSocket,
    peers: &[MeshPeerIdentity],
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    let message = CoordinatorToRelay::MeshPeers {
        peers: peers.to_vec(),
    };
    let json = serde_json::to_string(&message).expect("a mesh-peers frame always serializes");
    tokio::select! {
        result = socket.send(Message::Text(json.into())) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "mesh-peers push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "mesh-peers push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// Runs a relay's coordinated-drain exchange after it sent a
/// [`RelayToCoordinator::Draining`]: mark it ineligible for new assignments, then —
/// if the mark applied — push its current descriptor set followed by a
/// [`CoordinatorToRelay::DrainAck`]. Returns whether the connection should keep
/// running (`false` on a send stall/error, which ends it like any other).
///
/// The mark is taken under the assignment lock ([`SessionSetup::lock_assignment`]),
/// so it linearizes against any in-flight `create_session`/`rehome`: after it lands,
/// every session that will ever name this relay has already staged its descriptor in
/// the relay's outbox. The set is then pushed **before** the ack, so a relay that
/// sees an empty descriptor set at ack time knows it is provably unassigned.
///
/// A mark that does **not** apply — a stale generation, meaning a newer connection
/// re-enrolled this relay (its fresh enroll cleared the flag) — draws no ack: that
/// live connection runs its own drain exchange when its `Draining` arrives.
async fn handle_drain_request(
    socket: &mut WebSocket,
    setup: &SessionSetup,
    relay_id: RelayId,
    generation: u64,
    rx: &mut tokio::sync::watch::Receiver<Vec<SessionDescriptor>>,
    deadline: tokio::time::Instant,
) -> bool {
    let applied = {
        let _assign = setup.lock_assignment();
        registry::mark_draining(setup.registry(), relay_id, generation)
    };
    if !applied {
        // A stale connection's Draining: the live successor acks its own drain.
        tracing::debug!(
            relay_id = relay_id.0,
            "ignoring a Draining frame from a stale control connection",
        );
        return true;
    }
    tracing::info!(relay_id = relay_id.0, "relay draining; sending set + ack");
    // Set before ack. Clone the set out of the watch borrow before awaiting — a
    // watch borrow must never be held across an await — and mark it seen so the
    // loop's `changed()` doesn't redundantly re-push the same set right after.
    let set = rx.borrow_and_update().clone();
    if !send_before_deadline(socket, &set, relay_id, deadline).await {
        return false;
    }
    send_drain_ack_before_deadline(socket, relay_id, deadline).await
}

/// Sends a [`CoordinatorToRelay::DrainAck`] down the connection, racing the same
/// liveness deadline as a descriptor push. Returns whether the connection should
/// keep running.
async fn send_drain_ack_before_deadline(
    socket: &mut WebSocket,
    relay_id: RelayId,
    deadline: tokio::time::Instant,
) -> bool {
    let json = serde_json::to_string(&CoordinatorToRelay::DrainAck)
        .expect("a drain-ack frame always serializes");
    tokio::select! {
        result = socket.send(Message::Text(json.into())) => {
            match result {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(%error, relay_id = relay_id.0, "drain-ack push failed");
                    false
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            tracing::info!(
                relay_id = relay_id.0,
                "drain-ack push stalled past the liveness deadline; dropping",
            );
            false
        }
    }
}

/// What an inbound relay frame asks the connection loop to do beyond the liveness
/// refresh every frame already triggers. Most frames drive their webhook/lifecycle
/// side effects inside [`note_inbound`] and ask nothing further ([`None`](Self::None));
/// a [`RelayToCoordinator::Draining`] asks the loop to run the drain exchange
/// ([`DrainRequested`](Self::DrainRequested)), which needs the connection's
/// generation and socket that only the loop holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundAction {
    /// Nothing beyond the liveness refresh.
    None,
    /// The relay asked to drain: mark it ineligible and run the set-before-ack
    /// exchange.
    DrainRequested,
}

/// Handles an inbound relay frame, returning what the connection loop should do
/// next. Any frame already counts as the liveness signal; a
/// [`RelayToCoordinator::Departure`], [`RelayToCoordinator::Desync`],
/// [`RelayToCoordinator::Result`], or [`RelayToCoordinator::SessionClosed`]
/// additionally drives its webhook and lifecycle paths here; a
/// [`RelayToCoordinator::Draining`] returns [`InboundAction::DrainRequested`] so the
/// loop can run the drain exchange (which needs the socket + generation it owns). A
/// heartbeat is just liveness; anything undecodable is flagged.
///
/// The lifecycle accounting (result/departure account a slot; `SessionClosed`
/// closes a serving relay) is fed *before* the webhook path and independent of the
/// dedup and notify-config gates the webhook path applies — the reap and the
/// `sessionClosed` signal must track a session even for a tenant with no webhook
/// configured. Redundant notices from multiple relays are idempotent in the
/// accounting (a set insert), so feeding every copy is harmless.
fn note_inbound(
    setup: &SessionSetup,
    notices: &NoticeDedup,
    lifecycle: &Lifecycle,
    relay_id: RelayId,
    generation: u64,
    message: &Message,
) -> InboundAction {
    let Message::Text(text) = message else {
        return InboundAction::None; // ping/pong/binary: liveness only, nothing to read
    };
    match serde_json::from_str::<RelayToCoordinator>(text) {
        Ok(RelayToCoordinator::Heartbeat {
            sessions,
            region_rtts: _,
        }) => {
            tracing::trace!(relay_id = relay_id.0, "relay heartbeat");
            // The beat's roster feeds active-player presence — but only from the
            // relay's CURRENT connection. A stale connection's late beat (a
            // reconnect raced it) is dropped whole: its roster describes a
            // superseded view, and applying it would overwrite what the live
            // connection reports. (The store's own generation fences are the
            // second line of defense.)
            if registry::generation_is_current(setup.registry(), relay_id, generation) {
                presence::apply_heartbeat(
                    setup.presence(),
                    relay_id,
                    generation,
                    &sessions,
                    std::time::Instant::now(),
                );
                // A session with at least one slot connected has a real
                // client, wherever the roster came from -- the never-started
                // reap's cancel signal (see `Lifecycle::on_presence_seen`).
                for session in &sessions {
                    if !session.slots.is_empty() {
                        lifecycle.on_presence_seen(session.tenant.clone(), session.session);
                    }
                }
            } else {
                tracing::debug!(
                    relay_id = relay_id.0,
                    "dropping a heartbeat roster from a stale control connection",
                );
            }
            InboundAction::None
        }
        Ok(RelayToCoordinator::Draining) => {
            // Presence is enough for liveness; the loop runs the set-before-ack drain
            // exchange, which needs the connection's socket and generation.
            InboundAction::DrainRequested
        }
        Ok(RelayToCoordinator::Departure(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "departure notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_departure(
                notice.tenant.clone(),
                notice.session,
                notice.slot,
                notice.kind,
            );
            notify::handle_departure(setup, &notices.departures, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::Desync(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    sync_ordinal = notice.sync_ordinal,
                    "desync notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            notify::handle_desync(setup, &notices.desyncs, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::Result(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "result notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_result(notice.tenant.clone(), notice.session, notice.slot);
            notify::handle_result(setup, &notices.results, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::SessionClosed { tenant, session }) => {
            lifecycle.on_session_closed(tenant, session, relay_id);
            InboundAction::None
        }
        // A second Hello or a future up-frame: presence is enough, content unused.
        Ok(_) => InboundAction::None,
        Err(error) => {
            tracing::debug!(%error, relay_id = relay_id.0, "undecodable relay control frame");
            InboundAction::None
        }
    }
}

/// Whether `relay_id` — the relay identity this control connection enrolled as —
/// is allowed to report a departure/desync/result for `(tenant, session)`. A
/// notice carries attacker-influenceable `tenant`/`session`/payload, and each one
/// drives a webhook signed with the tenant's own key; without this gate any
/// connected relay could name a victim tenant + session and have the coordinator
/// sign and deliver forged bytes to that tenant's webhook.
///
/// The rule: the reporting relay must be one of the session's serving relays.
/// When the coordinator holds **no** serving-relay record for the session, the
/// notice is allowed through — this is the routine post-restart tail case, where a
/// relay still holds a session created in a previous coordinator lifetime and
/// reports its closing events, but the in-memory serving set was wiped, so there
/// is nothing to check the reporter against. Enforcement therefore applies only
/// when serving-relay information exists this lifetime.
///
/// Residual gap: the unverifiable no-record path still trusts the reporter, and
/// the shared bootstrap secret authenticates "a relay," not a specific relay id,
/// so a secret holder could forge a tail notice for a session with no live serving
/// record. Fully closing that needs per-relay identity — the same work that binds
/// a control connection to its claimed relay id — and is out of scope here.
fn relay_serves_session(
    setup: &SessionSetup,
    relay_id: RelayId,
    tenant: &TenantId,
    session: SessionId,
) -> bool {
    let serving = setup.serving_relays(tenant, session);
    serving.is_empty() || serving.contains(&relay_id)
}

/// Reads the relay's opening [`RelayToCoordinator::Hello`] from a freshly
/// upgraded connection, returning the [`RelayHello`] it carries.
///
/// The first *application* frame must be a Hello: the protocol puts enrollment
/// first, so anything else (a non-Hello message, an undecodable frame, binary)
/// is a violation and closes the connection (`None`) rather than waiting — a
/// later-protocol relay still works because its Hello decodes as one (unknown
/// fields are ignored). Only WebSocket ping/pong control frames are skipped; the
/// caller's deadline bounds how long a silent connection may sit before the Hello.
async fn read_hello(socket: &mut WebSocket) -> Option<RelayHello> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                return match serde_json::from_str::<RelayToCoordinator>(&text) {
                    Ok(RelayToCoordinator::Hello(hello)) => Some(hello),
                    // A heartbeat, a departure, a desync, a result, an identity
                    // proof, or any future up-frame before the enroll Hello is a
                    // protocol violation: enrollment comes first.
                    Ok(
                        RelayToCoordinator::Heartbeat { .. }
                        | RelayToCoordinator::Draining
                        | RelayToCoordinator::Departure(_)
                        | RelayToCoordinator::Desync(_)
                        | RelayToCoordinator::Result(_)
                        | RelayToCoordinator::SessionClosed { .. }
                        | RelayToCoordinator::IdentityProof { .. }
                        | RelayToCoordinator::Unknown,
                    ) => {
                        tracing::warn!("first control frame was not a Hello; closing");
                        None
                    }
                    Err(error) => {
                        tracing::warn!(%error, "bad first control frame; closing");
                        None
                    }
                };
            }
            // Ping/pong control frames may precede the Hello; keep waiting (the
            // caller's timeout bounds the wait).
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            // A close, a stream end, a binary frame, or a read error before any
            // Hello ends the handshake.
            Some(Ok(_)) | None => return None,
            Some(Err(error)) => {
                tracing::debug!(%error, "control connection error before hello");
                return None;
            }
        }
    }
}

/// Reads the relay's answer to an [`CoordinatorToRelay::IdentityChallenge`],
/// returning the raw signature bytes from a
/// [`RelayToCoordinator::IdentityProof`]. Any other outcome — a different
/// frame kind, an undecodable frame, a close, a stream end, or a read error —
/// is `None`: the caller treats all of them as an unanswered challenge
/// uniformly, since none proves possession of the claimed key. Ping/pong
/// control frames are skipped, exactly like [`read_hello`]; the caller's own
/// timeout bounds how long a silent connection may sit before answering.
async fn read_identity_proof(socket: &mut WebSocket) -> Option<Vec<u8>> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                return match serde_json::from_str::<RelayToCoordinator>(&text) {
                    Ok(RelayToCoordinator::IdentityProof { signature }) => Some(signature),
                    _ => None,
                };
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(_)) | None => return None,
            Some(Err(error)) => {
                tracing::debug!(%error, "control connection error awaiting identity proof");
                return None;
            }
        }
    }
}

/// Sends a descriptor set down a relay's control connection as one tagged JSON
/// text frame.
async fn push_descriptors(
    socket: &mut WebSocket,
    set: &[SessionDescriptor],
) -> Result<(), axum::Error> {
    let message = CoordinatorToRelay::Descriptors {
        descriptors: set.to_vec(),
    };
    let json = serde_json::to_string(&message).expect("a descriptor set always serializes");
    socket.send(Message::Text(json.into())).await
}

/// Whether a request may open the control connection under `auth`. `Open` admits
/// any caller; `Secret` requires the matching bearer token.
fn control_auth_ok(headers: &HeaderMap, auth: &ControlAuth) -> bool {
    match auth {
        ControlAuth::Open => true,
        ControlAuth::Secret(expected) => bearer_matches(headers, expected),
    }
}

/// Whether the request's `Authorization` header carries exactly `expected` as a
/// bearer token. The comparison is constant-time so the secret isn't probed a
/// byte at a time via response timing.
fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(presented) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// Constant-time byte-slice equality, so a secret comparison leaks no timing
/// signal that would let it be brute-forced a byte at a time. Differing lengths
/// short-circuit (a length mismatch is already a non-match), then equal-length
/// inputs are compared with no data-dependent branch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The domain-separation prefix on a tenant request signature, the mirror of
/// the webhook's `rp2-webhook-v1:`. Binds a signature to the request-auth
/// scheme so it can never be confused with a webhook signature (opposite
/// direction) or a player-token signature made by a different key.
const REQUEST_SIG_DOMAIN: &str = "rp2-request-v1:";
/// Header carrying the request signing timestamp: unix epoch *seconds*, decimal
/// (the webhook direction uses milliseconds; these are independent schemes).
const REQUEST_TIMESTAMP_HEADER: &str = "x-rp2-timestamp";
/// Header carrying the Ed25519 request signature: lowercase hex of the 64-byte
/// signature over the domain-separated, method+path-bound, timestamped message.
const REQUEST_SIGNATURE_HEADER: &str = "x-rp2-signature";
/// How far a request's `x-rp2-timestamp` may drift from now (in either
/// direction) before it is rejected as stale/replayed. Matches the consumer
/// window the app server enforces on webhook timestamps.
const REQUEST_TIMESTAMP_WINDOW_SECS: u64 = 5 * 60;

/// The bytes a tenant request signature covers: `rp2-request-v1:<ts>:<METHOD>:
/// <path>:<raw body>`. The method (uppercased — `Method::as_str` already yields
/// the canonical uppercase form for standard methods) and the path-as-sent are
/// bound in so a captured, validly-signed body cannot be replayed against a
/// different endpoint or verb.
fn build_request_message(timestamp: &str, method: &Method, path: &str, body: &[u8]) -> Vec<u8> {
    let method = method.as_str();
    let mut message = Vec::with_capacity(
        REQUEST_SIG_DOMAIN.len() + timestamp.len() + method.len() + path.len() + body.len() + 3,
    );
    message.extend_from_slice(REQUEST_SIG_DOMAIN.as_bytes());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b':');
    message.extend_from_slice(method.as_bytes());
    message.push(b':');
    message.extend_from_slice(path.as_bytes());
    message.push(b':');
    message.extend_from_slice(body);
    message
}

/// The least tenant state a tenant-authenticated endpoint accepts, passed to
/// [`verify_tenant_request`] as a required argument. Making it required is the
/// point: a tenant-authenticated endpoint cannot be wired up without calling
/// [`verify_tenant_request`], and it cannot call that without choosing which
/// tenant states may reach it — so the suspended/revoked gate can never be
/// silently omitted for a future endpoint.
#[derive(Clone, Copy, Debug)]
enum TenantAccess {
    /// New-game machinery — only an active tenant. A suspended or revoked tenant
    /// is refused with `403`. For the operations that begin or prepare a
    /// brand-new game (session create, region warming), which suspension halts.
    NewGame,
    /// Live-game machinery — any tenant that is not revoked (active or
    /// suspended). Only a revoked tenant is refused with `403`. For the
    /// operations a game already in progress relies on (failover re-home, the
    /// liveness probe, the presence query), which suspension must not strand.
    LiveGame,
}

/// Verifies a tenant-scoped request's signature and then enforces the tenant's
/// state against `access`, so signature verification and the state gate are one
/// inseparable step every tenant-authenticated endpoint performs.
///
/// A signature problem fails closed with `401` — a missing/unparseable
/// timestamp, a stale timestamp (outside [`REQUEST_TIMESTAMP_WINDOW_SECS`]), a
/// missing/non-hex signature, a tenant with no enrolled verification key, or a
/// signature that verifies against none of the tenant's keys. Every one maps to
/// the same `UNAUTHORIZED` so the response never reveals which check failed;
/// `ring`'s `verify` is itself constant-time. A tenant may list more than one
/// verification key (for zero-downtime request-key rotation); a signature is
/// accepted if it verifies against ANY of them.
///
/// The state gate runs only *after* a good signature, and a state refusal is a
/// distinct `403`: the tenant is proven before its state can shape the outcome,
/// so an unauthenticated caller learns nothing about the tenant's state. A
/// revoked tenant is refused by every `access`; a suspended tenant is refused
/// only [`TenantAccess::NewGame`]. The refusal names only its class in the
/// server log and carries no detail on the wire beyond the status code.
///
/// The signed message binds the request method and the path as sent (see
/// [`build_request_message`]); `path` uses the full path-and-query so a future
/// query-carrying endpoint signs what is on the wire (today's endpoints carry
/// none).
fn verify_tenant_request(
    setup: &SessionSetup,
    tenant: &TenantId,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    access: TenantAccess,
) -> Result<(), StatusCode> {
    let timestamp = headers
        .get(REQUEST_TIMESTAMP_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ts_secs: u64 = timestamp.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_secs.abs_diff(ts_secs) > REQUEST_TIMESTAMP_WINDOW_SECS {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let signature = headers
        .get(REQUEST_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let client_pubkeys = tenant::client_pubkeys(setup.tenants(), tenant);
    if client_pubkeys.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let message = build_request_message(timestamp, method, path, body);

    let verified = client_pubkeys.iter().any(|key| {
        UnparsedPublicKey::new(&ED25519, key.as_ref())
            .verify(&message, &signature)
            .is_ok()
    });
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    enforce_tenant_state(setup, tenant, access)
}

/// Enforces an authenticated tenant's state against what `access` requires,
/// mapping a refusal to `403` and logging its class. Called only from
/// [`verify_tenant_request`], after the signature is proven — a revoked tenant is
/// refused by every endpoint, a suspended tenant by the new-game ones. A tenant
/// that vanished between the signature check and here reads as `None` and is
/// refused as unauthorized.
fn enforce_tenant_state(
    setup: &SessionSetup,
    tenant: &TenantId,
    access: TenantAccess,
) -> Result<(), StatusCode> {
    let state = tenant::tenant_state(setup.tenants(), tenant).ok_or(StatusCode::UNAUTHORIZED)?;
    let permitted = match access {
        TenantAccess::NewGame => matches!(state, tenant::TenantState::Active),
        TenantAccess::LiveGame => !matches!(state, tenant::TenantState::Revoked),
    };
    if permitted {
        Ok(())
    } else {
        tracing::warn!(
            tenant = tenant.as_ref(),
            state = ?state,
            access = ?access,
            "tenant request refused: the tenant's state does not permit this endpoint",
        );
        Err(StatusCode::FORBIDDEN)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
    use rally_point_proto::version::ProtocolVersion;
    use ring::signature::Ed25519KeyPair;
    use tower::ServiceExt;

    /// A fixed dev-style client seed for the `sb-test` tenant: its public half
    /// is enrolled by [`state_with_relay_and_tenant`], and [`sign_request`]
    /// signs with it so a request verifies. Not a real secret — a test fixture.
    const TEST_CLIENT_SEED: [u8; 32] = [0x11; 32];

    /// The player-token lifetime the test coordinator states mint with. A plain
    /// finite span so a minted expiry is `now + this`, observable without waiting.
    const TEST_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

    /// Produces the `(x-rp2-timestamp, x-rp2-signature)` header pair a tenant
    /// sends, signing the canonical request message with `seed` at the current
    /// time. Mirrors the app server's `signCoordinatorRequest`.
    fn sign_request(seed: &[u8], method: &str, path: &str, body: &[u8]) -> (String, String) {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let message = build_request_message(
            &ts,
            &Method::from_bytes(method.as_bytes()).unwrap(),
            path,
            body,
        );
        let sig = pair.sign(&message);
        (ts, hex::encode(sig.as_ref()))
    }

    /// Sends a signed `POST` to `app`, signing `body` with `seed` for `path`.
    async fn signed_post(
        app: Router,
        path: &str,
        body: &[u8],
        seed: &[u8],
    ) -> axum::http::Response<axum::body::Body> {
        let (ts, sig) = sign_request(seed, "POST", path, body);
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header(REQUEST_TIMESTAMP_HEADER, ts)
                .header(REQUEST_SIGNATURE_HEADER, sig)
                .body(axum::body::Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn state_with_relay_and_tenant() -> CoordinatorState {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![0xC1; 4],
            ),
        );
        let tenants = crate::tenant::new_store();
        crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        // Enroll the tenant's inbound-request verifying key so signed requests
        // authenticate.
        let client_pubkey = crate::tenant::client_pubkey_from_seed(&TEST_CLIENT_SEED).unwrap();
        crate::tenant::set_client_pubkeys(
            &tenants,
            &TenantId("sb-test".to_owned()),
            vec![client_pubkey],
        );
        let setup = crate::session::SessionSetup::new(reg, tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
            regions: RegionsConfig::default(),
            player_token_lifetime: TEST_TOKEN_LIFETIME,
            ledger: None,
        }
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

    #[tokio::test]
    async fn create_session_endpoint_returns_tokens() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session: SessionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(session.tokens.len(), 2);
        assert_eq!(session.home_relay.relay_id, RelayId(1));
    }

    #[tokio::test]
    async fn create_session_endpoint_replays_a_duplicate_and_keeps_one_live_session() {
        let state = state_with_relay_and_tenant();
        let app = router(state.clone());

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();

        let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let first: SessionResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let second: SessionResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            first, second,
            "a retry of the same create replays the exact original response",
        );
        assert!(
            state
                .lifecycle
                .is_alive(&TenantId("sb-test".to_owned()), first.session),
            "the replayed create leaves the one original session live and undisturbed",
        );
    }

    #[tokio::test]
    async fn create_session_endpoint_conflicts_on_a_reused_live_id_with_a_different_roster() {
        let state = state_with_relay_and_tenant();
        let app = router(state.clone());

        let original = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&original).unwrap();
        let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let created: SessionResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        // The same external_id, still bound to the live session, but slot 1 now
        // carries a different client pubkey: a different game reusing a live id.
        // The coordinator maps this to 409 rather than minting a duplicate or
        // handing back the first game's tokens.
        let conflicting = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
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
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&conflicting).unwrap();
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        assert!(
            state
                .lifecycle
                .is_alive(&TenantId("sb-test".to_owned()), created.session),
            "the refused conflict must leave the original session's accounting intact",
        );
    }

    #[tokio::test]
    async fn create_session_rejects_an_unsigned_request() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        // No signature headers at all — fails closed.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/create")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_session_rejects_a_wrong_key_signature() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();
        // Signed with a key whose public half is not the tenant's enrolled one.
        let resp = signed_post(app, "/session/create", &body, &[0x22; 32]).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_session_rejects_a_stale_timestamp() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();

        // A correctly-keyed signature, but over a timestamp far outside the
        // replay window — a captured request replayed long after the fact.
        let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_CLIENT_SEED).unwrap();
        let stale_ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (REQUEST_TIMESTAMP_WINDOW_SECS + 60))
            .to_string();
        let message = build_request_message(&stale_ts, &Method::POST, "/session/create", &body);
        let sig = hex::encode(pair.sign(&message).as_ref());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/create")
                    .header("content-type", "application/json")
                    .header(REQUEST_TIMESTAMP_HEADER, stale_ts)
                    .header(REQUEST_SIGNATURE_HEADER, sig)
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn the_request_signature_message_matches_the_cross_impl_vector() {
        // The cross-implementation test vector, pinned byte-for-byte on both
        // sides: the RFC 8032 §7.1 vector-1 seed, its derived public key, and a
        // Node-produced Ed25519 signature (netcode-v2-service.test.ts pins the
        // identical hex) over a fixed request message. Ed25519 is deterministic,
        // so ring and Node produce the same 64 bytes for the same key+message —
        // a drift in either side's message construction breaks one of the two
        // tests.
        const RFC8032_SEED: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        const EXPECTED_SIG_HEX: &str = "33a9c1ee42248bc26e7844a880a5c82512cf534b200937b607a2259b3ee8dded4f1cae21671be4f949145ac5888874c845024daae6e1c405dd9a051a12d4f209";

        let pubkey = crate::tenant::client_pubkey_from_seed(&RFC8032_SEED).unwrap();
        assert_eq!(
            hex::encode(pubkey),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );

        // The exact canonical bytes both sides sign.
        let message = build_request_message(
            "1700000000",
            &Method::POST,
            "/session/create",
            br#"{"tenant":"sb-dev"}"#,
        );
        assert_eq!(
            message,
            b"rp2-request-v1:1700000000:POST:/session/create:{\"tenant\":\"sb-dev\"}",
        );

        // The Node-produced signature verifies under ring.
        let sig = hex::decode(EXPECTED_SIG_HEX).unwrap();
        UnparsedPublicKey::new(&ED25519, pubkey.as_ref())
            .verify(&message, &sig)
            .expect("the cross-impl signature verifies under ring");
    }

    #[test]
    fn control_auth_secret_accepts_the_matching_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        assert!(control_auth_ok(
            &headers,
            &ControlAuth::Secret("s3cret".to_owned())
        ));
    }

    #[test]
    fn control_auth_secret_rejects_a_wrong_or_missing_bearer() {
        let secret = ControlAuth::Secret("s3cret".to_owned());

        // Wrong secret.
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer nope".parse().unwrap());
        assert!(!control_auth_ok(&headers, &secret));

        // Missing header entirely.
        assert!(!control_auth_ok(&HeaderMap::new(), &secret));

        // Present but not a Bearer scheme.
        let mut basic = HeaderMap::new();
        basic.insert(AUTHORIZATION, "Basic s3cret".parse().unwrap());
        assert!(!control_auth_ok(&basic, &secret));
    }

    #[test]
    fn control_auth_open_accepts_any_request() {
        // Open is the explicit dev/loopback posture: any request (even without a
        // header) is accepted. It is never the default — the binary only builds
        // it under an explicit insecure opt-in.
        assert!(control_auth_ok(&HeaderMap::new(), &ControlAuth::Open));
    }

    #[test]
    fn resolve_control_auth_with_a_secret_requires_it() {
        let auth = resolve_control_auth(Some("s3cret".to_owned()), false).unwrap();
        assert!(matches!(auth, ControlAuth::Secret(s) if s == "s3cret"));
        // A secret takes precedence even if insecure is also (redundantly) set.
        let auth = resolve_control_auth(Some("s3cret".to_owned()), true).unwrap();
        assert!(matches!(auth, ControlAuth::Secret(_)));
    }

    #[test]
    fn resolve_control_auth_allows_open_only_with_the_explicit_opt_in() {
        assert!(matches!(
            resolve_control_auth(None, true).unwrap(),
            ControlAuth::Open
        ));
    }

    #[test]
    fn resolve_control_auth_fails_closed_without_a_secret_or_opt_in() {
        // The no-ship default: no secret and no explicit insecure flag is a hard
        // error, not a silently open endpoint.
        assert!(resolve_control_auth(None, false).is_err());
    }

    #[tokio::test]
    async fn sessions_alive_reports_live_and_omits_gone_or_unknown_and_caps() {
        let state = state_with_relay_and_tenant();
        // A live session registered directly on the shared lifecycle.
        state.lifecycle.register_session(
            TenantId("sb-test".to_owned()),
            SessionId(5),
            vec![RelayId(1)],
            std::collections::HashSet::from([SlotId(0)]),
            std::collections::HashSet::new(),
            rally_point_proto::token::ExpiresAt(u64::MAX),
        );
        let app = router(state);

        // Probe a live id (5), an unknown id (6): only the live one is returned.
        let req_body = serde_json::to_vec(&serde_json::json!({
            "tenant": "sb-test",
            "sessions": [5, 6],
        }))
        .unwrap();
        let resp = signed_post(app.clone(), "/sessions/alive", &req_body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["alive"].as_array().unwrap(),
            &vec![serde_json::json!(5)],
            "only the live session id is returned; gone/unknown are omitted",
        );

        // An over-cap probe list is rejected rather than scanned (the request is
        // still signed — the cap check is past the auth gate).
        let too_many: Vec<u64> = (0..=(MAX_LIVENESS_SESSIONS as u64)).collect();
        let big_body =
            serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "sessions": too_many }))
                .unwrap();
        let resp = signed_post(app, "/sessions/alive", &big_body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn create_session_no_relays_returns_503() {
        // A tenant enrolled (with a client key, so the request authenticates) but
        // no relays registered — the 503 path is reached only past the auth gate.
        let tenants = crate::tenant::new_store();
        crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let client_pubkey = crate::tenant::client_pubkey_from_seed(&TEST_CLIENT_SEED).unwrap();
        crate::tenant::set_client_pubkeys(
            &tenants,
            &TenantId("sb-test".to_owned()),
            vec![client_pubkey],
        );
        let setup = crate::session::SessionSetup::new(registry::new_registry(), tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        let state = CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
            regions: RegionsConfig::default(),
            player_token_lifetime: TEST_TOKEN_LIFETIME,
            ledger: None,
        };
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_session_stamps_expiry_at_now_plus_configured_lifetime() {
        // The handler mints each token's expiry as (now + the configured
        // lifetime); decode a token out of the response and confirm it lands in
        // the window bracketing the call, offset by the lifetime.
        let state = state_with_relay_and_tenant();
        let lifetime_secs = state.player_token_lifetime.as_secs();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();

        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session_resp: SessionResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!session_resp.tokens.is_empty(), "a session mints tokens");
        for player_token in &session_resp.tokens {
            let token = rally_point_proto::token::SignedToken::decode(&player_token.token).unwrap();
            let expires = token.claims.expires_at.0;
            assert!(
                expires >= before.saturating_add(lifetime_secs)
                    && expires <= after.saturating_add(lifetime_secs),
                "expiry {expires} should be now + {lifetime_secs}s (call window {before}..={after})",
            );
        }
    }

    #[tokio::test]
    async fn create_session_unenrolled_tenant_fails_auth() {
        // A tenant with no enrolled client key cannot produce a verifiable
        // signature, so auth fails closed (401) before the session logic's own
        // unenrolled-tenant 400 is ever reached — auth precedes tenant lookup.
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("not-enrolled".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        };
        let body = serde_json::to_vec(&req).unwrap();
        // Even a signature made by *some* valid key can't help: the tenant named
        // in the body has no enrolled client_pubkey to verify against.
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tenant_pubkey_endpoint_returns_the_enrolled_key() {
        let reg = registry::new_registry();
        let tenants = crate::tenant::new_store();
        let expected_pubkey = crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = crate::session::SessionSetup::new(reg, tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        let state = CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
            regions: RegionsConfig::default(),
            player_token_lifetime: TEST_TOKEN_LIFETIME,
            ledger: None,
        };
        let app = router(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/tenant/sb-test/pubkey")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Exactly the two camelCase fields — nothing else on the shape.
        let map = json.as_object().unwrap();
        assert_eq!(
            map.keys().collect::<std::collections::HashSet<_>>(),
            std::collections::HashSet::from([&"kid".to_owned(), &"publicKey".to_owned()]),
            "the response is exactly {{kid, publicKey}}",
        );
        assert_eq!(json["kid"], "test-key-1");
        // Hex round-trips against what enroll returned: 64 lowercase hex chars
        // decoding back to the exact 32-byte verifying key.
        assert_eq!(json["publicKey"], hex::encode(expected_pubkey));
        assert_eq!(json["publicKey"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn tenant_pubkey_endpoint_404s_for_an_unknown_tenant() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/tenant/not-enrolled/pubkey")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    async fn get_regions(app: Router) -> serde_json::Value {
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/regions")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn regions_endpoint_returns_the_configured_list() {
        // The unauthenticated GET serves the config verbatim (snake_case), in file
        // order — the shape the SB server forwards to every client.
        let mut state = state_with_relay_and_tenant();
        state.regions = crate::regions::RegionsConfig::from_json(
            r#"{"regions": [
                {"id": "us-east", "display_name": "US East", "beacon": "e:20000", "fallback": "e:443"},
                {"id": "eu-west", "display_name": "EU West", "beacon": "w:20000", "fallback": "w:443"}
            ]}"#,
        )
        .unwrap();
        let json = get_regions(router(state)).await;

        let regions = json["regions"].as_array().unwrap();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0]["id"], "us-east", "file order is preserved");
        assert_eq!(regions[0]["display_name"], "US East");
        assert_eq!(regions[0]["beacon"], "e:20000");
        assert_eq!(regions[0]["fallback"], "e:443");
        assert_eq!(regions[1]["id"], "eu-west");
    }

    #[tokio::test]
    async fn regions_endpoint_is_empty_without_config() {
        // No config = an empty list, not an error — the region-blind posture.
        let json = get_regions(router(state_with_relay_and_tenant())).await;
        assert_eq!(json["regions"].as_array().unwrap().len(), 0);
    }

    // -- Notice reporter authorization (cross-tenant forgery guard) --

    /// A stand-in tenant webhook receiver: an axum server that signals on a
    /// channel each time it receives a POST (the body is irrelevant here — the
    /// test only cares whether a webhook was signed and delivered at all).
    /// Returns the hook URL and the receive end.
    async fn spawn_webhook_receiver() -> (String, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State(tx): State<tokio::sync::mpsc::UnboundedSender<()>>,
                          _body: Bytes| async move {
                        let _ = tx.send(());
                        StatusCode::OK
                    },
                ),
            )
            .with_state(tx);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/hook"), rx)
    }

    /// A setup with one relay (id 1) and a tenant enrolled, a notify config
    /// pointed at `url`, and a session created — so the session's serving set is
    /// exactly `[RelayId(1)]`. Returns the setup, a fresh dedup, a lifecycle over
    /// it, and the created session id.
    fn setup_with_session_and_notify(
        url: String,
    ) -> (SessionSetup, NoticeDedup, Lifecycle, SessionId) {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![0xC1; 4],
            ),
        );
        let tenants = crate::tenant::new_store();
        crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        crate::tenant::set_notify(
            &tenants,
            &TenantId("sb-test".to_owned()),
            Some(crate::tenant::NotifyConfig { url }),
        );
        let setup = session::SessionSetup::new(reg, tenants);
        let resp = session::create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: Some("sb-user-0".to_owned()),
                    observer: false,
                    region: None,
                }],
                external_id: Some("game-1".to_owned()),
                latency_estimate_ms: None,
            },
            rally_point_proto::token::ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response;
        let lifecycle = Lifecycle::new(setup.clone());
        (setup, notify::new_dedup(), lifecycle, resp.session)
    }

    /// A `Result` notice framed as an inbound control message, carrying its own
    /// correlation ids so it would sign and deliver a webhook if accepted.
    fn result_message(session: SessionId, slot: u8) -> Message {
        let notice = rally_point_proto::control::ResultNotice {
            tenant: TenantId("sb-test".to_owned()),
            session,
            slot: SlotId(slot),
            external_id: Some("game-1".to_owned()),
            external_ref: Some("sb-user-0".to_owned()),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            arrival_ms: 1_700_000_000_000,
            session_frame: Some(1),
            slot_frame: Some(1),
        };
        let json = serde_json::to_string(&RelayToCoordinator::Result(notice)).unwrap();
        Message::Text(json.into())
    }

    #[test]
    fn relay_serves_session_enforces_membership_only_when_a_serving_set_exists() {
        let (setup, _notices, _lifecycle, session) =
            setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
        let tenant = TenantId("sb-test".to_owned());
        // The session's serving set is [RelayId(1)].
        assert!(
            relay_serves_session(&setup, RelayId(1), &tenant, session),
            "the session's serving relay may report",
        );
        assert!(
            !relay_serves_session(&setup, RelayId(2), &tenant, session),
            "a relay outside the serving set may not report",
        );
        // A session the coordinator never recorded a serving set for: unverifiable
        // (the post-restart tail case), so the reporter is allowed through.
        assert!(
            relay_serves_session(&setup, RelayId(2), &tenant, SessionId(999_999)),
            "with no serving record there is nothing to check against, so allow",
        );
    }

    #[tokio::test]
    async fn a_notice_from_a_relay_not_serving_the_session_signs_no_webhook() {
        // The cross-tenant forgery guard: relay 2 never served this session, so a
        // result it reports for the victim tenant + session must not be signed with
        // the tenant's key and delivered to its webhook.
        let (url, mut rx) = spawn_webhook_receiver().await;
        let (setup, notices, lifecycle, session) = setup_with_session_and_notify(url);

        note_inbound(
            &setup,
            &notices,
            &lifecycle,
            RelayId(2),
            0, // no live connection generation in this direct-call test
            &result_message(session, 0),
        );

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a result from a relay outside the serving set delivers no webhook",
        );
    }

    #[tokio::test]
    async fn a_notice_from_a_serving_relay_delivers_its_webhook() {
        let (url, mut rx) = spawn_webhook_receiver().await;
        let (setup, notices, lifecycle, session) = setup_with_session_and_notify(url);

        note_inbound(
            &setup,
            &notices,
            &lifecycle,
            RelayId(1),
            0, // no live connection generation in this direct-call test
            &result_message(session, 0),
        );

        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("a result from the serving relay delivers its webhook")
            .expect("the receiver got it");
    }

    #[tokio::test]
    async fn a_notice_for_a_session_with_no_serving_record_still_delivers() {
        // Post-restart tail: the coordinator holds no serving-relay record for the
        // session (created in a previous lifetime), so there is nothing to check the
        // reporter against and the notice must still be honored.
        let (url, mut rx) = spawn_webhook_receiver().await;
        let (setup, notices, lifecycle, _created) = setup_with_session_and_notify(url);

        // A session id the coordinator never created this lifetime -> empty serving
        // set, so even an arbitrary relay id is allowed through.
        note_inbound(
            &setup,
            &notices,
            &lifecycle,
            RelayId(2),
            0, // no live connection generation in this direct-call test
            &result_message(SessionId(4242), 0),
        );

        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("a notice for a session with no serving record still delivers")
            .expect("the receiver got it");
    }

    // --- Re-home endpoint ---

    /// A dev client seed for a *second* tenant (`sb-other`) in the cross-tenant
    /// probe test: its public half is enrolled as that tenant's request key, so
    /// `sb-other` can sign a request that authenticates as itself.
    const OTHER_CLIENT_SEED: [u8; 32] = [0x44; 32];

    /// Enrolls a second relay (id 2) into `state`'s registry, so a re-home whose home
    /// relay died has a live relay to move to.
    fn enroll_second_relay(state: &CoordinatorState) {
        registry::enroll(
            state.setup.registry(),
            RelayHello::new(
                RelayId(2),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                ProtocolVersion::CURRENT,
                vec![0xC2; 4],
            ),
        );
    }

    /// Creates a one-slot session owned by the `sb-test` tenant, returning its id.
    /// The re-home endpoint is now tenant-authenticated (the app server mediates),
    /// so the session's tokens no longer ride the request — only the session's
    /// existence and its `(tenant, session)` ownership matter.
    fn create_rehome_session(state: &CoordinatorState) -> SessionId {
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        };
        crate::session::create_session(&state.setup, req, ExpiresAt(u64::MAX))
            .unwrap()
            .response
            .session
    }

    /// Enrolls a second tenant (`sb-other`), with [`OTHER_CLIENT_SEED`]'s public
    /// half as its request-signing key, so a cross-tenant probe can authenticate as
    /// a *different* tenant than the one that owns the target session.
    fn enroll_other_tenant(state: &CoordinatorState) {
        crate::tenant::enroll(
            state.setup.tenants(),
            KeyId("other-key-1".to_owned()),
            TenantId("sb-other".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let client_pubkey = crate::tenant::client_pubkey_from_seed(&OTHER_CLIENT_SEED).unwrap();
        crate::tenant::set_client_pubkeys(
            state.setup.tenants(),
            &TenantId("sb-other".to_owned()),
            vec![client_pubkey],
        );
    }

    /// Builds the tenant-signed rehome request body `{tenant, session, dead_relay_id}`
    /// (snake_case, the control-plane wire style).
    fn rehome_body(tenant: &str, session: SessionId, dead_relay: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "tenant": tenant,
            "session": session.0,
            "dead_relay_id": dead_relay,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn rehome_endpoint_returns_a_new_target_when_the_home_died() {
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state);
        let session = create_rehome_session(&state);
        // The home relay (1) dies; the session should move to the live relay 2.
        registry::remove(state.setup.registry(), RelayId(1));

        let body = rehome_body("sb-test", session, 1);
        let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "newTarget");
        // Response fields are snake_case, matching the rest of the tenant-facing API,
        // and `relay` is the same proto `RelayEndpoint` shape as `home_relay` —
        // `cert_der` rides as a JSON byte array, not hex.
        assert_eq!(json["relay"]["relay_id"], 2);
        assert!(json["relay"]["cert_der"].is_array());
    }

    #[tokio::test]
    async fn rehome_endpoint_stays_when_the_relay_is_still_live() {
        let state = state_with_relay_and_tenant();
        let session = create_rehome_session(&state);
        // Relay 1 is still enrolled: the coordinator overrules the caller's belief.
        let body = rehome_body("sb-test", session, 1);
        let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "stay");
    }

    #[tokio::test]
    async fn rehome_endpoint_rejects_a_wrong_key_signature() {
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state);
        let session = create_rehome_session(&state);
        registry::remove(state.setup.registry(), RelayId(1));

        // Signed by a key whose public half is not the tenant's enrolled request key.
        let body = rehome_body("sb-test", session, 1);
        let resp = signed_post(router(state), "/session/rehome", &body, &[0x99; 32]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rehome_endpoint_rejects_a_stale_timestamp() {
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state);
        let session = create_rehome_session(&state);
        registry::remove(state.setup.registry(), RelayId(1));
        let app = router(state);

        // A correctly-keyed signature, but over a timestamp far outside the window.
        let body = rehome_body("sb-test", session, 1);
        let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_CLIENT_SEED).unwrap();
        let stale_ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (REQUEST_TIMESTAMP_WINDOW_SECS + 60))
            .to_string();
        let message = build_request_message(&stale_ts, &Method::POST, "/session/rehome", &body);
        let sig = hex::encode(pair.sign(&message).as_ref());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/rehome")
                    .header("content-type", "application/json")
                    .header(REQUEST_TIMESTAMP_HEADER, stale_ts)
                    .header(REQUEST_SIGNATURE_HEADER, sig)
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rehome_endpoint_unavailable_for_a_cross_tenant_session() {
        // A different tenant (sb-other) names sb-test's session id in a validly
        // *self*-signed request. The session lookup is tenant-keyed, so sb-other
        // finds no serving set for that id and gets `unavailable` — no cross-tenant
        // state is touched or leaked, and (relay 1 removed so the stay-guard cannot
        // fire) the answer is unambiguously unavailable rather than stay.
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state);
        enroll_other_tenant(&state);
        let session = create_rehome_session(&state); // owned by sb-test
        registry::remove(state.setup.registry(), RelayId(1));

        let body = rehome_body("sb-other", session, 1);
        let resp = signed_post(router(state), "/session/rehome", &body, &OTHER_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "unavailable");
        assert!(
            json.get("relay").is_none(),
            "no relay leaks to another tenant"
        );
    }

    #[tokio::test]
    async fn rehome_endpoint_rate_limits_repeated_requests() {
        // Relay 1 stays live, so every ask resolves to `stay` — a non-recorded
        // outcome that spends a rate-limit token each time (the free recorded-rehome
        // fast path never applies, since a `stay` records no replacement). This is
        // the token-spending path the reorder must still rate-limit: the default
        // burst is 3, so the first three are admitted and the fourth is a 429.
        let state = state_with_relay_and_tenant();
        let session = create_rehome_session(&state);
        let app = router(state);

        let body = rehome_body("sb-test", session, 1);
        for _ in 0..3 {
            let resp = signed_post(app.clone(), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = signed_post(app, "/session/rehome", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_recorded_rehome_re_ask_does_not_consume_a_token() {
        // The idempotent recorded-rehome answer must be served without spending a
        // rate-limit token, so an already-answered straggler can never starve a real
        // survivor's ask. Prove it by exhausting the session's bucket, then showing a
        // recorded re-ask still succeeds while a fresh (non-recorded) ask is a 429.
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state);
        let session = create_rehome_session(&state);
        // The home relay (1) dies; the first ask records the move to the live relay
        // 2 (spending one token of the default burst of 3).
        registry::remove(state.setup.registry(), RelayId(1));
        let app = router(state);

        let recorded_body = rehome_body("sb-test", session, 1);
        let resp = signed_post(
            app.clone(),
            "/session/rehome",
            &recorded_body,
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Exhaust the remaining tokens with garbage dead-relay asks on the SAME
        // session (each unrecorded and unserving → `unavailable`, but token-spending).
        // Relay ids 77/88 drain the last two tokens; 99 then hits the empty bucket.
        for dead in [77u64, 88] {
            let resp = signed_post(
                app.clone(),
                "/session/rehome",
                &rehome_body("sb-test", session, dead),
                &TEST_CLIENT_SEED,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = signed_post(
            app.clone(),
            "/session/rehome",
            &rehome_body("sb-test", session, 99),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a fresh, non-recorded ask is rate-limited once the bucket is empty",
        );

        // The straggler re-asks about the recorded dead relay 1. Even though the
        // bucket is exhausted, the recorded fast path answers `newTarget` (relay 2)
        // without charging a token.
        let resp = signed_post(app, "/session/rehome", &recorded_body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "newTarget");
        assert_eq!(
            json["relay"]["relay_id"], 2,
            "the recorded replacement is served despite the exhausted bucket",
        );
    }

    // --- Active-player presence query ---

    /// Creates a one-slot session for `sb-test` whose slot 0 carries the given
    /// user ref, returning its id. The session homes on the fixture's relay 1.
    fn create_session_with_user(state: &CoordinatorState, user: &str) -> SessionId {
        crate::session::create_session(
            &state.setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: Some(user.to_owned()),
                    observer: false,
                    region: None,
                }],
                external_id: None,
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response
        .session
    }

    /// The heartbeat roster naming `session`'s slot 0 — what relay 1's beat
    /// carries while that slot's client is connected.
    fn slot0_roster(session: SessionId) -> Vec<rally_point_proto::control::SessionPresence> {
        vec![rally_point_proto::control::SessionPresence {
            tenant: TenantId("sb-test".to_owned()),
            session,
            slots: vec![SlotId(0)],
        }]
    }

    /// The signed presence-query body `{tenant, users}`.
    fn presence_body(tenant: &str, users: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "tenant": tenant, "users": users })).unwrap()
    }

    #[tokio::test]
    async fn presence_query_reports_a_beating_user_in_game_and_an_unknown_one_not() {
        let state = state_with_relay_and_tenant();
        let session = create_session_with_user(&state, "sb-user-7");
        // Relay 1's heartbeat reports the slot connected.
        presence::apply_heartbeat(
            state.setup.presence(),
            RelayId(1),
            1,
            &slot0_roster(session),
            std::time::Instant::now(),
        );

        let body = presence_body("sb-test", &["sb-user-7", "sb-user-9"]);
        let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let users = json["users"].as_array().unwrap();
        assert_eq!(users.len(), 2, "one answer per queried user, in order");
        assert_eq!(users[0]["user"], "sb-user-7");
        assert_eq!(users[0]["in_game"], true);
        assert_eq!(
            users[0]["sessions"].as_array().unwrap(),
            &vec![serde_json::json!(session.0)],
            "the present user's session id rides along for observability",
        );
        assert_eq!(users[1]["user"], "sb-user-9");
        assert_eq!(users[1]["in_game"], false, "no evidence means not in game");
        assert!(users[1]["sessions"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn presence_query_reads_an_expired_entry_as_not_in_game() {
        // A beat older than the TTL no longer counts — fail-open: a silent relay's
        // players read as queueable rather than locked out.
        let state = state_with_relay_and_tenant();
        let session = create_session_with_user(&state, "sb-user-7");
        let stale = std::time::Instant::now()
            .checked_sub(presence::PRESENCE_TTL + Duration::from_secs(1))
            .expect("host uptime exceeds the presence TTL");
        presence::apply_heartbeat(
            state.setup.presence(),
            RelayId(1),
            1,
            &slot0_roster(session),
            stale,
        );

        let body = presence_body("sb-test", &["sb-user-7"]);
        let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["users"][0]["in_game"], false);
    }

    #[tokio::test]
    async fn presence_query_reads_a_cleared_connection_as_not_in_game() {
        // The relay's control connection dropped: its presence was cleared
        // promptly, so its players read as queueable without waiting out the TTL.
        let state = state_with_relay_and_tenant();
        let session = create_session_with_user(&state, "sb-user-7");
        presence::apply_heartbeat(
            state.setup.presence(),
            RelayId(1),
            1,
            &slot0_roster(session),
            std::time::Instant::now(),
        );
        presence::clear_connection(state.setup.presence(), RelayId(1), 1);

        let body = presence_body("sb-test", &["sb-user-7"]);
        let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["users"][0]["in_game"], false);
    }

    #[tokio::test]
    async fn presence_query_rejects_unsigned_and_wrong_key_requests_alike() {
        let state = state_with_relay_and_tenant();
        let app = router(state);
        let body = presence_body("sb-test", &["sb-user-7"]);

        // No signature headers at all — fails closed.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/presence/query")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Signed by a key that is not the tenant's enrolled request key — the
        // same indistinguishable 401.
        let resp = signed_post(app, "/presence/query", &body, &[0x99; 32]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn presence_query_rejects_an_over_cap_user_list() {
        // An over-cap list is rejected rather than resolved, past the auth gate —
        // the same shape as the sessions-alive probe cap.
        let state = state_with_relay_and_tenant();
        let too_many: Vec<String> = (0..=MAX_PRESENCE_USERS)
            .map(|i| format!("sb-user-{i}"))
            .collect();
        let body =
            serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "users": too_many }))
                .unwrap();
        let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // --- Warm endpoint + hold-until-ready create ---

    /// A region config listing each of `ids` (with placeholder display/ping fields
    /// the endpoint does not exercise).
    fn regions_config(ids: &[&str]) -> RegionsConfig {
        let entries: Vec<String> = ids
            .iter()
            .map(|id| {
                format!(r#"{{"id":"{id}","display_name":"{id}","beacon":"h:1","fallback":"h:2"}}"#)
            })
            .collect();
        RegionsConfig::from_json(&format!(r#"{{"regions":[{}]}}"#, entries.join(","))).unwrap()
    }

    /// A coordinator state with `region_ids` configured and relay 1 enrolled
    /// untagged (the region-blind fallback). `provisioning` installs the gate so
    /// the warm endpoint holds demand and a cold-region create returns `202`; the
    /// dormant case still answers the warm endpoint but holds nothing.
    fn provisioning_state(region_ids: &[&str], provisioning: bool) -> CoordinatorState {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![0xC1; 4],
            ),
        );
        let tenants = crate::tenant::new_store();
        crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let client_pubkey = crate::tenant::client_pubkey_from_seed(&TEST_CLIENT_SEED).unwrap();
        crate::tenant::set_client_pubkeys(
            &tenants,
            &TenantId("sb-test".to_owned()),
            vec![client_pubkey],
        );
        let mut setup = crate::session::SessionSetup::new(reg, tenants);
        if provisioning {
            setup = setup.with_provision_gate(crate::session::ProvisionGate::provisioning(
                crate::provision::WarmTargets::new(),
                Duration::from_secs(600),
                Duration::from_secs(75),
            ));
        }
        let lifecycle = Lifecycle::new(setup.clone());
        CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
            regions: regions_config(region_ids),
            player_token_lifetime: TEST_TOKEN_LIFETIME,
            ledger: None,
        }
    }

    /// A single-player create request naming `region` for its slot, anchored on
    /// `external_id`.
    fn region_create_body(region: &str, external_id: &str) -> Vec<u8> {
        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: Some(rally_point_proto::control::RegionId(region.to_owned())),
            }],
            external_id: Some(external_id.to_owned()),
            latency_estimate_ms: None,
        };
        serde_json::to_vec(&req).unwrap()
    }

    async fn body_json(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn warm_endpoint_warms_known_regions_and_reports_unknown() {
        let state = provisioning_state(&["region-a", "region-b"], true);
        let warm = state.setup.provision().warm().clone();
        let app = router(state);

        let body = serde_json::to_vec(&serde_json::json!({
            "tenant": "sb-test",
            "regions": ["region-a", "region-b", "atlantis"],
        }))
        .unwrap();
        let resp = signed_post(app, "/regions/warm", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(
            v["warmed"],
            serde_json::json!(["region-a", "region-b"]),
            "the configured regions are warmed",
        );
        assert_eq!(
            v["unknown"],
            serde_json::json!(["atlantis"]),
            "an unconfigured region is reported, not an error",
        );
        // The loop reads target 1 for each warmed region, and never for the unknown.
        assert_eq!(warm.target_at(&region("region-a"), 0), 1);
        assert_eq!(warm.target_at(&region("region-b"), 0), 1);
        assert_eq!(warm.target_at(&region("atlantis"), 0), 0);
    }

    #[tokio::test]
    async fn warm_endpoint_requires_a_valid_signature() {
        let state = provisioning_state(&["region-a"], true);
        let app = router(state);
        let body = serde_json::to_vec(&serde_json::json!({
            "tenant": "sb-test",
            "regions": ["region-a"],
        }))
        .unwrap();

        // Signed with a key whose public half is not the tenant's enrolled one.
        let resp = signed_post(app.clone(), "/regions/warm", &body, &[0x22; 32]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // No signature headers at all — fails closed.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/regions/warm")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn warm_endpoint_with_no_provisioning_loop_still_reports_known_regions() {
        // A dormant gate: the endpoint acknowledges known regions and reports
        // unknown ones the same way, though nothing consumes the demand.
        let state = provisioning_state(&["region-a"], false);
        let app = router(state);
        let body = serde_json::to_vec(&serde_json::json!({
            "tenant": "sb-test",
            "regions": ["region-a", "atlantis"],
        }))
        .unwrap();
        let resp = signed_post(app, "/regions/warm", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["warmed"], serde_json::json!(["region-a"]));
        assert_eq!(v["unknown"], serde_json::json!(["atlantis"]));
    }

    #[tokio::test]
    async fn cold_region_create_returns_202_then_200_once_a_relay_enrolls() {
        let state = provisioning_state(&["region-a"], true);
        let app = router(state.clone());
        let body = region_create_body("region-a", "g1");

        // region-a has no relay: the create is held with a 202 provisioning body and
        // nothing is minted.
        let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "provisioning");
        assert_eq!(v["regions"], serde_json::json!(["region-a"]));
        assert_eq!(v["retryAfterMs"], 2000);
        assert!(
            state.setup.descriptors().current_for(RelayId(1)).is_empty(),
            "a held create stages no descriptor and mints no session",
        );

        // A relay for region-a enrolls; the identical retry now places in-region.
        registry::enroll(
            state.setup.registry(),
            RelayHello::new(
                RelayId(2),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                ProtocolVersion::CURRENT,
                vec![0xC2; 4],
            )
            .with_region(rally_point_proto::control::RegionId("region-a".to_owned())),
        );
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let session: SessionResponse = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            session.home_relay.relay_id,
            RelayId(2),
            "the retry placed on the region's freshly enrolled relay",
        );
    }

    fn region(name: &str) -> rally_point_proto::control::RegionId {
        rally_point_proto::control::RegionId(name.to_owned())
    }

    // --- Multi-key inbound verification + per-state enforcement ---

    /// The retired half of a request-key rotation: still listed, so a signature
    /// from it must keep verifying until it is dropped.
    const ROTATION_SEED_OLD: [u8; 32] = [0x55; 32];
    /// The incoming half of a request-key rotation: listed alongside the old key,
    /// so a signature from it verifies too.
    const ROTATION_SEED_NEW: [u8; 32] = [0x66; 32];
    /// A key that is not among the tenant's listed verification keys — its
    /// signatures must be refused.
    const UNLISTED_SEED: [u8; 32] = [0x77; 32];

    /// A single-player create body anchored on `external_id`, so two otherwise
    /// identical creates are independent sessions rather than an idempotent
    /// replay.
    fn create_body(external_id: &str) -> Vec<u8> {
        serde_json::to_vec(&SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: Some(external_id.to_owned()),
            latency_estimate_ms: None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn verify_accepts_any_listed_client_key_and_refuses_an_unlisted_one() {
        // A request-key rotation in flight: the tenant lists both the old and the
        // new key at once. A signature from either verifies; one from an unlisted
        // key does not. This is what makes app-server key rotation zero-downtime.
        let state = state_with_relay_and_tenant();
        let old = crate::tenant::client_pubkey_from_seed(&ROTATION_SEED_OLD).unwrap();
        let new = crate::tenant::client_pubkey_from_seed(&ROTATION_SEED_NEW).unwrap();
        crate::tenant::set_client_pubkeys(
            state.setup.tenants(),
            &TenantId("sb-test".to_owned()),
            vec![old, new],
        );
        let app = router(state);

        // The first (retiring) key verifies.
        let resp = signed_post(
            app.clone(),
            "/session/create",
            &create_body("rot-old"),
            &ROTATION_SEED_OLD,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The second (incoming) key verifies.
        let resp = signed_post(
            app.clone(),
            "/session/create",
            &create_body("rot-new"),
            &ROTATION_SEED_NEW,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // A key absent from the list is refused, indistinguishably from any other
        // auth failure.
        let resp = signed_post(
            app,
            "/session/create",
            &create_body("rot-bad"),
            &UNLISTED_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Sends a `GET /tenant/sb-test/pubkey` and returns the status.
    async fn get_pubkey_status(app: Router) -> StatusCode {
        app.oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/tenant/sb-test/pubkey")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn a_suspended_tenant_is_refused_create_but_still_serves_live_games() {
        let state = state_with_relay_and_tenant();
        // Live-game state the suspended tenant must keep serving: a session to
        // re-home (homed on the still-live relay 1), a liveness-probe target, and
        // a presence session.
        let rehome = create_rehome_session(&state);
        state.lifecycle.register_session(
            TenantId("sb-test".to_owned()),
            SessionId(9001),
            vec![RelayId(1)],
            std::collections::HashSet::from([SlotId(0)]),
            std::collections::HashSet::new(),
            rally_point_proto::token::ExpiresAt(u64::MAX),
        );
        let presence_session = create_session_with_user(&state, "sb-user-7");
        presence::apply_heartbeat(
            state.setup.presence(),
            RelayId(1),
            1,
            &slot0_roster(presence_session),
            std::time::Instant::now(),
        );

        crate::tenant::set_state(
            state.setup.tenants(),
            &TenantId("sb-test".to_owned()),
            crate::tenant::TenantState::Suspended,
        );
        let app = router(state);

        // Create is refused — but with 403 (state), a distinct status from the 401
        // an auth failure yields: the signature verified, the state did not permit.
        let resp = signed_post(
            app.clone(),
            "/session/create",
            &create_body("suspended-create"),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Re-home still works (relay 1 is alive, so the decision is "stay").
        let resp = signed_post(
            app.clone(),
            "/session/rehome",
            &rehome_body("sb-test", rehome, 1),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["decision"], "stay");

        // The liveness probe still works.
        let resp = signed_post(
            app.clone(),
            "/sessions/alive",
            &serde_json::to_vec(&serde_json::json!({"tenant": "sb-test", "sessions": [9001]}))
                .unwrap(),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["alive"], serde_json::json!([9001]));

        // The presence query still works.
        let resp = signed_post(
            app.clone(),
            "/presence/query",
            &presence_body("sb-test", &["sb-user-7"]),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["users"][0]["in_game"], true);

        // The verifying-key fetch still works (a suspended tenant's live games
        // keep signing webhooks the consumer validates against this key).
        assert_eq!(get_pubkey_status(app).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_revoked_tenant_is_refused_everywhere_and_its_pubkey_404s() {
        let state = state_with_relay_and_tenant();
        let rehome = create_rehome_session(&state);
        state.lifecycle.register_session(
            TenantId("sb-test".to_owned()),
            SessionId(9001),
            vec![RelayId(1)],
            std::collections::HashSet::from([SlotId(0)]),
            std::collections::HashSet::new(),
            rally_point_proto::token::ExpiresAt(u64::MAX),
        );
        let _presence_session = create_session_with_user(&state, "sb-user-7");

        crate::tenant::set_state(
            state.setup.tenants(),
            &TenantId("sb-test".to_owned()),
            crate::tenant::TenantState::Revoked,
        );
        let app = router(state);

        // Every tenant-authenticated endpoint refuses with 403 — the signature
        // still verifies (the key is unchanged), the state permits nothing.
        for (path, body) in [
            ("/session/create", create_body("revoked-create")),
            ("/session/rehome", rehome_body("sb-test", rehome, 1)),
            (
                "/sessions/alive",
                serde_json::to_vec(&serde_json::json!({"tenant": "sb-test", "sessions": [9001]}))
                    .unwrap(),
            ),
            ("/presence/query", presence_body("sb-test", &["sb-user-7"])),
        ] {
            let resp = signed_post(app.clone(), path, &body, &TEST_CLIENT_SEED).await;
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{path} must be refused with 403 for a revoked tenant",
            );
        }

        // The pubkey endpoint reports the revoked tenant as absent.
        assert_eq!(get_pubkey_status(app).await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_explicitly_active_tenant_is_unaffected() {
        // Setting the state to Active is the same as the default: create mints and
        // the pubkey endpoint serves, exactly as with no state enforcement.
        let state = state_with_relay_and_tenant();
        crate::tenant::set_state(
            state.setup.tenants(),
            &TenantId("sb-test".to_owned()),
            crate::tenant::TenantState::Active,
        );
        let app = router(state);

        let resp = signed_post(
            app.clone(),
            "/session/create",
            &create_body("active-create"),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(get_pubkey_status(app).await, StatusCode::OK);
    }
}
