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
//! (`SB_RP2_CLIENT_KEY`); the coordinator verifies against the public half it
//! holds (`client_pubkey`, set at enrollment). Headers: `x-rp2-timestamp`
//! (unix *seconds*) + `x-rp2-signature` (hex) over `rp2-request-v1:<ts>:<METHOD
//! uppercased>:<path as sent>:<raw body>`. Binding method + path stops a
//! signed body being replayed against a different endpoint. Verification is
//! **required** (fail closed): a missing/invalid signature, a stale timestamp
//! (outside a ±5 minute window), or a tenant with no enrolled client key all
//! 401 without revealing which check failed. There is deliberately **no
//! nonce** — a request captured inside the window can be replayed, but at worst
//! that mints a garbage session that is reaped, and the transport is HTTPS in
//! prod / loopback in dev, so a captured-in-window replay is not a meaningful
//! threat. `GET /tenant/:tenant/pubkey` stays unsigned (bootstrap: it hands out
//! public key material only, the same posture as `/session/create` returning
//! relay certs).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Method, StatusCode, Uri, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rally_point_proto::control::{
    CoordinatorToRelay, RelayEndpoint, RelayHello, RelayToCoordinator, SessionDescriptor,
    SessionRequest, SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_proto::version::{self, CONTROL_CLOSE_PROTOCOL_MISMATCH};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::descriptors::SlotClose;
use crate::lifecycle::Lifecycle;
use crate::notify::{self, NoticeDedup};
use crate::presence;
use crate::registry;
use crate::session::{self, RehomeOutcome, SessionSetup};
use crate::tenant;

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
}

/// Builds the coordinator's HTTP router over `state`.
pub fn router(state: CoordinatorState) -> Router {
    Router::new()
        .route("/session/create", post(create_session))
        .route("/session/rehome", post(rehome_session))
        .route("/sessions/alive", post(sessions_alive))
        .route("/presence/query", post(presence_query))
        .route("/tenant/{tenant}/pubkey", get(tenant_pubkey))
        .route("/relay/control", get(relay_control))
        .with_state(state)
}

/// Creates a game session: assigns relays, mints tokens.
///
/// Authenticated by the tenant's request signature (see the module docs): the
/// body is deserialized to learn the tenant, then the signature is verified
/// against that tenant's enrolled `client_pubkey` before any work is done.
/// Reads the raw body (rather than a `Json` extractor) so the signature covers
/// exactly the bytes on the wire.
///
/// Token expiry is set to `u64::MAX` for now (dev/loopback). Production must
/// set it to the game session lifetime plus margin -- this is no longer just a
/// token concern: the never-started reaper's grace window (see
/// `lifecycle::never_started_grace`) reads `u64::MAX` as "no real expiry was
/// set" and falls back to a fixed floor, so a real expiry here is also what
/// lets that reaper size its window from the session's actual lifetime
/// instead of the floor alone.
async fn create_session(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionResponse>, StatusCode> {
    let request: SessionRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
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

    let expires_at = rally_point_proto::token::ExpiresAt(u64::MAX);
    let session::CreatedSession {
        response: resp,
        replayed,
    } = session::create_session(&state.setup, request, expires_at).map_err(|e| {
        tracing::warn!(error = %e, "session setup failed");
        match e {
            registry::SessionSetupError::NoRelaysAvailable => StatusCode::SERVICE_UNAVAILABLE,
            registry::SessionSetupError::IdempotentCreateMismatch => StatusCode::CONFLICT,
            registry::SessionSetupError::TenantNotFound(_)
            | registry::SessionSetupError::SlotOutOfRange(_)
            | registry::SessionSetupError::NoPlayers
            | registry::SessionSetupError::DuplicateSlot(_)
            | registry::SessionSetupError::ExternalIdTooLong
            | registry::SessionSetupError::ExternalRefTooLong(_)
            | registry::SessionSetupError::DevRelaySplitTooLong(_) => StatusCode::BAD_REQUEST,
        }
    })?;

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
    Ok(Json(resp))
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
/// re-asks too fast.
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
/// that tenant's enrolled `client_pubkey` before the probe. Rejects an over-cap
/// list rather than scan it.
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
/// under. Rejects an over-cap user list rather than resolve it.
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
/// enrolled (never provisioned, or removed).
async fn tenant_pubkey(
    State(state): State<CoordinatorState>,
    Path(tenant): Path<String>,
) -> Result<Json<TenantPubkeyResponse>, StatusCode> {
    let (kid, public_key) = tenant::verifying_key(state.setup.tenants(), &TenantId(tenant))
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(TenantPubkeyResponse {
        kid: kid.0,
        public_key: hex::encode(public_key),
    }))
}

/// Accepts a relay's persistent control connection (a WebSocket).
///
/// Authenticates against the bootstrap secret before the upgrade — a rejected
/// relay gets a `401` rather than an open socket — then upgrades and serves the
/// connection, which enrolls the relay (from its `Hello`) and pushes descriptors.
///
/// **Known limitation (deferred):** the bootstrap secret authenticates "a relay,"
/// not a specific relay id. A holder of the shared secret can connect, enroll as
/// any relay id, and receive that relay's descriptor set; the id in the `Hello`
/// is an unverified claim. Binding the connection to a relay identity — per-relay
/// credentials or a signed bootstrap token carrying the id — lands with the
/// relay-identity / mTLS work, the same effort that brings coordinator→relay
/// trust. Until then this endpoint is for trusted (loopback / internal)
/// deployment only.
async fn relay_control(
    State(state): State<CoordinatorState>,
    headers: HeaderMap,
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
    ws.on_upgrade(move |socket| {
        serve_relay_control(
            socket,
            setup,
            notices,
            lifecycle,
            hello_timeout,
            liveness_timeout,
        )
    })
}

/// Serves one relay's control connection: enroll from its `Hello`, push
/// descriptors, watch the relay's liveness, and deregister it when the connection
/// drops.
///
/// The relay's first frame must be its [`RelayToCoordinator::Hello`], sent within
/// `hello_timeout`; it enrolls the relay into the registry and yields the
/// connection's generation. The connection then serves descriptors and watches
/// liveness ([`push_and_watch`]) until it ends — the relay closes, the socket
/// errors, the relay goes silent past `liveness_timeout`, or the coordinator's
/// outbox is dropped (shutdown).
///
/// When the connection drops, the relay is deregistered — but only if this
/// connection is still the current one ([`registry::remove_if_current`]): a relay
/// that already reconnected (a newer connection re-enrolled it) keeps its live
/// entry, so a stale drop racing a reconnect does not evict a relay that is in fact
/// connected.
async fn serve_relay_control(
    mut socket: WebSocket,
    setup: SessionSetup,
    notices: NoticeDedup,
    lifecycle: Lifecycle,
    hello_timeout: Duration,
    liveness_timeout: Duration,
) {
    // The first frame enrolls the relay, and must arrive within the deadline — a
    // connection that opens the socket but never sends a Hello is dropped rather
    // than left to pin a task. A bad/absent first frame likewise just closes.
    let hello = match tokio::time::timeout(hello_timeout, read_hello(&mut socket)).await {
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
    let relay_id = hello.relay_id;
    let registry = setup.registry();
    let generation = registry::enroll(registry, hello);
    tracing::info!(
        relay_id = relay_id.0,
        negotiated = %negotiated,
        "relay enrolled over control connection"
    );

    push_and_watch(
        &mut socket,
        &setup,
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
async fn push_and_watch(
    socket: &mut WebSocket,
    setup: &SessionSetup,
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

    // A relay silent past this deadline — or one whose send stalls past it — is
    // treated as dead. Every inbound frame pushes it forward; a heartbeat lands
    // well inside the window, so it only lapses when the relay stops making
    // progress (a crash, a half-open connection, or a peer that stopped reading).
    let mut deadline = tokio::time::Instant::now() + liveness_timeout;

    // Initial re-sync, bounded by the deadline. Clone the set out of the watch
    // borrow before awaiting — a watch borrow must never be held across an await.
    let initial = rx.borrow_and_update().clone();
    if !send_before_deadline(socket, &initial, relay_id, deadline).await {
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
        Ok(RelayToCoordinator::Heartbeat { sessions }) => {
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
                    // A heartbeat, a departure, a desync, a result, or any future
                    // up-frame before the enroll Hello is a protocol violation:
                    // enrollment comes first.
                    Ok(
                        RelayToCoordinator::Heartbeat { .. }
                        | RelayToCoordinator::Draining
                        | RelayToCoordinator::Departure(_)
                        | RelayToCoordinator::Desync(_)
                        | RelayToCoordinator::Result(_)
                        | RelayToCoordinator::SessionClosed { .. }
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

/// Verifies a tenant-scoped mutating request's signature, failing closed with
/// `401` on any problem — a missing/unparseable timestamp, a stale timestamp
/// (outside [`REQUEST_TIMESTAMP_WINDOW_SECS`]), a missing/non-hex signature, a
/// tenant with no enrolled `client_pubkey`, or a signature that does not verify.
/// Every failure maps to the same `UNAUTHORIZED` so the response never reveals
/// which check failed. `ring`'s `verify` is itself constant-time.
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

    let client_pubkey =
        tenant::client_pubkey(setup.tenants(), tenant).ok_or(StatusCode::UNAUTHORIZED)?;

    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let message = build_request_message(timestamp, method, path, body);

    UnparsedPublicKey::new(&ED25519, client_pubkey.as_ref())
        .verify(&message, &signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)
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
        crate::tenant::set_client_pubkey(&tenants, &TenantId("sb-test".to_owned()), client_pubkey);
        let setup = crate::session::SessionSetup::new(reg, tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
        crate::tenant::set_client_pubkey(&tenants, &TenantId("sb-test".to_owned()), client_pubkey);
        let setup = crate::session::SessionSetup::new(registry::new_registry(), tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        let state = CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
        };
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            dev_relay_split: Vec::new(),
        };
        let body = serde_json::to_vec(&req).unwrap();
        let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
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
            dev_relay_split: Vec::new(),
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
                dev_relay_split: Vec::new(),
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
            dev_relay_split: Vec::new(),
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
        crate::tenant::set_client_pubkey(
            state.setup.tenants(),
            &TenantId("sb-other".to_owned()),
            client_pubkey,
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
                dev_relay_split: Vec::new(),
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
}
