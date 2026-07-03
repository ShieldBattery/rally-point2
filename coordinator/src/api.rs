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
//! WebSocket. App-server auth on `session/create` is still open — that is a
//! separate per-tenant credential, not the relay bootstrap secret.

use std::time::Duration;

use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rally_point_proto::control::{
    CoordinatorToRelay, RelayHello, RelayToCoordinator, SessionDescriptor, SessionRequest,
    SessionResponse,
};
use rally_point_proto::ids::RelayId;

use crate::registry::{self, RelayRegistry};
use crate::session::{self, SessionSetup};

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
        .route("/relay/control", get(relay_control))
        .with_state(state)
}

/// Creates a game session: assigns relays, mints tokens.
///
/// Token expiry is set to `u64::MAX` for now (dev/loopback). Production sets
/// it to the game session lifetime plus margin.
async fn create_session(
    State(state): State<CoordinatorState>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    let resp = session::create_session(
        &state.setup,
        request,
        rally_point_proto::token::ExpiresAt(u64::MAX),
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "session setup failed");
        match e {
            registry::SessionSetupError::NoRelaysAvailable
            | registry::SessionSetupError::NotEnoughRelays { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            registry::SessionSetupError::TenantNotFound(_)
            | registry::SessionSetupError::SlotOutOfRange(_)
            | registry::SessionSetupError::NoPlayers => StatusCode::BAD_REQUEST,
        }
    })?;

    tracing::info!(
        session = %resp.session,
        home_relay = %resp.home_relay.relay_id,
        players = resp.tokens.len(),
        "session created"
    );
    Ok(Json(resp))
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
    let registry = state.setup.registry().clone();
    let descriptors = state.setup.descriptors().clone();
    let hello_timeout = state.hello_timeout;
    let liveness_timeout = state.liveness_timeout;
    ws.on_upgrade(move |socket| {
        serve_relay_control(
            socket,
            registry,
            descriptors,
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
    registry: RelayRegistry,
    descriptors: crate::descriptors::RelayDescriptors,
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
    let relay_id = hello.relay_id;
    let generation = registry::enroll(&registry, hello);
    tracing::info!(
        relay_id = relay_id.0,
        "relay enrolled over control connection"
    );

    push_and_watch(&mut socket, &descriptors, relay_id, liveness_timeout).await;

    if registry::remove_if_current(&registry, relay_id, generation) {
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
    descriptors: &crate::descriptors::RelayDescriptors,
    relay_id: RelayId,
    liveness_timeout: Duration,
) {
    let mut rx = descriptors.subscribe(relay_id);

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
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(message)) => {
                        note_inbound(relay_id, &message);
                        // Any frame proves the relay is alive — push the deadline out.
                        deadline = tokio::time::Instant::now() + liveness_timeout;
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

/// Notes what an inbound relay frame was, for observability. The content drives
/// nothing yet — any frame already counts as the liveness signal — but recognizing
/// the heartbeat (and flagging anything undecodable) keeps the channel legible.
fn note_inbound(relay_id: RelayId, message: &Message) {
    let Message::Text(text) = message else {
        return; // a ping/pong/binary frame: a liveness signal with nothing to read
    };
    match serde_json::from_str::<RelayToCoordinator>(text) {
        Ok(RelayToCoordinator::Heartbeat) => {
            tracing::trace!(relay_id = relay_id.0, "relay heartbeat")
        }
        // A second Hello or a future up-frame: presence is enough, content unused.
        Ok(_) => {}
        Err(error) => {
            tracing::debug!(%error, relay_id = relay_id.0, "undecodable relay control frame")
        }
    }
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
                    // A heartbeat (or any future up-frame) before the enroll Hello
                    // is a protocol violation: enrollment must come first.
                    Ok(RelayToCoordinator::Heartbeat | RelayToCoordinator::Unknown) => {
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, KeyId};
    use rally_point_proto::version::ProtocolVersion;
    use tower::ServiceExt;

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
        let setup = crate::session::SessionSetup::new(reg, tenants);
        CoordinatorState {
            setup,
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
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
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
        };
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

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session: SessionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(session.tokens.len(), 2);
        assert_eq!(session.home_relay.relay_id, RelayId(1));
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
    async fn create_session_no_relays_returns_503() {
        let state = CoordinatorState {
            setup: crate::session::SessionSetup::new(
                registry::new_registry(),
                crate::tenant::new_store(),
            ),
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
        };
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
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

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_session_unenrolled_tenant_returns_400() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("not-enrolled".to_owned()),
            players: two_players(),
        };
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
