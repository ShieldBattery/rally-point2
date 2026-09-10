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
//!   [`SessionRequest`](rally_point_proto::control::SessionRequest); response:
//!   [`SessionResponse`](rally_point_proto::control::SessionResponse) with per-player tokens
//!   and the relay topology.
//! - `GET /tenant/:tenant/pubkey` — fetches a tenant's Ed25519 verifying key
//!   (`{"kid", "publicKey"}`, hex-encoded), so an app server can validate
//!   departure-webhook signatures without pinning the key in its own config.
//!   Public key material only, so — like `/session/create` handing out relay
//!   certs — it needs no auth; 404s for an unenrolled tenant.
//! - `GET /relay/control` — a relay opens its persistent control connection (a
//!   WebSocket). The relay's first frame is a
//!   [`RelayToCoordinator::Hello`](rally_point_proto::control::RelayToCoordinator::Hello) that
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
    routing::{get, post},
};

use crate::flight_store::S3FlightStore;
use crate::ledger::RelayLedger;
use crate::lifecycle::Lifecycle;
use crate::notify::NoticeDedup;
use crate::pair_rtts::PairRttStore;
use crate::regions::RegionsConfig;
use crate::session::SessionSetup;

mod control;
mod control_flight;
mod control_hello;
mod control_inbound;
mod control_writer;
mod load_state;
mod queries;
mod request_auth;
mod sessions;

#[cfg(test)]
mod tests;

use control::relay_control;
use load_state::session_load_state;
use queries::{flight_blob, flight_blobs, presence_query, regions, tenant_pubkey, warm_regions};
use sessions::{create_session, rehome_session, sessions_alive};

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

/// The most bytes a single control-connection WebSocket message (reassembled
/// from its frames) may carry, applied to both the message and the frame —
/// legitimate control frames are never fragmented, so a lower frame cap would
/// just reject the same traffic in a more confusing way.
///
/// Flight recordings no longer ride this connection (a relay uploads them straight to
/// object storage via a presigned URL), so the cap is sized to the largest frame that
/// actually does: a relay's heartbeat roster. A heartbeat carries up to
/// [`MAX_HEARTBEAT_SESSIONS`](control_inbound::MAX_HEARTBEAT_SESSIONS) session entries — one per session the relay holds,
/// each a tenant id (at most
/// [`token::MAX_STRING_LEN`](rally_point_proto::token::MAX_STRING_LEN) = 255 bytes), a
/// session id, up to
/// [`MAX_HEARTBEAT_SESSION_SLOTS`](control_inbound::MAX_HEARTBEAT_SESSION_SLOTS) connected
/// slot numbers, and the
/// session's retained load state (that same slot ceiling again for each of its two
/// slot sets, plus a start stamp) — plus up to
/// [`MAX_HEARTBEAT_REGION_RTTS`](control_inbound::MAX_HEARTBEAT_REGION_RTTS)
/// region-RTT entries. Even at a generous ~512 bytes per session entry — a real
/// tenant id is a short label, nowhere near the 255-byte ceiling — that worst case
/// stays under 2 MiB, so this bounds every
/// legitimate inbound frame with headroom. Left unset, axum/tungstenite default to
/// 64 MiB / 16 MiB — high enough that a single connection could pin tens of megabytes
/// per frame it merely claims to be sending, before any application-level check ever
/// runs.
const MAX_CONTROL_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

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
    /// The backbone-RTT pair table: the aggregate of the region-to-region round-trips
    /// relays measure and report on their heartbeats. Written from each relay control
    /// connection's heartbeat ingest and read by `GET /regions` to serve the pair
    /// list. Seeded from the ledger at startup when one is present, so last-known
    /// values survive a restart; memory-only otherwise. Shared (an `Arc`) across all
    /// relay control connections and the HTTP state.
    pub pair_rtts: PairRttStore,
    /// The flight-recorder durable sink, when the coordinator was started with one
    /// (`--flight-store`). Present ⇒ the recordings relays ship up their control
    /// connections are stored, and the flight read endpoints serve them. Absent ⇒ a
    /// shipped recording is dropped with a rate-limited warn and the read endpoints
    /// report nothing — the dev / no-store posture. Shared (an `Arc`) across all relay
    /// control connections and the HTTP state.
    pub flight_store: Option<Arc<S3FlightStore>>,
}

/// Builds the coordinator's HTTP router over `state`.
pub fn router(state: CoordinatorState) -> Router {
    Router::new()
        .route("/session/create", post(create_session))
        .route("/session/rehome", post(rehome_session))
        .route("/sessions/alive", post(sessions_alive))
        .route("/session/load-state", post(session_load_state))
        .route("/presence/query", post(presence_query))
        .route("/flight/blobs", post(flight_blobs))
        .route("/flight/blob", post(flight_blob))
        .route("/regions/warm", post(warm_regions))
        .route("/tenant/{tenant}/pubkey", get(tenant_pubkey))
        .route("/regions", get(regions))
        .route("/relay/control", get(relay_control))
        .with_state(state)
}
