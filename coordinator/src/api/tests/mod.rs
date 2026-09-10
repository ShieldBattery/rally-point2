//! Shared fixtures for the `api` tests: request signing, a coordinator state with
//! one relay and one tenant enrolled, and the frame/roster builders the control
//! connection tests drive `note_inbound` with. The topic modules below hold the
//! test functions themselves.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::*;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::Message;
use axum::http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION, header::RETRY_AFTER};
use rally_point_proto::control::{
    BufferBounds, DescriptorKey, PlayerHandoff, RegionId, RegionRttReport, RelayHello,
    RelayToCoordinator, SessionDescriptor, SessionRequest, SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::ProtocolVersion;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use tower::ServiceExt;

use crate::attest::LOAD_STATE_ATTEST_TIMEOUT;
use crate::flight_store;
use crate::lifecycle::Lifecycle;
use crate::notify;
use crate::pair_rtts;
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session;

use super::control::*;
use super::control_flight::*;
use super::control_inbound::*;
use super::control_writer::*;
use super::queries::*;
use super::request_auth::*;
use super::sessions::*;

mod control_inbound;
mod control_writer;
mod flight;
mod load_state;
mod notices;
mod presence_query;
mod regions;
mod rehome;
mod request_auth;
mod sessions;
mod tenant_auth;

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
        pair_rtts: pair_rtts::new_store(),
        flight_store: None,
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

/// A stand-in tenant webhook receiver: an axum server that signals on a
/// channel each time it receives a POST (the body is irrelevant here — the
/// test only cares whether a webhook was signed and delivered at all).
/// Returns the hook URL and the receive end.
async fn spawn_webhook_receiver() -> (String, tokio::sync::mpsc::UnboundedReceiver<()>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let app =
        Router::new()
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
fn setup_with_session_and_notify(url: String) -> (SessionSetup, NoticeDedup, Lifecycle, SessionId) {
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

/// A no-op backbone-RTT ingest for the notice tests, whose inbound messages are
/// never heartbeats — its store stays empty and untouched. Borrows caller-owned
/// temporaries so the returned view lives as long as they do.
fn idle_rtt_ingest<'a>(regions: &'a RegionsConfig, store: &'a PairRttStore) -> RegionRttIngest<'a> {
    RegionRttIngest {
        relay_region: None,
        regions,
        store,
        ledger: None,
    }
}

/// Runs [`note_inbound`] over one frame's inputs, bundling them into a
/// [`ControlInbound`] with no flight store — these direct-call tests never
/// exercise the flight-upload path, so the flight state is a throwaway.
fn note_inbound_frame(
    setup: &SessionSetup,
    notices: &NoticeDedup,
    lifecycle: &Lifecycle,
    relay_id: RelayId,
    generation: u64,
    message: &Message,
    rtt: &RegionRttIngest<'_>,
) -> InboundAction {
    let mut flight = FlightUploadState::new(tokio::sync::mpsc::unbounded_channel().0);
    note_inbound(
        &ControlInbound {
            setup,
            notices,
            lifecycle,
            relay_id,
            generation,
            rtt,
            flight_store: None,
        },
        &mut flight,
        message,
    )
}

/// A roster entry naming slot 0 connected and no load state — the common
/// shape for tests that only care that the session is on the beat.
fn session_presence(
    tenant: TenantId,
    session: SessionId,
) -> rally_point_proto::control::SessionPresence {
    rally_point_proto::control::SessionPresence {
        tenant,
        session,
        slots: vec![SlotId(0)],
        ever_connected: vec![],
        started: vec![],
        started_at_ms: None,
    }
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
    vec![session_presence(TenantId("sb-test".to_owned()), session)]
}

/// The signed presence-query body `{tenant, users}`.
fn presence_body(tenant: &str, users: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "tenant": tenant, "users": users })).unwrap()
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

async fn body_json(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
