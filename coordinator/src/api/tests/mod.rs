//! Shared fixtures for the `api` tests: request signing, a coordinator state with
//! one relay and one tenant enrolled, and the frame/roster builders the control
//! connection tests drive `note_inbound` with. The topic modules below hold the
//! test functions themselves.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::*;
use axum::Router;
use axum::extract::ws::Message;
use axum::http::{HeaderMap, Method, StatusCode, header::AUTHORIZATION, header::RETRY_AFTER};
use rally_point_proto::control::{
    BufferBounds, DescriptorKey, PlayerHandoff, RegionId, RegionRttReport, RelayToCoordinator,
    SessionDescriptor, SessionRequest, SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use tower::ServiceExt;

use crate::flight_store;
use crate::lifecycle::Lifecycle;
use crate::notify;
use crate::pair_rtts;
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session;
use crate::test_support::*;

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

/// A seed whose public half is enrolled for no tenant at all, so a signature
/// from it is well-formed and still refused.
const UNENROLLED_SEED: [u8; 32] = [0x22; 32];

/// The player-token lifetime the test coordinator states mint with. A plain
/// finite span so a minted expiry is `now + this`, observable without waiting.
const TEST_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

/// The tenant id every fixture in this area enrolls and signs as.
fn tenant_id() -> TenantId {
    TenantId(TEST_TENANT.to_owned())
}

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

/// Sends a `POST` carrying no signature headers at all.
async fn unsigned_post(
    app: Router,
    path: &str,
    body: &[u8],
) -> axum::http::Response<axum::body::Body> {
    app.oneshot(
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// Sends a `POST` signed correctly by the tenant's enrolled key, but over a
/// timestamp far outside the replay window — a captured request replayed long
/// after the fact.
async fn stale_signed_post(
    app: Router,
    path: &str,
    body: &[u8],
) -> axum::http::Response<axum::body::Body> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_CLIENT_SEED).unwrap();
    let stale_ts = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - (REQUEST_TIMESTAMP_WINDOW_SECS + 60))
        .to_string();
    let message = build_request_message(&stale_ts, &Method::POST, path, body);
    let sig = hex::encode(pair.sign(&message).as_ref());
    app.oneshot(
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(REQUEST_TIMESTAMP_HEADER, stale_ts)
            .header(REQUEST_SIGNATURE_HEADER, sig)
            .body(axum::body::Body::from(body.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// Enrolls `seed`'s public half as `tenant`'s only inbound-request verifying
/// key, so a request signed with it authenticates.
fn set_request_key(setup: &SessionSetup, tenant: &str, seed: &[u8; 32]) {
    let client_pubkey = crate::tenant::client_pubkey_from_seed(seed).unwrap();
    crate::tenant::set_client_pubkeys(
        setup.tenants(),
        &TenantId(tenant.to_owned()),
        vec![client_pubkey],
    );
}

/// The coordinator state the endpoint tests drive: relay 1 enrolled, the test
/// tenant enrolled with [`TEST_CLIENT_SEED`]'s public half as its request key,
/// and an observable token lifetime.
fn state_with_relay_and_tenant() -> CoordinatorState {
    state_over(SessionFixture::default().setup_only())
}

/// Wraps `setup` in the test coordinator state: an open control endpoint and a
/// finite token lifetime, everything else at its production default.
fn state_over(setup: SessionSetup) -> CoordinatorState {
    set_request_key(&setup, TEST_TENANT, &TEST_CLIENT_SEED);
    CoordinatorState {
        player_token_lifetime: TEST_TOKEN_LIFETIME,
        ..CoordinatorState::new(setup, ControlAuth::Open)
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

/// A setup with one relay (id 1) and a tenant enrolled, a notify config
/// pointed at `url`, and a session created — so the session's serving set is
/// exactly `[RelayId(1)]`. Returns the setup, a fresh dedup, a lifecycle over
/// it, and the created session id.
fn setup_with_session_and_notify(url: String) -> (SessionSetup, NoticeDedup, Lifecycle, SessionId) {
    let (setup, session) = SessionFixture {
        players: vec![PlayerSpec {
            slot: 0,
            external_ref: Some("sb-user-0"),
            region: None,
        }],
        external_id: Some("game-1"),
        notify_url: Some(url),
        ..Default::default()
    }
    .build();
    let lifecycle = Lifecycle::new(setup.clone());
    (setup, notify::new_dedup(), lifecycle, session)
}

/// The inputs `note_inbound` needs with nothing staged: a registry holding
/// relay 1 at `generation`, an empty tenant store, a fresh lifecycle and dedup,
/// no region config, and an idle RTT store. Returned as owned values the caller
/// keeps alive, since the ingest view borrows the last two.
struct InboundFixture {
    setup: SessionSetup,
    notices: NoticeDedup,
    lifecycle: Lifecycle,
    generation: u64,
    regions: RegionsConfig,
    store: PairRttStore,
}

impl InboundFixture {
    /// The RTT ingest view over this fixture's own region config and store.
    fn rtt(&self) -> RegionRttIngest<'_> {
        idle_rtt_ingest(&self.regions, &self.store)
    }

    /// Stages a descriptor for `session` in relay 1's outbox — the declarative
    /// per-relay assignment index the heartbeat's empty-roster accounting walks,
    /// so a session absent from it is never even considered.
    fn stage_descriptor(&self, tenant: &TenantId, session: SessionId) {
        self.setup.descriptors().record(
            RelayId(1),
            SessionDescriptor {
                finalized_drops: false,
                tenant: tenant.clone(),
                session,
                peers: vec![],
                bounds: BufferBounds::new(1, 6).unwrap(),
                authority_order: vec![RelayId(1)],
                external_id: None,
                slot_refs: vec![],
                observer_slots: vec![],
                expected_slots: vec![],
                homed_slots: vec![],
                resumed: false,
                departed_slots: vec![],
                latency_estimate_ms: None,
                relay_regions: Vec::new(),
            },
        );
    }

    /// Runs one frame from relay 1's current connection through `note_inbound`.
    fn note(&self, message: &Message) {
        note_inbound_frame(
            &self.setup,
            &self.notices,
            &self.lifecycle,
            RelayId(1),
            self.generation,
            message,
            &self.rtt(),
        );
    }
}

fn bare_inbound_fixture() -> InboundFixture {
    let reg = registry::new_registry();
    let generation = registry::enroll(
        &reg,
        (RelaySpec {
            id: 1,
            region: None,
        })
        .hello(),
    );
    let setup = session::SessionSetup::new(reg, crate::tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    InboundFixture {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        generation,
        regions: RegionsConfig::default(),
        store: pair_rtts::new_store(),
    }
}

/// A `Result` notice framed as an inbound control message, carrying its own
/// correlation ids so it would sign and deliver a webhook if accepted.
fn result_message(session: SessionId, slot: u8) -> Message {
    let notice = rally_point_proto::control::ResultNotice {
        tenant: tenant_id(),
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
        &ControlInbound::new(setup, notices, lifecycle, relay_id, generation, rtt, None),
        &mut flight,
        message,
    )
}

// --- Re-home endpoint ---

/// A dev client seed for a *second* tenant (`sb-other`) in the cross-tenant
/// probe tests: its public half is enrolled as that tenant's request key, so
/// `sb-other` can sign a request that authenticates as itself.
const OTHER_CLIENT_SEED: [u8; 32] = [0x44; 32];

/// Enrolls a second relay (id 2) into `state`'s registry, so a re-home whose home
/// relay died has a live relay to move to. `region` labels it when the test cares
/// what the answer says about where the replacement lives.
fn enroll_second_relay(state: &CoordinatorState, region: Option<&'static str>) {
    registry::enroll(
        state.setup.registry(),
        (RelaySpec { id: 2, region }).hello(),
    );
}

/// Creates a one-slot session owned by the `sb-test` tenant, returning its id.
/// The re-home endpoint is now tenant-authenticated (the app server mediates),
/// so the session's tokens no longer ride the request — only the session's
/// existence and its `(tenant, session)` ownership matter.
fn create_rehome_session(state: &CoordinatorState) -> SessionId {
    let req = SessionRequest {
        tenant: tenant_id(),
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
    set_request_key(&state.setup, "sb-other", &OTHER_CLIENT_SEED);
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
            tenant: tenant_id(),
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
    vec![presence_entry(&tenant_id(), session, &[0])]
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
