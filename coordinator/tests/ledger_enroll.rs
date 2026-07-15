//! Provisioned-relay ledger enrollment, exercised end to end over a real
//! WebSocket control connection: a ledger-backed coordinator mints a relay id
//! with a one-time token, admits the relay that presents that token (binding its
//! certificate), refuses a token-less or wrong-token enroll with a single generic
//! close code, admits the bound relay's reconnect on its certificate alone, and
//! refuses a different certificate claiming the bound id. It also proves the
//! coordinator-recorded advertise set overrides the hello's self-reported
//! addresses at enroll.
//!
//! The tokenless dev / loopback path is proven unchanged by the sibling
//! `enroll_identity` suite, which runs against a coordinator with no ledger.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::ledger::RelayLedger;
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::{self, RelayRegistry};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, tenant};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::CONTROL_CLOSE_ENROLL_UNAUTHORIZED;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

mod common;
use common::{
    ControlSocket, answer_challenge, connect_and_send_hello, expect_identity_challenge,
    hello_at_current, read_to_descriptors, self_signed,
};

/// A generous liveness deadline — these tests don't exercise the timeout.
const LIVENESS: Duration = Duration::from_secs(30);

/// The token lifetime tests mint with — comfortably longer than any test runs.
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Serves a ledger-backed coordinator (open auth, no regions, no tenant) on an
/// ephemeral port. Returns the base URL, a handle to the registry so a test can
/// observe enrollment, and the shared ledger so a test can mint ids and record
/// tasks the served handler then authorizes against.
async fn serve_ledger_coordinator() -> (String, RelayRegistry, Arc<RelayLedger>) {
    let ledger =
        Arc::new(RelayLedger::open(Path::new(":memory:")).expect("in-memory ledger opens"));
    let reg = registry::new_registry();
    let setup = SessionSetup::new(reg.clone(), tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: LIVENESS,
        regions: RegionsConfig::default(),
        player_token_lifetime: Duration::from_secs(3600),
        ledger: Some(ledger.clone()),
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), reg, ledger)
}

/// Reads the coordinator's next frame and asserts it is a close with
/// `expected_code`.
async fn expect_close(socket: &mut ControlSocket, expected_code: u16) {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Close(Some(close)) = frame else {
        panic!("expected a close frame, got {frame:?}");
    };
    assert_eq!(
        u16::from(close.code),
        expected_code,
        "reason: {}",
        close.reason
    );
}

/// Reads down-frames until the descriptor re-sync every accepted enroll includes —
/// proof the connection enrolled rather than being closed. The enrolled path leads
/// with the tenant-key push before the first descriptor, so this reads past it.
async fn expect_enrolled(socket: &mut ControlSocket) {
    let _ = read_to_descriptors(socket).await;
}

/// Polls the registry until `id` enrolls, up to a couple of seconds.
async fn wait_for_enrollment(reg: &RelayRegistry, id: RelayId) -> bool {
    for _ in 0..100 {
        if registry::peer(reg, id).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn a_minted_relay_enrolls_with_its_token_and_advertises_its_hello_addr() {
    let (base_url, reg, ledger) = serve_ledger_coordinator().await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");

    let (cert_der, key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;

    assert!(
        wait_for_enrollment(&reg, minted.relay_id).await,
        "a minted relay presenting its token enrolls",
    );
    // Nothing was recorded for the id, so it enrolls with its self-reported
    // hello address.
    let entry = registry::entry(&reg, minted.relay_id).unwrap();
    assert_eq!(
        entry.relay_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        "with no recorded advertise set, the hello's own address is used",
    );
}

#[tokio::test]
async fn a_recorded_advertise_set_overrides_the_hello_addresses() {
    let (base_url, reg, ledger) = serve_ledger_coordinator().await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");

    // The coordinator-resolved advertise set, recorded before the relay enrolls.
    let v4: SocketAddr = "203.0.113.5:15000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::5]:15000".parse().unwrap();
    ledger
        .record_task(minted.relay_id, "arn:aws:ecs:task/abc", &[], &[v4, v6])
        .expect("record the task's advertise set");

    // The hello self-reports a different (loopback) address.
    let (cert_der, key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;

    assert!(wait_for_enrollment(&reg, minted.relay_id).await);
    let entry = registry::entry(&reg, minted.relay_id).unwrap();
    assert_eq!(
        entry.relay_addr, v4,
        "the ledger's primary address wins over the hello's self-report",
    );
    assert_eq!(
        entry.relay_addrs,
        vec![v4, v6],
        "the ledger's full advertise set is enrolled, not the hello's",
    );
}

#[tokio::test]
async fn a_tokenless_or_wrong_token_enroll_is_refused() {
    let (base_url, reg, ledger) = serve_ledger_coordinator().await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();

    // No token at all: refused with the single generic close code.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(&reg, minted.relay_id).is_none(),
        "a token-less enroll never reaches the registry",
    );

    // A wrong token: the same generic refusal, indistinguishable on the wire.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token("not-the-real-token".to_owned());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(registry::peer(&reg, minted.relay_id).is_none());
}

#[tokio::test]
async fn the_bound_cert_reconnects_tokenless_and_a_new_cert_is_refused() {
    let (base_url, reg, ledger) = serve_ledger_coordinator().await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();

    // First enroll with the token binds this certificate to the id.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der.clone())
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;
    assert!(wait_for_enrollment(&reg, minted.relay_id).await);
    drop(socket);
    // Let the coordinator observe the drop and deregister before reconnecting.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect with the SAME certificate and NO token: the bound certificate
    // alone authorizes the reconnect.
    let hello = hello_at_current(minted.relay_id.0, 14901, cert_der.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;
    expect_enrolled(&mut socket).await;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Reconnect with a DIFFERENT certificate claiming the bound id — even with a
    // valid-looking token — is refused: the fingerprint does not match the bound
    // one, so the ledger closes 4005 before the registry is ever touched.
    let (other_cert, other_key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14902, other_cert)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &other_key, &nonce).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
}

#[tokio::test]
async fn a_retired_id_is_refused_even_with_its_token() {
    let (base_url, reg, ledger) = serve_ledger_coordinator().await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    ledger.retire(minted.relay_id).expect("retire the id");

    let (cert_der, key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(&reg, minted.relay_id).is_none(),
        "a retired id can never enroll",
    );
}
