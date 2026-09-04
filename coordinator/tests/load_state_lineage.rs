//! Relay process lineage, exercised end to end over a real WebSocket control
//! connection: whether a session's load record may still claim completeness turns
//! on whether the relays serving it have held it in one unbroken stretch of
//! process memory.
//!
//! A relay's retained load state lives in its process. A control connection
//! redialing keeps it; a restarted process comes back empty, and whatever the old
//! one observed and never restated is gone for good. The `boot_id` a hello carries
//! is what tells those apart, and this is where the coordinator's reading of it is
//! checked against real enrolls rather than a direct call.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry;
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, pair_rtts, tenant};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rustls_pki_types::PrivateKeyDer;

mod common;
use common::{
    ControlSocket, connect_and_send_hello, hello_at_current, prove_identity, read_to_descriptors,
    self_signed,
};

/// A generous liveness deadline — these tests don't exercise the timeout.
const LIVENESS: Duration = Duration::from_secs(30);

fn tenant_id() -> TenantId {
    TenantId("sb-test".to_owned())
}

/// Serves a bare coordinator on an ephemeral port, returning its base URL and the
/// lifecycle whose per-session state the assertions read.
async fn serve_coordinator() -> (String, Lifecycle) {
    let setup = SessionSetup::new(registry::new_registry(), tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle: lifecycle.clone(),
        control_auth: ControlAuth::Open,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: LIVENESS,
        regions: RegionsConfig::default(),
        player_token_lifetime: Duration::from_secs(3600),
        ledger: None,
        pair_rtts: pair_rtts::new_store(),
        flight_store: None,
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), lifecycle)
}

/// Enrolls a relay: sends the hello, proves possession of `key`, and reads through
/// to the descriptor push that only an accepted enroll ever produces — so the
/// caller knows the enrollment has landed before it asserts on its effects.
async fn enroll(
    base_url: &str,
    id: u64,
    cert_der: Vec<u8>,
    key: &PrivateKeyDer<'static>,
    boot_id: Option<u64>,
) -> ControlSocket {
    let mut hello = hello_at_current(id, 14_900 + id as u16, cert_der);
    if let Some(boot_id) = boot_id {
        hello = hello.with_boot_id(boot_id);
    }
    let mut socket = connect_and_send_hello(base_url, hello).await;
    prove_identity(&mut socket, key).await;
    read_to_descriptors(&mut socket).await;
    socket
}

/// Whether the session's load record can still claim to cover its whole life.
fn attestable(lifecycle: &Lifecycle, session: SessionId) -> bool {
    lifecycle
        .load_state(&tenant_id(), session)
        .expect("the session was registered here")
        .attestable
}

#[tokio::test]
async fn a_reconnect_under_the_same_boot_id_keeps_the_completeness_claim() {
    // The relay's process never died — its socket did. Everything it retained is
    // still in memory, so a snapshot it produces after this reconnect covers the
    // session's whole life exactly as one before it would have.
    let (base_url, lifecycle) = serve_coordinator().await;
    let (cert_der, key) = self_signed();
    let socket = enroll(&base_url, 1, cert_der.clone(), &key, Some(0xAB)).await;

    let session = SessionId(5);
    lifecycle.register_session(
        tenant_id(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    assert!(attestable(&lifecycle, session));

    drop(socket);
    let _reconnected = enroll(&base_url, 1, cert_der, &key, Some(0xAB)).await;
    assert!(
        attestable(&lifecycle, session),
        "the same process came back; nothing it held was lost",
    );
}

#[tokio::test]
async fn a_new_boot_id_ends_the_claim_for_exactly_that_relays_sessions() {
    // The relay restarted: its retained load state is gone, and no snapshot from
    // the new process can speak for what the old one saw and never restated. That
    // is a statement about the sessions *this* relay serves and no others.
    let (base_url, lifecycle) = serve_coordinator().await;
    let (cert_one, key_one) = self_signed();
    let (cert_two, key_two) = self_signed();
    let socket = enroll(&base_url, 1, cert_one.clone(), &key_one, Some(0xAB)).await;
    let _relay_two = enroll(&base_url, 2, cert_two, &key_two, Some(0xCD)).await;

    let shared = SessionId(5);
    let elsewhere = SessionId(6);
    lifecycle.register_session(
        tenant_id(),
        shared,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lifecycle.register_session(
        tenant_id(),
        elsewhere,
        vec![RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    drop(socket);
    let _restarted = enroll(&base_url, 1, cert_one, &key_one, Some(0xEF)).await;
    assert!(!attestable(&lifecycle, shared));
    assert!(
        attestable(&lifecycle, elsewhere),
        "a session relay 1 does not serve is untouched by its restart",
    );
}

#[tokio::test]
async fn a_relay_that_carries_no_boot_id_can_never_claim_continuity() {
    // A build that predates the field is indistinguishable from a restart, so its
    // reconnect is read as one. Anything else would let a session claim a
    // completeness its relays cannot back.
    let (base_url, lifecycle) = serve_coordinator().await;
    let (cert_der, key) = self_signed();
    let socket = enroll(&base_url, 1, cert_der.clone(), &key, None).await;

    let session = SessionId(5);
    lifecycle.register_session(
        tenant_id(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    assert!(attestable(&lifecycle, session));

    drop(socket);
    let _reconnected = enroll(&base_url, 1, cert_der, &key, None).await;
    assert!(!attestable(&lifecycle, session));
}
