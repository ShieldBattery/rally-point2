//! Enroll proof-of-possession + duplicate-id refusal, exercised end to end over
//! a real WebSocket control connection: the coordinator challenges every
//! accepted relay, verifies the signed answer against the certificate the
//! `Hello` presented, and — once proven — refuses a second relay claiming an
//! already-live id under a different certificate while accepting the same
//! relay's own reconnect.
//!
//! Negotiation refuses any relay advertising a version below the challenge
//! threshold, so there is no un-challenged enroll path; a downgrade Hello that
//! tries to reach one is turned away before it can enroll or displace a live
//! relay.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::identity;
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::{self, RelayRegistry};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, pair_rtts, tenant};
use rally_point_proto::control::{RelayHello, RelayToCoordinator};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_IDENTITY_UNPROVEN,
    CONTROL_CLOSE_PROTOCOL_MISMATCH, ProtocolVersion,
};
use rally_point_relay::coordinator_client;
use rustls_pki_types::PrivateKeyDer;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

mod common;
use common::{
    ControlSocket, answer_challenge, connect_and_send_hello, expect_identity_challenge,
    hello_at_current, read_to_descriptors, self_signed,
};

/// A generous liveness deadline — these tests don't exercise the timeout.
const LIVENESS: Duration = Duration::from_secs(30);

/// Serves a bare coordinator (open auth, no regions, no tenant) on an
/// ephemeral port. Returns the base URL and a handle to the registry so a test
/// can observe enrollment.
async fn serve_bare_coordinator() -> (String, RelayRegistry) {
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
        ledger: None,
        pair_rtts: pair_rtts::new_store(),
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), reg)
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
async fn a_correctly_proven_relay_enrolls() {
    let (base_url, reg) = serve_bare_coordinator().await;
    let (cert_der, key) = self_signed();
    let mut socket = connect_and_send_hello(&base_url, hello_at_current(1, 14900, cert_der)).await;

    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;

    assert!(
        wait_for_enrollment(&reg, RelayId(1)).await,
        "a relay that proves possession of its certificate's key enrolls",
    );
}

#[tokio::test]
async fn a_relay_that_never_answers_the_challenge_is_refused_and_never_enrolls() {
    // A short hello_timeout so the test doesn't wait the production deadline —
    // the same window bounds the proof-of-possession wait as the initial Hello.
    let reg = registry::new_registry();
    let setup = SessionSetup::new(reg.clone(), tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: Duration::from_millis(200),
        liveness_timeout: LIVENESS,
        regions: RegionsConfig::default(),
        player_token_lifetime: Duration::from_secs(3600),
        ledger: None,
        pair_rtts: pair_rtts::new_store(),
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base_url = format!("http://{addr}");

    let (cert_der, _key) = self_signed();
    let mut socket = connect_and_send_hello(&base_url, hello_at_current(2, 14901, cert_der)).await;
    let _nonce = expect_identity_challenge(&mut socket).await;
    // Never answer.

    expect_close(&mut socket, CONTROL_CLOSE_IDENTITY_UNPROVEN).await;
    assert!(
        registry::peer(&reg, RelayId(2)).is_none(),
        "a relay that never answers the challenge is never enrolled",
    );
}

#[tokio::test]
async fn a_garbage_signature_is_refused_with_identity_unproven_and_never_enrolls() {
    let (base_url, reg) = serve_bare_coordinator().await;
    let (cert_der, _key) = self_signed();
    let mut socket = connect_and_send_hello(&base_url, hello_at_current(3, 14902, cert_der)).await;

    let _nonce = expect_identity_challenge(&mut socket).await;
    let bad_proof = serde_json::to_string(&RelayToCoordinator::IdentityProof {
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
    })
    .unwrap();
    socket.send(Message::Text(bad_proof.into())).await.unwrap();

    expect_close(&mut socket, CONTROL_CLOSE_IDENTITY_UNPROVEN).await;
    assert!(
        registry::peer(&reg, RelayId(3)).is_none(),
        "a relay with an unverifiable proof is never enrolled",
    );
}

#[tokio::test]
async fn a_signature_from_the_wrong_key_is_refused_with_identity_unproven() {
    // A well-formed signature, but not from the key backing the presented
    // certificate — the impostor case the whole exchange exists to catch.
    let (base_url, reg) = serve_bare_coordinator().await;
    let (cert_der, _honest_key) = self_signed();
    let (_other_cert, impostor_key) = self_signed();
    let mut socket = connect_and_send_hello(&base_url, hello_at_current(4, 14903, cert_der)).await;

    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &impostor_key, &nonce).await;

    expect_close(&mut socket, CONTROL_CLOSE_IDENTITY_UNPROVEN).await;
    assert!(
        registry::peer(&reg, RelayId(4)).is_none(),
        "a signature from an unrelated key is never enrolled",
    );
}

#[tokio::test]
async fn a_downgrade_hello_is_refused_at_negotiation_and_does_not_displace_a_live_entry() {
    // A bootstrap-secret holder cannot dodge proof-of-possession by advertising
    // an older protocol version: MIN_SUPPORTED tracks CURRENT, so a Hello whose
    // window tops out below the current version shares no version with the
    // coordinator and is refused at negotiation — it never reaches the challenge,
    // never enrolls, and never displaces a relay that legitimately holds the id.
    let (base_url, reg) = serve_bare_coordinator().await;

    // A legitimate current relay enrolls under id 5, proving possession, and
    // holds its connection open (a live entry).
    let (cert_der, key) = self_signed();
    let mut live = connect_and_send_hello(&base_url, hello_at_current(5, 14904, cert_der)).await;
    let nonce = expect_identity_challenge(&mut live).await;
    answer_challenge(&mut live, &key, &nonce).await;
    assert!(wait_for_enrollment(&reg, RelayId(5)).await);
    let live_fingerprint = registry::live_cert_fingerprint(&reg, RelayId(5));
    assert!(live_fingerprint.is_some());

    // The downgrade attempt claims the same id, advertising a version just below
    // the current one to try to reach the unconditional-replace path enroll PoP
    // closed. Negotiation refuses it outright.
    let downgrade = ProtocolVersion(ProtocolVersion::CURRENT.0 - 1);
    let hello = RelayHello::new(
        RelayId(5),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14999)),
        downgrade,
        vec![0xAB; 4],
    );
    let mut attacker = connect_and_send_hello(&base_url, hello).await;
    expect_close(&mut attacker, CONTROL_CLOSE_PROTOCOL_MISMATCH).await;

    // The live relay's entry is untouched: still present, still its own cert.
    assert!(
        registry::peer(&reg, RelayId(5)).is_some(),
        "the live entry survives the refused downgrade",
    );
    assert_eq!(
        registry::live_cert_fingerprint(&reg, RelayId(5)),
        live_fingerprint,
        "the downgrade attempt did not displace the live relay's certificate",
    );
}

#[tokio::test]
async fn a_duplicate_id_under_a_different_certificate_is_refused_while_the_first_stays_live() {
    let (base_url, reg) = serve_bare_coordinator().await;

    // Relay 1 enrolls first and holds the connection open (a live entry).
    let (cert_a, key_a) = self_signed();
    let mut socket_a = connect_and_send_hello(&base_url, hello_at_current(1, 14900, cert_a)).await;
    let nonce_a = expect_identity_challenge(&mut socket_a).await;
    answer_challenge(&mut socket_a, &key_a, &nonce_a).await;
    assert!(wait_for_enrollment(&reg, RelayId(1)).await);

    // A second connection claims the same id with a DIFFERENT certificate —
    // proven possession of a real key, just not the one already on file.
    let (cert_b, key_b) = self_signed();
    let mut socket_b = connect_and_send_hello(&base_url, hello_at_current(1, 14900, cert_b)).await;
    let nonce_b = expect_identity_challenge(&mut socket_b).await;
    answer_challenge(&mut socket_b, &key_b, &nonce_b).await;

    expect_close(&mut socket_b, CONTROL_CLOSE_DUPLICATE_RELAY_ID).await;

    // The first relay's entry is untouched by the refused second connection.
    assert!(
        registry::peer(&reg, RelayId(1)).is_some(),
        "the live entry survives the refused duplicate claim",
    );
    let entry = registry::entry(&reg, RelayId(1)).unwrap();
    assert_eq!(
        registry::live_cert_fingerprint(&reg, RelayId(1)),
        Some(sha256_fingerprint(&entry.cert_der)),
        "the registry still records relay 1's own certificate",
    );
}

/// The SHA-256 fingerprint of DER bytes — mirrors the coordinator's own
/// (crate-private) `registry::cert_fingerprint`, recomputed here since this
/// test crate has no access to it.
fn sha256_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, cert_der).as_ref());
    out
}

#[tokio::test]
async fn a_reconnect_under_the_same_certificate_replaces_the_entry() {
    let (base_url, reg) = serve_bare_coordinator().await;
    let (cert_der, key) = self_signed();

    // First connection enrolls, then drops (simulating a redial: the control
    // connection closed and the relay is reconnecting with the same identity).
    {
        let mut socket =
            connect_and_send_hello(&base_url, hello_at_current(1, 14900, cert_der.clone())).await;
        let nonce = expect_identity_challenge(&mut socket).await;
        answer_challenge(&mut socket, &key, &nonce).await;
        assert!(wait_for_enrollment(&reg, RelayId(1)).await);
        drop(socket);
        // Wait for the drop to be observed so the reconnect below is unambiguous.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Same relay id, same certificate, a fresh connection: this is the same
    // relay reconnecting (proof-of-possession proves it holds the same key
    // again), and it replaces the entry exactly as an unproven reconnect
    // always has.
    let mut socket = connect_and_send_hello(&base_url, hello_at_current(1, 14900, cert_der)).await;
    let nonce = expect_identity_challenge(&mut socket).await;
    answer_challenge(&mut socket, &key, &nonce).await;

    // The reconnect is accepted (not refused as a duplicate): the enrolled path
    // proceeds — the tenant-key lead then the descriptor re-sync arrive, not a
    // close.
    let _ = read_to_descriptors(&mut socket).await;
    assert!(registry::peer(&reg, RelayId(1)).is_some());
}

#[tokio::test]
async fn the_relay_signing_helper_produces_signatures_the_coordinator_verifier_accepts() {
    // Cross-crate round trip: the exact function a real relay calls
    // (`coordinator_client::sign_enroll_proof`) against the exact function the
    // coordinator calls (`identity::verify_enroll_proof`) — proving the two
    // sides agree on the signed message and the supported algorithms, not just
    // that each one's own unit tests are internally consistent.
    let nonce = [0x42; 32];

    let (ecdsa_cert, ecdsa_key) = self_signed();
    let ecdsa_signature = coordinator_client::sign_enroll_proof(&ecdsa_key, &nonce)
        .expect("an ECDSA P-256 key signs");
    assert!(identity::verify_enroll_proof(
        &ecdsa_cert,
        &nonce,
        &ecdsa_signature
    ));

    // A different nonce must not verify — the signature is bound to the exact
    // challenge, not replayable against a later one.
    assert!(!identity::verify_enroll_proof(
        &ecdsa_cert,
        &[0x43; 32],
        &ecdsa_signature
    ));

    let ed_cert_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ed_cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&ed_cert_key)
        .unwrap();
    let ed_key = PrivateKeyDer::try_from(ed_cert_key.serialize_der()).unwrap();
    let ed_signature =
        coordinator_client::sign_enroll_proof(&ed_key, &nonce).expect("an Ed25519 key signs");
    assert!(identity::verify_enroll_proof(
        ed_cert.der(),
        &nonce,
        &ed_signature
    ));
}
