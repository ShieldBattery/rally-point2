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

use futures_util::SinkExt;
use rally_point_coordinator::identity;
use rally_point_coordinator::registry;
use rally_point_proto::control::{RelayHello, RelayToCoordinator};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_IDENTITY_UNPROVEN,
    CONTROL_CLOSE_PROTOCOL_MISMATCH, ProtocolVersion,
};
use rally_point_relay::coordinator;
use rustls_pki_types::PrivateKeyDer;
use tokio_tungstenite::tungstenite::Message;

mod common;
use common::{
    CoordinatorBuilder, answer_challenge, connect_and_send_hello, expect_close,
    expect_identity_challenge, hello_at_current, prove_identity, read_to_descriptors, self_signed,
    wait_for_deregistration, wait_for_enrollment,
};

#[tokio::test]
async fn a_correctly_proven_relay_enrolls() {
    let served = CoordinatorBuilder::new().serve().await;
    let (cert_der, key) = self_signed();
    let mut socket =
        connect_and_send_hello(&served.base_url, hello_at_current(1, 14900, cert_der)).await;

    prove_identity(&mut socket, &key).await;

    assert!(
        wait_for_enrollment(served.registry(), RelayId(1)).await,
        "a relay that proves possession of its certificate's key enrolls",
    );
}

#[tokio::test]
async fn a_relay_that_never_answers_the_challenge_is_refused_and_never_enrolls() {
    // A short hello_timeout so the test doesn't wait the production deadline —
    // the same window bounds the proof-of-possession wait as the initial Hello.
    let served = CoordinatorBuilder::new()
        .with_hello_timeout(Duration::from_millis(200))
        .serve()
        .await;

    let (cert_der, _key) = self_signed();
    let mut socket =
        connect_and_send_hello(&served.base_url, hello_at_current(2, 14901, cert_der)).await;
    let _nonce = expect_identity_challenge(&mut socket).await;
    // Never answer.

    expect_close(&mut socket, CONTROL_CLOSE_IDENTITY_UNPROVEN).await;
    assert!(
        registry::peer(served.registry(), RelayId(2)).is_none(),
        "a relay that never answers the challenge is never enrolled",
    );
}

#[tokio::test]
async fn an_unverifiable_proof_is_refused_with_identity_unproven_and_never_enrolls() {
    // Both ways a proof can fail verification land on the one refusal: bytes
    // that are not a signature at all, and a well-formed signature from a key
    // that does not back the presented certificate — the impostor case the whole
    // exchange exists to catch.
    #[derive(Clone, Copy)]
    enum Proof {
        GarbageBytes,
        WrongKey,
    }

    for (relay_id, port, proof, why) in [
        (
            3,
            14902,
            Proof::GarbageBytes,
            "a relay whose proof is not a signature at all is never enrolled",
        ),
        (
            4,
            14903,
            Proof::WrongKey,
            "a signature from an unrelated key is never enrolled",
        ),
    ] {
        let served = CoordinatorBuilder::new().serve().await;
        let (cert_der, _honest_key) = self_signed();
        let mut socket =
            connect_and_send_hello(&served.base_url, hello_at_current(relay_id, port, cert_der))
                .await;

        let nonce = expect_identity_challenge(&mut socket).await;
        match proof {
            Proof::GarbageBytes => {
                let frame = serde_json::to_string(&RelayToCoordinator::IdentityProof {
                    signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
                })
                .unwrap();
                socket.send(Message::Text(frame.into())).await.unwrap();
            }
            Proof::WrongKey => {
                let (_impostor_cert, impostor_key) = self_signed();
                answer_challenge(&mut socket, &impostor_key, &nonce).await;
            }
        }

        expect_close(&mut socket, CONTROL_CLOSE_IDENTITY_UNPROVEN).await;
        assert!(
            registry::peer(served.registry(), RelayId(relay_id)).is_none(),
            "{why}",
        );
    }
}

#[tokio::test]
async fn a_downgrade_hello_is_refused_at_negotiation_and_does_not_displace_a_live_entry() {
    // A bootstrap-secret holder cannot dodge proof-of-possession by advertising
    // an older protocol version: MIN_SUPPORTED sits at or above ENROLL_POP_MIN,
    // so a Hello whose window tops out below the supported floor shares no version
    // with the coordinator and is refused at negotiation — it never reaches the
    // challenge, never enrolls, and never displaces a relay that legitimately
    // holds the id.
    let served = CoordinatorBuilder::new().serve().await;

    // A legitimate current relay enrolls under id 5, proving possession, and
    // holds its connection open (a live entry).
    let (cert_der, key) = self_signed();
    let mut live =
        connect_and_send_hello(&served.base_url, hello_at_current(5, 14904, cert_der)).await;
    prove_identity(&mut live, &key).await;
    assert!(wait_for_enrollment(served.registry(), RelayId(5)).await);
    let live_fingerprint = registry::live_cert_fingerprint(served.registry(), RelayId(5));
    assert!(live_fingerprint.is_some());

    // The downgrade attempt claims the same id, advertising a version below the
    // supported floor to try to reach the unconditional-replace path enroll PoP
    // closed. Negotiation refuses it outright.
    let downgrade = ProtocolVersion(ProtocolVersion::MIN_SUPPORTED.0 - 1);
    let hello = RelayHello::new(
        RelayId(5),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14999)),
        downgrade,
        vec![0xAB; 4],
    );
    let mut attacker = connect_and_send_hello(&served.base_url, hello).await;
    expect_close(&mut attacker, CONTROL_CLOSE_PROTOCOL_MISMATCH).await;

    // The live relay's entry is untouched: still present, still its own cert.
    assert!(
        registry::peer(served.registry(), RelayId(5)).is_some(),
        "the live entry survives the refused downgrade",
    );
    assert_eq!(
        registry::live_cert_fingerprint(served.registry(), RelayId(5)),
        live_fingerprint,
        "the downgrade attempt did not displace the live relay's certificate",
    );
}

#[tokio::test]
async fn a_duplicate_id_under_a_different_certificate_is_refused_while_the_first_stays_live() {
    let served = CoordinatorBuilder::new().serve().await;

    // Relay 1 enrolls first and holds the connection open (a live entry).
    let (cert_a, key_a) = self_signed();
    let mut socket_a =
        connect_and_send_hello(&served.base_url, hello_at_current(1, 14900, cert_a)).await;
    prove_identity(&mut socket_a, &key_a).await;
    assert!(wait_for_enrollment(served.registry(), RelayId(1)).await);

    // A second connection claims the same id with a DIFFERENT certificate —
    // proven possession of a real key, just not the one already on file.
    let (cert_b, key_b) = self_signed();
    let mut socket_b =
        connect_and_send_hello(&served.base_url, hello_at_current(1, 14900, cert_b)).await;
    prove_identity(&mut socket_b, &key_b).await;

    expect_close(&mut socket_b, CONTROL_CLOSE_DUPLICATE_RELAY_ID).await;

    // The first relay's entry is untouched by the refused second connection.
    assert!(
        registry::peer(served.registry(), RelayId(1)).is_some(),
        "the live entry survives the refused duplicate claim",
    );
    let entry = registry::entry(served.registry(), RelayId(1)).unwrap();
    assert_eq!(
        registry::live_cert_fingerprint(served.registry(), RelayId(1)),
        Some(registry::cert_fingerprint(&entry.cert_der)),
        "the registry still records relay 1's own certificate",
    );
}

#[tokio::test]
async fn a_reconnect_under_the_same_certificate_replaces_the_entry() {
    let served = CoordinatorBuilder::new().serve().await;
    let (cert_der, key) = self_signed();

    // First connection enrolls, then drops (simulating a redial: the control
    // connection closed and the relay is reconnecting with the same identity).
    {
        let mut socket = connect_and_send_hello(
            &served.base_url,
            hello_at_current(1, 14900, cert_der.clone()),
        )
        .await;
        prove_identity(&mut socket, &key).await;
        assert!(wait_for_enrollment(served.registry(), RelayId(1)).await);
        drop(socket);
        // Wait for the drop to be observed, so the reconnect below is unambiguous.
        assert!(wait_for_deregistration(served.registry(), RelayId(1)).await);
    }

    // Same relay id, same certificate, a fresh connection: this is the same
    // relay reconnecting (proof-of-possession proves it holds the same key
    // again), and it replaces the entry exactly as an unproven reconnect
    // always has.
    let mut socket =
        connect_and_send_hello(&served.base_url, hello_at_current(1, 14900, cert_der)).await;
    prove_identity(&mut socket, &key).await;

    // The reconnect is accepted (not refused as a duplicate): the enrolled path
    // proceeds — the tenant-key lead then the descriptor re-sync arrive, not a
    // close.
    let _ = read_to_descriptors(&mut socket).await;
    assert!(registry::peer(served.registry(), RelayId(1)).is_some());
}

#[tokio::test]
async fn the_relay_signing_helper_produces_signatures_the_coordinator_verifier_accepts() {
    // Cross-crate round trip: the exact function a real relay calls
    // (`rally_point_relay::coordinator::client::sign_enroll_proof`) against the exact function the
    // coordinator calls (`identity::verify_enroll_proof`) — proving the two
    // sides agree on the signed message and the supported algorithms, not just
    // that each one's own unit tests are internally consistent.
    let nonce = [0x42; 32];

    let (ecdsa_cert, ecdsa_key) = self_signed();
    let ecdsa_signature = coordinator::client::sign_enroll_proof(&ecdsa_key, &nonce)
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
        coordinator::client::sign_enroll_proof(&ed_key, &nonce).expect("an Ed25519 key signs");
    assert!(identity::verify_enroll_proof(
        ed_cert.der(),
        &nonce,
        &ed_signature
    ));
}
