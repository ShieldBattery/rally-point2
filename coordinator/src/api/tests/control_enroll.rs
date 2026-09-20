//! The enroll handshake walked without a socket: the happy path in order, and
//! every point the sequence refuses a connection.
//!
//! The sequence's order is the security property, so these assert where the
//! pending-Hello permit is still held and where it has been released, not only
//! which close frame comes back.

use std::path::Path;
use std::sync::Arc;

use rally_point_proto::control::{CoordinatorToRelay, ENROLL_POP_CONTEXT, RelayHello};
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
    ProtocolVersion,
};
use tokio::sync::Semaphore;

use super::*;
use crate::ledger::RelayLedger;

/// A relay's real self-signed certificate and the private key that proves it —
/// the pair a `Hello` claims and the identity challenge tests.
///
/// The signing below is written from scratch rather than reused from the relay's
/// enroll client on purpose: if the proof context or the signed message layout
/// ever drifted and both sides drifted together, an end-to-end enroll test would
/// still pass while this one would fail.
struct RelayIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl RelayIdentity {
    /// A fresh Ed25519 self-signed certificate and its PKCS#8 key.
    fn generate() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Self {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    /// The `Hello` a relay with this identity presents under `id`.
    fn hello(&self, id: u64) -> RelayHello {
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
            ProtocolVersion::CURRENT,
            self.cert_der.clone(),
        )
    }

    /// The proof frame answering a challenge `nonce`: a signature over the
    /// enroll context followed by the nonce.
    fn proof(&self, nonce: &[u8; 32]) -> RelayToCoordinator {
        let mut message = ENROLL_POP_CONTEXT.to_vec();
        message.extend_from_slice(nonce);
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&self.key_der).unwrap();
        RelayToCoordinator::IdentityProof {
            signature: pair.sign(&message).as_ref().to_vec(),
        }
    }
}

/// A setup with the test tenant enrolled and no relays, so every relay in these
/// tests arrives through the handshake itself.
fn relayless_setup() -> SessionSetup {
    SessionFixture {
        relays: vec![],
        ..Default::default()
    }
    .setup_only()
}

/// The challenge nonce a `Send` step carries, or a panic naming what came back
/// instead.
fn challenge_nonce(step: EnrollStep) -> [u8; 32] {
    match step {
        EnrollStep::Send(CoordinatorToRelay::IdentityChallenge { nonce }) => nonce,
        other => panic!("expected an identity challenge, got {other:?}"),
    }
}

/// The close a `Refuse` step carries, or a panic naming what came back instead.
fn refusal(step: EnrollStep) -> ControlClose {
    match step {
        EnrollStep::Refuse(Some(close)) => close,
        other => panic!("expected a refusal with a close frame, got {other:?}"),
    }
}

/// How many relays the registry holds — zero for every refused connection.
fn enrolled_count(setup: &SessionSetup) -> usize {
    registry::enrolled_relays(setup.registry()).len()
}

#[test]
fn the_sequence_runs_hello_then_challenge_then_enroll_and_frees_the_permit() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let gate = Arc::new(Semaphore::new(1));

    let mut handshake =
        EnrollHandshake::start(&context, &gate).expect("the gate has a slot to claim");
    assert_eq!(
        gate.available_permits(),
        0,
        "the handshake claims its pending-Hello slot before reading anything",
    );

    let relay = RelayIdentity::generate();
    let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(relay.hello(1)))));
    assert_eq!(
        gate.available_permits(),
        0,
        "a negotiated, region-valid Hello is still an unproven identity; the slot stays held",
    );
    assert_eq!(
        enrolled_count(&setup),
        0,
        "nothing reaches the registry before the identity is proven",
    );

    let step = handshake.offer(Some(relay.proof(&nonce)));
    let EnrollStep::Enrolled(enrolled) = step else {
        panic!("expected the connection to enroll, got {step:?}");
    };
    assert_eq!(enrolled.relay_id, RelayId(1));
    assert_eq!(enrolled.negotiated, ProtocolVersion::CURRENT);
    assert_eq!(enrolled.relay_region, None);
    assert_eq!(
        gate.available_permits(),
        1,
        "the permit is released the moment the identity is proven, not when the connection ends",
    );
    assert!(
        registry::generation_is_current(setup.registry(), RelayId(1), enrolled.generation),
        "the handshake hands back the generation the registry issued",
    );
}

#[test]
fn a_saturated_pending_hello_gate_refuses_before_any_frame_is_read() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);

    let close = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(0)))
        .err()
        .expect("a saturated gate refuses the connection");
    assert_eq!(close.code, CONTROL_CLOSE_TRY_AGAIN_LATER);
    assert_eq!(
        close.reason,
        "too many pending control connections; retry shortly"
    );
}

#[test]
fn a_hello_with_no_common_protocol_version_never_reaches_the_challenge() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let gate = Arc::new(Semaphore::new(1));
    let mut handshake = EnrollHandshake::start(&context, &gate).unwrap();

    // A window entirely above this build's: no version both sides can speak.
    let relay = RelayIdentity::generate();
    let future_only = RelayHello::new(
        RelayId(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
        ProtocolVersion(99),
        relay.cert_der.clone(),
    )
    .with_min_protocol(ProtocolVersion(99));
    let close = refusal(handshake.offer(Some(RelayToCoordinator::Hello(future_only))));

    assert_eq!(close.code, CONTROL_CLOSE_PROTOCOL_MISMATCH);
    assert_eq!(
        enrolled_count(&setup),
        0,
        "a relay this coordinator cannot drive at any version never enrolls",
    );
    assert_eq!(
        gate.available_permits(),
        0,
        "the refusal precedes the proof, so the slot is still held until the handshake is dropped",
    );
}

#[test]
fn a_hello_naming_a_region_the_config_does_not_list_never_reaches_the_challenge() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let relay = RelayIdentity::generate();

    let refuse_region = |regions: RegionsConfig| {
        let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
        let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
        let tagged = relay.hello(1).with_region(RegionId("region-z".to_owned()));
        refusal(handshake.offer(Some(RelayToCoordinator::Hello(tagged))))
    };

    let close = refuse_region(regions_config(&["region-a"]));
    assert_eq!(close.code, CONTROL_CLOSE_UNKNOWN_REGION);
    assert_eq!(close.reason, "unknown region: region-z");

    // A coordinator with no region config at all lists nothing, so a tagged
    // hello is refused there too rather than silently serving nobody.
    assert_eq!(
        refuse_region(RegionsConfig::default()).code,
        CONTROL_CLOSE_UNKNOWN_REGION,
    );
    assert_eq!(
        enrolled_count(&setup),
        0,
        "a typo'd region tag is a failed enroll, never a registry entry",
    );
}

#[test]
fn an_unproven_identity_is_refused_and_leaves_the_permit_held() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let relay = RelayIdentity::generate();

    // A signature over some other nonce proves possession of nothing this
    // challenge asked about.
    let gate = Arc::new(Semaphore::new(1));
    let mut handshake = EnrollHandshake::start(&context, &gate).unwrap();
    let _nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(relay.hello(1)))));
    let close = refusal(handshake.offer(Some(relay.proof(&[0x5A; 32]))));
    assert_eq!(close.code, CONTROL_CLOSE_IDENTITY_UNPROVEN);
    assert_eq!(close.reason, "enroll proof-of-possession failed");
    assert_eq!(
        gate.available_permits(),
        0,
        "an unproven connection is exactly the population the gate bounds; it keeps its slot",
    );

    // No answer at all — a different frame kind, an undecodable one, or silence
    // past the deadline all arrive here as `None` — refuses identically.
    let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
    let _nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(relay.hello(1)))));
    assert_eq!(
        refusal(handshake.offer(None)).code,
        CONTROL_CLOSE_IDENTITY_UNPROVEN,
    );

    assert_eq!(
        enrolled_count(&setup),
        0,
        "proof of possession is what makes an id claim trustworthy; neither claim enrolled",
    );
}

#[test]
fn a_ledger_refusal_lands_after_the_permit_drops_and_before_the_registry() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    // A ledger that minted nothing: every id is one it does not know.
    let ledger = RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens");
    let context = EnrollContext::new(&setup, &lifecycle, &regions, Some(&ledger), None);
    let gate = Arc::new(Semaphore::new(1));
    let mut handshake = EnrollHandshake::start(&context, &gate).unwrap();

    let relay = RelayIdentity::generate();
    let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(relay.hello(1)))));
    let close = refusal(handshake.offer(Some(relay.proof(&nonce))));

    assert_eq!(close.code, CONTROL_CLOSE_ENROLL_UNAUTHORIZED);
    assert_eq!(
        close.reason, "enrollment not authorized for this relay id",
        "one generic reason, so a caller cannot probe which ids the ledger minted",
    );
    assert_eq!(
        gate.available_permits(),
        1,
        "the identity was proven before the ledger ran, so the slot is already free",
    );
    assert_eq!(
        enrolled_count(&setup),
        0,
        "an unauthorized enroll never reaches the registry",
    );
}

#[test]
fn a_second_certificate_claiming_a_live_relay_id_is_refused_as_a_duplicate() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);

    let enroll = |identity: &RelayIdentity| {
        let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
        let nonce =
            challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(identity.hello(1)))));
        handshake.offer(Some(identity.proof(&nonce)))
    };

    let first = RelayIdentity::generate();
    assert!(matches!(enroll(&first), EnrollStep::Enrolled(_)));

    // A second process proving a DIFFERENT certificate under the same id is an
    // id collision, not this relay's own redial.
    let impostor = RelayIdentity::generate();
    let close = refusal(enroll(&impostor));
    assert_eq!(close.code, CONTROL_CLOSE_DUPLICATE_RELAY_ID);
    assert_eq!(
        enrolled_count(&setup),
        1,
        "the live entry is refused a replacement, never silently evicted",
    );

    // The same certificate redialing is this relay's own reconnect and replaces
    // the entry, exactly as it always has.
    assert!(matches!(enroll(&first), EnrollStep::Enrolled(_)));
}
