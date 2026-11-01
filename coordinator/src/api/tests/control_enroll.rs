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

/// A public address the provisioner resolved for a relay's task, distinct from
/// the loopback self-report in [`RelayIdentity::hello`].
fn resolved_addr() -> SocketAddr {
    "[2001:db8::7]:14900".parse().unwrap()
}

/// Runs one handshake for `relay` presenting `hello`, returning the final step.
fn handshake_once(
    context: &EnrollContext<'_>,
    relay: &RelayIdentity,
    hello: RelayHello,
) -> EnrollStep {
    let gate = Arc::new(Semaphore::new(1));
    let mut handshake = EnrollHandshake::start(context, &gate).unwrap();
    let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(hello))));
    handshake.offer(Some(relay.proof(&nonce)))
}

#[test]
fn a_relay_whose_addresses_are_not_recorded_is_deferred_without_spending_its_token() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let ledger = RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens");
    // Launched and recorded, but its task has not reported an address yet: the
    // window in which a fast-starting relay used to enroll on its loopback
    // self-report and be handed to clients at 127.0.0.1.
    let minted = ledger.mint(None, Duration::from_secs(300)).unwrap();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, Some(&ledger), None);
    let relay = RelayIdentity::generate();
    let mut hello = relay.hello(minted.relay_id.0);
    hello.enroll_token = Some(minted.token.clone());

    let close = refusal(handshake_once(&context, &relay, hello.clone()));
    assert_eq!(
        close.code, CONTROL_CLOSE_TRY_AGAIN_LATER,
        "a retry-later close, which every relay version answers with its short redial",
    );
    assert_eq!(enrolled_count(&setup), 0);

    // The token was not consumed, so the id is still a launch in flight (scale-up
    // must not launch a second relay for it) and the same token binds once the
    // address lands.
    let now = rally_point_proto::time::unix_secs_fail_closed();
    assert_eq!(ledger.count_launching(None, now).unwrap(), 1);
    ledger
        .record_task(minted.relay_id, "task/late", &[], &[resolved_addr()])
        .unwrap();
    assert!(matches!(
        handshake_once(&context, &relay, hello),
        EnrollStep::Enrolled(_)
    ));
}

#[test]
fn a_provisioned_relay_enrolls_at_its_recorded_addresses_never_its_self_report() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let ledger = RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens");
    let minted = ledger.mint(None, Duration::from_secs(300)).unwrap();
    let secondary: SocketAddr = "198.51.100.7:14900".parse().unwrap();
    ledger
        .record_task(
            minted.relay_id,
            "task/a",
            &[],
            &[resolved_addr(), secondary],
        )
        .unwrap();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, Some(&ledger), None);
    let relay = RelayIdentity::generate();
    let mut hello = relay.hello(minted.relay_id.0);
    hello.enroll_token = Some(minted.token);

    assert!(matches!(
        handshake_once(&context, &relay, hello),
        EnrollStep::Enrolled(_)
    ));
    let entry = registry::entry(setup.registry(), minted.relay_id).unwrap();
    assert_eq!(entry.relay_addr, resolved_addr());
    assert_eq!(entry.relay_addrs, vec![resolved_addr(), secondary]);
}

#[test]
fn an_id_retired_after_authorization_is_refused_at_the_registry_insert() {
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let ledger = RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens");
    let minted = ledger.mint(None, Duration::from_secs(300)).unwrap();
    let relay_id = minted.relay_id;
    ledger
        .record_task(relay_id, "task/retired", &[], &[resolved_addr()])
        .unwrap();
    // The ledger authorizes this enroll, then a drain tombstones the id before the
    // registry insert, the way the reconcile loop can between its own steps.
    let context = EnrollContext::new(&setup, &lifecycle, &regions, Some(&ledger), None)
        .with_after_authorize(|| ledger.retire(relay_id).unwrap());
    let gate = Arc::new(Semaphore::new(1));
    let mut handshake = EnrollHandshake::start(&context, &gate).unwrap();

    let relay = RelayIdentity::generate();
    let mut hello = relay.hello(relay_id.0);
    hello.enroll_token = Some(minted.token);
    let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(hello))));
    let close = refusal(handshake.offer(Some(relay.proof(&nonce))));

    assert_eq!(close.code, CONTROL_CLOSE_ENROLL_UNAUTHORIZED);
    assert_eq!(
        enrolled_count(&setup),
        0,
        "a retired id never gets back into the registry",
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

#[tokio::test]
async fn capability_downgrade_rehomes_required_sessions_and_preserves_optional_sessions() {
    for restarted in [false, true] {
        check_evidence_downgrade(true, restarted).await;
    }
}

#[tokio::test]
async fn capability_downgrade_retires_only_required_sessions_without_a_replacement() {
    for restarted in [false, true] {
        check_evidence_downgrade(false, restarted).await;
    }
}

async fn check_evidence_downgrade(replacement: bool, restarted: bool) {
    use rally_point_proto::control::{CAPABILITY_EVIDENCE_V1, EvidenceKey};
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let relay = RelayIdentity::generate();
    let enroll = |capable, boot| {
        let mut hello = relay.hello(1).with_boot_id(boot);
        if capable {
            hello = hello.with_capabilities(vec![CAPABILITY_EVIDENCE_V1.into()]);
        }
        let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
        let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(hello))));
        handshake.offer(Some(relay.proof(&nonce)))
    };
    assert!(matches!(enroll(true, 7), EnrollStep::Enrolled(_)));
    let mut request = crate::test_support::request(vec![crate::test_support::player(0)]);
    request.players[0].require_evidence = true;
    request.evidence_keys = vec![EvidenceKey {
        key_id: 1,
        public_key: ClientPublicKey([3; 32]),
    }];
    let required = session::create_session(&setup, request, ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    let optional = session::create_session(
        &setup,
        crate::test_support::request(vec![crate::test_support::player(0)]),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
    .session;
    for session in [required, optional] {
        lifecycle.register_session(
            tenant_id(),
            session,
            vec![RelayId(1)],
            std::collections::HashSet::from([SlotId(0)]),
            Default::default(),
        );
    }
    let (url, mut webhooks) = WebhookReceiver::default().spawn().await;
    crate::tenant::set_notify(
        setup.tenants(),
        &tenant_id(),
        Some(crate::tenant::NotifyConfig { url }),
    );
    if replacement {
        registry::enroll(
            setup.registry(),
            crate::test_support::hello(2, 14902)
                .with_capabilities(vec![CAPABILITY_EVIDENCE_V1.into()]),
        );
    }
    let EnrollStep::Enrolled(enrolled) = enroll(false, if restarted { 8 } else { 7 }) else {
        panic!("the relay remains available for optional sessions");
    };
    assert!(registry::generation_is_current(
        setup.registry(),
        RelayId(1),
        enrolled.generation
    ));
    assert!(registry::is_available(setup.registry(), RelayId(1)));
    assert_eq!(
        setup.serving_relays(&tenant_id(), optional),
        vec![RelayId(1)]
    );
    assert!(lifecycle.load_state(&tenant_id(), optional).is_some());
    let descriptors = setup.descriptors().current_for(RelayId(1));
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].session, optional);
    assert!(descriptors[0].required_evidence_slots.is_empty());
    if replacement {
        assert_eq!(
            setup.serving_relays(&tenant_id(), required),
            vec![RelayId(2)]
        );
        assert_eq!(
            lifecycle
                .load_state(&tenant_id(), required)
                .unwrap()
                .serving_relays,
            vec![RelayId(2)]
        );
        let descriptors = setup.descriptors().current_for(RelayId(2));
        assert_eq!(descriptors[0].session, required);
        assert_eq!(descriptors[0].required_evidence_slots, vec![SlotId(0)]);
        assert_eq!(descriptors[0].evidence_assignments[0].revision, 2);
        assert!(webhooks.try_recv().is_err());
    } else {
        assert!(setup.serving_relays(&tenant_id(), required).is_empty());
        assert!(session::session_refs(&setup, &tenant_id(), required).is_none());
        assert!(lifecycle.load_state(&tenant_id(), required).is_none());
        let webhook = tokio::time::timeout(Duration::from_secs(2), webhooks.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(webhook.body["event"], "sessionClosed");
        assert_eq!(webhook.body["session"], required.0);
    }
}

#[test]
fn reenrollment_refreshes_periodic_policy_without_rehoming_the_session() {
    use rally_point_proto::control::{CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceKey};
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let relay = RelayIdentity::generate();
    let enroll = |capable| {
        let mut hello = relay.hello(1).with_boot_id(7);
        if capable {
            hello = hello.with_capabilities(vec![CAPABILITY_PERIODIC_EVIDENCE_V1.into()]);
        }
        let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
        let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(hello))));
        assert!(matches!(
            handshake.offer(Some(relay.proof(&nonce))),
            EnrollStep::Enrolled(_)
        ));
    };
    enroll(false);
    let mut request = crate::test_support::request(vec![crate::test_support::player(0)]);
    request.periodic_evidence = true;
    request.evidence_keys = vec![EvidenceKey {
        key_id: 1,
        public_key: ClientPublicKey([3; 32]),
    }];
    let session = session::create_session(&setup, request, ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    assert!(!setup.descriptors().current_for(RelayId(1))[0].periodic_evidence);
    for capable in [true, false, true] {
        enroll(capable);
        assert_eq!(
            setup.descriptors().current_for(RelayId(1))[0].periodic_evidence,
            capable
        );
        assert_eq!(
            setup.serving_relays(&tenant_id(), session),
            vec![RelayId(1)]
        );
    }
}

#[test]
fn a_returning_relay_rejoins_the_peer_lists_staged_while_it_was_away() {
    // Relay 1 homes slot 0; relay 2 (region-b, a real enrolled identity) homes
    // slot 1; relay 3 is idle.
    let setup = relayless_setup();
    let lifecycle = Lifecycle::new(setup.clone());
    let regions = crate::test_support::regions_config(&["region-b"]);
    let context = EnrollContext::new(&setup, &lifecycle, &regions, None, None);
    let relay_two = RelayIdentity::generate();
    let enroll_two = || {
        let mut handshake = EnrollHandshake::start(&context, &Arc::new(Semaphore::new(1))).unwrap();
        let hello = relay_two
            .hello(2)
            .with_region(crate::test_support::region("region-b"));
        let nonce = challenge_nonce(handshake.offer(Some(RelayToCoordinator::Hello(hello))));
        assert!(matches!(
            handshake.offer(Some(relay_two.proof(&nonce))),
            EnrollStep::Enrolled(_)
        ));
    };
    registry::enroll(setup.registry(), crate::test_support::hello(1, 14901));
    enroll_two();
    registry::enroll(setup.registry(), crate::test_support::hello(3, 14903));
    let mut players = crate::test_support::two_players();
    players[1].region = Some(crate::test_support::region("region-b"));
    let session = session::create_session(
        &setup,
        crate::test_support::request(players),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
    .session;

    // Relay 2's control connection blips while relay 1 dies, and relay 1's group
    // is re-homed onto relay 3 in that window: relay 3's descriptor is built
    // while relay 2 is not enrolled.
    registry::remove(setup.registry(), RelayId(2));
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        session::rehome(&setup, &tenant_id(), session, RelayId(1), vec![]),
        session::RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(3)
    ));

    // Relay 2 reconnects. Both relays serve the session, so relay 3 must be
    // told to mesh with it again.
    enroll_two();
    let staged = setup
        .descriptors()
        .current_descriptor(RelayId(3), &tenant_id(), session)
        .unwrap();
    assert_eq!(
        staged.peers.iter().map(|p| p.relay_id).collect::<Vec<_>>(),
        vec![RelayId(2)],
        "relay 3's staged peer list names its fellow serving relay",
    );
}
