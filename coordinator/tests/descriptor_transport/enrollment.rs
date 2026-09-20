//! Enrollment at the control connection's start: a relay's Hello enrolls it into
//! the registry, a connection that never sends one (or sends the wrong first
//! frame) is dropped without waiting out the full handshake deadline, the gate
//! bounding how many connections may sit unenrolled at once refuses the overflow
//! and frees a slot the moment an identity is proven, a dropped connection
//! deregisters the relay, and protocol-version negotiation refuses a relay whose
//! window shares nothing with the coordinator's while downgrading one whose
//! window merely overlaps.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::api;
use rally_point_coordinator::registry;
use rally_point_proto::control::{RelayHello, RelayToCoordinator, ResultNotice, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator;
use rally_point_relay::mesh::control::MeshControl;
use rustls_pki_types::PrivateKeyDer;

use crate::common::{
    CoordinatorBuilder, connect_and_send_hello, expect_close, expect_closed_unserved,
    expect_identity_challenge, prove_identity, read_to_descriptors, relay_key,
};
use crate::helpers::*;

/// The standard WebSocket "try again later" close code (RFC 6455 / the IANA
/// close-code registry) the coordinator refuses a connection with when its
/// pending-Hello gate is saturated. Not one of the `CONTROL_CLOSE_*` codes: it
/// names a transient capacity refusal, which a relay handles with its ordinary
/// short-delay reconnect.
const CONTROL_CLOSE_TRY_AGAIN_LATER: u16 = 1013;

#[tokio::test]
async fn a_relays_hello_enrolls_it_into_the_registry() {
    // The coordinator pre-enrolls relays 1 and 2; relay 5 is not enrolled.
    let (base_url, _session, setup) = coordinator_with_session(None).await;
    assert!(
        registry::peer(setup.registry(), RelayId(5)).is_none(),
        "relay 5 starts unenrolled",
    );

    // Relay 5 opens its control connection; its Hello (the first frame) enrolls it
    // — no separate phone-home. It has no peers, so the empty descriptor set it
    // receives drives nothing.
    let control = MeshControl::new(
        RelayId(5),
        &rally_point_relay::mesh::MeshState::default(),
        rally_point_relay::routing::Sessions::default(),
    );
    tokio::spawn(coordinator::client::run_descriptor_subscriber_with(
        coordinator::client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(5, 15000),
            identity_key: relay_key(5),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));

    assert!(
        wait_for_enrollment(setup.registry(), RelayId(5)).await,
        "the relay should enroll via its Hello",
    );
    let peer = registry::peer(setup.registry(), RelayId(5)).expect("relay 5 enrolled");
    assert_eq!(peer.relay_addr, "127.0.0.1:15000".parse().unwrap());
}

#[tokio::test]
async fn a_connection_that_never_sends_a_hello_is_dropped() {
    // A short handshake deadline so the test doesn't wait the production timeout.
    let (base_url, _reg) = serve_bare_coordinator(Duration::from_millis(150), LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // Connect, then send nothing. The coordinator must end the connection after
    // the deadline, having served it nothing at all.
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    expect_closed_unserved(&mut socket).await;
}

#[tokio::test]
async fn a_first_frame_that_is_not_a_hello_is_rejected_promptly() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // Enrollment comes first, so any other opening frame is a protocol violation
    // — whether it decodes to nothing this build knows or to a frame that would
    // be perfectly legitimate on an already-enrolled connection. A long handshake
    // deadline makes the point: if the coordinator merely waited for a Hello it
    // would hold the connection far past this test's bound.
    let result = RelayToCoordinator::Result(ResultNotice {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(1),
        slot: SlotId(0),
        external_id: None,
        external_ref: None,
        payload: vec![0x01, 0x02, 0x03],
        arrival_ms: 1,
        session_frame: None,
        slot_frame: None,
    });
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: vec![],
    };
    let first_frames = [
        // A well-formed frame of a type this build does not recognize at all.
        r#"{"type":"not_a_hello"}"#.to_owned(),
        // A frame that decodes to a known variant — legitimate after enroll.
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&heartbeat).unwrap(),
    ];

    let (base_url, _reg) = serve_bare_coordinator(Duration::from_secs(30), LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    for frame in first_frames {
        let (mut socket, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
        socket.send(Message::Text(frame.into())).await.unwrap();
        expect_closed_unserved(&mut socket).await;
    }
}

#[tokio::test]
async fn a_saturated_pending_hello_gate_refuses_further_connections() {
    // The gate bounds how many connections may sit between the upgrade and a
    // verified Hello at once — the window in which a caller has proven only that
    // it holds the bootstrap secret, not which relay it is. Shrunk to one permit
    // here; in production it sits well above a whole fleet reconnecting at once.
    let served = CoordinatorBuilder::new()
        .with_pending_hello_limit(1)
        .serve()
        .await;

    // Hold the only permit: a connection that has sent its Hello and been
    // challenged is demonstrably inside the gate, and never answers.
    let mut parked = connect_and_send_hello(&served.base_url, relay_hello(1, 14900)).await;
    let _nonce = expect_identity_challenge(&mut parked).await;

    // The next connection is refused outright rather than queued — a caller
    // waiting on the permit would be exactly the parked socket the gate exists
    // to bound.
    let (mut refused, _resp) = tokio_tungstenite::connect_async(served.ws_url())
        .await
        .unwrap();
    expect_close(&mut refused, CONTROL_CLOSE_TRY_AGAIN_LATER).await;
}

#[tokio::test]
async fn the_pending_hello_permit_is_released_once_an_identity_is_proven() {
    // The permit covers only the unauthenticated window: a relay that has proven
    // which relay it is drops out of the population the gate bounds, so a
    // long-lived enrolled connection must not occupy a slot. With a single
    // permit, the second relay can only enroll if the first released its one.
    let served = CoordinatorBuilder::new()
        .with_pending_hello_limit(1)
        .serve()
        .await;

    let mut first = connect_and_send_hello(&served.base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut first, &relay_key(1)).await;
    let _ = read_to_descriptors(&mut first).await;
    assert!(wait_for_enrollment(served.registry(), RelayId(1)).await);

    // `first` stays open throughout.
    let mut second = connect_and_send_hello(&served.base_url, relay_hello(2, 14901)).await;
    prove_identity(&mut second, &relay_key(2)).await;
    assert!(
        wait_for_enrollment(served.registry(), RelayId(2)).await,
        "an enrolled connection must not keep holding a pending-Hello permit",
    );
}

#[tokio::test]
async fn dropping_the_control_connection_deregisters_the_relay() {
    let (base_url, reg) = serve_bare_coordinator(api::HELLO_TIMEOUT, LIVENESS).await;

    // A relay holds its control connection open; its Hello enrolls it.
    let control = MeshControl::new(
        RelayId(7),
        &rally_point_relay::mesh::MeshState::default(),
        rally_point_relay::routing::Sessions::default(),
    );
    let handle = tokio::spawn(coordinator::client::run_descriptor_subscriber_with(
        coordinator::client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(7, 15007),
            identity_key: relay_key(7),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)), // effectively no heartbeat during the test
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));
    assert!(
        wait_for_enrollment(&reg, RelayId(7)).await,
        "the relay enrolls from its Hello",
    );

    // The relay goes away: dropping its connection deregisters it. This is the
    // clean-close path, well inside the (generous) liveness deadline, so the
    // removal is driven by the drop, not the timeout.
    handle.abort();
    assert!(
        wait_for_deregistration(&reg, RelayId(7)).await,
        "a dropped control connection deregisters the relay",
    );
}

// --- Protocol-version negotiation at the enroll Hello ---

#[tokio::test]
async fn a_relay_sharing_no_version_with_the_coordinator_is_refused_and_never_enrolled() {
    // Skew in either direction is the same refusal. An old relay speaking only a
    // version below MIN_SUPPORTED (no window field at all — an old build predates
    // it) and a new relay whose whole window sits above CURRENT (it dropped
    // support for our newest version) both leave no version this coordinator
    // could drive them at, so both are refused with the version close and neither
    // enters the registry — no session can be assigned to them and no descriptor
    // is ever pushed.
    let below_floor = RelayHello::new(
        RelayId(9),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14909)),
        ProtocolVersion(ProtocolVersion::MIN_SUPPORTED.0 - 1),
        vec![0xC9; 4],
    );
    let future = ProtocolVersion(ProtocolVersion::CURRENT.0 + 1);
    let above_current = RelayHello::new(
        RelayId(9),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14909)),
        future,
        vec![0xC9; 4],
    )
    .with_min_protocol(future);

    for (hello, why) in [
        (below_floor, "a relay below the supported floor"),
        (
            above_current,
            "a relay whose window sits entirely above CURRENT",
        ),
    ] {
        let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
        let mut socket = connect_and_send_hello(&base_url, hello).await;
        expect_version_refusal_close(&mut socket).await;
        assert!(
            registry::peer(setup.registry(), RelayId(9)).is_none(),
            "{why} is never enrolled",
        );
    }
}

#[tokio::test]
async fn a_newer_relay_with_an_overlapping_window_downgrades_and_enrolls() {
    // The downgrade rule: a relay one version ahead that still speaks CURRENT
    // (min_protocol = CURRENT) overlaps this coordinator's window, so it enrolls —
    // negotiated at CURRENT — receives its descriptor re-sync, and can be assigned
    // sessions.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let identity_key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

    let hello = RelayHello::new(
        RelayId(9),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14909)),
        ProtocolVersion(ProtocolVersion::CURRENT.0 + 1),
        cert_der,
    )
    .with_min_protocol(ProtocolVersion::CURRENT);
    let mut socket = connect_and_send_hello(&base_url, hello).await;

    // Negotiating at CURRENT reaches the proof-of-possession threshold, so the
    // challenge arrives before enrollment; answer it with a real signature.
    prove_identity(&mut socket, &identity_key).await;

    // The enrolled path proceeds (not a refusal close): the tenant-key lead is
    // followed by the initial descriptor re-sync.
    let _ = read_to_descriptors(&mut socket).await;

    assert!(
        wait_for_enrollment(setup.registry(), RelayId(9)).await,
        "the overlapping-window relay enrolls",
    );

    // The enrolled relay is assignable: a session create succeeds and homes on it.
    let session = create_one_slot_session(&setup);
    assert_eq!(
        setup.serving_relays(&TenantId(TENANT.to_owned()), session),
        vec![RelayId(9)]
    );
}
