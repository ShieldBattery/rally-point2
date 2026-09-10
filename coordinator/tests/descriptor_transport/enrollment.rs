//! Enrollment at the control connection's start: a relay's Hello enrolls it into
//! the registry, a connection that never sends one (or sends the wrong first
//! frame) is dropped without waiting out the full handshake deadline, a dropped
//! connection deregisters the relay, and protocol-version negotiation refuses a
//! relay whose window shares nothing with the coordinator's while downgrading one
//! whose window merely overlaps.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::api;
use rally_point_coordinator::registry;
use rally_point_proto::control::{
    CoordinatorToRelay, RelayHello, RelayToCoordinator, ResultNotice, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator;
use rally_point_relay::mesh::control::MeshControl;
use rustls_pki_types::PrivateKeyDer;
use tokio::time::timeout;

use crate::common::{connect_and_send_hello, read_to_descriptors, relay_key};
use crate::helpers::*;

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
        std::sync::Arc::default(),
        std::sync::Arc::default(),
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
    use futures_util::StreamExt;

    // A short handshake deadline so the test doesn't wait the production timeout.
    let (base_url, _reg) = serve_bare_coordinator(Duration::from_millis(150), LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // Connect, then send nothing. The coordinator must drop the connection after
    // the deadline; without the timeout the stream would hang until the outer
    // bound and the test would fail.
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let closed = timeout(Duration::from_secs(2), async {
        // Drain until the coordinator closes (stream ends) or errors.
        while let Some(Ok(_)) = socket.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "the coordinator should drop a connection that never enrolls",
    );
}

#[tokio::test]
async fn a_non_hello_first_frame_is_rejected_promptly() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A long deadline: if the coordinator merely waited for a Hello it would hold
    // the connection for the full timeout, and the test's outer bound would trip.
    // The tightened handshake closes on a non-Hello first frame instead.
    let (base_url, _reg) = serve_bare_coordinator(Duration::from_secs(30), LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // A well-formed frame that is not a Hello (an unrecognized message type).
    socket
        .send(Message::Text(r#"{"type":"not_a_hello"}"#.into()))
        .await
        .unwrap();

    let closed = timeout(Duration::from_secs(2), async {
        // Drain until the coordinator closes (stream ends) or errors.
        while let Some(Ok(_)) = socket.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "a non-Hello first frame must be rejected without waiting out the deadline",
    );
}

#[tokio::test]
async fn a_result_first_frame_is_a_protocol_violation() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A well-formed result frame sent before any enroll Hello is a protocol
    // violation, exactly like a departure or desync would be: enrollment comes
    // first. The coordinator must close promptly rather than wait out the (long)
    // handshake deadline.
    let (base_url, _reg) = serve_bare_coordinator(Duration::from_secs(30), LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

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
    socket
        .send(Message::Text(
            serde_json::to_string(&result).unwrap().into(),
        ))
        .await
        .unwrap();

    let closed = timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = socket.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "a result frame before the enroll Hello must be rejected without waiting out the deadline",
    );
}

#[tokio::test]
async fn dropping_the_control_connection_deregisters_the_relay() {
    let (base_url, reg) = serve_bare_coordinator(api::HELLO_TIMEOUT, LIVENESS).await;

    // A relay holds its control connection open; its Hello enrolls it.
    let control = MeshControl::new(
        RelayId(7),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
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
async fn an_old_relay_below_min_supported_is_refused_and_never_enrolled() {
    // Old-relay/new-coordinator skew: a Hello speaking only a version below
    // MIN_SUPPORTED (no window field — an old build predates it) is refused with
    // the version close, and the relay never enters the registry, so no session
    // can ever be assigned to it and no descriptor is ever pushed.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;

    let hello = RelayHello::new(
        RelayId(9),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14909)),
        ProtocolVersion(ProtocolVersion::MIN_SUPPORTED.0 - 1),
        vec![0xC9; 4],
    );
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_version_refusal_close(&mut socket).await;

    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "a refused relay is never enrolled",
    );
}

#[tokio::test]
async fn a_future_only_relay_is_refused_the_same_way() {
    // New-relay/old-coordinator skew, seen from this coordinator: a relay whose
    // whole window sits above CURRENT (it dropped support for our newest version)
    // cannot be driven at any version — refused exactly like the old relay.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;

    let future = ProtocolVersion(ProtocolVersion::CURRENT.0 + 1);
    let hello = RelayHello::new(
        RelayId(9),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14909)),
        future,
        vec![0xC9; 4],
    )
    .with_min_protocol(future);
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_version_refusal_close(&mut socket).await;

    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "a refused relay is never enrolled",
    );
}

#[tokio::test]
async fn a_newer_relay_with_an_overlapping_window_downgrades_and_enrolls() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    // The downgrade rule: a relay one version ahead that still speaks CURRENT
    // (min_protocol = CURRENT) overlaps this coordinator's window, so it enrolls —
    // negotiated at CURRENT — receives its descriptor re-sync, and can be assigned
    // sessions. Negotiating at CURRENT means ENROLL_POP_MIN is reached, so unlike
    // most of this file's hellos (pinned below that threshold — see
    // `relay_hello`), this one needs a real certificate and must answer the
    // coordinator's proof-of-possession challenge before enrollment proceeds.
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

    // The challenge arrives before enrollment; answer it with a real signature.
    let challenge = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator challenges promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Text(text) = challenge else {
        panic!("expected an identity challenge, got {challenge:?}");
    };
    let CoordinatorToRelay::IdentityChallenge { nonce } = serde_json::from_str(&text).unwrap()
    else {
        panic!("expected an identity_challenge frame, got: {text}");
    };
    let signature = coordinator::client::sign_enroll_proof(&identity_key, &nonce)
        .expect("an ECDSA P-256 key always signs");
    let proof = serde_json::to_string(&RelayToCoordinator::IdentityProof { signature }).unwrap();
    {
        use futures_util::SinkExt;
        socket.send(Message::Text(proof.into())).await.unwrap();
    }

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
