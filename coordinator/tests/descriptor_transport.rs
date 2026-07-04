//! End-to-end coordinator→relay descriptor transport over the persistent control
//! connection: a relay holds a real WebSocket open to the coordinator, and the
//! descriptors the coordinator pushes drive that relay's Join source.
//!
//! This is the seam the two halves were built to meet at, exercised for real: a
//! bound coordinator WebSocket server and the relay's live `coordinator_client`.
//! It covers the behaviors that matter — the relay's Hello enrolls it, the initial
//! push on connect drives a `Join`, a session ending pushes a `Leave`, and a wrong
//! bootstrap secret drives nothing — none of which the per-side unit tests show.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::registry::RelayRegistry;
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, registry, session, tenant};
use rally_point_proto::control::{
    BufferBounds, DepartureNotice, PlayerHandoff, RelayHello, RelayToCoordinator, SessionRequest,
    TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator_client;
use rally_point_relay::mesh::MeshCommand;
use rally_point_relay::mesh_control::MeshControl;
use rally_point_relay::routing::SessionKey;
use tokio::sync::mpsc;
use tokio::time::timeout;

const TENANT: &str = "sb-test";

/// A generous liveness deadline for tests that don't exercise the timeout — long
/// enough that no enrolled relay is ever deregistered for going silent.
const LIVENESS: Duration = Duration::from_secs(30);

/// A departure drain that never receives anything: these descriptor-transport
/// tests don't exercise leave notification, so the subscriber's notifier arm
/// simply idles (the sender is dropped, so the arm disables itself).
fn no_departures() -> mpsc::UnboundedReceiver<DepartureNotice> {
    mpsc::unbounded_channel().1
}

fn session_key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    }
}

/// The relay's enroll `Hello` (id + a loopback address on `port`), the first frame
/// the subscriber sends on each connection.
fn relay_hello(id: u64, port: u16) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        vec![id as u8; 4],
    )
}

/// Polls the registry until `id` enrolls, up to a couple of seconds. Returns
/// whether it appeared — enrollment happens asynchronously once the relay's
/// subscriber connects and sends its Hello.
async fn wait_for_enrollment(reg: &RelayRegistry, id: RelayId) -> bool {
    for _ in 0..100 {
        if registry::peer(reg, id).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Polls the registry until `id` is gone, up to a couple of seconds. Returns
/// whether it disappeared — deregistration happens asynchronously once the relay's
/// control connection drops or its liveness deadline lapses.
async fn wait_for_deregistration(reg: &RelayRegistry, id: RelayId) -> bool {
    for _ in 0..100 {
        if registry::peer(reg, id).is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Serves a bare coordinator (empty registry/tenant, open auth) on an ephemeral
/// port with the given Hello-handshake and liveness deadlines, for tests that
/// drive the control endpoint directly rather than through a session. Returns the
/// base URL and a handle to the same registry so a test can observe enrollment and
/// deregistration.
async fn serve_bare_coordinator(
    hello_timeout: Duration,
    liveness_timeout: Duration,
) -> (String, RelayRegistry) {
    let reg = registry::new_registry();
    let setup = session::SessionSetup::new(reg.clone(), tenant::new_store());
    let app = api::router(CoordinatorState {
        setup,
        departures: notify::new_dedup(),
        control_auth: ControlAuth::Open,
        hello_timeout,
        liveness_timeout,
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

/// Stands up a coordinator with two relays + a tenant, creates a session, and
/// serves the API on an ephemeral port. Returns the base URL, the created session
/// id, and a handle to the same outbox (so a test can drive a later change).
async fn coordinator_with_session(
    bootstrap_secret: Option<&str>,
) -> (String, SessionId, SessionSetup) {
    let reg = registry::new_registry();
    for (id, port) in [(1u64, 14900u16), (2, 14901)] {
        registry::enroll(&reg, relay_hello(id, port));
    }
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId(TENANT.to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = session::SessionSetup::new(reg, tenants);

    let resp = session::create_session(
        &setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                },
            ],
            external_id: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();

    // Keep a handle to the outbox before the setup moves into the router state.
    let outbox = setup.clone();
    let control_auth = match bootstrap_secret {
        Some(secret) => ControlAuth::Secret(secret.to_owned()),
        None => ControlAuth::Open,
    };
    let app = api::router(CoordinatorState {
        setup,
        departures: notify::new_dedup(),
        control_auth,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: api::LIVENESS_TIMEOUT,
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), resp.session, outbox)
}

/// A relay's Join source with a link to peer 2 registered, plus the receiver
/// standing in for that link's driver so the test can observe what it was told.
fn relay_one_with_peer_link() -> (MeshControl, mpsc::UnboundedReceiver<MeshCommand>) {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, rx2) = mpsc::unbounded_channel::<MeshCommand>();
    control.register_link(RelayId(2), tx2);
    (control, rx2)
}

#[tokio::test]
async fn the_pushed_descriptor_drives_a_join_on_connect() {
    let secret = "bootstrap-secret";
    let (base_url, session, _outbox) = coordinator_with_session(Some(secret)).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    // The relay holds its control connection open with the matching secret.
    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(1, 14900),
        Some(secret.to_owned()),
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_secs(3600),
    ));

    // The coordinator pushes relay 1's current set on connect; it names peer 2,
    // so the link to peer 2 is told to join the session.
    let joined = timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("a Join should arrive over the control connection")
        .expect("the link sender should be live");
    assert_eq!(joined, MeshCommand::Join(session_key(session)));
}

#[tokio::test]
async fn ending_a_session_pushes_a_leave_over_the_open_connection() {
    let (base_url, session, outbox) = coordinator_with_session(None).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(1, 14900),
        None,
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_secs(3600),
    ));

    // The initial push joins the session.
    let joined = timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("a Join should arrive")
        .unwrap();
    assert_eq!(joined, MeshCommand::Join(session_key(session)));

    // The session ends: dropping relay 1's descriptor pushes the shrunk set down
    // the still-open connection, and the relay leaves the session.
    outbox
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), session);
    let left = timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("a Leave should be pushed when the session ends")
        .unwrap();
    assert_eq!(left, MeshCommand::Leave(session_key(session)));
}

#[tokio::test]
async fn a_wrong_bootstrap_secret_drives_no_join() {
    let (base_url, _session, _outbox) = coordinator_with_session(Some("right-secret")).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    // The relay presents the wrong secret, so every handshake is rejected (401)
    // and it keeps retrying without ever receiving a descriptor.
    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(1, 14900),
        Some("wrong-secret".to_owned()),
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_secs(3600),
    ));

    let result = timeout(Duration::from_millis(500), rx2.recv()).await;
    assert!(result.is_err(), "a rejected relay must never drive a Join");
}

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
    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(5, 15000),
        None,
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_secs(3600),
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
async fn dropping_the_control_connection_deregisters_the_relay() {
    let (base_url, reg) = serve_bare_coordinator(api::HELLO_TIMEOUT, LIVENESS).await;

    // A relay holds its control connection open; its Hello enrolls it.
    let control = MeshControl::new(
        RelayId(7),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let handle = tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(7, 15007),
        None,
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_secs(3600), // effectively no heartbeat during the test
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

#[tokio::test]
async fn a_silent_relay_is_deregistered_after_the_liveness_deadline() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A short liveness deadline so the test doesn't wait the production timeout.
    let (base_url, reg) =
        serve_bare_coordinator(api::HELLO_TIMEOUT, Duration::from_millis(300)).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll with a Hello, then go silent — never send a heartbeat.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(7, 15007))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    assert!(
        wait_for_enrollment(&reg, RelayId(7)).await,
        "the relay enrolls from its Hello",
    );

    // Past the deadline with no heartbeat, the coordinator deregisters the relay
    // and closes the connection.
    assert!(
        wait_for_deregistration(&reg, RelayId(7)).await,
        "a silent relay is deregistered after the liveness deadline",
    );
    let closed = timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = socket.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "the coordinator closes the timed-out connection",
    );
}

#[tokio::test]
async fn a_heartbeating_relay_stays_registered_past_the_liveness_deadline() {
    // The liveness deadline is short, but the relay heartbeats well inside it, so
    // the coordinator keeps resetting the deadline and never deregisters it. This
    // exercises the relay actually sending heartbeats over a live connection.
    let (base_url, reg) =
        serve_bare_coordinator(api::HELLO_TIMEOUT, Duration::from_millis(300)).await;
    let control = MeshControl::new(
        RelayId(7),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let _handle = tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        base_url,
        relay_hello(7, 15007),
        None,
        control,
        no_departures(),
        Duration::from_millis(50),
        Duration::from_millis(100), // heartbeat three times inside the 300ms deadline
    ));
    assert!(
        wait_for_enrollment(&reg, RelayId(7)).await,
        "the relay enrolls from its Hello",
    );

    // Wait well past the liveness deadline; the heartbeats keep the relay alive.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        registry::peer(&reg, RelayId(7)).is_some(),
        "a heartbeating relay must not be deregistered",
    );
}
