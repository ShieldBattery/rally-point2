//! Fixtures shared by more than one topic module in this suite: minting relay
//! hellos, standing up a coordinator (bare, with a session, with regions, with a
//! chosen liveness deadline), the loop-source/outbound-queue stand-ins the real
//! relay client needs to run, and the down-frame readers the raw-socket tests
//! drive against. Anything used by exactly one topic file lives in that file
//! instead — this module is only for what crosses topic boundaries.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::RelayRegistry;
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, pair_rtts, registry, session, tenant};
use rally_point_proto::control::{
    BufferBounds, CoordinatorToRelay, MeshPeerIdentity, PlayerHandoff, RegionId, RelayHello,
    RelayPeer, RelayToCoordinator, SessionDescriptor, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::{
    CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION, ProtocolVersion,
};
use rally_point_relay::consensus::{self, RelayNotice};
use rally_point_relay::coordinator;
use rally_point_relay::coordinator::region_ping;
use rally_point_relay::mesh::MeshCommand;
use rally_point_relay::mesh::control::MeshControl;
use rally_point_relay::routing::SessionKey;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::common::{self, relay_cert};
use rally_point_relay::auth::SharedRegistry;

pub(crate) const TENANT: &str = "sb-test";

/// A generous liveness deadline for tests that don't exercise the timeout — long
/// enough that no enrolled relay is ever deregistered for going silent.
pub(crate) const LIVENESS: Duration = Duration::from_secs(30);

/// A notice drain that never receives anything: these descriptor-transport tests
/// don't exercise departure/desync notification, so the subscriber's notifier arm
/// simply idles (the sender is dropped, so the arm disables itself).
pub(crate) fn no_notices() -> mpsc::UnboundedReceiver<RelayNotice> {
    mpsc::unbounded_channel().1
}

/// A flight-shipment drain that never receives anything: these tests don't
/// exercise the flight-recording pipe, so the subscriber's flight arm idles (its
/// sender is dropped, disabling the arm).
pub(crate) fn no_flight()
-> mpsc::Receiver<rally_point_relay::observability::flight_recorder::FlightShipment> {
    mpsc::channel(1).1
}

/// A never-signaling drain receiver for subscriber spawns that don't exercise the
/// coordinated-drain seam (the sender end drops immediately, disabling the arm).
pub(crate) fn no_drain_rx() -> watch::Receiver<bool> {
    watch::channel(false).1
}

/// A throwaway drain-ack sender for the same subscribers — nothing awaits it.
pub(crate) fn no_drain_ack() -> watch::Sender<bool> {
    watch::channel(false).0
}

/// A throwaway control-connected sender for subscribers that don't assert on
/// the connection-state signal itself.
pub(crate) fn no_control_connected() -> watch::Sender<bool> {
    watch::channel(false).0
}

/// Apply targets with default (empty) stores and a throwaway drain-ack sender, over
/// the given Join source — the common case for these transport tests.
pub(crate) fn apply_targets(control: MeshControl) -> coordinator::client::ControlApplyTargets {
    coordinator::client::ControlApplyTargets {
        control,
        applied: coordinator::client::AppliedSessions::default(),
        fleet: coordinator::client::FleetMeshPeers::default(),
        verifying_keys: SharedRegistry::default(),
        region_targets: region_ping::RegionPingTargets::default(),
        drain_acked: no_drain_ack(),
    }
}

/// Empty outbound queues (no notices, no flight) with a fresh depth reporter — these
/// tests don't exercise the notice or flight pipes.
pub(crate) fn no_outbound() -> coordinator::client::OutboundQueues {
    coordinator::client::OutboundQueues::new(
        no_notices(),
        no_flight(),
        coordinator::client::ControlConnStats::new(),
    )
}

/// A heartbeat over an empty roster and RTT cache at the given interval.
pub(crate) fn heartbeat(interval: Duration) -> coordinator::client::HeartbeatConfig {
    coordinator::client::HeartbeatConfig {
        sources: coordinator::client::HeartbeatSources {
            sessions: std::sync::Arc::default(),
            decision_makers: std::sync::Arc::new(consensus::new_decision_makers()),
            region_rtt_cache: region_ping::RegionRttCache::default(),
            load_fence: rally_point_relay::coordinator::load_fence::LoadStateFence::new(),
        },
        interval,
    }
}

/// The transport tests' redial backoff: a fast ordinary delay and a longer
/// version-refusal delay.
pub(crate) fn backoff() -> coordinator::client::ReconnectBackoff {
    coordinator::client::ReconnectBackoff {
        ordinary: Duration::from_millis(50),
        version_refused: Duration::from_secs(60),
    }
}

pub(crate) fn session_key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    }
}

/// The relay's enroll `Hello` (id + a loopback address on `port`), the first frame
/// the subscriber sends on each connection.
///
/// Negotiates at `CURRENT` (which `MIN_SUPPORTED` tracks), so the coordinator
/// challenges the connection for enroll proof-of-possession — every accepted
/// control connection is challenged now. The certificate is this relay id's
/// stable self-signed identity ([`common::relay_cert`]); the matching key is
/// [`common::relay_key`]`(id)`. A `run_descriptor_subscriber_with` relay answers
/// the challenge with that key automatically; a test driving a raw control socket
/// answers it with [`common::prove_identity`] before the enrolled path proceeds.
pub(crate) fn relay_hello(id: u64, port: u16) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        relay_cert(id),
    )
}

/// Polls the registry until `id` enrolls, up to a couple of seconds. Returns
/// whether it appeared — enrollment happens asynchronously once the relay's
/// subscriber connects and sends its Hello.
pub(crate) async fn wait_for_enrollment(reg: &RelayRegistry, id: RelayId) -> bool {
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
pub(crate) async fn wait_for_deregistration(reg: &RelayRegistry, id: RelayId) -> bool {
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
pub(crate) async fn serve_bare_coordinator(
    hello_timeout: Duration,
    liveness_timeout: Duration,
) -> (String, RelayRegistry) {
    let reg = registry::new_registry();
    let setup = session::SessionSetup::new(reg.clone(), tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout,
        liveness_timeout,
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
    (format!("http://{addr}"), reg)
}

/// Stands up a coordinator with two relays + a tenant, creates a session, and
/// serves the API on an ephemeral port. Returns the base URL, the created session
/// id, and a handle to the same outbox (so a test can drive a later change).
pub(crate) async fn coordinator_with_session(
    bootstrap_secret: Option<&str>,
) -> (String, SessionId, SessionSetup) {
    let reg = registry::new_registry();
    registry::enroll(&reg, relay_hello(1, 14900));
    registry::enroll(
        &reg,
        relay_hello(2, 14901).with_region(RegionId("region-b".to_owned())),
    );
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
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    // Homes slot 1 on relay 2 (the only relay enrolled in
                    // region-b) so both relays serve and mesh — the topology
                    // these transport tests exercise.
                    region: Some(RegionId("region-b".to_owned())),
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // Keep a handle to the outbox before the setup moves into the router state.
    let outbox = setup.clone();
    let lifecycle = Lifecycle::new(setup.clone());
    let control_auth = match bootstrap_secret {
        Some(secret) => ControlAuth::Secret(secret.to_owned()),
        None => ControlAuth::Open,
    };
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: api::LIVENESS_TIMEOUT,
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

    (format!("http://{addr}"), resp.session, outbox)
}

/// A relay's Join source with a link to peer 2 registered, plus the receiver
/// standing in for that link's driver so the test can observe what it was told.
pub(crate) fn relay_one_with_peer_link() -> (MeshControl, mpsc::UnboundedReceiver<MeshCommand>) {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, rx2) = mpsc::unbounded_channel::<MeshCommand>();
    let _ = control.register_link(RelayId(2), 1, tx2);
    (control, rx2)
}

/// Serves a bare coordinator (empty registry/tenant, given control auth) on an
/// ephemeral port and returns its base URL plus a handle to its descriptor outbox,
/// so a test can enroll a relay against it and then drive descriptor changes
/// directly to exercise the writer's steady-state push (full set vs. delta).
pub(crate) async fn serve_coordinator_returning_setup(
    control_auth: ControlAuth,
) -> (String, SessionSetup) {
    let reg = registry::new_registry();
    let setup = session::SessionSetup::new(reg, tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let outbox = setup.clone();
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth,
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
    (format!("http://{addr}"), outbox)
}

/// A session descriptor for `session` meshing the given peer relays, for driving
/// the descriptor outbox directly.
pub(crate) fn a_descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
        peers: peers
            .iter()
            .map(|&id| RelayPeer {
                relay_id: RelayId(id),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                cert_der: vec![id as u8; 4],
                relay_addrs: vec![],
            })
            .collect(),
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    }
}

/// A relay `Hello` (id + loopback address) advertising the single version
/// `protocol` — no `min_protocol`, so its negotiation window is exactly that one
/// version. Lets a test negotiate a pre-delta version to exercise the writer's
/// full-set fallback.
pub(crate) fn relay_hello_at(id: u64, port: u16, protocol: ProtocolVersion) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        protocol,
        relay_cert(id),
    )
}

/// Reads the coordinator's next control frame, decoding it. Panics on a close or a
/// non-text frame.
pub(crate) async fn next_control_frame(socket: &mut common::ControlSocket) -> CoordinatorToRelay {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator sends a frame promptly")
        .expect("a frame arrives before the stream ends")
        .unwrap();
    match frame {
        Message::Text(text) => {
            serde_json::from_str(&text).expect("a coordinator control frame decodes")
        }
        Message::Close(f) => panic!("expected a control frame, got a close: {f:?}"),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

/// Reads down-frames until a descriptor push arrives — either a full
/// [`CoordinatorToRelay::Descriptors`] set or a [`CoordinatorToRelay::DescriptorDelta`]
/// — returning it. Skips the connect-time `tenant_keys`/`region_beacons` lead and any
/// `mesh_peers` push, so a test asserts only on the descriptor transport itself.
pub(crate) async fn read_to_descriptor_update(
    socket: &mut common::ControlSocket,
) -> CoordinatorToRelay {
    loop {
        match next_control_frame(socket).await {
            frame @ (CoordinatorToRelay::Descriptors { .. }
            | CoordinatorToRelay::DescriptorDelta { .. }) => return frame,
            _ => continue,
        }
    }
}

/// Whether no descriptor push (full set or delta) arrives within `dur`. A
/// `mesh_peers` or other non-descriptor frame in the window is skipped, not counted;
/// only a descriptor push makes this return `false`.
pub(crate) async fn no_descriptor_update_within(
    socket: &mut common::ControlSocket,
    dur: Duration,
) -> bool {
    timeout(dur, read_to_descriptor_update(socket))
        .await
        .is_err()
}

/// Sends a [`RelayToCoordinator::Draining`] up the socket, asking the coordinator to
/// run its drain exchange (a full descriptor set, then a `DrainAck`).
pub(crate) async fn send_draining(socket: &mut common::ControlSocket) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let frame = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
}

/// Reads the coordinator's next frame and asserts it is the drain acknowledgement.
pub(crate) async fn expect_drain_ack(socket: &mut common::ControlSocket) {
    match next_control_frame(socket).await {
        CoordinatorToRelay::DrainAck => {}
        other => panic!("expected a DrainAck, got {other:?}"),
    }
}

/// Serves a coordinator with a tenant enrolled and the given relays pre-enrolled,
/// on an ephemeral port (open auth, production handshake/liveness deadlines).
/// Returns the base URL and a handle to the same `SessionSetup` so a drain test can
/// create sessions and observe registry availability. Unlike
/// [`serve_bare_coordinator`], this exposes the setup and enrolls a tenant, which a
/// drain test needs to prove the assignment path excludes the drained relay.
pub(crate) async fn serve_coordinator_exposing_setup(
    pre_enrolled: &[(u64, u16)],
) -> (String, SessionSetup) {
    serve_coordinator_with_liveness(pre_enrolled, LIVENESS).await
}

/// Like [`serve_coordinator_exposing_setup`] but with a caller-chosen liveness
/// deadline, for tests that must observe a timeout-driven drop without waiting the
/// production window.
pub(crate) async fn serve_coordinator_with_liveness(
    pre_enrolled: &[(u64, u16)],
    liveness_timeout: Duration,
) -> (String, SessionSetup) {
    let reg = registry::new_registry();
    for &(id, port) in pre_enrolled {
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
    let handle = setup.clone();
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout,
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
    (format!("http://{addr}"), handle)
}

/// Creates a single-slot session for the test tenant on `setup`, returning its id.
pub(crate) fn create_one_slot_session(setup: &SessionSetup) -> SessionId {
    session::create_session(
        setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
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

/// Reads down-frames from `socket` until a [`CoordinatorToRelay::DrainAck`] arrives,
/// returning the descriptor set carried by the last [`CoordinatorToRelay::Descriptors`]
/// seen before it — the set-before-ack the coordinator pushes. Panics if the ack
/// never arrives within a few seconds.
pub(crate) async fn read_until_drain_ack(
    socket: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
) -> Vec<SessionDescriptor> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let mut last: Vec<SessionDescriptor> = Vec::new();
    timeout(Duration::from_secs(5), async {
        while let Some(Ok(message)) = socket.next().await {
            if let Message::Text(text) = message {
                match serde_json::from_str::<CoordinatorToRelay>(&text).unwrap() {
                    CoordinatorToRelay::Descriptors { descriptors, .. } => last = descriptors,
                    CoordinatorToRelay::DrainAck => return,
                    _ => {}
                }
            }
        }
        panic!("the connection closed before a DrainAck arrived");
    })
    .await
    .expect("a DrainAck should arrive after the descriptor set");
    last
}

/// Reads the coordinator's answer to an incompatible Hello and asserts it is the
/// version-refusal close — code [`CONTROL_CLOSE_PROTOCOL_MISMATCH`] with a reason
/// naming both windows — arriving as the FIRST frame (never a descriptor push).
pub(crate) async fn expect_version_refusal_close(
    socket: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
) {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let answer = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers the incompatible Hello promptly")
        .expect("a frame arrives before the stream ends")
        .unwrap();
    let Message::Close(Some(frame)) = answer else {
        panic!("expected a version-refusal close frame, got {answer:?}");
    };
    assert_eq!(u16::from(frame.code), CONTROL_CLOSE_PROTOCOL_MISMATCH);
    assert!(
        frame.reason.contains("no common protocol version"),
        "the reason names the mismatch: {}",
        frame.reason,
    );
    assert!(
        frame.reason.contains(&format!(
            "local supports {}",
            ProtocolVersion::MIN_SUPPORTED
        )),
        "the reason names the coordinator's window: {}",
        frame.reason,
    );
    assert!(
        frame.reason.contains("peer supports"),
        "the reason names the relay's window: {}",
        frame.reason,
    );
}

/// Serves a coordinator with the given region config (and the test tenant
/// enrolled, no relays pre-enrolled), returning the base URL and a setup handle so
/// a test can inspect the registry after an enroll attempt.
pub(crate) async fn serve_coordinator_with_regions(
    regions: RegionsConfig,
) -> (String, SessionSetup) {
    let reg = registry::new_registry();
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId(TENANT.to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = session::SessionSetup::new(reg, tenants);
    let handle = setup.clone();
    let lifecycle = Lifecycle::new(setup.clone());
    let app = api::router(CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: LIVENESS,
        regions,
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
    (format!("http://{addr}"), handle)
}

/// A two-region config (`region-a`, `region-b`) for the enroll-validation tests.
pub(crate) fn two_region_config() -> RegionsConfig {
    RegionsConfig::from_json(
        r#"{"regions": [
            {"id": "region-a", "display_name": "Region A", "beacon": "a:20000", "fallback": "a:443"},
            {"id": "region-b", "display_name": "Region B", "beacon": "b:20000", "fallback": "b:443"}
        ]}"#,
    )
    .unwrap()
}

/// Reads the coordinator's answer to a Hello tagged with an unknown region and
/// asserts it is the unknown-region close — code [`CONTROL_CLOSE_UNKNOWN_REGION`]
/// with a reason naming the offered region — arriving as the FIRST frame.
pub(crate) async fn expect_unknown_region_close(
    socket: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    offered_region: &str,
) {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let answer = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers the tagged Hello promptly")
        .expect("a frame arrives before the stream ends")
        .unwrap();
    let Message::Close(Some(frame)) = answer else {
        panic!("expected an unknown-region close frame, got {answer:?}");
    };
    assert_eq!(u16::from(frame.code), CONTROL_CLOSE_UNKNOWN_REGION);
    assert!(
        frame.reason.contains(offered_region),
        "the reason names the offered region: {}",
        frame.reason,
    );
}

/// Reads down-frames from `socket` until a [`CoordinatorToRelay::MeshPeers`] frame
/// carrying exactly `want` peers arrives, returning its peer set. The coordinator
/// interleaves descriptor and mesh-peer pushes down the one connection, so this
/// skips every frame that is not a mesh-peer set of the wanted size.
pub(crate) async fn read_mesh_peers_until(
    socket: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    want: usize,
) -> Vec<MeshPeerIdentity> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    timeout(Duration::from_secs(5), async {
        while let Some(Ok(message)) = socket.next().await {
            if let Message::Text(text) = message
                && let CoordinatorToRelay::MeshPeers { peers } =
                    serde_json::from_str::<CoordinatorToRelay>(&text).unwrap()
                && peers.len() == want
            {
                return peers;
            }
        }
        panic!("the connection closed before a MeshPeers set of the wanted size arrived");
    })
    .await
    .expect("a MeshPeers set of the wanted size should arrive")
}

/// Wall clock as unix epoch milliseconds — the same base both the coordinator's
/// staging stamp and this in-process test read.
pub(crate) fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Fetches `GET {base_url}/regions` over a throwaway HTTP/1.1 connection and returns
/// the parsed JSON body. A raw request keeps these tests free of an HTTP-client
/// dependency; `Connection: close` lets the read run to EOF.
pub(crate) async fn get_regions_json(base_url: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = base_url
        .strip_prefix("http://")
        .expect("an http:// base url");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("GET /regions HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).expect("the response is UTF-8");
    let (_headers, body) = text
        .split_once("\r\n\r\n")
        .expect("the response separates headers from the body");
    serde_json::from_str(body).expect("the body is JSON")
}
