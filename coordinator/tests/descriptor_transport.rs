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
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::RelayRegistry;
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, pair_rtts, registry, session, tenant};
use rally_point_proto::control::{
    BufferBounds, CoordinatorToRelay, DescriptorKey, MeshPeerIdentity, PlayerHandoff,
    RegionBeaconTarget, RegionId, RegionRttReport, RelayHello, RelayPeer, RelayToCoordinator,
    ResultNotice, SessionDescriptor, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::{
    CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION, ProtocolVersion,
};
use rally_point_relay::consensus::RelayNotice;
use rally_point_relay::coordinator_client;
use rally_point_relay::mesh::MeshCommand;
use rally_point_relay::mesh_control::MeshControl;
use rally_point_relay::region_ping;
use rally_point_relay::routing::SessionKey;
use rustls_pki_types::PrivateKeyDer;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

mod common;
use common::{
    connect_and_send_hello, expect_region_beacons, expect_tenant_keys, prove_identity,
    read_to_descriptors, relay_cert, relay_key,
};
use rally_point_relay::auth::SharedRegistry;

const TENANT: &str = "sb-test";

/// A generous liveness deadline for tests that don't exercise the timeout — long
/// enough that no enrolled relay is ever deregistered for going silent.
const LIVENESS: Duration = Duration::from_secs(30);

/// A notice drain that never receives anything: these descriptor-transport tests
/// don't exercise departure/desync notification, so the subscriber's notifier arm
/// simply idles (the sender is dropped, so the arm disables itself).
fn no_notices() -> mpsc::UnboundedReceiver<RelayNotice> {
    mpsc::unbounded_channel().1
}

/// A flight-shipment drain that never receives anything: these tests don't
/// exercise the flight-recording pipe, so the subscriber's flight arm idles (its
/// sender is dropped, disabling the arm).
fn no_flight() -> mpsc::Receiver<rally_point_relay::flight_recorder::FlightShipment> {
    mpsc::channel(1).1
}

/// A never-signaling drain receiver for subscriber spawns that don't exercise the
/// coordinated-drain seam (the sender end drops immediately, disabling the arm).
fn no_drain_rx() -> watch::Receiver<bool> {
    watch::channel(false).1
}

/// A throwaway drain-ack sender for the same subscribers — nothing awaits it.
fn no_drain_ack() -> watch::Sender<bool> {
    watch::channel(false).0
}

/// A throwaway control-connected sender for subscribers that don't assert on
/// the connection-state signal itself.
fn no_control_connected() -> watch::Sender<bool> {
    watch::channel(false).0
}

/// Apply targets with default (empty) stores and a throwaway drain-ack sender, over
/// the given Join source — the common case for these transport tests.
fn apply_targets(control: MeshControl) -> coordinator_client::ControlApplyTargets {
    coordinator_client::ControlApplyTargets {
        control,
        applied: coordinator_client::AppliedSessions::default(),
        fleet: coordinator_client::FleetMeshPeers::default(),
        verifying_keys: SharedRegistry::default(),
        region_targets: region_ping::RegionPingTargets::default(),
        drain_acked: no_drain_ack(),
    }
}

/// Empty outbound queues (no notices, no flight) with a fresh depth reporter — these
/// tests don't exercise the notice or flight pipes.
fn no_outbound() -> coordinator_client::OutboundQueues {
    coordinator_client::OutboundQueues::new(
        no_notices(),
        no_flight(),
        coordinator_client::ControlConnStats::new(),
    )
}

/// A heartbeat over an empty roster and RTT cache at the given interval.
fn heartbeat(interval: Duration) -> coordinator_client::HeartbeatConfig {
    coordinator_client::HeartbeatConfig {
        sessions: std::sync::Arc::default(),
        region_rtt_cache: region_ping::RegionRttCache::default(),
        interval,
    }
}

/// The transport tests' redial backoff: a fast ordinary delay and a longer
/// version-refusal delay.
fn backoff() -> coordinator_client::ReconnectBackoff {
    coordinator_client::ReconnectBackoff {
        ordinary: Duration::from_millis(50),
        version_refused: Duration::from_secs(60),
    }
}

fn session_key(session: SessionId) -> SessionKey {
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
fn relay_hello(id: u64, port: u16) -> RelayHello {
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
async fn coordinator_with_session(
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

/// Serves a bare coordinator (empty registry/tenant, given control auth) on an
/// ephemeral port and returns its base URL plus a handle to its descriptor outbox,
/// so a test can enroll a relay against it and then drive descriptor changes
/// directly to exercise the writer's steady-state push (full set vs. delta).
async fn serve_coordinator_returning_setup(control_auth: ControlAuth) -> (String, SessionSetup) {
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
fn a_descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
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
    }
}

/// A relay `Hello` (id + loopback address) advertising the single version
/// `protocol` — no `min_protocol`, so its negotiation window is exactly that one
/// version. Lets a test negotiate a pre-delta version to exercise the writer's
/// full-set fallback.
fn relay_hello_at(id: u64, port: u16, protocol: ProtocolVersion) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        protocol,
        relay_cert(id),
    )
}

/// Reads the coordinator's next control frame, decoding it. Panics on a close or a
/// non-text frame.
async fn next_control_frame(socket: &mut common::ControlSocket) -> CoordinatorToRelay {
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
async fn read_to_descriptor_update(socket: &mut common::ControlSocket) -> CoordinatorToRelay {
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
async fn no_descriptor_update_within(socket: &mut common::ControlSocket, dur: Duration) -> bool {
    timeout(dur, read_to_descriptor_update(socket))
        .await
        .is_err()
}

/// Sends a [`RelayToCoordinator::Draining`] up the socket, asking the coordinator to
/// run its drain exchange (a full descriptor set, then a `DrainAck`).
async fn send_draining(socket: &mut common::ControlSocket) {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let frame = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
}

/// Reads the coordinator's next frame and asserts it is the drain acknowledgement.
async fn expect_drain_ack(socket: &mut common::ControlSocket) {
    match next_control_frame(socket).await {
        CoordinatorToRelay::DrainAck => {}
        other => panic!("expected a DrainAck, got {other:?}"),
    }
}

#[tokio::test]
async fn a_delta_capable_relay_gets_a_full_set_then_deltas() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    // The connect-time re-sync is always the full set (here empty), whatever the
    // negotiated version — it seeds the baseline every later delta diffs against.
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert!(descriptors.is_empty()),
        other => panic!("expected a full descriptor set on connect, got {other:?}"),
    }

    // An add: one upsert, no removals.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(
                upserts.iter().map(|d| d.session).collect::<Vec<_>>(),
                vec![SessionId(1)],
            );
            assert!(removals.is_empty());
        }
        other => panic!("expected an add delta, got {other:?}"),
    }

    // A second add is likewise carried as just its own upsert, not the whole set.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(
                upserts.iter().map(|d| d.session).collect::<Vec<_>>(),
                vec![SessionId(2)],
            );
            assert!(removals.is_empty());
        }
        other => panic!("expected a second add delta, got {other:?}"),
    }

    // An in-place mutation: session 1's peers change. The diff is by value, so the
    // unchanged key still surfaces as an upsert carrying the new value.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[9]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(upserts.len(), 1);
            assert_eq!(upserts[0].session, SessionId(1));
            assert_eq!(upserts[0].peers[0].relay_id, RelayId(9));
            assert!(removals.is_empty());
        }
        other => panic!("expected an in-place mutation delta, got {other:?}"),
    }

    // A removal: one removal, no upserts.
    setup
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(2));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert!(upserts.is_empty());
            assert_eq!(
                removals,
                vec![DescriptorKey {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(2),
                }],
            );
        }
        other => panic!("expected a removal delta, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pre_delta_relay_receives_full_sets_not_deltas() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    // A relay negotiating only the supported floor — below the delta threshold, so it
    // would decode a delta as an unknown frame and drift.
    let mut socket = connect_and_send_hello(
        &base_url,
        relay_hello_at(1, 14900, ProtocolVersion::MIN_SUPPORTED),
    )
    .await;
    prove_identity(&mut socket, &relay_key(1)).await;

    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert!(descriptors.is_empty()),
        other => panic!("expected a full set on connect, got {other:?}"),
    }

    // Every steady-state change is the whole current set, never a delta.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1)],
        ),
        other => panic!("a pre-delta relay must receive a full set, got {other:?}"),
    }

    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1), SessionId(2)],
            "the whole current set, not just the change",
        ),
        other => panic!("a pre-delta relay must receive a full set, got {other:?}"),
    }
}

#[tokio::test]
async fn the_drain_exchange_pushes_a_full_set_and_later_deltas_stay_correct() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    // Full set on connect, then two adds delivered as deltas.
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    let _ = read_to_descriptor_update(&mut socket).await;

    // The relay requests a drain: the coordinator pushes the whole current set (a full
    // set, not a delta), then a DrainAck.
    send_draining(&mut socket).await;
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1), SessionId(2)],
            "the drain exchange pushes the whole set",
        ),
        other => panic!("the drain exchange must push a full set, got {other:?}"),
    }
    expect_drain_ack(&mut socket).await;

    // Steady state resumes as deltas, correct against the baseline the drain refreshed
    // from its full set: removing session 1 yields a removal-only delta.
    setup
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(1));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert!(upserts.is_empty());
            assert_eq!(
                removals,
                vec![DescriptorKey {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(1),
                }],
            );
        }
        other => panic!("post-drain steady state must resume deltas, got {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_diff_wake_sends_no_frame() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    // The connect-time full set, then a real add to establish the baseline.
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta { upserts, .. } => assert_eq!(upserts.len(), 1),
        other => panic!("expected the baseline-establishing delta, got {other:?}"),
    }

    // Add then immediately remove the same session, with no await between the two
    // synchronous outbox calls: on the current-thread test runtime the writer cannot
    // run between them, so it wakes once to a set identical to what it last sent — an
    // empty diff — and must send nothing.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    setup
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(2));
    assert!(
        no_descriptor_update_within(&mut socket, Duration::from_millis(300)).await,
        "an empty-diff wake must send no frame",
    );

    // A subsequent real change still produces a delta — the writer resumed normally.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(3, &[4]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(
                upserts.iter().map(|d| d.session).collect::<Vec<_>>(),
                vec![SessionId(3)],
            );
            assert!(removals.is_empty());
        }
        other => panic!("expected a delta for the real change, got {other:?}"),
    }
}

#[tokio::test]
async fn churn_through_the_real_client_converges_to_the_watch_set() {
    // The full delta round trip end to end: the real coordinator writer emits deltas
    // and the real relay client applies them. A burst of adds and removals must leave
    // the relay's meshed sessions equal to the coordinator's final watch set.
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        coordinator_client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));

    // Churn: add sessions 1..=6 (each meshing peer 2), then remove the even ones.
    for s in 1..=6u64 {
        setup
            .descriptors()
            .record(RelayId(1), a_descriptor(s, &[2]));
    }
    for s in [2u64, 4, 6] {
        setup
            .descriptors()
            .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(s));
    }

    // The relay's meshed sessions (the net of the Join/Leave stream on peer 2's link)
    // converge to the odd sessions — exactly the coordinator's final watch set.
    let want: std::collections::HashSet<SessionKey> = [1u64, 3, 5]
        .into_iter()
        .map(|s| session_key(SessionId(s)))
        .collect();
    let mut net: std::collections::HashSet<SessionKey> = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(200), rx2.recv()).await {
            Ok(Some(MeshCommand::Join(k))) => {
                net.insert(k);
            }
            Ok(Some(MeshCommand::Leave(k))) => {
                net.remove(&k);
            }
            Ok(None) => break,
            Err(_) => {
                if net == want {
                    break;
                }
            }
        }
    }
    assert_eq!(
        net, want,
        "the relay's meshed sessions converge to the coordinator's watch set",
    );
}

#[tokio::test]
async fn the_pushed_descriptor_drives_a_join_on_connect() {
    let secret = "bootstrap-secret";
    let (base_url, session, _outbox) = coordinator_with_session(Some(secret)).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    // The relay holds its control connection open with the matching secret.
    tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        coordinator_client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: Some(secret.to_owned()),
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
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
        coordinator_client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
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
        coordinator_client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: Some("wrong-secret".to_owned()),
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
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
        coordinator_client::EnrollConfig {
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
    let handle = tokio::spawn(coordinator_client::run_descriptor_subscriber_with(
        coordinator_client::EnrollConfig {
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

#[tokio::test]
async fn a_silent_relay_is_deregistered_after_the_liveness_deadline() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A short liveness deadline so the test doesn't wait the production timeout.
    let (base_url, reg) =
        serve_bare_coordinator(api::HELLO_TIMEOUT, Duration::from_millis(300)).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll with a Hello and prove possession, then go silent — never send a
    // heartbeat.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(7, 15007))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(7)).await;
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

/// Serves a coordinator with a tenant enrolled and the given relays pre-enrolled,
/// on an ephemeral port (open auth, production handshake/liveness deadlines).
/// Returns the base URL and a handle to the same `SessionSetup` so a drain test can
/// create sessions and observe registry availability. Unlike
/// [`serve_bare_coordinator`], this exposes the setup and enrolls a tenant, which a
/// drain test needs to prove the assignment path excludes the drained relay.
async fn serve_coordinator_exposing_setup(pre_enrolled: &[(u64, u16)]) -> (String, SessionSetup) {
    serve_coordinator_with_liveness(pre_enrolled, LIVENESS).await
}

/// Like [`serve_coordinator_exposing_setup`] but with a caller-chosen liveness
/// deadline, for tests that must observe a timeout-driven drop without waiting the
/// production window.
async fn serve_coordinator_with_liveness(
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
fn create_one_slot_session(setup: &SessionSetup) -> SessionId {
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
async fn read_until_drain_ack(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
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

#[tokio::test]
async fn a_draining_relay_gets_its_set_then_an_ack_and_is_excluded_from_new_sessions() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // One relay, enrolled over the socket; it serves one session, then drains.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll relay 1 via its Hello (proving possession), then give it a session so
    // its descriptor set is non-empty at drain time.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(1)).await,
        "the relay enrolls from its Hello",
    );
    let session = create_one_slot_session(&setup);

    // The relay asks to drain.
    let draining = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(draining.into())).await.unwrap();

    // It receives its current descriptor set (naming the session) and then a
    // DrainAck — set before ack.
    let set = read_until_drain_ack(&mut socket).await;
    assert!(
        set.iter().any(|d| d.session == session),
        "the descriptor set pushed before the ack names the relay's session",
    );

    // The coordinator has marked it draining: a new session can no longer be
    // assigned (it was the only relay), and the registry reports it unavailable.
    assert!(!registry::is_available(setup.registry(), RelayId(1)));
    let err = session::create_session(
        &setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xCC; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap_err();
    assert_eq!(err, registry::SessionSetupError::NoRelaysAvailable);
}

#[tokio::test]
async fn a_draining_relay_is_skipped_and_a_create_picks_the_other_relay() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // Relay 2 is pre-enrolled; relay 1 enrolls over the socket, then drains. A
    // create after the drain homes on the still-available relay 2.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[(2, 14901)]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    let draining = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(draining.into())).await.unwrap();
    // Its set is empty (it serves no session), and the ack still arrives after it.
    let set = read_until_drain_ack(&mut socket).await;
    assert!(
        set.is_empty(),
        "a relay serving nothing drains with an empty set"
    );

    // A fresh session homes on relay 2 — relay 1 (lower id, normally the primary) is
    // draining and excluded from the pick.
    let resp = session::create_session(
        &setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xDD; 32]),
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
    .response;
    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(2),
        "a create skips the draining relay and homes on the available one",
    );
}

// --- Protocol-version negotiation at the enroll Hello ---

/// Reads the coordinator's answer to an incompatible Hello and asserts it is the
/// version-refusal close — code [`CONTROL_CLOSE_PROTOCOL_MISMATCH`] with a reason
/// naming both windows — arriving as the FIRST frame (never a descriptor push).
async fn expect_version_refusal_close(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
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
    let signature = coordinator_client::sign_enroll_proof(&identity_key, &nonce)
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

// --- Region validation at the enroll Hello ---

/// Serves a coordinator with the given region config (and the test tenant
/// enrolled, no relays pre-enrolled), returning the base URL and a setup handle so
/// a test can inspect the registry after an enroll attempt.
async fn serve_coordinator_with_regions(regions: RegionsConfig) -> (String, SessionSetup) {
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
fn two_region_config() -> RegionsConfig {
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
async fn expect_unknown_region_close(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
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

#[tokio::test]
async fn a_region_less_hello_enrolls_even_with_a_region_config() {
    // An untagged relay always enrolls — regions are for tagged relays; a
    // region-less hello is the dev/loopback and region-blind-fallback path.
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(9, 14909)).await;
    // Region validation passes (untagged), so the coordinator challenges before
    // enrolling; answer it, then the enrolled path proceeds — the tenant-key lead
    // followed by the descriptor re-sync, not a close.
    prove_identity(&mut socket, &relay_key(9)).await;
    let _ = read_to_descriptors(&mut socket).await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(9)).await,
        "an untagged relay enrolls",
    );
}

#[tokio::test]
async fn a_valid_region_enrolls_and_lands_in_the_registry_entry() {
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    // A configured region passes validation, so the coordinator challenges before
    // enrolling; answer it, then drain the initial descriptor re-sync.
    prove_identity(&mut socket, &relay_key(9)).await;
    let _ = timeout(Duration::from_secs(5), {
        use futures_util::StreamExt;
        socket.next()
    })
    .await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(9)).await,
        "a relay in a configured region enrolls",
    );
    let entry = registry::entry(setup.registry(), RelayId(9)).expect("relay 9 enrolled");
    assert_eq!(
        entry.region,
        Some(RegionId("region-a".to_owned())),
        "the registry entry carries the enrolled region",
    );
}

#[tokio::test]
async fn an_unknown_region_is_refused_and_never_enrolled() {
    // A typo'd region tag is refused rather than silently serving nobody.
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-z".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_unknown_region_close(&mut socket, "region-z").await;
    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "a relay tagged with an unknown region is never enrolled",
    );
}

#[tokio::test]
async fn any_region_is_refused_when_no_regions_are_configured() {
    // With no region config at all, a region tag is unrecognizable, so a tagged
    // relay is refused — the empty-config case of the unknown-region rule.
    let (base_url, setup) = serve_coordinator_with_regions(RegionsConfig::default()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_unknown_region_close(&mut socket, "region-a").await;
    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "with no region config a tagged relay is never enrolled",
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
        coordinator_client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(7, 15007),
            identity_key: relay_key(7),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_millis(100)), // heartbeat three times inside the 300ms deadline
        no_drain_rx(),
        no_control_connected(),
        backoff(),
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

// --- Fleet mesh-peer distribution ---

/// Reads down-frames from `socket` until a [`CoordinatorToRelay::MeshPeers`] frame
/// carrying exactly `want` peers arrives, returning its peer set. The coordinator
/// interleaves descriptor and mesh-peer pushes down the one connection, so this
/// skips every frame that is not a mesh-peer set of the wanted size.
async fn read_mesh_peers_until(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
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

#[tokio::test]
async fn the_fleet_mesh_peer_set_is_pushed_and_tracks_membership() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (base_url, reg) = serve_bare_coordinator(api::HELLO_TIMEOUT, LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // Relay 1 opens its control connection, proves possession, and enrolls.
    let (mut socket1, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let hello1 = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket1.send(Message::Text(hello1.into())).await.unwrap();
    prove_identity(&mut socket1, &relay_key(1)).await;
    assert!(wait_for_enrollment(&reg, RelayId(1)).await);

    // On connect it is pushed the fleet set — just itself so far — carrying the
    // fingerprint the coordinator recorded for it at enroll.
    let solo = read_mesh_peers_until(&mut socket1, 1).await;
    assert_eq!(solo, registry::mesh_peers(&reg));
    assert_eq!(solo[0].relay_id, RelayId(1));

    // Relay 2 enrolls over its own connection.
    let (mut socket2, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let hello2 = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(2, 14901))).unwrap();
    socket2.send(Message::Text(hello2.into())).await.unwrap();
    prove_identity(&mut socket2, &relay_key(2)).await;
    assert!(wait_for_enrollment(&reg, RelayId(2)).await);

    // The membership change pushes an updated set to BOTH connections, each naming
    // both relays with the coordinator's recorded fingerprints.
    let expected = registry::mesh_peers(&reg);
    assert_eq!(expected.len(), 2);
    let on_one = read_mesh_peers_until(&mut socket1, 2).await;
    assert_eq!(
        on_one, expected,
        "the earlier relay is pushed the grown set"
    );
    let on_two = read_mesh_peers_until(&mut socket2, 2).await;
    assert_eq!(
        on_two, expected,
        "the newly-connected relay receives the full set on connect",
    );
    // The two relays carry distinct fingerprints — they enrolled distinct certs.
    assert_ne!(on_one[0].cert_sha256, on_one[1].cert_sha256);

    // Relay 2 goes away: its deregistration shrinks the set pushed to relay 1.
    drop(socket2);
    assert!(wait_for_deregistration(&reg, RelayId(2)).await);
    let shrunk = read_mesh_peers_until(&mut socket1, 1).await;
    assert_eq!(shrunk, registry::mesh_peers(&reg));
    assert_eq!(shrunk[0].relay_id, RelayId(1));
}

// --- Tenant verifying-key distribution ---

#[tokio::test]
async fn the_tenant_key_set_is_pushed_before_the_first_descriptor() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with one enrolled tenant (sb-test / test-key-1) and a session
    // relay 1 serves. Relay 1 enrolls over a raw control socket so the test can
    // read the exact post-enroll frame order.
    let (base_url, _session, setup) = coordinator_with_session(None).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;

    // The first frame after enrollment is the tenant-key set — before any
    // descriptor — carrying every configured tenant, each with the verifying key
    // the coordinator holds for it.
    let pushed = expect_tenant_keys(&mut socket).await;
    let expected = tenant::all_verifying_keys(setup.tenants());
    assert_eq!(pushed.len(), expected.len());
    assert_eq!(
        pushed.len(),
        1,
        "the coordinator has exactly one tenant enrolled"
    );

    let (kid, verifying_key) = tenant::verifying_key(setup.tenants(), &TenantId(TENANT.to_owned()))
        .expect("the tenant is enrolled");
    assert_eq!(kid, KeyId("test-key-1".to_owned()));
    let entry = pushed
        .iter()
        .find(|k| k.kid == kid)
        .expect("the pushed set names the configured tenant");
    assert_eq!(entry.tenant, TenantId(TENANT.to_owned()));
    assert_eq!(
        entry.verifying_key,
        verifying_key.to_vec(),
        "the pushed verifying key matches the coordinator's signing key's public half",
    );

    // The descriptor re-sync follows the tenant-key lead on the same connection.
    let descriptors = read_to_descriptors(&mut socket).await;
    assert!(descriptors.contains("\"type\":\"descriptors\""));
}

/// Wall clock as unix epoch milliseconds — the same base both the coordinator's
/// staging stamp and this in-process test read.
fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn the_pushed_descriptor_set_carries_a_recent_staging_stamp() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with a session relay 1 serves. Relay 1 enrolls over a raw
    // control socket so the test can read the descriptor frame and inspect its
    // staging stamp — the coordinator's wall-clock at the moment the set left its
    // outbox, which the relay differences against its own clock to measure apply lag.
    let (base_url, _session, _setup) = coordinator_with_session(None).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // The coordinator runs in this same process, so it stamps against this same
    // clock: the stamp must land in `[before, after]`, bracketing the whole exchange.
    let before = unix_ms_now();
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;

    let descriptors = read_to_descriptors(&mut socket).await;
    let after = unix_ms_now();

    let CoordinatorToRelay::Descriptors {
        staged_at_unix_ms, ..
    } = serde_json::from_str(&descriptors).unwrap()
    else {
        panic!("read_to_descriptors returns a descriptors frame");
    };
    let staged = staged_at_unix_ms.expect("a current coordinator stamps every descriptor push");
    assert!(
        (before..=after).contains(&staged),
        "the stamp is the coordinator's wall-clock when the set was pushed \
         (before={before}, staged={staged}, after={after})",
    );
}

// --- Region ping-beacon distribution ---

#[tokio::test]
async fn the_region_beacon_set_is_pushed_before_the_first_descriptor() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with two configured regions and the test tenant enrolled. A
    // relay enrolls over a raw control socket so the test can read the exact
    // post-enroll frame order.
    let (base_url, _setup) = serve_coordinator_with_regions(two_region_config()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(9, 14909))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(9)).await;

    // The tenant-key lead comes first; the region-beacon set follows it, still
    // ahead of any descriptor. Every configured region's beacon is pushed — the
    // relay filters its own later — in file order.
    let _ = expect_tenant_keys(&mut socket).await;
    let beacons = expect_region_beacons(&mut socket).await;
    assert_eq!(
        beacons,
        vec![
            RegionBeaconTarget {
                region: RegionId("region-a".to_owned()),
                beacon: "a:20000".to_owned(),
            },
            RegionBeaconTarget {
                region: RegionId("region-b".to_owned()),
                beacon: "b:20000".to_owned(),
            },
        ],
        "the beacon set names every configured region, in file order",
    );

    // The descriptor re-sync follows the beacon lead on the same connection.
    let descriptors = read_to_descriptors(&mut socket).await;
    assert!(descriptors.contains("\"type\":\"descriptors\""));
}

#[tokio::test]
async fn no_region_beacons_are_pushed_without_a_region_config() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with no region config: the region-blind posture has no beacons
    // to measure, so the connect-time lead is the tenant keys followed directly by
    // the descriptor re-sync, with no region-beacons frame between them.
    let (base_url, _setup) = serve_coordinator_with_regions(RegionsConfig::default()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(9, 14909))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(9)).await;

    // After the tenant-key lead, the very next frame is the descriptor re-sync — a
    // region-beacons frame interposed here would fail this assertion.
    let _ = expect_tenant_keys(&mut socket).await;
    let next = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers promptly")
        .expect("a frame arrives before the stream ends")
        .unwrap();
    let Message::Text(text) = next else {
        panic!("expected the descriptor re-sync, got {next:?}");
    };
    assert!(
        text.contains("\"type\":\"descriptors\""),
        "with no region config the descriptor re-sync directly follows the tenant keys, \
         with no region-beacons frame between: {text}",
    );
}

// --- Backbone RTT ingest + serve (end to end) ---

/// Fetches `GET {base_url}/regions` over a throwaway HTTP/1.1 connection and returns
/// the parsed JSON body. A raw request keeps these tests free of an HTTP-client
/// dependency; `Connection: close` lets the read run to EOF.
async fn get_regions_json(base_url: &str) -> serde_json::Value {
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

#[tokio::test]
async fn a_heartbeats_region_rtts_are_served_on_the_regions_endpoint() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with two configured regions. A relay enrolls in region-a and
    // heartbeats a measured round-trip to region-b; the coordinator folds it into the
    // pair table and serves it on GET /regions.
    let (base_url, _setup) = serve_coordinator_with_regions(two_region_config()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let frame = serde_json::to_string(&RelayToCoordinator::Hello(hello)).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(9)).await;
    // Drain the connect-time lead (tenant keys, region beacons, descriptor re-sync) so
    // the socket is not backpressured before the heartbeat is sent.
    let _ = read_to_descriptors(&mut socket).await;

    // Report a round-trip to region-b (the relay's own region-a is skipped by the pair
    // definition). The heartbeat is declarative, so one beat carries the whole set.
    let heartbeat = RelayToCoordinator::Heartbeat {
        sessions: vec![],
        region_rtts: vec![RegionRttReport {
            region: RegionId("region-b".to_owned()),
            rtt_ms: 87,
        }],
    };
    let beat = serde_json::to_string(&heartbeat).unwrap();
    socket.send(Message::Text(beat.into())).await.unwrap();

    // The ingest is asynchronous; poll GET /regions until the pair appears.
    let mut served = None;
    for _ in 0..100 {
        let json = get_regions_json(&base_url).await;
        if let Some(rtts) = json.get("backbone_rtts").and_then(|v| v.as_array())
            && !rtts.is_empty()
        {
            served = Some(json);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let json = served.expect("the reported pair is served on GET /regions");
    let rtts = json["backbone_rtts"].as_array().unwrap();
    assert_eq!(rtts.len(), 1);
    assert_eq!(rtts[0]["a"].as_str().unwrap(), "region-a");
    assert_eq!(rtts[0]["b"].as_str().unwrap(), "region-b");
    assert_eq!(rtts[0]["rtt_ms"].as_u64().unwrap(), 87);
    assert!(
        rtts[0].get("measured_at").is_some(),
        "each served pair carries its recorded age",
    );
}

// --- Split reader/writer: concurrency, reap coalescing, and the send-stall bound ---

#[tokio::test]
async fn an_inbound_flood_does_not_delay_a_descriptor_push() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A relay enrolls, then floods the coordinator with inbound heartbeats while a
    // session is created. Because reads and writes run on independent halves, the
    // writer keeps making progress under the reader's load, so the descriptor push
    // naming the new session still arrives promptly.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    let (mut write, mut read) = socket.split();

    // Flood inbound heartbeats continuously from a side task.
    let flood = tokio::spawn(async move {
        let beat = serde_json::to_string(&RelayToCoordinator::Heartbeat {
            sessions: vec![],
            region_rtts: vec![],
        })
        .unwrap();
        loop {
            if write
                .send(Message::Text(beat.clone().into()))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    // Create a session homed on the relay; its descriptor must be pushed.
    let session = create_one_slot_session(&setup);

    // Despite the flood, the descriptor push naming the session arrives quickly. The
    // session is created after enroll, so a delta-capable relay receives it as a
    // delta upsert; either the full set or a delta naming the session counts.
    let found = timeout(Duration::from_secs(3), async {
        while let Some(Ok(message)) = read.next().await {
            if let Message::Text(text) = message
                && let Ok(frame) = serde_json::from_str::<CoordinatorToRelay>(&text)
            {
                let names_session = match &frame {
                    CoordinatorToRelay::Descriptors { descriptors, .. } => {
                        descriptors.iter().any(|d| d.session == session)
                    }
                    CoordinatorToRelay::DescriptorDelta { upserts, .. } => {
                        upserts.iter().any(|d| d.session == session)
                    }
                    _ => false,
                };
                if names_session {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("the descriptor push must arrive well within the bound despite the flood");
    assert!(
        found,
        "the writer pushed the new session's descriptor while the reader was flooded",
    );
    flood.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn queued_reaps_for_one_session_arrive_as_a_single_frame() {
    use futures_util::{SinkExt, StreamExt};
    use rally_point_coordinator::descriptors::SlotClose;
    use tokio_tungstenite::tungstenite::Message;

    // A burst of reap nudges for the SAME session, queued before the writer's reap
    // arm wakes, coalesces into one CloseSlot frame carrying the merged slot union.
    // A single-threaded runtime makes the burst-before-drain deterministic: the
    // writer task cannot run while this test task fires the nudges without awaiting.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    // Drain the connect-time lead so the next frames read are the reap directives,
    // and so the writer is parked in its steady-state select before the burst.
    let _ = read_to_descriptors(&mut socket).await;

    // Fire the nudges synchronously (no await between), so they all queue on the
    // relay's reap channel before the writer drains any. Each nudge carries the
    // merged-so-far slot union for its session, so the last is the most complete.
    let tenant = TenantId(TENANT.to_owned());
    for slot in 0u8..8 {
        setup.reaps().send(
            RelayId(1),
            SlotClose {
                tenant: tenant.clone(),
                session: SessionId(1),
                slots: (0..=slot).map(SlotId).collect(),
            },
        );
    }

    // Exactly one CloseSlot frame arrives, carrying the full union of every nudge's
    // slots.
    let (session, slots) = timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            if let Ok(CoordinatorToRelay::CloseSlot { session, slots, .. }) =
                serde_json::from_str::<CoordinatorToRelay>(&text)
            {
                return (session, slots);
            }
        }
        panic!("no CloseSlot frame arrived");
    })
    .await
    .expect("a CloseSlot frame should arrive");
    assert_eq!(session, SessionId(1));
    assert_eq!(
        slots,
        (0u8..8).map(SlotId).collect::<Vec<_>>(),
        "the single frame carries the union of every coalesced nudge",
    );

    // No further CloseSlot for the same session follows within a short window — the
    // queued nudges collapsed into the one frame.
    let another = timeout(Duration::from_millis(300), async {
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            if matches!(
                serde_json::from_str::<CoordinatorToRelay>(&text),
                Ok(CoordinatorToRelay::CloseSlot { .. })
            ) {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(another, Err(_) | Ok(false)),
        "the queued nudges coalesced into a single frame, not one per nudge",
    );
}

#[tokio::test]
async fn a_relay_that_stops_reading_is_dropped_by_the_send_stall_bound_despite_heartbeats() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // The send-stall bound: a relay that keeps heartbeating — refreshing the
    // reader's liveness deadline forever — but stops READING must still lose its
    // registry entry, because the writer's per-send timeout runs from each send's
    // start, independent of the reader-refreshed deadline.
    //
    // Arranged over a real socket without guessing OS buffer sizes: a short liveness
    // plus a descriptor set the coordinator re-pushes (in full) every time it grows.
    // The peer never drains those pushes, so the unread bytes climb past whatever the
    // buffers hold and a writer send eventually stalls — while the heartbeats keep
    // the reader's deadline fresh throughout, so only the writer's bound can be what
    // drops the connection.
    let liveness = Duration::from_millis(400);
    let (base_url, setup) = serve_coordinator_with_liveness(&[(1, 14900)], liveness).await;

    // A sizeable initial set, so each re-push already carries real weight.
    for _ in 0..1000 {
        create_one_slot_session(&setup);
    }

    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll (the handshake requires reading the coordinator's challenge)...
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    // ...then never read again, only heartbeat — every ~25ms, well inside the 400ms
    // liveness — while growing the descriptor set so the coordinator keeps re-pushing
    // an ever-larger full set to a peer that never reads it.
    let heartbeat = serde_json::to_string(&RelayToCoordinator::Heartbeat {
        sessions: vec![],
        region_rtts: vec![],
    })
    .unwrap();
    let mut beats = 0u32;
    let dropped = loop {
        // Deregistration is the drop being waited for; check before doing more work
        // (once the relay is gone, no session can home on it).
        if registry::peer(setup.registry(), RelayId(1)).is_none() {
            break true;
        }
        if socket
            .send(Message::Text(heartbeat.clone().into()))
            .await
            .is_err()
        {
            break true; // the coordinator tore the connection down; the send errors
        }
        beats += 1;
        if beats > 400 {
            break false; // ~10s of heartbeats with no drop: the bound never fired
        }
        // One more session → one more full re-push the peer will not drain, so the
        // coordinator's unread backlog keeps rising until a send stalls. A create
        // that fails for want of a relay means the drop already happened.
        let created = session::create_session(
            &setup,
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
        .is_ok();
        if !created {
            break true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(
        dropped,
        "a relay that heartbeats but never reads is dropped by the send-stall bound",
    );
    assert!(
        beats >= 2,
        "the relay actually heartbeated (refreshing the reader deadline) before the drop",
    );
    assert!(
        wait_for_deregistration(setup.registry(), RelayId(1)).await,
        "the wedged relay is deregistered",
    );
}
