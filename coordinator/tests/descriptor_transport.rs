//! End-to-end coordinator→relay descriptor transport over the persistent control
//! connection: a relay holds a real WebSocket open to the coordinator, and the
//! descriptors the coordinator pushes drive that relay's Join source.
//!
//! This is the seam the two halves were built to meet at, exercised for real: a
//! bound coordinator WebSocket server and the relay's live `coordinator_client`.
//! It covers the three behaviors that matter — the initial push on connect drives
//! a `Join`, a session ending pushes a `Leave`, and a wrong bootstrap secret
//! drives nothing — none of which the per-side unit tests can show on their own.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{registry, session, tenant};
use rally_point_proto::control::{
    BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
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

fn session_key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    }
}

/// Stands up a coordinator with two relays + a tenant, creates a session, and
/// serves the API on an ephemeral port. Returns the base URL, the created session
/// id, and a handle to the same outbox (so a test can drive a later change).
async fn coordinator_with_session(
    bootstrap_secret: Option<&str>,
) -> (String, SessionId, SessionSetup) {
    let reg = registry::new_registry();
    for (id, port) in [(1u64, 14900u16), (2, 14901)] {
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(id),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                ProtocolVersion::CURRENT,
            ),
        );
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
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                },
            ],
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
        control_auth,
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
    let control = MeshControl::new(RelayId(1));
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
        RelayId(1),
        Some(secret.to_owned()),
        control,
        Duration::from_millis(50),
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
        RelayId(1),
        None,
        control,
        Duration::from_millis(50),
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
        RelayId(1),
        Some("wrong-secret".to_owned()),
        control,
        Duration::from_millis(50),
    ));

    let result = timeout(Duration::from_millis(500), rx2.recv()).await;
    assert!(result.is_err(), "a rejected relay must never drive a Join");
}
