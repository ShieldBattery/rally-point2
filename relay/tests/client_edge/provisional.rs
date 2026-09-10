//! Sessions admitted before their coordinator descriptor arrives: the sweep that
//! reaps them at their deadline, and the descriptor that saves them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::server;
use rally_point_transport::noq;
use rally_point_transport::quic::server_config;

/// A session admitted by a client dial with no applied descriptor is
/// provisional and bounded: left undescribed past its window, the relay's
/// sweep closes the connection (with a distinct, retryable-looking close
/// code) and drops the session's roster state, rather than trusting an
/// admit-first session indefinitely. This drives the real admission gate
/// (`server.rs`'s `serve_connection`) and the real sweep
/// (`provisional::run_sweep_with`), not a hand-simulated mark and reap.
#[tokio::test]
async fn a_provisional_session_with_no_descriptor_is_reaped_at_its_deadline() {
    use rally_point_relay::routing::{self, PROVISIONAL_EXPIRED_CLOSE, SessionKey};
    use rally_point_relay::session::provisional::{self, ProvisionalSessions};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(303);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let window = Duration::from_millis(150);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let provisional: ProvisionalSessions = mesh.provisional.clone();
    let decision_makers = mesh.decision_makers.clone();
    // Armed exactly as production coordinator wiring arms it, so the reap
    // exercises the journal paths a coordinator-managed relay runs.
    mesh.provisional_turns.arm();
    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
    ));

    // Armed from the start (standing in for an established control
    // connection), with a fast sweep cadence so the test doesn't wait a whole
    // production tick.
    let (_armed_tx, armed_rx) = tokio::sync::watch::channel(true);
    tokio::spawn(provisional::run_sweep_with(
        provisional,
        Arc::clone(&sessions),
        decision_makers,
        armed_rx,
        Duration::from_millis(20),
    ));

    let client_endpoint = client_endpoint(&ca);
    // No descriptor is ever applied for this session -- admission's
    // provisional mark stands until the sweep reaps it.
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    match tokio::time::timeout(window * 5, client_connection.closed())
        .await
        .expect("the client observes the connection end within the deadline")
    {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            PROVISIONAL_EXPIRED_CLOSE,
            "reaped with the provisional-expired close code",
        ),
        other => panic!("expected the provisional-expired application close, got {other:?}"),
    }

    // The session's roster state is gone too, not just the connection.
    wait_until(
        tokio::time::Instant::now() + Duration::from_secs(5),
        "the reaped session's roster entry never cleared",
        || sessions.lock().get(&key).is_none(),
    )
    .await;

    // A genuinely slow descriptor only delays, never bricks: the same slot
    // redials and is admitted fresh, with its own new provisional window
    // (not a leftover already-expired one), and is reaped again on its own
    // timer rather than being refused outright or reaped instantly.
    let redial_start = tokio::time::Instant::now();
    let slot0_again = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let redialed_connection = slot0_again.connection().clone();
    match tokio::time::timeout(window * 5, redialed_connection.closed())
        .await
        .expect("the redialed connection also ends within a fresh deadline")
    {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            PROVISIONAL_EXPIRED_CLOSE,
            "the redial is reaped with the same close code, on its own new window",
        ),
        other => panic!("expected the provisional-expired application close, got {other:?}"),
    }
    assert!(
        redial_start.elapsed() >= window,
        "the redial got a full fresh window rather than inheriting an already-expired deadline",
    );
}

/// A descriptor that arrives inside a provisional session's window clears its
/// mark, so the sweep leaves the connection alone past the original deadline
/// -- the intended common case: the coordinator's descriptor push usually
/// beats the window by a wide margin, and a legitimate session must never be
/// punished for winning the very create-response-to-dial race the
/// provisional window exists to bound.
#[tokio::test]
async fn a_descriptor_arriving_inside_the_window_saves_the_session_from_the_sweep() {
    use rally_point_proto::control::SessionDescriptor;
    use rally_point_proto::ids::RelayId;
    use rally_point_relay::mesh::control::MeshControl;
    use rally_point_relay::routing::{self, SessionKey};
    use rally_point_relay::session::provisional::{self, ProvisionalSessions};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(304);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let window = Duration::from_millis(150);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let provisional: ProvisionalSessions = mesh.provisional.clone();
    let decision_makers = mesh.decision_makers.clone();
    // Armed exactly as production coordinator wiring arms it, so the reap
    // exercises the journal paths a coordinator-managed relay runs.
    mesh.provisional_turns.arm();
    // Points at the same decision-maker registry and provisional map the
    // relay serves this session with, so `apply_descriptor` here is
    // indistinguishable from one the coordinator subscriber would have
    // applied -- this test drives the real clearing path, not a hand call
    // into `ProvisionalSessions` directly.
    let control = MeshControl::new(RelayId(1), mesh.decision_makers.clone(), Arc::default())
        .with_provisional(provisional.clone());

    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
    ));

    let (_armed_tx, armed_rx) = tokio::sync::watch::channel(true);
    tokio::spawn(provisional::run_sweep_with(
        provisional,
        Arc::clone(&sessions),
        decision_makers,
        armed_rx,
        Duration::from_millis(20),
    ));

    let client_endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    // A descriptor arrives well inside the window.
    tokio::time::sleep(Duration::from_millis(30)).await;
    control.apply_descriptor(&SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![],
        bounds: rally_point_proto::control::BufferBounds::new(1, 6).unwrap(),
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
    });

    // Wait well past the original deadline: the sweep must have left the
    // connection alone.
    tokio::time::sleep(window * 3).await;
    assert!(
        client_connection.close_reason().is_none(),
        "a descriptor inside the window saves the session; the sweep must not have reaped it",
    );
    assert!(
        sessions.lock().get(&key).is_some(),
        "the slot is still registered",
    );
}

/// Dev/static mode (`--mesh-peer`, no `--coordinator-url`) never spawns the
/// provisional-admission sweep at all -- there is no separate "unarmed" flag
/// to fail closed on, the sweep task simply does not exist. This drives that
/// exact shape: a provisionally-admitted session on a relay with no sweep
/// running whatsoever survives indefinitely, however long its window would
/// otherwise have bounded it.
#[tokio::test]
async fn with_no_sweep_running_a_provisional_session_is_never_reaped() {
    use rally_point_relay::routing::{self, SessionKey};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(305);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A window tiny enough that, were any sweep running, it would have reaped
    // this many times over by the time the test's own wait below elapses.
    let window = Duration::from_millis(20);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
        // No `provisional::run_sweep`/`run_sweep_with` task spawned anywhere
        // for this relay -- exactly the dev/static (`--mesh-peer`, no
        // `--coordinator-url`) wiring in `main.rs`, which never constructs
        // one either.
    ));

    let client_endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    tokio::time::sleep(window * 10).await;
    assert!(
        client_connection.close_reason().is_none(),
        "with no sweep running, the connection is never reaped no matter how long its window would have allowed",
    );
    assert!(
        sessions.lock().get(&key).is_some(),
        "the slot is still registered",
    );
}
