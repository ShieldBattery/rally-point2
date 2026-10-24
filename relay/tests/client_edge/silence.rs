//! The silence watch over real links: a client whose game stopped while its
//! network stack still answers is evicted and refused its re-dials, while a
//! client whose whole network path died is left to the transport's idle
//! timeout, so it can come back while the survivors still hold its drop.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::consensus::{Authority, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_relay::observability::flight_recorder::FlightEvent;
use rally_point_relay::routing::run_silence_watch;
use rally_point_transport::Link;
use rally_point_transport::control::send_control_game_started;
use rally_point_transport::noq::{ConnectionError, VarInt};

/// Short enough that a test spends its time on the transport's own clocks,
/// not on the verdict.
const WINDOW: Duration = Duration::from_millis(300);
const INTERVAL: Duration = Duration::from_millis(50);

/// The turns slot 1 sends before its game stops. Slot 0 sends more after, so
/// slot 1 is the strictly earliest stopper.
const SLOT1_TURNS: u64 = 3;
const SLOT0_TURNS: u64 = 5;

/// A UDP proxy between one client and `server` that drops every packet in both
/// directions while the returned flag is set: a network path that died with
/// no close of any kind reaching either end.
async fn blackhole_proxy(server: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_facing = Arc::new(UdpSocket::bind(bind).await.unwrap());
    let server_facing = Arc::new(UdpSocket::bind(bind).await.unwrap());
    server_facing.connect(server).await.unwrap();
    let address = client_facing.local_addr().unwrap();
    let dead = Arc::new(AtomicBool::new(false));
    let client: Arc<parking_lot::Mutex<Option<SocketAddr>>> = Arc::default();

    {
        let (client_facing, server_facing, client, dead) = (
            Arc::clone(&client_facing),
            Arc::clone(&server_facing),
            Arc::clone(&client),
            Arc::clone(&dead),
        );
        tokio::spawn(async move {
            let mut buf = vec![0; 65_536];
            while let Ok((len, from)) = client_facing.recv_from(&mut buf).await {
                *client.lock() = Some(from);
                if !dead.load(Ordering::Relaxed) {
                    let _ = server_facing.send(&buf[..len]).await;
                }
            }
        });
    }
    {
        let dead = Arc::clone(&dead);
        tokio::spawn(async move {
            let mut buf = vec![0; 65_536];
            while let Ok(len) = server_facing.recv(&mut buf).await {
                let to = *client.lock();
                if let Some(to) = to
                    && !dead.load(Ordering::Relaxed)
                {
                    let _ = client_facing.send_to(&buf[..len], to).await;
                }
            }
        });
    }
    (address, dead)
}

/// A two-slot session homed on one relay that is its authority, with the
/// silence watch running.
fn relay_for(session: SessionId) -> (TestRelay, SessionKey, Tenant) {
    let tenant = make_default_tenant();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    let _ = makers.sync_maker(
        &key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            homed_slots: [SlotId(0), SlotId(1)].into(),
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let relay = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    tokio::spawn(run_silence_watch(
        makers,
        relay.sessions.clone(),
        WINDOW,
        INTERVAL,
    ));
    (relay, key, tenant)
}

fn events(relay: &TestRelay, key: &SessionKey) -> Vec<FlightEvent> {
    relay
        .mesh
        .session
        .decision_makers
        .flight_recorder()
        .events(key)
        .into_iter()
        .map(|record| record.event)
        .collect()
}

/// Both slots report their game loops running, then play until slot 1's game
/// stops: slot 0 receives every turn slot 1 sent, and then sends more of its
/// own that slot 1 never answers. `before_slot0_turns` runs between the two,
/// for a test that cuts slot 1's path there.
async fn play_until_slot1_stops(
    relay: &TestRelay,
    key: &SessionKey,
    slot0: &mut Link,
    slot1: &mut Link,
    before_slot0_turns: impl FnOnce(),
) {
    for link in [&*slot0, &*slot1] {
        let (mut control, _recv) = link.connection().open_bi().await.unwrap();
        send_control_game_started(&mut control).await.unwrap();
        // The stream stays open for the rest of the test: the relay reads a
        // closed control stream as the client leaving.
        std::mem::forget((control, _recv));
    }
    wait_until("the relay never recorded both game loops running", || {
        let events = events(relay, key);
        [0, 1]
            .iter()
            .all(|&slot| events.contains(&FlightEvent::SlotGameStarted { slot }))
    })
    .await;

    for seq in 0..SLOT1_TURNS {
        slot1
            .send(Some(build_turn(1, seq, Some(10 + seq as u32))))
            .unwrap();
    }
    let mut received = 0;
    while received < SLOT1_TURNS {
        let got = tokio::time::timeout(Duration::from_secs(5), slot0.recv())
            .await
            .expect("slot 1's turns reach slot 0")
            .expect("slot 0's link stays up");
        received += got.fresh.len() as u64;
    }
    before_slot0_turns();
    for seq in 0..SLOT0_TURNS {
        slot0
            .send(Some(build_turn(0, seq, Some(10 + seq as u32))))
            .unwrap();
    }
}

#[tokio::test]
async fn a_slot_whose_game_stopped_behind_a_live_link_is_evicted_and_refused() {
    let session = SessionId(360);
    let (relay, key, tenant) = relay_for(session);
    let endpoint = client_endpoint(&relay.ca);
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    wait_for_slots(&relay.sessions, &key, 2).await;

    play_until_slot1_stops(&relay, &key, &mut slot0, &mut slot1, || {}).await;

    // Slot 1's network stack keeps running: its keepalives are the evidence. The
    // wait allows one keepalive interval past the naming and some slack, and
    // stays well short of the grace that would evict it with no evidence.
    let reason = tokio::time::timeout(Duration::from_secs(8), slot1.connection().closed())
        .await
        .expect("the stalled slot's link is closed");
    assert!(
        matches!(
            reason,
            ConnectionError::ApplicationClosed(ref close)
                if close.error_code == VarInt::from_u32(close_codes::SILENT_SLOT)
        ),
        "closed as a silent slot, got {reason:?}",
    );
    let recorded = events(&relay, &key);
    assert!(
        recorded
            .iter()
            .any(|event| matches!(event, FlightEvent::SlotSilent { slot: 1, .. })),
        "{recorded:?}",
    );
    assert!(
        recorded
            .iter()
            .any(|event| matches!(event, FlightEvent::SlotEvictedSilent { slot: 1, .. }))
            && !recorded
                .iter()
                .any(|event| matches!(event, FlightEvent::SlotQuietLinkClosed { .. })),
        "evicted on the frames its link kept receiving, not on the grace: {recorded:?}",
    );

    // Its game cannot restart, so its re-dial is refused, and the refusal is
    // in the recording.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let redial = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _ = handshake(&redial, &token, &client_key, &[]).await;
    let reason = tokio::time::timeout(Duration::from_secs(5), redial.closed())
        .await
        .expect("the re-dial is closed");
    assert!(
        matches!(
            reason,
            ConnectionError::ApplicationClosed(ref close)
                if close.error_code == VarInt::from_u32(close_codes::SLOT_DEPARTED)
        ),
        "a re-dial is refused as departed, got {reason:?}",
    );
    wait_until("the refused re-dial never reached the recording", || {
        events(&relay, &key).iter().any(|event| {
            matches!(
                event,
                FlightEvent::SlotDialRefused { slot: 1, close_code, .. }
                    if *close_code == close_codes::SLOT_DEPARTED
            )
        })
    })
    .await;
}

#[tokio::test]
async fn a_slot_whose_network_path_died_can_come_back_while_its_drop_is_held() {
    let session = SessionId(361);
    let (relay, key, tenant) = relay_for(session);
    let makers = relay.mesh.session.decision_makers.clone();
    let drop_holds = relay.mesh.session.drop_holds.clone();
    let endpoint = client_endpoint(&relay.ca);
    let (proxy, dead) = blackhole_proxy(relay.addr).await;
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, proxy, &tenant, session, SlotId(1)).await;
    wait_for_slots(&relay.sessions, &key, 2).await;

    play_until_slot1_stops(&relay, &key, &mut slot0, &mut slot1, || {
        dead.store(true, Ordering::Relaxed)
    })
    .await;

    wait_until("the watch never named the slot whose path died", || {
        events(&relay, &key)
            .iter()
            .any(|event| matches!(event, FlightEvent::SlotSilent { slot: 1, .. }))
    })
    .await;
    // The transport's idle timeout, not the watch, ends the dead link. The
    // wait outlasts that timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !(makers.has_departure(&key, SlotId(1)) && drop_holds.is_pending(&key, SlotId(1))) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dead link was never closed as a held disconnect",
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let recorded = events(&relay, &key);
    assert!(
        !recorded
            .iter()
            .any(|event| matches!(event, FlightEvent::SlotEvictedSilent { .. })),
        "a dead path is not evicted: {recorded:?}",
    );

    // The path comes back: the client re-dials and is reinstated.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let redial = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&redial, &token, &client_key, &[])
        .await
        .expect("the re-dial is admitted while the drop is held");
    assert!(
        !makers.has_departure(&key, SlotId(1)),
        "the re-dial reinstated the slot",
    );
    assert!(!drop_holds.is_pending(&key, SlotId(1)));
}
