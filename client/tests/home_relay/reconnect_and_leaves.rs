//! What happens when a link dies mid-game: a reconnecting client's driver
//! re-dials while its drop is held and replays what it missed exactly once,
//! and a survivor's manual drop request against a disconnected peer — refused
//! before the unlock floor, honored past it, and terminal for the departed
//! slot's later re-dial.

use std::time::Duration;

use rally_point_client::{ClientEndpoint, DialError};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::noq;

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, recv_turn, registry_for,
    start_relay_with_mesh, wait_connectivity,
};

#[tokio::test]
async fn a_dropped_client_reconnects_and_replays_the_missed_turns_exactly_once() {
    use std::collections::HashSet;

    use rally_point_client::{LinkDriver, Reconnect};
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full reconnect path against a real relay: a client's link drops mid-game,
    // its driver re-dials itself while its drop is still held (undecided) presenting
    // resume cursors, the relay releases the hold and replays the turns missed
    // during the outage, and the driver folds them into the ordered stream exactly
    // once — while signalling its own disconnect then reconnect on the connectivity
    // channel, the channels staying alive throughout.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(70);

    // Seed the session as started with the two expected slots, so the relay records
    // forwarded turns in its replay ring.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0 runs with reconnection. Keep a handle to its connection so the test can
    // sever it, simulating a network drop (not a clean leave), which marks the
    // relay's drop hold and keeps the session alive.
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint.endpoint().clone()),
        relay_addr: addr,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    // Slot 1 runs plainly; it is the peer whose turns slot 0 will miss and replay.
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    // Both slots connected: session-start fires, so the ring now records turns.
    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");

    // A valid SC:R build command the relay's turn validator accepts; the four turns
    // are told apart by the origin seq the sender's driver assigns (0..3), not by
    // their bytes.
    let turn = || Payload {
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };

    // Slot 1 sends two turns; slot 0 receives them, advancing its cursor to seq 2.
    chan1.outbound.send(turn()).await.unwrap();
    chan1.outbound.send(turn()).await.unwrap();
    assert_eq!(recv_turn(&mut chan0.inbound).await.seq, 0);
    assert_eq!(recv_turn(&mut chan0.inbound).await.seq, 1);

    // Sever slot 0's link. Its driver must surface its own disconnect, not close the
    // channels.
    conn0.close(noq::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;

    // While slot 0 is away, slot 1 produces two more turns; the relay records them
    // for replay.
    chan1.outbound.send(turn()).await.unwrap();
    chan1.outbound.send(turn()).await.unwrap();

    // Slot 0 re-establishes its link while its drop is still held.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;

    // The relay replays the two missed turns (seq 2, 3); the driver folds them back
    // into the ordered stream, in order, each exactly once.
    let third = recv_turn(&mut chan0.inbound).await;
    let fourth = recv_turn(&mut chan0.inbound).await;
    assert_eq!(third.seq, 2);
    assert_eq!(fourth.seq, 3);
    assert_eq!(&third.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // No duplicate delivery: the dedup absorbed any overlap between the replay and
    // the resumed live stream.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), chan0.inbound.recv())
            .await
            .is_err(),
        "the missed turns must be delivered exactly once",
    );

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_survivor_manually_drops_a_disconnected_peer_past_the_unlock() {
    use std::collections::HashSet;

    use rally_point_client::LinkDriver;
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full manual-drop path against a real relay: one client's link dies, and
    // the surviving client asks the relay to drop it. Before the unlock floor the
    // request is refused (the drop may still be a blip); past it, the relay honors
    // the request and pushes the synced leave down the survivor's stream — the
    // dropped slot is never removed on its own, only on this human decision. The
    // dropped client's later re-dial is then refused terminally.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(71);

    // A tiny drop-unlock floor so the test can cross it quickly. Seed this relay as
    // the authority over an expected {0, 1} set so the session starts and a decided
    // leave is real.
    let unlock = Duration::from_millis(300);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_drop_unlock(unlock);
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0 is the client that will disconnect; keep its connection handle so the
    // test can sever it. It runs plainly (no reconnection) — its link death is the
    // disconnect the survivor then resolves manually.
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, chan0) = LinkDriver::new(link0);
    let task0 = tokio::spawn(driver0.run());

    // Slot 1 is the survivor who requests the drop.
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    // Both connected: the session started.
    tokio::time::timeout(Duration::from_secs(5), chan1.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 1's session-start channel closed");

    // A framed turn from slot 0 gives its leave an apply-frame basis; slot 1
    // receives it, so the relay has observed slot 0's frame before it disconnects.
    chan0
        .outbound
        .send(Payload {
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            game_frame_count: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(recv_turn(&mut chan1.inbound).await.seq, 0);

    // Sever slot 0's link — a network drop, not a clean leave. Slot 1 hears the
    // disconnect; the relay records the departure and marks the drop hold.
    conn0.close(noq::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan1.connectivity, (SlotId(0), false)).await;

    // Pre-unlock: the survivor requests the drop, but the hold has not stood past
    // the floor, so no leave is decided — the slot could still be a blip.
    chan1.request_drop.send(SlotId(0)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), chan1.leaves.recv())
            .await
            .is_err(),
        "a pre-unlock request must not remove the disconnected slot",
    );

    // Past the unlock floor, the survivor requests again — now the authority honors
    // it and pushes the synced leave for slot 0 down the survivor's stream.
    tokio::time::sleep(unlock).await;
    chan1.request_drop.send(SlotId(0)).await.unwrap();
    let leave = tokio::time::timeout(Duration::from_secs(5), chan1.leaves.recv())
        .await
        .expect("the leave arrives once the request is honored past the unlock")
        .expect("slot 1's leaves channel stays open");
    assert_eq!(leave.slot, 0);
    assert_eq!(
        leave.reason, 0x4000_0006,
        "a manual drop uses the native dropped reason",
    );

    // Slot 0's later re-dial is refused terminally with the slot-departed close: its
    // leave was decided, so the game has moved on without it. This is the same
    // re-dial path the driver's own reconnection uses, which classifies that close
    // code as terminal rather than a retryable transport error.
    match endpoint
        .reconnect_with_timeout(addr, "localhost", &id0, &[], Duration::from_secs(5))
        .await
    {
        Err(DialError::SlotDeparted) => {}
        Err(other) => panic!("expected a slot-departed refusal, got {other:?}"),
        Ok(_) => panic!("the re-dial was accepted even though the slot had departed"),
    }

    drop(chan0);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}
