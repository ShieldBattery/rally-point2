//! Reconnecting into a held drop: the slot is reinstated, the turns it missed
//! are replayed, and a leave decided while it was gone is delivered.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;

#[tokio::test]
async fn a_reconnect_while_the_drop_is_held_reinstates_the_slot_and_replays_missed_turns() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(300);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Seed this relay as the authority over an expected {0, 1} set: the session then
    // starts (turns are ring-buffered only once started). A dropped slot is never
    // auto-decided regardless of the unlock floor, so the floor here matters only to
    // bound how long the test waits before asserting no leave ever fired.
    let unlock = Duration::from_millis(1000);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_drop_unlock(unlock);
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0.connection().clone());
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Both connected, so the session started. Slot 0's first framed turn reaches
    // slot 1 live and gives the session a frame basis.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut got = Vec::new();
    while got.is_empty() {
        got = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(got[0].seq, 0);

    // Slot 1's link dies. Wait until slot 0 hears the disconnect — proof the relay
    // has run the departure path and marked the drop hold for slot 1.
    drop(slot1);
    wait_for_connectivity(&mut ctrl0, SlotId(1), false).await;

    // While slot 1 is gone, slot 0 produces two more framed turns. They fan to no
    // peer (slot 1 is deregistered) but are recorded into the session's replay ring.
    for (seq, frame, byte) in [(1u64, 11u32, 2u8), (2, 12, 3)] {
        slot0
            .send(Some(Payload {
                seq,
                slot: 0,
                game_frame_count: Some(frame),
                commands: vec![0x0C, byte, 2, 3, 4, 5, 6, 7].into(),
                ..Default::default()
            }))
            .unwrap();
    }
    // Let the relay validate and record the two turns before the reconnect reads the
    // ring.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Slot 1 re-dials while its drop is still held, resuming from slot 0 seq 1 (it
    // already has seq 0). The relay accepts it (the hold is still pending), releases
    // the hold, and replays the two missed turns on the reliable control stream.
    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(0), 1)],
    )
    .await;
    let mut ctrl1 = spawn_control_reader(slot1b.connection().clone());

    let replayed = collect_oversize_turns(&mut ctrl1, 2).await;
    assert_eq!(
        replayed.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![1, 2],
        "exactly the missed turns, in seq order",
    );
    assert_eq!(&replayed[0].commands[..], &[0x0C, 2, 2, 3, 4, 5, 6, 7]);
    assert_eq!(&replayed[1].commands[..], &[0x0C, 3, 2, 3, 4, 5, 6, 7]);
    assert_eq!(replayed[0].slot, 0, "a replayed turn keeps its origin slot");

    // The hold was released and the slot reinstated: even well past the unlock floor
    // (past which a drop would only ever be honored on request, never automatically),
    // slot 0 never receives a synced leave for slot 1 (it only hears slot 1 reconnect).
    let deadline = tokio::time::Instant::now() + unlock + Duration::from_millis(500);
    loop {
        match tokio::time::timeout_at(deadline, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                panic!("a reinstated slot still had a leave decided: {leave:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => break,
        }
    }
}

/// A leave decided while a client's link was down must reach that client when
/// it reconnects. The live push (`fan_out_leave`) reaches only the survivors
/// rostered at decision time — a blipped client is not among them — so without
/// a reconnect-time replay the client replays turns up to the departed slot's
/// last frame and then stalls forever waiting for a turn that will never come.
/// The reconnect replays the session's leave state down the fresh control
/// stream: the departed slot as a connectivity-down, the decided leave as the
/// directive itself.
#[tokio::test]
async fn a_reconnecting_client_is_replayed_a_leave_decided_while_it_was_gone() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    // The native SC:R `pending_leave_reason` a voluntary quit writes -- see
    // `relay::routing::LEAVE_REASON_LEFT`.
    const LEAVE_REASON_LEFT: u32 = 3;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(310);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Authority over an expected {0, 1} set, so the session starts and a clean
    // leave-intent is decided here rather than merely recorded.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0.connection().clone());
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // A framed turn from slot 0 reaches slot 1 live: the session has started
    // and `decide_leave` has a frame basis to schedule against.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut got = Vec::new();
    while got.is_empty() {
        got = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(got[0].seq, 0);

    // Slot 1's link dies. Wait until slot 0 hears the disconnect — proof the
    // relay has run the departure path and holds slot 1's drop undecided (which
    // is also what keeps the session's state alive once slot 0 leaves below).
    drop(slot1);
    wait_for_connectivity(&mut ctrl0, SlotId(1), false).await;

    // While slot 1 is gone, slot 0 leaves cleanly. The authority decides the
    // leave and pushes it to the survivors rostered right now — which the
    // blipped slot 1 is not.
    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();
    expect_closed(&mut slot0).await;

    // Slot 1 re-dials while its own drop is still held. The reconnect must
    // replay the leave state it missed: slot 0's departure as a
    // connectivity-down and the decided leave as the directive itself.
    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(0), 1)],
    )
    .await;
    let mut ctrl1 = spawn_control_reader(slot1b.connection().clone());

    let mut saw_departed_connectivity = false;
    let leave = loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), ctrl1.recv())
            .await
            .expect("the replayed leave arrives before the timeout")
            .expect("the reconnected control stream stays open");
        match frame {
            ControlInbound::Connectivity(change) if change.slot == 0 && !change.connected => {
                saw_departed_connectivity = true;
            }
            ControlInbound::Leave(leave) => break leave,
            _ => continue,
        }
    };
    assert_eq!(leave.slot, 0, "the replayed leave names the departed slot");
    assert_eq!(
        leave.reason, LEAVE_REASON_LEFT,
        "the replayed directive is the decided one, reason intact",
    );
    assert!(
        saw_departed_connectivity,
        "the departed slot replays as connectivity-down before its leave",
    );
    let events: Vec<_> = makers
        .flight_recorder()
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert!(
        events.iter().any(|event| matches!(
            event,
            rally_point_relay::observability::flight_recorder::FlightEvent::LeaveControlWrite {
                recipient: 1,
                slot: 0,
                reason: LEAVE_REASON_LEFT,
                replayed: true,
                succeeded: true,
                ..
            }
        )),
        "the reconnect replay write is recorded at the control-stream boundary: {events:?}",
    );
}

#[tokio::test]
async fn a_resumed_turn_past_the_window_on_a_nonzero_slot_is_forwarded_not_closed() {
    // The same-relay resume regression, end to end: a client authorized on a NONZERO
    // slot re-homes mid-game and resumes its own-slot seq stream well past the 4096
    // receive window. The real DLL leaves the wire slot at 0 on every turn, while the
    // resume anchor is keyed on the authorized slot — so a relay edge that keyed dedup
    // on the wire slot would anchor slot 1 yet dedup slot 0, reject the first resumed
    // turn as out-of-window, and fatally close the link. The ingress-slot rebind keeps
    // dedup and the anchor on the authorized slot, so the turn is accepted and fanned
    // out. (Presenting a high own-slot resume cursor reproduces the anchored,
    // past-window state without pushing 4096 real turns through the loopback first.)
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(320);

    // The peer that should receive slot 1's resumed turn. It is deep in the same
    // game, so its own fan-in dedup has already tracked slot 1's stream up to the
    // resume point — anchor it there so the past-window forwarded turn is in this
    // peer's window (exactly as a real re-home, where every peer resumes too).
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    slot0.anchor_receive_window(SlotId(1), 8000);

    // Slot 1 (re)connects presenting a resume cursor for its OWN slot at a high
    // absolute seq — the oldest seq it will re-send after a re-home. The relay anchors
    // slot 1's receive window there.
    let mut slot1 = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(1), 8000)],
    )
    .await;

    // Slot 1 re-sends its resumed turn, stamping wire slot 0 exactly as the DLL does,
    // at a seq far past the from-zero window. Keyed on the wire slot this trips
    // PayloadOutOfWindow and closes the link — the regression.
    slot1
        .send(Some(Payload {
            seq: 8000,
            slot: 0,
            game_frame_count: Some(9000),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    // The turn is forwarded to slot 0, bound to the authorized slot 1.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot0.recv().await.unwrap().fresh;
    }
    assert_eq!(
        delivered[0].slot, 1,
        "the resumed turn keeps its authorized slot"
    );
    assert_eq!(delivered[0].seq, 8000);
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // And slot 1's link was not torn down over the past-window resumed turn.
    assert!(
        slot1.connection().close_reason().is_none(),
        "the resumed nonzero-slot link must survive its first past-window turn",
    );
}
