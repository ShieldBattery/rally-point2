//! The per-turn forwarding path: validation and slot rebinding on fan-out, the
//! buffer directive a forwarded turn carries, the oversize cap, and what happens
//! when a slot's control stream dies or it has no peer traffic to ride on.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::noq;

#[tokio::test]
async fn fans_a_validated_turn_to_the_other_slot() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(42);

    // Both clients must be registered before the turn is sent, or fan-out has no
    // peer to reach — the relay does not buffer for not-yet-connected slots.
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // A keep-alive, a client-injected latency change (relay strips it), and a
    // build. The wire slot is a lie the relay must overwrite with the authorized 0.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 9,
            commands: vec![0x05, 0x55, 0x02, 0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }

    assert_eq!(delivered.len(), 1);
    let turn = &delivered[0];
    // Bound to the authorized slot, not the value on the wire.
    assert_eq!(turn.slot, 0);
    // The latency control is stripped; gameplay commands pass through verbatim.
    assert_eq!(&turn.commands[..], &[0x05, 0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn stamps_a_pending_buffer_directive_onto_a_forwarded_turn() {
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::{LinkConditions, SlotConditions};
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(77);

    // Seed a buffer decision into the relay's decision-maker before any client
    // connects: create the session's maker as the authority, then feed it a
    // high-RTT sample so it decides to raise the buffer and queues that change
    // for broadcast. Holding the registry that `MeshState` carries is what lets
    // the test set this up; the relay's turn path then stamps it.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    // A framed turn was observed at frame 1, then a 150ms RTT sample -> target
    // 4 turns, raised from the min of 0, so the pending directive names buffer
    // 4 applied a horizon past frame 1.
    consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(1));
    let seed = LinkConditions {
        slots: vec![SlotConditions {
            slot: 0,
            rtt_us: 150_000,
            lost_packets: 0,
            sent_packets: 100,
            connection_epoch: None,
        }],
    };
    let decision = consensus::ingest_local_conditions(&makers, &key, &seed)
        .expect("the seeded high-RTT sample raises the buffer");

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Slot 0 sends a plain build with no frame of its own. The relay's live
    // loopback samples can't displace the seeded decision (a raise needs a
    // worse target than the seeded 150ms; a lower is dwell-gated), so the
    // pending directive stands, and the relay forwards the turn to slot 1.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }

    // The forwarded turn carries the buffer change the relay decided: slot 1 now
    // learns the new buffer and the frame to apply it at, riding the turn stream
    // it already receives — no separate channel, no forged command.
    let turn = &delivered[0];
    let directive = turn
        .buffer_directive
        .as_ref()
        .expect("the forwarded turn carries the pending buffer directive");
    assert_eq!(directive.buffer_turns, 4);
    assert_eq!(directive.apply_at_frame, decision.applied_frame.0);
    // The command bytes are untouched — the directive is envelope metadata, not a
    // command the game parses.
    assert_eq!(&turn.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn an_over_cap_oversize_turn_is_rejected_and_never_reaches_the_peer() {
    // The oversize-turn divert path fans a client's control-stream turn out to the
    // other slots' count-bounded forward queues, so a turn far larger than any real
    // one would occupy disproportionate buffered bytes there. A turn past the
    // amplification cap is not one any real client produces, so the relay rejects it
    // like a malformed turn — closing the link — before it can be buffered or fanned
    // out, rather than dropping it and stranding the peer on the seq gap.
    use rally_point_transport::control::send_control_turn;

    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(205);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // 9000 well-formed keep-alives: past the 8 KiB amplification cap, but under the
    // 64 KiB control-frame cap, so it reaches the relay's own size check rather than
    // the framing guard.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    let over_cap = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0x05u8; 9000].into(),
        game_frame_count: Some(1),
        ..Default::default()
    };
    send_control_turn(&mut ctrl0_send, over_cap).await.unwrap();

    // The relay closes the offending slot's link rather than buffering the turn.
    expect_closed(&mut slot0).await;

    // The peer never receives it: rejected before fan-out. Drain any maintenance
    // packets over a short window and assert none carries a fresh turn.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    while let Ok(received) = tokio::time::timeout_at(deadline, slot1.recv()).await {
        match received {
            Ok(delivery) => assert!(
                delivery.fresh.is_empty(),
                "an over-cap oversize turn must not reach the peer",
            ),
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn a_dead_control_stream_reader_closes_the_slot_link() {
    // The client's control stream is the only channel `RequestDrop` and a
    // clean leave-intent ever arrive on. If its reader task ends while the
    // connection is otherwise alive -- here a clean EOF, no reset -- the relay
    // must close the connection so the client's reconnect machinery takes
    // over with fresh streams, rather than just disarming and serving
    // datagrams forever while permanently losing both of those.
    //
    // Mirrors the private `routing::CONTROL_STREAM_LOST_CLOSE`, the same way
    // the decided-departure test below mirrors `server::SLOT_DEPARTED_CLOSE`
    // (that one is `pub` and imported directly; this one isn't, so the value
    // is hardcoded here).
    const CONTROL_STREAM_LOST_CLOSE: u32 = 0x07;

    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(206);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Open the client's outbound control stream -- the one the relay's
    // `control_rx` reads -- then immediately finish it: a clean EOF with the
    // connection itself left fully alive, exactly the "control stream dead,
    // link fine" split this bug is about.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    let _ = ctrl0_send.finish();

    // The relay closes the whole connection in response.
    expect_closed(&mut slot0).await;
    match slot0.connection().closed().await {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            CONTROL_STREAM_LOST_CLOSE,
            "the relay closes with the control-stream-lost code",
        ),
        other => panic!("expected an application close, got {other:?}"),
    }
}

#[tokio::test]
async fn acks_a_one_way_sender_with_no_peer_traffic() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // A lone slot: nothing is ever fanned back to it, so the relay has no forwarded
    // turn to carry acks on and must flush ack-only packets on its own cadence.
    let mut solo = connect_slot(&endpoint, addr, &tenant, SessionId(7), SlotId(0)).await;

    for seq in 0..3u64 {
        solo.send(Some(Payload {
            seq,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .unwrap();
    }
    assert_eq!(solo.payloads_in_flight(), 3);

    // Draining the relay's ack-only packets must retire everything in flight, even
    // though no turn ever comes back the other way. Each recv yields the relay's
    // idle ack flush; the per-recv timeout sits above the flush delay, and the loop
    // is bounded so a missing flush fails rather than hangs.
    let mut retired = false;
    for _ in 0..15 {
        let _ = tokio::time::timeout(Duration::from_millis(400), solo.recv()).await;
        if solo.payloads_in_flight() == 0 {
            retired = true;
            break;
        }
    }
    assert!(
        retired,
        "relay never acked the one-way sender; {} payloads still in flight",
        solo.payloads_in_flight()
    );
}
