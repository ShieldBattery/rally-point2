//! Frames off the reliable control stream: what stalls the driver when the
//! game stops draining it, what is dropped instead, and forward compatibility
//! with a frame kind this build predates.

use super::*;

#[tokio::test]
async fn an_undrained_leave_channel_surfaces_a_stall_instead_of_parking() {
    // The driver's one loop carries turns and acks; a send into a
    // correctness-critical game channel whose receiver is retained but
    // never drained must surface as a stall, not park the loop (and the
    // whole session with it) on the wedged consumer.
    use rally_point_transport::control::send_control_leave;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // Push more synced leaves than the channel holds, with the receiver
    // (inside `chan_a`) alive but never drained.
    let (mut ctrl_send, _our_recv) = link_b.connection().open_bi().await.unwrap();
    for i in 0..(LEAVE_CHANNEL_CAPACITY as u32 + 4) {
        send_control_leave(
            &mut ctrl_send,
            LeaveDirective {
                finalized: false,
                slot: i,
                reason: 0,
                apply_at_frame: 0,
                leave_seq: i + 1,
                final_turn_count: None,
            },
        )
        .await
        .unwrap();
    }

    let joined = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver parked on the wedged leave consumer")
        .unwrap();
    assert!(
        matches!(joined, Err(DriverError::GameStalled)),
        "a wedged correctness-critical consumer is a stall: {joined:?}",
    );
    drop(chan_a);
}

#[tokio::test]
async fn released_region_labels_surface_on_the_game_channel() {
    // The relay releases the whole map at once; the driver hands the game the
    // complete `(relay_id, region)` list off the reliable control stream.
    use rally_point_proto::messages::RegionLabel;
    use rally_point_transport::control::send_control_region_labels;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, mut chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    send_control_region_labels(
        &mut peer_control_send,
        vec![
            RegionLabel {
                relay_id: 3,
                region: "us-east".to_owned(),
            },
            RegionLabel {
                relay_id: 8,
                region: "eu-central".to_owned(),
            },
        ],
    )
    .await
    .unwrap();

    let labels = tokio::time::timeout(Duration::from_secs(5), chan_a.region_labels.recv())
        .await
        .expect("the region labels arrive before the timeout")
        .expect("the channel stays open");
    assert_eq!(
        labels,
        vec![(3, "us-east".to_owned()), (8, "eu-central".to_owned()),],
    );

    // A re-send (the relay's re-fan after a re-home changes the map) replaces
    // rather than accumulates: the game reads the second frame's whole map.
    send_control_region_labels(
        &mut peer_control_send,
        vec![RegionLabel {
            relay_id: 11,
            region: "ap-southeast".to_owned(),
        }],
    )
    .await
    .unwrap();
    let labels = tokio::time::timeout(Duration::from_secs(5), chan_a.region_labels.recv())
        .await
        .expect("the re-sent map arrives before the timeout")
        .expect("the channel stays open");
    assert_eq!(labels, vec![(11, "ap-southeast".to_owned())]);

    drop(chan_a);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops once the game seam closes")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_control_frame_kind_this_build_predates_is_skipped_without_ending_the_stream() {
    // A relay running ahead of this client sends a frame kind it has no arm
    // for. The reader must skip it and keep reading, so a rolling deploy never
    // costs a client the frames it *does* understand.
    use rally_point_transport::control::send_control_session_start;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, mut chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    // A hand-built `ControlFrame` body carrying only an unknown oneof arm
    // (field 99, length-delimited, empty) — a tag no arm of this build claims.
    let body: &[u8] = &[0x9A, 0x06, 0x00];
    let mut framed = (body.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(body);
    peer_control_send.write_all(&framed).await.unwrap();

    // A kind this build does know, written straight after on the same stream:
    // it arrives, proving the unknown frame neither desynced the framing nor
    // tore the stream down.
    send_control_session_start(&mut peer_control_send, Some(3))
        .await
        .unwrap();
    let start = tokio::time::timeout(Duration::from_secs(5), chan_a.session_start.recv())
        .await
        .expect("the frame after the unknown one arrives before the timeout")
        .expect("the channel stays open");
    assert_eq!(start, Some(3));

    drop(chan_a);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops once the game seam closes")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn undrained_best_effort_channels_drop_instead_of_stalling_turns() {
    // Chat, skins, and connectivity are best-effort: a receiver that is
    // retained but never drained costs only the overflowing messages — the
    // turn stream (and the driver's acks with it) must keep flowing.
    use rally_point_proto::messages::{GameChat, PlayerSkin};
    use rally_point_transport::control::{send_control_chat, send_control_skin};

    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    // Hold every game-side channel half open; only `inbound` is drained.
    let TurnChannels {
        outbound: _outbound,
        mut inbound,
        result_expected: _result_expected,
        leaves: _leaves,
        leave_intent: _leave_intent,
        result: _result,
        game_started: _game_started,
        lobby_out: _lobby_out,
        lobby_in: _lobby_in,
        chat_out: _chat_out,
        chat_in: _chat_in,
        skin_out: _skin_out,
        skin_in: _skin_in,
        request_drop: _request_drop,
        session_start: _session_start,
        connectivity: _connectivity,
        region_labels: _region_labels,
        phase_status: _phase_status,
    } = chan_a;

    // Flood chat far past its buffer with nothing draining it.
    let (mut ctrl_send, _our_recv) = link_b.connection().open_bi().await.unwrap();
    for i in 0..(CHAT_CHANNEL_CAPACITY + 50) {
        send_control_chat(
            &mut ctrl_send,
            GameChat {
                slot: 1,
                target_kind: 0,
                target_slot: 0,
                text: format!("m{i}"),
            },
        )
        .await
        .unwrap();
    }

    // Flood skins far past their buffer too, with nothing draining them.
    for i in 0..(SKIN_CHANNEL_CAPACITY + 50) {
        send_control_skin(
            &mut ctrl_send,
            PlayerSkin {
                slot: 1,
                payload: vec![i as u8].into(),
            },
        )
        .await
        .unwrap();
    }

    // A turn sent after the flood still reaches the game: the overflow was
    // dropped, not parked on.
    link_b.send(Some(turn(0, &[0xAB]))).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("turns must still flow past a wedged chat consumer")
        .expect("the driver must still be running");
    assert_eq!(got.commands[0], 0xAB);

    drop(inbound);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
