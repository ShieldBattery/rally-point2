//! Turns reaching the game: both delivery paths, in-order release across
//! datagram reordering, envelope metadata, and out-of-range slot ids.

use super::*;

#[tokio::test]
async fn carries_turns_from_one_driver_to_the_other() {
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (driver_b, chan_b) = LinkDriver::new(link_b);
    let task_a = tokio::spawn(driver_a.run());
    let task_b = tokio::spawn(driver_b.run());

    // Three turns pushed into A's seam arrive in order, bytes intact, on B's.
    for i in 0..3u8 {
        chan_a.outbound.send(turn(0, &[i])).await.unwrap();
    }
    let mut inbound_b = chan_b.inbound;
    let mut got = Vec::new();
    while got.len() < 3 {
        got.push(inbound_b.recv().await.unwrap());
    }
    let bytes: Vec<u8> = got.iter().map(|p| p.commands[0]).collect();
    assert_eq!(bytes, vec![0, 1, 2]);

    // Dropping both senders stops both drivers cleanly.
    drop(chan_a.outbound);
    drop(chan_b.outbound);
    assert!(task_a.await.unwrap().is_ok());
    assert!(task_b.await.unwrap().is_ok());
}

#[tokio::test]
async fn an_over_mtu_turn_is_delivered_via_the_control_stream() {
    // A turn far larger than any datagram can never ride the datagram path
    // — no bundle could carry it, and no redundancy could recover it. The
    // driver must divert it to the reliable control stream, and the peer's
    // driver must fold it back into the ordered turn stream, interleaved
    // correctly with ordinary datagram turns around it.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (driver_b, chan_b) = LinkDriver::new(link_b);
    let task_a = tokio::spawn(driver_a.run());
    let task_b = tokio::spawn(driver_b.run());

    // An ordinary turn, then the oversize one, then another ordinary one:
    // the oversize turn takes a different path but must arrive in seq
    // order between its neighbors.
    chan_a.outbound.send(turn(0, &[0x01])).await.unwrap();
    chan_a
        .outbound
        .send(turn(0, &vec![0x42; 4096]))
        .await
        .unwrap();
    chan_a.outbound.send(turn(0, &[0x03])).await.unwrap();

    let mut inbound_b = chan_b.inbound;
    let mut got = Vec::new();
    while got.len() < 3 {
        let payload = tokio::time::timeout(Duration::from_secs(5), inbound_b.recv())
            .await
            .expect("the oversize turn never arrived")
            .expect("driver b closed early");
        got.push(payload);
    }
    assert_eq!(got[0].commands[0], 0x01);
    assert_eq!(
        got[1].commands.len(),
        4096,
        "the oversize turn arrives whole"
    );
    assert_eq!(got[1].commands[0], 0x42);
    assert_eq!(got[2].commands[0], 0x03);
    assert_eq!(
        got.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "one ordered stream regardless of delivery path",
    );

    drop(chan_a.outbound);
    drop(chan_b.outbound);
    let _ = task_a.await;
    let _ = task_b.await;
}

#[tokio::test]
async fn a_dead_control_stream_reader_surfaces_as_a_link_failure_while_the_connection_stays_up() {
    // The bug this guards: the control stream is the only channel a synced
    // `LeaveDirective`, `SessionStart`, and `SlotConnectivity` ever arrive on.
    // If its reader task ends while the connection is otherwise healthy (a
    // one-sided reset, an over-cap frame, a decode failure, or here a clean
    // EOF), the old code just disarmed the branch and limped on with
    // datagrams alone -- silently losing all three for the rest of the
    // session. The fix treats it as a link failure the same way
    // `link.recv()`'s own error arm does.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (mut link, mut seam, mut state) = into_session_parts(driver_a);

    // The peer opens its outbound control stream -- mirroring the relay's own
    // `open_bi()` in `routing::run_slot_link` -- then immediately finishes it:
    // a clean EOF with the connection itself left fully alive, exactly the
    // "control stream dead, link fine" split this bug is about.
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    let _ = peer_control_send.finish();

    let result = LinkDriver::session(&mut link, &mut seam, &mut state, SlotId(0)).await;
    assert!(
        matches!(result, Err(DriverError::ControlStreamLost)),
        "expected ControlStreamLost, got {result:?}",
    );
    assert!(
        is_link_failure(result.as_ref().unwrap_err()),
        "a dead control stream must be reconnect-eligible, like a broken link",
    );

    // The connection itself was never closed by `session` -- proof this is
    // a control-stream-only death, not a whole-link failure in disguise.
    // The close is the caller's job, after classification:
    // `run_reconnecting` closes it before re-dialing (see the test below),
    // and closing it in here instead would destroy the very distinction
    // this asserts.
    assert!(
        link.connection().close_reason().is_none(),
        "the underlying connection must stay alive; only the control stream died",
    );

    // Held for the whole test so the game-facing channel halves stay open
    // throughout `session()` -- nothing here exercises them, but a premature
    // drop would close `seam`'s peers and risk a different, unrelated exit.
    drop(chan_a);
}

#[tokio::test]
async fn delivers_reordered_payloads_to_the_game_in_seq_order() {
    use prost::Message;
    use rally_point_proto::messages::Packet;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut inbound = chan_a.inbound;

    // Hand-build two single-payload packets and deliver the higher payload seq
    // first; the driver must hold it until the lower seq arrives.
    let raw = |pkt_seq: u32, payload_seq: u64, byte: u8| {
        Packet {
            seq: pkt_seq,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: payload_seq,
                slot: 0,
                commands: vec![byte].into(),
                ..Default::default()
            }],
        }
        .encode_to_vec()
    };
    let conn = link_b.connection();
    conn.send_datagram(raw(0, 1, 0xB1).into()).unwrap();

    // Seq 1 must be held while seq 0 is missing — nothing reaches the game yet.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), inbound.recv())
            .await
            .is_err(),
        "seq 1 was delivered before the missing seq 0"
    );

    // Once seq 0 arrives, both drain in seq order.
    conn.send_datagram(raw(1, 0, 0xB0).into()).unwrap();
    let first = inbound.recv().await.unwrap();
    let second = inbound.recv().await.unwrap();
    assert_eq!((first.seq, first.commands[0]), (0, 0xB0));
    assert_eq!((second.seq, second.commands[0]), (1, 0xB1));

    drop(chan_a.outbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_datagram_turn_with_an_out_of_range_slot_ends_the_link_as_a_failure() {
    use prost::Message;
    use rally_point_proto::messages::Packet;

    // A payload whose slot id overflows `u8` names no real slot; a truncating
    // cast would alias it onto `slot % 256` and corrupt that player's turn
    // stream. The transport layer refuses the whole packet rather than risk
    // that aliasing, which surfaces here as a link failure -- reconnect-
    // eligible, not a turn silently dropped while the link limps on.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut inbound = chan_a.inbound;

    let raw = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![Payload {
            seq: 0,
            slot: 256,
            commands: vec![0xEE].into(),
            ..Default::default()
        }],
    }
    .encode_to_vec();
    link_b.connection().send_datagram(raw.into()).unwrap();

    // Nothing is ever delivered to the game...
    assert!(
        tokio::time::timeout(Duration::from_millis(300), inbound.recv())
            .await
            .unwrap()
            .is_none(),
        "an out-of-range inbound slot must not be delivered to the game",
    );
    // ...because the link itself ended as a failure, not a clean stop.
    match task.await.unwrap() {
        Err(DriverError::Link(_)) => {}
        other => panic!("expected a link failure, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversize_turn_with_an_out_of_range_slot_is_dropped() {
    // The control-stream divert path has its own guard, independent of the
    // datagram path's transport-layer rejection: a payload arriving this
    // way is already past `Link`'s dedup (this stream carries no dedup key
    // of its own), so the driver itself must reject an out-of-range slot
    // here rather than alias it onto a different player's turn stream.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut inbound = chan_a.inbound;

    let (mut control_send, _recv) = link_b.connection().open_bi().await.unwrap();
    send_control_turn(
        &mut control_send,
        Payload {
            seq: 0,
            slot: 256,
            commands: vec![0xEE].into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(300), inbound.recv())
            .await
            .is_err(),
        "an out-of-range oversize-turn slot must not be delivered to the game",
    );

    drop(chan_a.outbound);
    let _ = task.await;
}

#[tokio::test]
async fn envelope_metadata_survives_delivery_to_the_game() {
    use rally_point_proto::messages::BufferDirective;

    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut inbound = chan_a.inbound;

    // A relay-forwarded turn carries more than its command bytes: the frame
    // annotation and any latency-buffer directive the authority stamped ride
    // the envelope. The driver must hand the payload to the game whole — the
    // envelope is the game's only channel for the buffer directive, so a
    // driver that rebuilt payloads and dropped it would silently break buffer
    // changes for this client. (Leaves ride the control stream, not the
    // envelope — see the control-stream leave test.)
    let stamped = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0x0C].into(),
        game_frame_count: Some(41),
        buffer_directive: Some(BufferDirective {
            buffer_turns: 4,
            apply_at_frame: 64,
            decision_seq: 1,
            authority_relay_id: None,
        }),
    };
    link_b.send(Some(stamped.clone())).unwrap();

    let delivered = inbound.recv().await.unwrap();
    assert_eq!(delivered, stamped);

    drop(chan_a.outbound);
    let _ = task.await;
}
