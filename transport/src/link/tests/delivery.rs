//! End-to-end tests over a loopback QUIC pair: what a live link delivers —
//! each payload exactly once, each slot independently, every payload field
//! carried verbatim — and what it refuses on the wire, an out-of-window seq
//! or a wire slot too wide for a `SlotId`.

use super::*;

#[tokio::test]
async fn delivers_each_payload_once_and_retires_on_ack() {
    let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

    for i in 0..5u8 {
        client.send(Some(turn(0, i as u64, i))).unwrap();
    }
    assert_eq!(client.payloads_in_flight(), 5);

    // Each packet re-carries earlier unacked payloads, but every payload is
    // returned exactly once, in order, with its bytes intact.
    let mut delivered = Vec::new();
    while delivered.len() < 5 {
        delivered.extend(server.recv().await.unwrap().fresh);
    }
    let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    let bytes: Vec<u8> = delivered.iter().map(|p| p.commands[0]).collect();
    assert_eq!(bytes, vec![0, 1, 2, 3, 4]);

    // The server's ack-only reply retires everything the client had in flight.
    server.send(None).unwrap();
    client.recv().await.unwrap();
    assert_eq!(client.payloads_in_flight(), 0);
}

#[tokio::test]
async fn preserves_game_frame_count_across_send_and_recv() {
    // The frame is a consensus annotation, not a transport key: the link
    // dedups and retires by (slot, seq) and must carry the frame through
    // verbatim so the relay and decision-maker can key on it. A None (lobby
    // turn) survives too — absent is a valid state, not zero.
    let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

    client
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(1337),
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .unwrap();
    client
        .send(Some(Payload {
            seq: 1,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.len() < 2 {
        delivered.extend(server.recv().await.unwrap().fresh);
    }
    delivered.sort_by_key(|p| p.seq);
    assert_eq!(delivered[0].game_frame_count, Some(1337));
    assert_eq!(delivered[1].game_frame_count, None);
}

#[tokio::test]
async fn preserves_buffer_directive_across_send_and_recv() {
    // A relay-authored buffer change rides the Payload envelope, so the link
    // must carry it through verbatim like any other payload field — it is not
    // a transport key (dedup and retirement stay on (slot, seq)), just metadata
    // the game applies out of band. Absent is the common case and survives too.
    use rally_point_proto::messages::BufferDirective;
    let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

    client
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(500),
            buffer_directive: Some(BufferDirective {
                buffer_turns: 6,
                apply_at_frame: 512,
                decision_seq: 3,
                authority_relay_id: None,
            }),
            commands: vec![0x0C].into(),
        }))
        .unwrap();
    client
        .send(Some(Payload {
            seq: 1,
            slot: 0,
            game_frame_count: Some(501),
            commands: vec![0x0C].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.len() < 2 {
        delivered.extend(server.recv().await.unwrap().fresh);
    }
    delivered.sort_by_key(|p| p.seq);
    assert_eq!(
        delivered[0].buffer_directive,
        Some(BufferDirective {
            buffer_turns: 6,
            apply_at_frame: 512,
            decision_seq: 3,
            authority_relay_id: None,
        }),
    );
    assert_eq!(delivered[1].buffer_directive, None);
}

#[tokio::test]
async fn delivers_each_slot_independently() {
    // Two slots' turns interleave on the wire; each is dedup'd by (slot, seq).
    let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

    client.send(Some(turn(0, 0, 0xA0))).unwrap();
    client.send(Some(turn(1, 0, 0xB0))).unwrap();
    client.send(Some(turn(0, 1, 0xA1))).unwrap();
    client.send(Some(turn(1, 1, 0xB1))).unwrap();

    let mut delivered = Vec::new();
    while delivered.len() < 4 {
        delivered.extend(server.recv().await.unwrap().fresh);
    }

    // Slot 0's turns and slot 1's turns each arrive in their own seq order;
    // the two streams are independent.
    let slot0: Vec<u8> = delivered
        .iter()
        .filter(|p| p.slot == 0)
        .map(|p| p.commands[0])
        .collect();
    let slot1: Vec<u8> = delivered
        .iter()
        .filter(|p| p.slot == 1)
        .map(|p| p.commands[0])
        .collect();
    assert_eq!(slot0, vec![0xA0, 0xA1]);
    assert_eq!(slot1, vec![0xB0, 0xB1]);
}

#[tokio::test]
async fn delivers_a_redundant_low_seq_carried_after_a_high_fresh_one() {
    let (client, mut server, _client_ep, _server_ep) = connected_links().await;

    // A deep-loss packet leads with a high fresh seq and re-carries an older
    // unacked one. Both must be delivered — the low seq is not dropped.
    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            Payload {
                seq: RECEIVE_WINDOW,
                slot: 0,
                commands: vec![0xAA].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xBB].into(),
                ..Default::default()
            },
        ],
    };
    client
        .connection()
        .send_datagram(packet.encode_to_vec().into())
        .unwrap();

    let delivered = server.recv().await.unwrap().fresh;
    let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
    assert_eq!(seqs, vec![0, RECEIVE_WINDOW]);
}

#[tokio::test]
async fn rejects_payload_seq_beyond_the_window() {
    let (client, mut server, _client_ep, _server_ep) = connected_links().await;

    // A seq racing far past our contiguous progress must be rejected, not
    // panic the receiver.
    let malformed = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![Payload {
            seq: u64::MAX,
            slot: 0,
            commands: vec![1].into(),
            ..Default::default()
        }],
    };
    client
        .connection()
        .send_datagram(malformed.encode_to_vec().into())
        .unwrap();

    match server.recv().await {
        Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
            assert_eq!(slot, SlotId(0));
            assert_eq!(seq, u64::MAX);
        }
        other => panic!("expected PayloadOutOfWindow, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_payload_whose_wire_slot_does_not_fit_a_slot_id() {
    let (client, mut server, _client_ep, _server_ep) = connected_links().await;

    // A wire slot past `u8` range must be refused, not silently truncated
    // onto a different, valid slot's dedup state (`300 as u8` would alias
    // onto slot 44).
    let malformed = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![Payload {
            seq: 0,
            slot: 300,
            commands: vec![1].into(),
            ..Default::default()
        }],
    };
    client
        .connection()
        .send_datagram(malformed.encode_to_vec().into())
        .unwrap();

    match server.recv().await {
        Err(LinkError::MalformedSlot(slot)) => assert_eq!(slot, 300),
        other => panic!("expected MalformedSlot, got {other:?}"),
    }
}

#[tokio::test]
async fn send_rejects_a_payload_whose_wire_slot_does_not_fit_a_slot_id() {
    let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

    // A wire slot past `u8` range is refused before any send-side state is
    // built for it, rather than narrowed onto a different, valid slot's
    // bookkeeping (`300 as u8` would alias onto slot 44).
    let malformed = Payload {
        seq: 0,
        slot: 300,
        commands: vec![1].into(),
        ..Default::default()
    };
    match client.send(Some(malformed)) {
        Err(LinkError::MalformedSlot(slot)) => assert_eq!(slot, 300),
        other => panic!("expected MalformedSlot, got {other:?}"),
    }
    // Nothing was tracked: the refused turn never entered the unacked window.
    assert_eq!(client.payloads_in_flight(), 0);
}
