//! End-to-end tests over a loopback QUIC pair: what a live link delivers —
//! each payload exactly once, every payload field carried verbatim — and what
//! the send side refuses before anything reaches the wire.

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
async fn preserves_payload_annotations_across_send_and_recv() {
    // The payload envelope is opaque to the link: it dedups and retires by
    // (slot, seq) alone and must carry every other field through verbatim —
    // the consensus frame and sync generation the relay and decision-maker key
    // on, and a relay-authored buffer directive the game applies out of band.
    // An absent field survives as absent too: None is a valid state (a lobby
    // turn, an ordinary turn with no directive), not zero.
    use rally_point_proto::messages::BufferDirective;
    let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

    let directive = BufferDirective {
        buffer_turns: 6,
        apply_at_frame: 512,
        decision_seq: 3,
        authority_relay_id: None,
    };
    client
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(1337),
            sync_generation: Some(73),
            buffer_directive: Some(directive),
            commands: vec![0x05].into(),
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
    assert_eq!(delivered[0].sync_generation, Some(73));
    assert_eq!(delivered[0].buffer_directive, Some(directive));
    assert_eq!(delivered[1].game_frame_count, None);
    assert_eq!(delivered[1].sync_generation, None);
    assert_eq!(delivered[1].buffer_directive, None);
}

#[tokio::test]
async fn delivers_a_redundant_low_seq_carried_after_a_high_fresh_one() {
    let (_client, mut server, _client_ep, _server_ep) = connected_links().await;

    // A deep-loss packet leads with a fresh seq at the very top of the receive
    // window and re-carries an older unacked one beside it. Leading with the
    // window edge must not shut the window on the seq-0 re-carry travelling in
    // the same packet: both are delivered, low seq first.
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

    let delivered = server.process_incoming(packet).unwrap().fresh;
    let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
    assert_eq!(seqs, vec![0, RECEIVE_WINDOW]);
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
