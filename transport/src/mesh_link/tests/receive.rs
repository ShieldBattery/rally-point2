//! What a session does with the payloads inside a datagram it accepted.
//!
//! Grouped around the receive window and the delivered-through cursors it
//! feeds: dedup and in-place compaction, rollback when a packet fails
//! part-way through, mid-stream resumption, and folding in a payload that
//! arrived over the control stream instead.

use super::*;

/// The mesh-link counterpart of `Link`'s transactional-recv regression
/// test: a packet whose earlier payload is genuinely acceptable but whose
/// later payload fails the whole packet must roll back the earlier
/// payload's dedup commit, not leave it marked delivered while discarding
/// it from the returned `fresh`. The packet-ending failure here is a
/// malformed slot (out of `SlotId` range): a far-ahead seq no longer ends
/// a mesh packet — the forward-collapsing window admits it — so a bad slot
/// is the failure that still exercises the rollback on this path.
#[tokio::test]
async fn a_mid_packet_malformed_slot_rolls_back_the_session_link_too() {
    let (sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    receiver.open_session(session);

    let mesh_packet = MeshPacket {
        session: session.0,
        packet: Some(Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                turn(0, 0, 0xAA),
                Payload {
                    seq: 0,
                    slot: 300, // out of u8 range
                    commands: vec![0xBB].into(),
                    ..Default::default()
                },
            ],
        }),
        conditions: None,
        tenant: None,
    };
    sender
        .connection()
        .send_datagram(mesh_packet.encode_to_vec().into())
        .unwrap();

    match receiver.recv().await {
        Err(MeshLinkError::MalformedSlot(slot)) => assert_eq!(slot, 300),
        other => panic!("expected MalformedSlot, got {other:?}"),
    }
    assert_eq!(
        receiver.delivered_through(session, SlotId(0)),
        None,
        "the in-window payload's provisional accept rolls back with the packet",
    );

    // Redelivered alone, the same seq is accepted as new.
    let retry = MeshPacket {
        session: session.0,
        packet: Some(Packet {
            seq: 1,
            ack: None,
            ack_bits: 0,
            payloads: vec![turn(0, 0, 0xAA)],
        }),
        conditions: None,
        tenant: None,
    };
    sender
        .connection()
        .send_datagram(retry.encode_to_vec().into())
        .unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(session, SlotId(0)), Some(0));
}

#[test]
fn session_receive_compacts_fresh_payloads_in_the_decoded_vector() {
    let mut link = SessionLink {
        acks: AckManager::new(),
        dedup: Dedup::with_forward_collapse(),
    };
    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            turn(0, 1, 0xB1),
            turn(0, 0, 0xA0),
            turn(0, 0, 0xD0),
            turn(1, 0, 0xC0),
        ],
    };
    let allocation = packet.payloads.as_ptr();
    let capacity = packet.payloads.capacity();

    let received = link.process_incoming(packet).unwrap();

    assert_eq!(received.fresh.as_ptr(), allocation);
    assert_eq!(received.fresh.capacity(), capacity);
    assert_eq!(received.fresh.len(), 3);
    assert_eq!(received.fresh[0].commands.as_ref(), &[0xA0]);
    assert_eq!(received.fresh[1].commands.as_ref(), &[0xB1]);
    assert_eq!(received.fresh[2].commands.as_ref(), &[0xC0]);
    assert_eq!(link.dedup.delivered_through(SlotId(0)), Some(1));
    assert_eq!(link.dedup.delivered_through(SlotId(1)), Some(0));
}

/// `delivered_through_all` is the mesh ack-cursor push's source: it must
/// report every slot that has actually delivered something (not just the
/// one a caller happens to ask `delivered_through` for), stay empty for a
/// session with nothing delivered yet, and never see slots or sessions it
/// isn't asked about.
#[tokio::test]
async fn delivered_through_all_reflects_every_slot_with_a_delivered_prefix() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session_a = SessionId(1);
    let session_b = SessionId(2);
    sender.open_session(session_a);
    sender.open_session(session_b);
    receiver.open_session(session_a);
    receiver.open_session(session_b);

    // Nothing delivered yet: empty, not an error.
    assert_eq!(receiver.delivered_through_all(session_a), Vec::new());

    // Each slot needs its own contiguous prefix from seq 0 to register a
    // delivered-through cursor at all (an isolated high seq just sits in
    // the out-of-order `ahead` set) -- so slot 2 gets seqs 0..=5 while
    // slot 0 gets only seq 0, proving the two cursors are independent.
    sender
        .send(session_a, Some(turn(0, 0, 0xA0)), None)
        .unwrap();
    for seq in 0..=5u64 {
        let payload = Payload {
            seq,
            slot: 2,
            commands: vec![0xA1].into(),
            ..Default::default()
        };
        sender.send(session_a, Some(payload), None).unwrap();
    }
    for _ in 0..7 {
        receiver.recv().await.unwrap();
    }

    let mut cursors = receiver.delivered_through_all(session_a);
    cursors.sort_by_key(|&(slot, _)| slot.0);
    assert_eq!(cursors, vec![(SlotId(0), 0), (SlotId(2), 5)]);

    // Session B never received anything, so it stays empty even though
    // session A (sharing the same connection) has state now -- the
    // session must not enter the reported set.
    assert_eq!(receiver.delivered_through_all(session_b), Vec::new());
}

/// A mesh session's receive window admits a mid-stream first contact far
/// past a from-zero window — a link that redialed deep into a game, or a
/// relay newly joining a running session, receives the live stream at
/// whatever seq the game has reached. The strict client-edge behavior
/// (reject and close) would reset the link forever; the mesh window
/// instead collapses forward and keeps a full window open *below* the far
/// seq, so the sender's still-unacked backlog behind it is delivered too,
/// not misread as already-seen.
#[tokio::test]
async fn a_mesh_session_accepts_a_mid_stream_first_contact_far_past_the_window() {
    let (sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    receiver.open_session(session);

    // The live stream's freshest seq arrives first (seq 8000, far past the
    // 4096-seq window), then the backlog behind it (the sender's unacked
    // re-carries). Deliver them as raw wire packets so the receiver's
    // acceptance is what's under test, not the sender's ack state.
    let mut send_seq = 0u32;
    let mut send_raw = |seqs: &[u64]| {
        let mesh_packet = MeshPacket {
            session: session.0,
            packet: Some(Packet {
                seq: send_seq,
                ack: None,
                ack_bits: 0,
                payloads: seqs.iter().map(|&seq| turn(0, seq, seq as u8)).collect(),
            }),
            conditions: None,
            tenant: None,
        };
        send_seq += 1;
        sender
            .connection()
            .send_datagram(mesh_packet.encode_to_vec().into())
            .unwrap();
    };

    send_raw(&[8000]);
    let received = receiver.recv().await.unwrap();
    assert_eq!(
        received.delivery.fresh.len(),
        1,
        "the far first-contact seq is delivered, not rejected as out-of-window",
    );

    // The backlog behind it is still within the collapsed window and must
    // be delivered as fresh — landing the window base any higher than a
    // full window below the far seq would silently drop it.
    send_raw(&[7990, 7991, 7992]);
    let received = receiver.recv().await.unwrap();
    let seqs: Vec<u64> = received.delivery.fresh.iter().map(|p| p.seq).collect();
    assert_eq!(seqs, vec![7990, 7991, 7992]);
}

/// `anchor_receive_window` resumes a session's slot mid-stream at its
/// forwarded-to-locals cursor: the resumed stream is accepted from the
/// anchor, copies below it dedup as already-delivered, and the
/// delivered-through cursor is truthful from the first datagram (no
/// collapse detour through a below-anchor base).
#[tokio::test]
async fn anchor_receive_window_resumes_a_mesh_session_at_its_cursor() {
    let (sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    receiver.open_session(session);
    receiver.anchor_receive_window(session, SlotId(0), 5000);

    let mesh_packet = MeshPacket {
        session: session.0,
        packet: Some(Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            // A replayed already-forwarded copy (4999) rides alongside the
            // resumed stream (5000..5002) — the anchor makes the former a
            // duplicate and the latter fresh.
            payloads: vec![
                turn(0, 4999, 0x00),
                turn(0, 5000, 0x01),
                turn(0, 5001, 0x02),
                turn(0, 5002, 0x03),
            ],
        }),
        conditions: None,
        tenant: None,
    };
    sender
        .connection()
        .send_datagram(mesh_packet.encode_to_vec().into())
        .unwrap();

    let received = receiver.recv().await.unwrap();
    let seqs: Vec<u64> = received.delivery.fresh.iter().map(|p| p.seq).collect();
    assert_eq!(seqs, vec![5000, 5001, 5002]);
    assert_eq!(
        receiver.delivered_through(session, SlotId(0)),
        Some(5002),
        "the prefix advances from the anchor, so the ack-cursor push is truthful",
    );
}

/// `deliver_external` folds a stream-delivered seq into the same per-slot
/// dedup the datagram path uses, exactly like the client edge's fold: the
/// delivered prefix advances across the stream-delivered gap (so the
/// ack-cursor push doesn't stall behind it forever), and a duplicate is
/// reported rather than re-delivered.
#[tokio::test]
async fn deliver_external_folds_a_stream_delivered_seq_into_the_session_dedup() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // Datagram seqs 0 and 1 arrive normally.
    sender.send(session, Some(turn(0, 0, 0xA0)), None).unwrap();
    sender.send(session, Some(turn(0, 1, 0xA1)), None).unwrap();
    for _ in 0..2 {
        receiver.recv().await.unwrap();
    }
    assert_eq!(receiver.delivered_through(session, SlotId(0)), Some(1));

    // Seq 2 was too large for a datagram and arrived over the control
    // stream: folding it advances the prefix as a datagram delivery would.
    assert!(receiver.deliver_external(session, SlotId(0), 2).unwrap());
    assert_eq!(
        receiver.delivered_through(session, SlotId(0)),
        Some(2),
        "the stream-delivered seq closes the gap instead of stalling the prefix",
    );

    // A redundant copy of the same stream-delivered seq is a duplicate.
    assert!(!receiver.deliver_external(session, SlotId(0), 2).unwrap());

    // The datagram path continues past the folded seq without a gap.
    sender.send(session, Some(turn(0, 3, 0xA3)), None).unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(session, SlotId(0)), Some(3));

    // A session that was never opened is a driver bug, surfaced like send.
    match receiver.deliver_external(SessionId(9), SlotId(0), 0) {
        Err(MeshLinkError::UnknownSession(sid)) => assert_eq!(sid, SessionId(9)),
        other => panic!("expected UnknownSession, got {other:?}"),
    }
}
