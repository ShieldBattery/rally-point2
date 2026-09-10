//! Tests for turning one decoded packet into deliveries: the single-slot
//! ingress edge's rewrite of the untrusted wire slot, the per-wire-slot demux
//! a multi-slot link keeps instead, the all-or-nothing dedup commit when a
//! packet fails partway, and the in-place compaction of the decoded vector.

use super::*;

#[tokio::test]
async fn ingress_slot_rebinds_a_wire_slot_zero_payload_to_the_authorized_slot() {
    // A relay's client edge authorizes one slot. The real game client leaves the
    // wire slot at 0 on every turn, but dedup and the receive-window anchor key
    // on the authorized slot. An ingress link rewrites the wire slot before
    // dedup, so a resumed high-seq stream anchored on the authorized slot is
    // accepted — not rejected as out-of-window under a phantom slot-0 key.
    let (raw, _peer, _ea, _eb) = connected_connections().await;
    let mut link = Link::with_ingress_slot(raw, SlotId(1));
    link.anchor_receive_window(SlotId(1), 8000);

    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![Payload {
            seq: 8000,
            slot: 0, // the untrusted wire claim the real client always sends
            commands: vec![0x05].into(),
            ..Default::default()
        }],
    };
    let received = link.process_incoming(packet).unwrap();
    assert_eq!(received.fresh.len(), 1);
    // Rebound to the authorized slot, both in the dedup key and on the payload.
    assert_eq!(received.fresh[0].slot, 1);
    assert_eq!(link.delivered_through(SlotId(1)), Some(8000));
    // Nothing was ever keyed under the wire slot 0.
    assert_eq!(link.delivered_through(SlotId(0)), None);
}

/// A packet whose earlier payloads are genuinely in-window but whose LAST
/// payload is out of window must not leave dedup believing the earlier
/// ones were delivered: the whole packet rolls back, so the caller can
/// re-receive them later rather than losing them to a permanent silent
/// gap. This is the core transactional-recv regression: the old code
/// committed each payload to dedup as it went and only bailed on the
/// offending one, discarding the already-accepted payloads from the
/// return value while dedup kept them marked delivered.
#[tokio::test]
async fn a_mid_packet_out_of_window_payload_rolls_back_the_whole_packets_dedup_commit() {
    let (raw, _peer, _ea, _eb) = connected_connections().await;
    let mut link = Link::new(raw);

    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            // Genuinely in-window and would be delivered on its own.
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xAA].into(),
                ..Default::default()
            },
            // Far beyond the receive window -- the whole packet fails.
            Payload {
                seq: u64::MAX,
                slot: 0,
                commands: vec![0xBB].into(),
                ..Default::default()
            },
        ],
    };
    match link.process_incoming(packet) {
        Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
            assert_eq!(slot, SlotId(0));
            assert_eq!(seq, u64::MAX);
        }
        other => panic!("expected PayloadOutOfWindow, got {other:?}"),
    }

    // The rollback: slot 0 must show no delivered prefix at all -- the
    // seq-0 payload was never actually handed to a caller (it's absent
    // from every `Received.fresh` this test ever saw), so dedup must not
    // remember it as delivered either.
    assert_eq!(
        link.delivered_through(SlotId(0)),
        None,
        "the in-window payload's provisional accept must be rolled back \
         along with the packet that failed",
    );

    // Proof it's genuinely recoverable: the same seq, redelivered alone
    // in a fresh packet, is accepted as new -- not rejected as a
    // duplicate of something the caller never actually received.
    let retry = Packet {
        seq: 1,
        ack: None,
        ack_bits: 0,
        payloads: vec![Payload {
            seq: 0,
            slot: 0,
            commands: vec![0xAA].into(),
            ..Default::default()
        }],
    };
    let received = link.process_incoming(retry).unwrap();
    assert_eq!(received.fresh.len(), 1, "the payload is deliverable again");
    assert_eq!(link.delivered_through(SlotId(0)), Some(0));
}

/// The same rollback, but the packet-ending failure is a malformed slot
/// (out of `u8` range) rather than an out-of-window seq -- an earlier
/// payload for a DIFFERENT, valid slot in the same packet must also be
/// rolled back, not left half-committed.
#[tokio::test]
async fn a_trailing_malformed_slot_rolls_back_an_earlier_valid_slots_commit_too() {
    let (raw, _peer, _ea, _eb) = connected_connections().await;
    let mut link = Link::new(raw);

    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xAA].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 300, // out of u8 range
                commands: vec![0xBB].into(),
                ..Default::default()
            },
        ],
    };
    match link.process_incoming(packet) {
        Err(LinkError::MalformedSlot(300)) => {}
        other => panic!("expected MalformedSlot(300), got {other:?}"),
    }
    assert_eq!(
        link.delivered_through(SlotId(0)),
        None,
        "slot 0's earlier commit rolls back alongside the malformed payload",
    );
}

#[tokio::test]
async fn a_non_ingress_link_keeps_per_wire_slot_demux() {
    // A link with no ingress slot (the fan-in and mesh links) trusts the wire
    // slot: two payloads with different wire slots dedup independently, each
    // under its own key. This is the behavior the ingress rebind must not
    // disturb on multi-slot links.
    let (raw, _peer, _ea, _eb) = connected_connections().await;
    let mut link = Link::new(raw);

    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xA0].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 1,
                commands: vec![0xB0].into(),
                ..Default::default()
            },
        ],
    };
    let received = link.process_incoming(packet).unwrap();
    assert_eq!(received.fresh.len(), 2);
    // Each wire slot advanced its own prefix; neither collapsed into the other.
    assert_eq!(link.delivered_through(SlotId(0)), Some(0));
    assert_eq!(link.delivered_through(SlotId(1)), Some(0));
}

#[tokio::test]
async fn receive_compacts_fresh_payloads_in_the_decoded_vector() {
    let (raw, _peer, _ea, _eb) = connected_connections().await;
    let mut link = Link::new(raw);

    // Deliberately unsorted, with two copies of (slot 0, seq 0). Stable
    // low-seq sorting keeps the first copy, then in-place dedup removes the
    // redundant one without replacing the protobuf decoder's Vec.
    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![
            Payload {
                seq: 1,
                slot: 0,
                commands: vec![0xB1].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xA0].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xD0].into(),
                ..Default::default()
            },
            Payload {
                seq: 0,
                slot: 1,
                commands: vec![0xC0].into(),
                ..Default::default()
            },
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
    assert_eq!(link.delivered_through(SlotId(0)), Some(1));
    assert_eq!(link.delivered_through(SlotId(1)), Some(0));
}

#[tokio::test]
async fn same_relay_resume_on_a_nonzero_slot_accepts_a_wire_slot_zero_stream() {
    // The exact production regression, one layer below the relay: the resuming
    // client is authorized on a NONZERO slot but — like the real DLL — stamps
    // wire slot 0 on every turn. The same-relay anchor is keyed on the authorized
    // slot, so a relay edge that keyed dedup on the wire slot would anchor slot N
    // yet dedup slot 0, making the anchor a silent no-op and rejecting the first
    // resumed turn past the window. The ingress-slot rebind keeps both on slot N.
    let (raw_sender, raw_relay, _ea, _eb) = connected_connections().await;
    let mut sender = Link::new(raw_sender);

    // The client counts its own seqs across the move but always sends wire slot 0.
    let turn = |seq: u64| Payload {
        seq,
        slot: 0,
        commands: vec![0u8; 4].into(),
        ..Default::default()
    };
    for seq in [8000u64, 8001, 8002] {
        sender.send(Some(turn(seq))).unwrap();
    }
    let anchor = sender
        .oldest_replayable_seq(SlotId(0))
        .expect("turns are in flight");
    assert_eq!(
        anchor, 8000,
        "the same-relay anchor is the oldest unacked seq"
    );

    // The fresh relay edge authorizes this client as slot 1 and anchors slot 1 at
    // the resume point. Even though every incoming payload claims wire slot 0, the
    // rebind keys them under slot 1, where the anchor lives.
    let mut relay = Link::with_ingress_slot(raw_relay, SlotId(1));
    relay.anchor_receive_window(SlotId(1), anchor);
    for seq in [8000u64, 8001, 8002] {
        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![turn(seq)],
        };
        let received = relay.process_incoming(packet).unwrap();
        assert_eq!(received.fresh.len(), 1);
        assert_eq!(received.fresh[0].slot, 1, "rebound to the authorized slot");
    }
    assert_eq!(relay.delivered_through(SlotId(1)), Some(8002));

    // The bug shape for contrast: a wire-slot-keyed edge (no ingress rebind)
    // anchors slot 1 but dedups the wire-slot-0 payload under slot 0's from-zero
    // window, so it rejects the very first resumed turn and would close the link.
    let (raw_bad, _peer, _ec, _ed) = connected_connections().await;
    let mut buggy = Link::new(raw_bad);
    buggy.anchor_receive_window(SlotId(1), anchor);
    let packet = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: vec![turn(8000)],
    };
    match buggy.process_incoming(packet) {
        Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
            assert_eq!(slot, SlotId(0));
            assert_eq!(seq, 8000);
        }
        other => panic!("expected the wire-slot-keyed edge to reject, got {other:?}"),
    }
}
