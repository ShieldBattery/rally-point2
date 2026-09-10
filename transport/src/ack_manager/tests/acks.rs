//! Packet seq assignment and the ack exchange: what a built packet is stamped
//! with, which of our payloads an incoming ack retires, and the inconsistent
//! ack states an incoming packet is rejected for.

use super::*;

#[test]
fn packet_seq_numbers_increment_and_payload_seq_is_preserved() {
    let mut manager = AckManager::new();
    for i in 0..10u64 {
        let packet = manager
            .build_outgoing(Some(test_payload(0, i)), MTU)
            .unwrap();
        assert_eq!(packet.seq, i as u32);
        // The fresh payload is always pushed first, its seq preserved.
        assert_eq!(packet.payloads[0].seq, i);
    }
}

#[test]
fn build_outgoing_surfaces_packet_seq_exhaustion_instead_of_panicking() {
    let mut manager = AckManager::new();
    // Drive the seq counter to its ceiling directly; assigning 2^32 seqs to
    // reach it for real is infeasible in a test. The next build would have to
    // wrap u32::MAX, which is refused.
    manager.packet_seq = u32::MAX;
    assert_eq!(
        manager.build_outgoing(Some(test_payload(0, 0)), MTU),
        Err(PacketSeqExhausted),
    );
    // No state was mutated: the counter is untouched and nothing was tracked,
    // so a caller that resets the connection can retry cleanly.
    assert_eq!(manager.next_packet_seq(), u32::MAX);
    assert_eq!(manager.payloads_in_flight(), 0);
}

#[test]
fn ack_only_packet_has_no_payloads() {
    let mut manager = AckManager::new();
    let packet = manager.build_outgoing(None, MTU).unwrap();

    assert!(packet.payloads.is_empty());
    assert_eq!(packet.ack, None);
    assert_eq!(packet.ack_bits, 0);
    // No payload was carried, but a packet seq was.
    assert_eq!(manager.next_packet_seq(), 1);
    assert_eq!(manager.payloads_in_flight(), 0);
}

#[test]
fn ack_with_early_receives() {
    // Budget of 0 suppresses redundancy so each payload rides exactly one
    // packet — giving fine-grained control over what's acked.
    let mut manager = AckManager::new();
    for i in 0..10u64 {
        build_sent(&mut manager, Some(test_payload(0, i)), 0);
    }
    assert_eq!(manager.payloads_in_flight(), 10);

    // A packet with no ack retires nothing.
    manager.handle_incoming(&incoming(0, None, &[])).unwrap();
    assert_eq!(manager.payloads_in_flight(), 10);

    manager.handle_incoming(&incoming(1, Some(0), &[])).unwrap();
    assert_eq!(manager.payloads_in_flight(), 9);

    manager
        .handle_incoming(&incoming(2, Some(1), &[0]))
        .unwrap();
    manager
        .handle_incoming(&incoming(3, Some(1), &[0]))
        .unwrap();
    manager
        .handle_incoming(&incoming(4, Some(2), &[0, 1]))
        .unwrap();
    // Our packet 3 was dropped on the way to the peer.
    manager
        .handle_incoming(&incoming(5, Some(4), &[0, 1, 2]))
        .unwrap();
    // Peer packets 5 and 6 reach us out of order acking up to our packet 9.
    manager
        .handle_incoming(&incoming(6, Some(9), &[0, 1, 2, 4, 7, 8]))
        .unwrap();
    assert_eq!(manager.payloads_in_flight(), 3);

    let packet = build_sent(&mut manager, Some(test_payload(0, 10)), 0);
    // We've received peer packets 0..=6, all present.
    assert_eq!(packet.ack, Some(6));
    assert_eq!(packet.ack_bits, 0b0011_1111);

    // Peer packet 7 was dropped; 8 arrives acking up to our packet 10.
    manager
        .handle_incoming(&incoming(8, Some(10), &[0, 1, 2, 3, 4, 7, 8, 9]))
        .unwrap();
    assert_eq!(manager.payloads_in_flight(), 2);

    let packet = build_sent(&mut manager, Some(test_payload(0, 11)), 0);
    assert_eq!(packet.ack, Some(8));
    // Bit 0 (peer packet 7) is clear; the rest of the window is set.
    assert_eq!(packet.ack_bits, 0b1111_1110);
}

#[test]
fn rejects_ack_for_unsent_packet() {
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap(); // only packet 0 sent

    assert_eq!(
        manager.handle_incoming(&incoming(0, Some(1), &[])),
        Err(AckError::AckAheadOfSent { ack: 1, sent: 1 })
    );
}

#[test]
fn rejects_ack_bits_without_ack() {
    let mut manager = AckManager::new();
    let mut packet = incoming(0, None, &[]);
    packet.ack_bits = 0b1;

    assert_eq!(
        manager.handle_incoming(&packet),
        Err(AckError::AckBitsWithoutAck)
    );
}

#[test]
fn rejects_ack_bits_referencing_prehistory() {
    // Send one packet so ack 0 is itself valid (0 < 1 sent).
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap();

    // ack 0 with bit 0 set claims to ack packet -1, which cannot exist.
    let packet = Packet {
        seq: 0,
        ack: Some(0),
        ack_bits: 0b1,
        payloads: Vec::new(),
    };

    assert_eq!(
        manager.handle_incoming(&packet),
        Err(AckError::AckBitsOutOfRange {
            ack: 0,
            ack_bits: 0b1
        })
    );
}

#[test]
fn symmetric_500_sends_without_loss() {
    let mut local = AckManager::new();
    let mut remote = AckManager::new();

    for i in 0..500u64 {
        let outgoing = build_sent(&mut local, Some(test_payload(0, i)), MTU);
        let incoming = build_sent(&mut remote, Some(test_payload(0, i)), MTU);
        remote.handle_incoming(&outgoing).unwrap();
        local.handle_incoming(&incoming).unwrap();
    }

    // Only the final payload from each side is still in flight: nothing was
    // built after it was seen, so it was never acked.
    assert_eq!(local.payloads_in_flight(), 1);
    assert_eq!(remote.payloads_in_flight(), 1);
}

#[test]
fn symmetric_100_sends_with_25pct_loss() {
    let mut local = AckManager::new();
    let mut remote = AckManager::new();

    let mut drop_count = 0;
    for i in 0..100u64 {
        let outgoing = build_sent(&mut local, Some(test_payload(0, i)), MTU);
        let incoming = build_sent(&mut remote, Some(test_payload(0, i)), MTU);

        // Drop every 4th local -> remote packet.
        if i % 4 == 0 {
            drop_count += 1;
        } else {
            remote.handle_incoming(&outgoing).unwrap();
        }
        local.handle_incoming(&incoming).unwrap();
    }
    assert_eq!(drop_count, 25);

    // Redundancy still delivers every payload (bar the last, never acked).
    assert_eq!(local.payloads_in_flight(), 1);
    assert_eq!(remote.payloads_in_flight(), 1);

    // remote -> local had no loss, so local sees a full ack window.
    let packet = local
        .build_outgoing(Some(test_payload(0, 100)), MTU)
        .unwrap();
    assert_eq!(packet.ack, Some(99));
    assert_eq!(packet.ack_bits, 0xFFFF_FFFF);

    // local -> remote dropped every 4th packet; reading right-to-left from
    // peer packet 98 down to 66, every 4th bit is clear.
    let packet = remote
        .build_outgoing(Some(test_payload(0, 100)), MTU)
        .unwrap();
    assert_eq!(packet.ack, Some(99));
    assert_eq!(packet.ack_bits, 0b1011_1011_1011_1011_1011_1011_1011_1011);
}
