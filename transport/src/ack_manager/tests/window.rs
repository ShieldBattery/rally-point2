//! The unacked window itself: per-slot force-retirement, re-injection after a
//! re-home, the resume anchors read off it, and the cached wire size that
//! every mutation must keep exact.

use super::*;

#[test]
fn retire_payloads_through_advances_only_one_slots_window() {
    // No redundancy, so each payload rides exactly one packet and none is
    // retired by datagram acks during this test.
    let mut manager = AckManager::new();
    // Sparse seqs exercise cursors below, exactly at, and beyond the live
    // range. Both slots carry the same seqs but remain independent.
    for seq in [2u64, 4, 6, 8, 10] {
        manager
            .build_outgoing(Some(test_payload(0, seq)), 0)
            .unwrap();
        manager
            .build_outgoing(Some(test_payload(1, seq)), 0)
            .unwrap();
    }
    assert_eq!(manager.payloads_in_flight(), 10);

    // A cursor below the oldest live seq visits/removes nothing.
    assert_eq!(manager.retire_payloads_through(SlotId(0), 1), 0);
    assert_eq!(manager.payloads_in_flight(), 10);

    // A cursor exactly at the oldest entry removes just that one. Slot 1's
    // identical seq remains untouched.
    assert_eq!(manager.retire_payloads_through(SlotId(0), 2), 1);
    assert_eq!(manager.payloads_in_flight(), 9);
    assert!(manager.unacked_payloads.contains_key(&(SlotId(1), 2)));

    // Idempotent: re-confirming an already-passed cursor retires nothing.
    assert_eq!(manager.retire_payloads_through(SlotId(0), 2), 0);
    assert_eq!(manager.payloads_in_flight(), 9);

    // A later cursor removes multiple entries from only the requested slot.
    assert_eq!(manager.retire_payloads_through(SlotId(0), 8), 3);
    assert_eq!(manager.payloads_in_flight(), 6); // slot 1's 5 + slot 0's seq 10
    for seq in [2u64, 4, 6, 8, 10] {
        assert!(manager.unacked_payloads.contains_key(&(SlotId(1), seq)));
    }

    // A subsequent packet only repacks the payloads still in flight.
    let packet = manager.build_outgoing(None, MTU).unwrap();
    let keys: Vec<(u8, u64)> = packet
        .payloads
        .iter()
        .map(|p| (p.slot as u8, p.seq))
        .collect();
    assert_eq!(keys, vec![(0, 10), (1, 2), (1, 4), (1, 6), (1, 8), (1, 10)]);

    // The ceiling removes the final slot-0 entry without touching slot 1.
    assert_eq!(manager.retire_payloads_through(SlotId(0), u64::MAX), 1);
    assert_eq!(manager.payloads_in_flight(), 5);
}

#[test]
fn cached_unacked_wire_len_tracks_every_window_mutation() {
    let mut manager = AckManager::new();
    assert_unacked_wire_len_is_exact(&mut manager);

    build_sent(&mut manager, Some(test_payload(0, 0)), MTU);
    build_sent(&mut manager, Some(test_payload(0, 1)), MTU);
    assert_unacked_wire_len_is_exact(&mut manager);

    manager.reinject_unacked(test_payload(1, 7));
    manager.reinject_unacked(test_payload(1, 7));
    assert_unacked_wire_len_is_exact(&mut manager);

    assert_eq!(manager.retire_payloads_through(SlotId(0), 0), 1);
    assert_unacked_wire_len_is_exact(&mut manager);

    // Packet 1 carried seq 1 fresh (and seq 0 as redundancy). Acking it
    // removes the surviving slot-0 payload but leaves the re-injected slot.
    manager.handle_incoming(&incoming(0, Some(1), &[])).unwrap();
    assert_unacked_wire_len_is_exact(&mut manager);
    assert_eq!(manager.payloads_in_flight(), 1);

    assert_eq!(manager.retire_payloads_through(SlotId(1), u64::MAX), 1);
    assert_unacked_wire_len_is_exact(&mut manager);
}

#[test]
fn oldest_replayable_seq_is_the_lowest_in_flight_per_slot() {
    let mut manager = AckManager::new();
    // Nothing in flight yet.
    assert_eq!(manager.oldest_replayable_seq(SlotId(0)), None);

    // No redundancy, so each payload rides one packet and stays in flight.
    for seq in [7u64, 8, 9] {
        manager
            .build_outgoing(Some(test_payload(0, seq)), 0)
            .unwrap();
    }
    manager.build_outgoing(Some(test_payload(1, 3)), 0).unwrap();
    assert_eq!(manager.oldest_replayable_seq(SlotId(0)), Some(7));
    assert_eq!(manager.oldest_replayable_seq(SlotId(1)), Some(3));
    // A slot with nothing in flight is still None.
    assert_eq!(manager.oldest_replayable_seq(SlotId(2)), None);

    // Retiring the oldest advances the answer to the next in flight.
    manager.retire_payloads_through(SlotId(0), 7);
    assert_eq!(manager.oldest_replayable_seq(SlotId(0)), Some(8));
}

#[test]
fn reinject_re_carries_an_already_retired_payload() {
    // The rehome re-inject: a payload that was acked (retired) is put back in
    // the unacked set so the next packet's redundancy re-carries it — the case
    // where the old relay acked a turn but never fanned it out before dying.
    let mut manager = AckManager::new();
    build_sent(&mut manager, Some(test_payload(0, 0)), MTU);
    // Ack it: it retires from the window.
    manager.handle_incoming(&incoming(1, Some(0), &[])).unwrap();
    assert_eq!(manager.payloads_in_flight(), 0);

    // Re-inject it (as after a rehome rebind). It is unacked again and the next
    // packet re-carries it.
    manager.reinject_unacked(test_payload(0, 0));
    assert_eq!(manager.payloads_in_flight(), 1);
    let packet = manager.build_outgoing(None, MTU).unwrap();
    let seqs: Vec<(u8, u64)> = packet
        .payloads
        .iter()
        .map(|p| (p.slot as u8, p.seq))
        .collect();
    assert_eq!(seqs, vec![(0, 0)]);
}

#[test]
fn reinject_does_not_double_track_a_still_unacked_payload() {
    // A payload still in flight (kept across a reset) must not be re-tracked by
    // a re-inject — the window stays at one, not two.
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap();
    assert_eq!(manager.payloads_in_flight(), 1);
    manager.reinject_unacked(test_payload(0, 0));
    assert_eq!(manager.payloads_in_flight(), 1);
}

#[test]
fn an_out_of_range_slot_does_not_alias_another_slots_bookkeeping() {
    // A wire slot past `u8` range narrows to a valid slot under a raw `as u8`
    // (256 becomes slot 0), so tracking it would silently poison that slot's
    // window while the forwarded wire payload kept its original slot. It must
    // instead be dropped from the bookkeeping entirely.
    let mut manager = AckManager::new();
    // A genuine slot-0 turn establishes slot 0's window at seq 5.
    manager
        .build_outgoing(Some(test_payload(0, 5)), MTU)
        .unwrap();
    assert_eq!(manager.oldest_replayable_seq(SlotId(0)), Some(5));

    // Slot 256 aliases onto slot 0 under a truncating cast; seq 3 would then
    // become slot 0's new oldest unacked seq.
    let aliasing = Payload {
        seq: 3,
        slot: 256,
        commands: vec![0u8; 4].into(),
        ..Default::default()
    };
    let packet = manager.build_outgoing(Some(aliasing), MTU).unwrap();

    // Slot 0's bookkeeping is untouched: its oldest unacked seq is still 5, and
    // only the one genuine turn is in flight.
    assert_eq!(manager.oldest_replayable_seq(SlotId(0)), Some(5));
    assert_eq!(manager.payloads_in_flight(), 1);
    // The malformed payload rode no datagram either, so the packet carries only
    // the genuine slot-0 turn as redundancy.
    assert!(
        packet.payloads.iter().all(|p| p.slot == 0 && p.seq == 5),
        "the out-of-range payload must not ride the wire: {:?}",
        packet
            .payloads
            .iter()
            .map(|p| (p.slot, p.seq))
            .collect::<Vec<_>>(),
    );
}

/// The re-home anchor descends from the retention front only through
/// contiguously unacked seqs: an acked hole below the front is in neither
/// replay source (not unacked, aged out of retention), so anchoring
/// beneath it would base a fresh relay's receive window on a permanent
/// void. A fully contiguous unacked tail — the outgrown-retention case —
/// still extends the anchor all the way down.
#[test]
fn contiguous_replayable_anchor_stops_at_an_acked_hole() {
    let mut manager = AckManager::new();
    // Budget 0 suppresses redundancy so each seq rides exactly one packet
    // and acks target seqs precisely.
    for seq in 0..8u64 {
        build_sent(&mut manager, Some(test_payload(0, seq)), 0);
    }
    // Ack packets 3 and 6 (each carried only its same-numbered seq):
    // the unacked window is now sparse: {0, 1, 2, 4, 5, 7}.
    manager
        .handle_incoming(&incoming(0, Some(6), &[3]))
        .unwrap();
    assert_eq!(manager.payloads_in_flight(), 6);

    // From front 8: seq 7 is unacked and contiguous; 6 is an acked hole.
    assert_eq!(manager.contiguous_replayable_anchor(SlotId(0), 8), 7);
    // From front 6: 5 and 4 extend; 3 is the hole.
    assert_eq!(manager.contiguous_replayable_anchor(SlotId(0), 6), 4);
    // From front 3: 2, 1, 0 are fully contiguous — the outgrown-retention
    // shape — and the descent covers them all.
    assert_eq!(manager.contiguous_replayable_anchor(SlotId(0), 3), 0);
    // A front with nothing unacked below it stands unmoved.
    assert_eq!(manager.contiguous_replayable_anchor(SlotId(1), 3), 3);
}
