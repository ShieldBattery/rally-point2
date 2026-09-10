//! The redundancy refill: which unacked payloads ride a packet when they all
//! fit, and how the constrained path ranks them when they do not — the
//! fairness properties that keep any one payload from being starved.

use prost::Message;

use crate::ack_manager::sent::payload_element_len;

use super::*;

#[test]
fn redundancy_repacks_all_unacked_payloads_within_a_slot() {
    // With a generous budget, each new packet should re-carry every earlier
    // unacked payload alongside the fresh one. Their serialization order is
    // immaterial when every candidate fits; the fresh payload remains first.
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap();
    manager
        .build_outgoing(Some(test_payload(0, 1)), MTU)
        .unwrap();
    let third = manager
        .build_outgoing(Some(test_payload(0, 2)), MTU)
        .unwrap();

    assert_eq!(third.payloads.first().map(|payload| payload.seq), Some(2));
    let mut redundant_seqs: Vec<u64> = third.payloads[1..]
        .iter()
        .map(|payload| payload.seq)
        .collect();
    redundant_seqs.sort_unstable();
    assert_eq!(redundant_seqs, vec![0, 1]);
}

#[test]
fn redundancy_refills_across_slots_oldest_per_slot_first() {
    // Two slots each with one unacked payload, tied on send_count (both
    // sent exactly once, as their own fresh payload). A tie falls back to
    // the underlying BTreeMap order on (slot, seq) — slot 0 before slot
    // 1, not a single global seq order (each slot has its own seq space,
    // so seq alone would be meaningless across slots).
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 100)), 0)
        .unwrap(); // slot 0, high seq
    manager.build_outgoing(Some(test_payload(1, 5)), 0).unwrap(); // slot 1, low seq

    // A packet with room for both unacked payloads.
    let packet = manager.build_outgoing(None, MTU).unwrap();
    let keys: Vec<(u8, u64)> = packet
        .payloads
        .iter()
        .map(|p| (p.slot as u8, p.seq))
        .collect();
    // Slot 0's seq 100 comes before slot 1's seq 5 because the key orders by
    // slot first — "oldest per slot", not "lowest seq globally".
    assert_eq!(keys, vec![(0, 100), (1, 5)]);
}

#[test]
fn all_fit_refill_carries_every_candidate_and_increments_each_once() {
    let mut manager = AckManager::new();
    let candidates = [test_payload(0, 7), test_payload(1, 3), test_payload(2, 11)];
    for payload in &candidates {
        manager.reinject_unacked(payload.clone());
    }

    // Give the candidates deliberately different coverage histories. When
    // all fit, their ranking is immaterial: every one must be carried and
    // incremented exactly once without constructing the sorted candidate
    // list used by the constrained path.
    let counts = [5, 1, 3];
    for (payload, count) in candidates.iter().zip(counts) {
        manager
            .unacked_payloads
            .get_mut(&(SlotId(payload.slot as u8), payload.seq))
            .expect("candidate was re-injected")
            .send_count = count;
    }

    let fresh = test_payload(3, 19);
    let exact_budget = Packet {
        seq: 0,
        ack: None,
        ack_bits: 0,
        payloads: std::iter::once(fresh.clone())
            .chain(candidates.iter().cloned())
            .collect(),
    }
    .encoded_len();
    let packet = build_sent(&mut manager, Some(fresh.clone()), exact_budget);

    assert_eq!(packet.encoded_len(), exact_budget);
    assert_eq!(packet.payloads.first(), Some(&fresh));
    let mut carried: Vec<(u8, u64)> = packet.payloads[1..]
        .iter()
        .map(|payload| (payload.slot as u8, payload.seq))
        .collect();
    carried.sort_unstable();
    assert_eq!(carried, vec![(0, 7), (1, 3), (2, 11)]);
    for (payload, old_count) in candidates.iter().zip(counts) {
        assert_eq!(
            manager
                .unacked_payloads
                .get(&(SlotId(payload.slot as u8), payload.seq))
                .expect("candidate stayed in flight")
                .send_count,
            old_count + 1,
        );
    }
    assert_eq!(
        manager
            .unacked_payloads
            .get(&(SlotId(3), fresh.seq))
            .expect("fresh payload entered the window")
            .send_count,
        1,
    );

    // The sent-packet record still contains every carried identity: one ack
    // retires the fresh payload and all fast-path redundancy candidates.
    manager.handle_incoming(&incoming(0, Some(0), &[])).unwrap();
    assert_eq!(manager.payloads_in_flight(), 0);
}

#[test]
fn constrained_refill_serves_the_longest_waiting_carry_first() {
    let mut manager = AckManager::with_policy(RecarryPolicy::unbounded());
    for slot in 0u8..4 {
        manager.reinject_unacked(test_payload(slot, 0));
    }
    // Advance the packet seq so the carry ages below are meaningful.
    for _ in 0..10 {
        manager.build_outgoing(None, 0).unwrap();
    }
    // Slot 1 has waited longest since its last carry; slots 2 and 3 tie
    // and therefore retain key order; slot 0 was carried most recently and
    // should be the one excluded.
    for (slot, last_carried) in [9, 2, 5, 5].into_iter().enumerate() {
        manager
            .unacked_payloads
            .get_mut(&(SlotId(slot as u8), 0))
            .expect("candidate was re-injected")
            .last_carried_packet_seq = Some(last_carried);
    }

    // Header sized with the packet seq this build will actually stamp —
    // a nonzero seq encodes wider than `Packet::default()`'s zero.
    let header = Packet {
        seq: manager.next_packet_seq(),
        ..Default::default()
    }
    .encoded_len();
    let exact_budget = header
        + (1u8..=3)
            .map(|slot| payload_element_len(test_payload(slot, 0).encoded_len()))
            .sum::<usize>();
    let packet = manager.build_outgoing(None, exact_budget).unwrap();
    let keys: Vec<(u8, u64)> = packet
        .payloads
        .iter()
        .map(|payload| (payload.slot as u8, payload.seq))
        .collect();

    assert_eq!(packet.encoded_len(), exact_budget);
    assert_eq!(keys, vec![(1, 0), (2, 0), (3, 0)]);
}

/// A payload that is due but keeps losing the budget race must still be
/// carried on a bounded cadence. Ranking by carry age guarantees it: a
/// passed-over candidate only ranks higher on the next packet, while a
/// continuous stream of fresh payloads always enters at the bottom.
/// (Ranking by lowest send count starved here: every new fresh payload
/// outranked the old one forever, and with no acks returning, the probe's
/// seq 0 stopped riding after a handful of packets and never returned.)
#[test]
fn a_due_payload_is_never_starved_by_continuous_fresh_traffic() {
    let mut manager = AckManager::new();
    let mut carried_in: Vec<u32> = Vec::new();
    for i in 0..120u64 {
        let packet = build_sent(&mut manager, Some(test_payload_sized(0, i, 110)), 1350);
        if packet.payloads.iter().any(|p| p.slot == 0 && p.seq == 0) {
            carried_in.push(packet.seq);
        }
    }
    // No fixed cadence exists when nothing is ever acked — the due backlog
    // grows without bound — but service must stay recurrent: seq 0 keeps
    // riding all the way through, with gaps bounded by the backlog's
    // round-robin cycle rather than growing into permanent absence.
    let last = *carried_in.last().expect("seq 0 rode at least once");
    assert!(
        last >= 90,
        "seq 0 last rode packet {last}; it was starved out of the stream",
    );
    let max_gap = carried_in
        .windows(2)
        .map(|w| w[1] - w[0])
        .max()
        .unwrap_or(0);
    assert!(
        max_gap <= 48,
        "seq 0 waited {max_gap} packets between carries (carried in {carried_in:?})",
    );
}

/// A tight, permanently-full budget must not let low slot numbers
/// monopolize redundancy coverage forever: over a long run where the
/// budget only ever fits ONE redundant payload per packet, every slot's
/// unacked payload should get roughly equal turns, not lose every single
/// time to whichever slot happens to sort first. Regression coverage for
/// the fairness fix — with the old `(slot, seq)` iteration order, slot
/// 0's payload would win every refill and slots 1-3 would never be
/// re-carried at all for as long as the budget stayed this tight.
#[test]
fn a_permanently_tight_budget_spreads_redundancy_coverage_across_slots() {
    // Unbounded policy: this test pins the constrained refill's fairness
    // ranking, so the spacing schedule (which would legitimately let
    // well-covered payloads sit out rounds) is disabled.
    let mut manager = AckManager::with_policy(RecarryPolicy::unbounded());
    // Four slots, each with one unacked payload that is never touched
    // again as "fresh" -- from here on each is purely along for the
    // redundancy ride, competing for the same tight budget.
    for slot in 0u8..4 {
        build_sent(&mut manager, Some(test_payload(slot, 0)), MTU);
    }
    assert_eq!(manager.payloads_in_flight(), 4);

    // A tight budget -- `lone_packet_len` sizes a packet for exactly one
    // payload under worst-case header state, so real (smaller) headers
    // can occasionally leave room for a second small element too. Either
    // way, which candidate(s) get chosen each round is the fairness
    // question: count how many times each slot's payload is picked
    // across many rounds.
    let tight_budget = lone_packet_len(&test_payload(0, 0));

    let mut picks_per_slot = [0u32; 4];
    for _ in 0..40 {
        let packet = build_sent(&mut manager, None, tight_budget);
        assert!(
            !packet.payloads.is_empty() && packet.payloads.len() <= 2,
            "expected a tight pick of one or two candidates, got {}",
            packet.payloads.len(),
        );
        for payload in &packet.payloads {
            picks_per_slot[payload.slot as usize] += 1;
        }
    }

    // Fair spreading: every slot's payload gets picked repeatedly across
    // the 40 rounds -- none is starved. With the old `(slot, seq)`
    // iteration order, slot 0 would win literally every round and slots
    // 1-3 would sit at 0 picks for as long as the budget stayed tight.
    for (slot, &picks) in picks_per_slot.iter().enumerate() {
        assert!(
            picks > 0,
            "slot {slot} was never picked across 40 rounds of a tight budget -- \
             starved instead of getting a fair share of redundancy coverage",
        );
    }
}

#[test]
fn redundancy_respects_size_budget() {
    let mut manager = AckManager::new();
    manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap();

    // A budget that fits only the fresh payload leaves no room to repack the
    // earlier one.
    let only_fresh = manager.build_outgoing(Some(test_payload(0, 1)), 0).unwrap();
    assert_eq!(only_fresh.payloads.len(), 1);
    assert_eq!(only_fresh.payloads[0].seq, 1);
}
