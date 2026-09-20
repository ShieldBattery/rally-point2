//! Payloads too wide for the ordinary redundancy budget: the first-element
//! exemption that keeps them re-carryable, the head-of-line block that leaves
//! a packet carrying nothing, and survival across a path-MTU shrink.

use super::*;

/// A payload wider than the policy's redundancy byte budget must still be
/// re-carried — the budget bounds the aggregate, and its first-element
/// exemption is what keeps a lost wide turn recoverable at all. At most one
/// over-budget element rides per packet, so two wide payloads alternate
/// across successive flushes instead of stacking.
#[test]
fn a_payload_wider_than_the_policy_budget_is_still_re_carried() {
    let mut manager = AckManager::with_policy(RecarryPolicy {
        redundancy_byte_budget: Some(64),
        spacing: Some(CarrySpacing {
            dense_carries: 2,
            max_spacing: 8,
        }),
    });
    let wide = |slot: u8, seq: u64| Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0u8; 300].into(),
        ..Default::default()
    };

    // Wide turn A goes out fresh (and its datagram is, say, lost).
    build_sent(&mut manager, Some(wide(0, 0)), MTU);
    // Wide turn B's packet re-carries A via the exemption: both fit the
    // datagram, and A alone is allowed past the 64-byte policy budget.
    let second = build_sent(&mut manager, Some(wide(0, 1)), MTU);
    let keys = |packet: &Packet| {
        packet
            .payloads
            .iter()
            .map(|p| (p.slot as u8, p.seq))
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&second), vec![(0, 1), (0, 0)]);

    // Flushes carry exactly one over-budget element each: the
    // longest-waiting wide payload wins the exempt slot, so the two
    // alternate rather than stack.
    let flush = build_sent(&mut manager, None, MTU);
    assert_eq!(keys(&flush), vec![(0, 0)]);
    let flush = build_sent(&mut manager, None, MTU);
    assert_eq!(keys(&flush), vec![(0, 1)]);
}

/// When the most overdue due payload cannot fit a packet at all — a wide
/// turn sharing the datagram with a fresh one — the packet must carry no
/// redundancy whatsoever, not pack smaller candidates around it. Both
/// drivers arm their maintenance flush exactly when a send re-carries
/// nothing, and the flush packet (no fresh payload) is the one place the
/// wide payload fits; packing around it would keep resetting that flush
/// from packets the wide payload can never ride, stranding it behind
/// continuous smaller traffic indefinitely.
///
/// The same holds when the path shrinks under the payload mid-flight: floor
/// admission means a fresh-free flush fits it alone at any legal MTU, so a
/// turn admitted on a discovered 1350-byte budget is still recoverable once
/// the path falls back to the 1200-byte floor.
#[test]
fn a_blocked_wide_payload_suppresses_all_redundancy_so_the_flush_stays_armed() {
    // (budget the wide turn was sent at, budget every later packet gets,
    //  fresh command bytes per later turn, how many of them follow)
    let cases = [
        ("a steady path", 1350usize, 1350usize, 450usize, 10u64),
        ("a path-MTU shrink to the floor", 1350, 1200, 300, 4),
    ];

    for (case, send_budget, flush_budget, fresh_commands, fresh_turns) in cases {
        let mut manager = AckManager::new();

        // A wide turn under the admission floor — it fits a datagram alone,
        // but never beside one of the mid-size fresh payloads that follow;
        // its datagram is lost.
        let wide_commands = GUARANTEED_DATAGRAM_BUDGET - 64;
        build_sent(
            &mut manager,
            Some(test_payload_sized(0, 0, wide_commands)),
            send_budget,
        );

        // Continuous mid-size fresh turns follow, never acked, so smaller
        // redundancy candidates are always available (any two of them share a
        // packet comfortably). Every packet must decline them all: the wide
        // payload heads the line and cannot ride.
        for i in 1..=fresh_turns {
            let packet = build_sent(
                &mut manager,
                Some(test_payload_sized(0, i, fresh_commands)),
                flush_budget,
            );
            assert_eq!(
                packet.payloads.len(),
                1,
                "{case}: packet {} packed redundancy around the blocked wide payload",
                packet.seq,
            );
        }

        // The flush the drivers fire on those redundancy-free sends has no
        // fresh payload, so the wide turn heads it — recovery rides there.
        let flush = build_sent(&mut manager, None, flush_budget);
        assert_eq!(flush.payloads.first().map(|p| p.seq), Some(0), "{case}");
    }
}
