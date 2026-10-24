//! Dedup unit tests: the per-slot delivered prefix, the out-of-order set, the
//! receive window, and the resume anchor, driven directly with no connection
//! in the way. Kept apart from the link-level tests because these reach into
//! the dedup state's own fields to prove exactly where a seq landed.

use std::collections::HashMap;

use super::*;

#[test]
fn dedup_contiguous_fast_path_never_buffers_in_order_seqs() {
    let mut dedup = Dedup::with_window(8);

    for seq in 0..32 {
        assert_eq!(dedup.accept(SlotId(0), seq), Delivery::New);
        let state = dedup.slots.get(&SlotId(0)).expect("slot was accepted");
        assert_eq!(state.delivered_through, Some(seq));
        assert!(state.ahead.is_empty());
    }

    assert_eq!(dedup.accept(SlotId(0), 31), Delivery::Duplicate);
}

#[test]
fn dedup_contiguous_fast_path_absorbs_a_buffered_run_after_gap_closes() {
    let mut dedup = Dedup::with_window(8);

    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 3), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 2), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 3), Delivery::Duplicate);

    // Seq 1 is the receive base. The direct prefix advance must still fold
    // the buffered 2..=3 run exactly as the tree insert/remove path did.
    assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
    let state = dedup.slots.get(&SlotId(0)).expect("slot was accepted");
    assert_eq!(state.delivered_through, Some(3));
    assert!(state.ahead.is_empty());
    assert_eq!(dedup.accept(SlotId(0), 2), Delivery::Duplicate);
}

#[test]
fn dedup_keeps_slots_independent() {
    // Two slots both have seq 0; both are new — the identity is (slot, seq).
    let mut dedup = Dedup::with_window(8);
    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    assert_eq!(dedup.accept(SlotId(1), 0), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate);
    assert_eq!(dedup.accept(SlotId(1), 0), Delivery::Duplicate);
}

#[test]
fn dedup_does_not_drop_a_low_seq_after_a_high_one() {
    // The regression: a high seq arriving first must not push an older, not
    // yet delivered seq out as "too old". Both are new deliveries.
    let mut dedup = Dedup::with_window(8);
    assert_eq!(dedup.accept(SlotId(0), 7), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
}

#[test]
fn dedup_rejects_seq_beyond_window() {
    let mut dedup = Dedup::with_window(8);
    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New); // prefix top = 0, base = 1
    assert_eq!(dedup.accept(SlotId(0), 9), Delivery::OutOfWindow); // 9 - 1 >= 8
    assert_eq!(dedup.accept(SlotId(0), 8), Delivery::New); // 8 - 1 < 8, still in window
}

/// An anchor at the u64 ceiling, followed by a payload at the u64 ceiling,
/// must not panic (debug) or silently wrap the window (release) — the
/// defense-in-depth backstop for a resume anchor that somehow reaches
/// this far unclamped (the real gate is the relay's own anchor
/// validation; this only proves the fold itself can't be driven into
/// undefined-by-overflow territory if that gate were ever bypassed).
#[test]
fn accept_and_anchor_never_overflow_at_the_u64_ceiling() {
    let mut dedup = Dedup::with_window(8);
    dedup.anchor(SlotId(0), u64::MAX);
    // Anchoring at u64::MAX sets delivered_through to u64::MAX - 1, so the
    // window's base is u64::MAX. A payload at u64::MAX itself is exactly
    // at that base (seq - base == 0), so it's accepted, and the absorb
    // loop's `next.checked_add(1)` must stop cleanly at the ceiling
    // rather than overflow.
    assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::New);
    assert_eq!(dedup.delivered_through(SlotId(0)), Some(u64::MAX));
    // A repeat at the exact ceiling is a duplicate: it sits at the prefix
    // top, which is compared directly rather than against a "one past
    // u64::MAX" that can't be represented. State is unchanged.
    assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::Duplicate);
    assert_eq!(dedup.delivered_through(SlotId(0)), Some(u64::MAX));
}

#[test]
fn anchored_window_accepts_a_resumed_high_seq_stream() {
    // A session re-homed onto a fresh dedup resumes its slot mid-stream. Without
    // an anchor the base is 0, so a seq at/beyond the window is rejected and the
    // prefix never forms. Anchored at the resume point, the resumed stream is
    // accepted and the prefix advances from there.
    let mut dedup = Dedup::with_window(8);

    // Unanchored: the resumed seq 20 is far beyond the from-zero window.
    assert_eq!(dedup.accept(SlotId(0), 20), Delivery::OutOfWindow);

    // Anchor slot 1 at its resume point (20): base becomes 20.
    dedup.anchor(SlotId(1), 20);
    assert_eq!(dedup.accept(SlotId(1), 20), Delivery::New);
    assert_eq!(dedup.accept(SlotId(1), 21), Delivery::New);
    // Seqs below the anchor are already-delivered (never re-delivered to the game).
    assert_eq!(dedup.accept(SlotId(1), 19), Delivery::Duplicate);
    // The prefix advanced from the anchor, so the window slides: a seq that would
    // be out-of-window against a from-zero base is fine here.
    assert_eq!(dedup.delivered_through(SlotId(1)), Some(21));
    assert_eq!(dedup.accept(SlotId(1), 25), Delivery::New);
}

/// A forward-collapsing dedup admits a far seq while preserving a full receive
/// window below it. Only gaps outside that window are considered delivered.
#[test]
fn forward_collapse_admits_a_far_seq_by_sliding_the_lower_bound() {
    let mut dedup = Dedup {
        slots: HashMap::new(),
        retired_through: HashMap::new(),
        window: 8,
        forward_collapse: true,
    };

    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    assert_eq!(dedup.accept(SlotId(0), 3), Delivery::New); // gap at 1, 2
    assert_eq!(dedup.accept(SlotId(0), 4), Delivery::New);

    // Far past the window (20 - 1 >= 8): strict mode would reject. Sliding
    // to base 13 discards received 3 and 4 below it and keeps 20 at the top.
    assert_eq!(dedup.accept(SlotId(0), 20), Delivery::New);
    assert_eq!(
        dedup.delivered_through(SlotId(0)),
        Some(12),
        "the prefix jumped to a full window below the far seq",
    );

    // The window below the far seq stayed open: the backlog riding behind
    // it is fresh, and once contiguous the prefix absorbs through it.
    for seq in 13..20u64 {
        assert_eq!(dedup.accept(SlotId(0), seq), Delivery::New);
    }
    assert_eq!(dedup.delivered_through(SlotId(0)), Some(20));

    // Seqs inside the swallowed gap are duplicates, never a re-delivery.
    assert_eq!(dedup.accept(SlotId(0), 1), Delivery::Duplicate);
    assert_eq!(dedup.accept(SlotId(0), 5), Delivery::Duplicate);
}

#[test]
fn anchor_is_a_no_op_on_zero_or_an_already_active_slot() {
    let mut dedup = Dedup::with_window(8);
    // Anchor 0 leaves the default from-zero base.
    dedup.anchor(SlotId(0), 0);
    assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    // Once a slot has received, a later anchor never rewinds its prefix.
    assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
    dedup.anchor(SlotId(0), 100);
    assert_eq!(dedup.accept(SlotId(0), 2), Delivery::New);
    assert_eq!(dedup.delivered_through(SlotId(0)), Some(2));
}

#[test]
fn forward_collapse_keeps_the_backlog_when_live_turns_advance() {
    let slot = SlotId(0);
    let mut dedup = Dedup::with_forward_collapse();
    assert_eq!(dedup.accept(slot, 9_999), Delivery::New);
    assert_eq!(dedup.accept(slot, 10_000), Delivery::New);
    assert_eq!(dedup.delivered_through(slot), Some(10_000 - RECEIVE_WINDOW));

    for seq in [9_997, 9_998, 10_000 - RECEIVE_WINDOW + 1] {
        assert_eq!(dedup.accept(slot, seq), Delivery::New);
        assert_eq!(dedup.accept(slot, seq), Delivery::Duplicate);
    }
    assert_eq!(
        dedup.accept(slot, 10_000 - RECEIVE_WINDOW),
        Delivery::Duplicate
    );
    assert_eq!(dedup.accept(SlotId(1), 0), Delivery::New);
}

#[test]
fn forward_collapse_absorbs_only_a_contiguous_run_at_the_new_lower_bound() {
    let slot = SlotId(0);
    let mut dedup = Dedup::with_window(8);
    dedup.forward_collapse = true;
    for seq in [9, 3, 4, 10] {
        assert_eq!(dedup.accept(slot, seq), Delivery::New);
    }
    // Moving the lower bound to 2 joins the received 3..=4 run, but not 9..=10.
    assert_eq!(dedup.delivered_through(slot), Some(4));
    for seq in 5..9 {
        assert_eq!(dedup.accept(slot, seq), Delivery::New);
    }
    assert_eq!(dedup.delivered_through(slot), Some(10));
}
