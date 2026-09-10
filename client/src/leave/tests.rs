//! Unit tests for the leave tracker: how directives are recorded, deduped,
//! superseded by a finalized restatement, and surfaced at their apply point.

use super::*;

fn leave(slot: u32, reason: u32, apply_at_frame: u32, leave_seq: u32) -> LeaveDirective {
    LeaveDirective {
        finalized: false,
        slot,
        reason,
        apply_at_frame,
        leave_seq,
        final_turn_count: None,
    }
}

fn counted_leave(slot: u32, reason: u32, final_turn_count: u64, leave_seq: u32) -> LeaveDirective {
    LeaveDirective {
        finalized: false,
        slot,
        reason,
        // A frame the frame-fallback would treat as never-due, so a test
        // passing this proves the count drove the surfacing.
        apply_at_frame: u32::MAX,
        leave_seq,
        final_turn_count: Some(final_turn_count),
    }
}

/// A consumed-count lookup for directives that carry no count (the
/// frame-fallback path never reads it).
fn no_counts(_slot: SlotId) -> u64 {
    panic!("a directive without final_turn_count must not consult consumption")
}

const DROPPED: u32 = 0x4000_0006;
const LEFT: u32 = 1;

#[test]
fn applies_exactly_at_the_apply_frame_and_only_once() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));

    for frame in 90..100 {
        assert!(
            tracker.take_due(frame, no_counts).is_empty(),
            "applied early at {frame}"
        );
    }
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
    assert!(
        tracker.take_due(100, no_counts).is_empty(),
        "a leave must surface once"
    );
    assert!(tracker.take_due(101, no_counts).is_empty());
}

#[test]
fn redundant_copies_of_the_same_leave_are_idempotent() {
    let mut tracker = LeaveTracker::new();
    let stamp = leave(2, DROPPED, 100, 1);
    // The same leave rides every forwarded turn until the session passes the
    // apply frame, so copies arrive constantly.
    tracker.observe(&stamp);
    tracker.observe(&stamp);
    tracker.observe(&stamp);

    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
    assert!(tracker.take_due(100, no_counts).is_empty());
}

#[test]
fn a_handoff_rederivation_with_a_higher_seq_does_not_double_apply() {
    // The promoted authority re-broadcasts the same slot's leave under a fresh
    // leave_seq. A client that already applied it must NOT apply it again
    // (that would consume synced RNG twice and desync). Dedup is by slot, so
    // the higher-seq copy is a no-op here.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);

    tracker.observe(&leave(2, DROPPED, 100, 7)); // re-derivation, higher seq
    assert!(
        tracker.take_due(200, no_counts).is_empty(),
        "a slot's leave must apply exactly once across a handoff"
    );
}

#[test]
fn a_handoff_rederivation_still_applies_for_a_client_that_missed_the_original() {
    // Same re-derivation, but this client never saw the original: it must
    // apply the re-derived copy (at the same frame the relay guarantees).
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 7));
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
}

#[test]
fn several_slots_leave_each_at_its_own_frame() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));
    tracker.observe(&leave(3, LEFT, 150, 2));

    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
    assert!(
        tracker.take_due(120, no_counts).is_empty(),
        "slot 3 not due yet"
    );
    assert_eq!(tracker.take_due(150, no_counts), vec![(SlotId(3), LEFT)]);
}

#[test]
fn simultaneous_leaves_at_one_frame_surface_together_in_slot_order() {
    // Two slots due at the same frame come out in one poll so the caller
    // writes both before the synced-leave pass drains them in slot order.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(5, DROPPED, 100, 2));
    tracker.observe(&leave(1, DROPPED, 100, 1));

    let due = tracker.take_due(100, no_counts);
    assert_eq!(due.len(), 2);
    assert!(due.contains(&(SlotId(5), DROPPED)));
    assert!(due.contains(&(SlotId(1), DROPPED)));
}

#[test]
fn a_late_copy_after_apply_does_not_re_surface() {
    let mut tracker = LeaveTracker::new();
    let stamp = leave(2, DROPPED, 100, 1);
    tracker.observe(&stamp);
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
    // The relay keeps broadcasting until the session passes the apply frame,
    // so a copy can arrive after we already applied it.
    tracker.observe(&stamp);
    assert!(tracker.take_due(101, no_counts).is_empty());
    assert!(tracker.take_due(200, no_counts).is_empty());
}

#[test]
fn a_leave_observed_after_its_frame_still_applies() {
    // Can't happen while the slot gates the step, but if it did, apply rather
    // than silently drop (the safe direction — everyone else applied it).
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));
    assert_eq!(tracker.take_due(140, no_counts), vec![(SlotId(2), DROPPED)]);
}

#[test]
fn an_out_of_range_slot_is_dropped_instead_of_aliasing() {
    // A relay bug (or a rogue/buggy relay) sending slot 256 must not alias
    // onto slot 0 via a truncating cast -- it must be rejected outright.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(256, DROPPED, 100, 1));
    assert!(
        !tracker.contains(0),
        "an out-of-range slot must not alias onto slot 0"
    );
    assert!(
        !tracker.contains(256),
        "the out-of-range directive must not be tracked at all"
    );
    assert!(
        tracker.take_due(100, no_counts).is_empty(),
        "no leave should surface for a rejected out-of-range directive"
    );

    // A legitimate slot 0 leave still applies normally afterward.
    tracker.observe(&leave(0, DROPPED, 100, 2));
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(0), DROPPED)]);
}

/// A relay contract violation — two directives for the same slot naming
/// different apply frames/reasons — must not panic (this used to be a
/// `debug_assert!`, which would abort a debug build outright, so this
/// scenario could never even run under `cargo test`'s own debug profile)
/// and must never re-open the slot: the first directive seen is kept and
/// surfaces normally, and the conflicting one is dropped without
/// mutating anything.
#[test]
fn a_conflicting_directive_never_reopens_the_slot_and_keeps_the_first() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));

    // A conflicting copy: same slot, different reason AND apply frame.
    tracker.observe(&leave(2, LEFT, 150, 2));

    // Not due before the FIRST directive's own apply frame.
    assert!(
        tracker.take_due(99, no_counts).is_empty(),
        "not due until frame 100"
    );

    // At frame 100 (the first directive's apply frame), it surfaces with
    // the first directive's own reason -- never the conflicting one's.
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
    // The conflicting directive's frame (150) never independently fires
    // anything -- the slot already surfaced and does not re-open.
    assert!(tracker.take_due(150, no_counts).is_empty());
}

/// The same conflict, but the conflicting copy arrives BEFORE the frame
/// the first directive named -- it still must not move the apply frame
/// or reason the slot eventually surfaces with.
#[test]
fn a_conflicting_directive_arriving_early_does_not_change_the_kept_apply_frame() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&leave(2, DROPPED, 100, 1));
    tracker.observe(&leave(2, LEFT, 50, 2)); // conflicting, earlier frame

    // Must not surface at the conflicting (earlier) frame.
    assert!(tracker.take_due(50, no_counts).is_empty());
    assert!(tracker.take_due(99, no_counts).is_empty());
    // Surfaces at the FIRST directive's own frame, with its own reason.
    assert_eq!(tracker.take_due(100, no_counts), vec![(SlotId(2), DROPPED)]);
}

#[test]
fn contains_reflects_tracked_slots_whether_or_not_theyve_surfaced() {
    let mut tracker = LeaveTracker::new();
    assert!(!tracker.contains(2), "nothing tracked yet");

    tracker.observe(&leave(2, DROPPED, 100, 1));
    assert!(tracker.contains(2), "tracked, even before its apply frame");
    assert!(!tracker.contains(3), "a different slot is untouched");

    tracker.take_due(100, no_counts);
    assert!(tracker.contains(2), "still tracked once surfaced");
}

#[test]
fn a_counted_leave_surfaces_exactly_at_its_consumed_count_and_only_once() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&counted_leave(2, LEFT, 40, 1));

    for consumed in 0..40u64 {
        assert!(
            tracker.take_due(0, |_| consumed).is_empty(),
            "surfaced early at {consumed} consumed turns"
        );
    }
    // The frame argument is irrelevant for a counted leave — even frame 0
    // (far below any scheduled frame) surfaces it once consumption arrives.
    assert_eq!(tracker.take_due(0, |_| 40), vec![(SlotId(2), LEFT)]);
    assert!(
        tracker.take_due(0, |_| 40).is_empty(),
        "a leave must surface once"
    );
}

#[test]
fn a_counted_leave_ignores_a_stale_apply_frame_already_passed() {
    // The exact hazard the count exists to remove: the directive's scheduled
    // frame is already behind this client's simulation when it arrives. A
    // frame-scheduled leave would apply immediately — at a per-client frame —
    // but the count holds it to the shared consumption point.
    let mut tracker = LeaveTracker::new();
    let mut directive = counted_leave(2, LEFT, 40, 1);
    directive.apply_at_frame = 10; // far behind a client already at frame 30+
    tracker.observe(&directive);

    assert!(
        tracker.take_due(30, |_| 35).is_empty(),
        "the passed frame must not surface a counted leave"
    );
    assert_eq!(tracker.take_due(31, |_| 40), vec![(SlotId(2), LEFT)]);
}

#[test]
fn a_zero_count_leave_is_due_immediately() {
    // A slot that never produced a turn (a pre-game departure) carries
    // count 0: nothing to consume, so the leave is due at the first poll.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&counted_leave(4, DROPPED, 0, 1));
    assert_eq!(tracker.take_due(0, |_| 0), vec![(SlotId(4), DROPPED)]);
}

#[test]
fn counted_and_frame_scheduled_leaves_coexist() {
    // A mixed session (one directive from a relay that stamps counts, one
    // from state recorded before the count existed): each surfaces by its
    // own rule, in the same poll when both come due together.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&counted_leave(2, LEFT, 40, 1));
    tracker.observe(&leave(3, DROPPED, 100, 2));

    let due = tracker.take_due(100, |slot| if slot == SlotId(2) { 40 } else { 0 });
    assert_eq!(due.len(), 2);
    assert!(due.contains(&(SlotId(2), LEFT)));
    assert!(due.contains(&(SlotId(3), DROPPED)));
}

#[test]
fn a_conflicting_count_keeps_the_first_directive() {
    // The relay contract extends to the count: every copy of a slot's leave
    // carries the same final_turn_count. A disagreeing copy is dropped like
    // a disagreeing frame/reason, never re-opening or rescheduling the slot.
    let mut tracker = LeaveTracker::new();
    tracker.observe(&counted_leave(2, LEFT, 40, 1));
    tracker.observe(&counted_leave(2, LEFT, 25, 2)); // conflicting count

    assert!(
        tracker.take_due(0, |_| 25).is_empty(),
        "the conflicting count must not drive surfacing"
    );
    assert_eq!(tracker.take_due(0, |_| 40), vec![(SlotId(2), LEFT)]);
}
/// A client leaving lockstep can make a scheduled leave due immediately — a
/// frame it is stalled short of, or a count needing turns that will never
/// come, no longer binds it — and the next poll surfaces the real reason.
#[test]
fn expedite_makes_a_scheduled_leave_due_at_the_next_poll() {
    let mut tracker = LeaveTracker::new();
    tracker.observe(&counted_leave(2, 0x3, 500, 1));
    tracker.observe(&leave(3, 0x40000006, 10_000, 2));
    assert!(
        tracker.take_due(5, |_| 0).is_empty(),
        "neither is due on its own terms"
    );

    assert!(tracker.expedite(2));
    assert!(tracker.expedite(3));
    assert!(!tracker.expedite(9), "nothing tracked for slot 9");

    let mut due = tracker.take_due(5, |_| 0);
    due.sort();
    assert_eq!(due, vec![(SlotId(2), 0x3), (SlotId(3), 0x40000006)]);
    assert!(
        !tracker.expedite(2),
        "an already-surfaced leave has nothing left to expedite"
    );
    assert!(
        tracker.take_due(5, |_| 0).is_empty(),
        "surfaced once, never again"
    );
}
