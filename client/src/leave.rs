//! Applying the relay's synced player-leave directives on the client.
//!
//! When a player leaves or drops, every remaining client must register the leave
//! at the *same* simulated step — in the same per-slot order, with the same
//! synced-RNG state — or lockstep desyncs. The authority relay carries that
//! agreement in a [`LeaveDirective`] it **pushes down each surviving client's
//! reliable control stream** (see `ControlFrame::leave_directive` in the wire
//! contract): it names the departing slot, the native leave reason, and the
//! synchronization point to apply at — primarily `final_turn_count`, the exact
//! number of the departed slot's turns to consume first (relay-authored,
//! reached at the same step by every client), with a scheduled frame as the
//! fallback for directives that predate the count (see
//! [`take_due`](LeaveTracker::take_due) for the fallback's known imprecision).
//! It rides the reliable stream, not the turn envelope, because a drop stalls
//! every survivor and stops the turn stream — so the leave that must unstall
//! them can only arrive off the turns. The driver hands each one to the game
//! over the `leaves` channel; the game feeds them here.
//!
//! [`LeaveTracker`] is the client-side state machine that turns that stream of
//! stamps into at-most-one leave per slot, surfaced at its apply frame. It is
//! the sibling of [`DirectiveTracker`](crate::DirectiveTracker), with two
//! deliberate differences that fall out of what a leave *is*:
//!
//! - **Set-valued, not single-pending.** Several slots can be leaving at once,
//!   each at its own frame; the tracker holds one pending leave per slot and can
//!   surface several in the same step.
//! - **Dedup by *slot*, not by a sequence number — and no "moot" case.** A slot
//!   leaves exactly once, permanently, so the first directive seen for a slot
//!   wins and every later directive for that slot (a redundant copy, a second
//!   mesh path, or an authority-handoff re-derivation with a fresh `leave_seq`)
//!   is ignored. Deduping by `leave_seq` would be *wrong*: a promoted
//!   authority re-broadcasts an unapplied slot's leave under a higher seq, and a
//!   client that had already applied it would then double-apply and desync.
//!   Deduping by slot makes the re-derivation a no-op for clients that already
//!   have it and the real thing for clients that missed the original. And unlike
//!   a buffer change, a leave can never arrive "too late": consumption of the
//!   departed slot's turns parks at `final_turn_count` (the relay forwards
//!   nothing past it), so the count comparison holds from the right step onward
//!   no matter when the directive lands — there is no moot directive to drop.
//!
//! **The relay's half of the contract:** every directive the relay ever emits for
//! a given slot must carry the *same* `final_turn_count`, `apply_at_frame`, and
//! `reason`. That is what makes "first copy seen wins, per slot" agree across
//! clients regardless of which copy each saw first — including across an
//! authority handoff, where the promoted relay must reproduce the same values
//! (from the same home-authored departure record). The tracker enforces "once
//! per slot"; the relay enforces "consistent per slot".
//!
//! The driver surfaces relay-pushed leaves over the `leaves` channel, which the
//! game drains into this tracker; buffer directives still ride the turn envelope
//! and are observed separately:
//!
//! ```ignore
//! // at the TOP of each step, before the readiness check (a due leave unstalls it):
//! while let Ok(leave) = turns.leaves.try_recv() { tracker.observe(&leave); }
//! for (slot, reason) in tracker.take_due(frame, |slot| consumed_turns(slot)) {
//!     // write that slot's native pending_leave_reason and drop it from `required`
//! }
//! ```

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::LeaveDirective;

/// One tracked slot-leave: the directive plus whether [`take_due`](LeaveTracker::take_due)
/// has already surfaced it (so a late redundant copy for an already-applied slot
/// is ignored rather than re-surfaced).
#[derive(Debug, Clone)]
struct TrackedLeave {
    directive: LeaveDirective,
    surfaced: bool,
}

/// Client-side synced-leave state: collapses the redundant, out-of-order stream
/// of envelope stamps into at-most-one leave per slot, each surfaced once at its
/// apply frame.
///
/// Owned by the game loop (single-threaded, no IO). Feed every received stamp to
/// [`observe`](Self::observe) while draining turns; poll [`take_due`](Self::take_due)
/// at the top of each simulation step, before checking readiness.
#[derive(Debug, Default)]
pub struct LeaveTracker {
    /// One entry per slot a leave has been seen for, in arrival order. Bounded by
    /// the player count (a slot leaves once), so a linear scan is cheaper than a
    /// map and needs no capacity guess.
    leaves: Vec<TrackedLeave>,
}

impl LeaveTracker {
    /// A tracker that has seen no leaves.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one received stamp in. The first directive seen for a slot is
    /// recorded; every later stamp for that slot — a redundant copy, a second
    /// mesh path, or an authority-handoff re-derivation — is ignored, because a
    /// slot leaves exactly once.
    ///
    /// Safe to call with every stamp the redundant, out-of-order turn stream
    /// delivers, in whatever order they arrive.
    pub fn observe(&mut self, directive: &LeaveDirective) {
        if u8::try_from(directive.slot).is_err() {
            // A slot id past `u8` range can't name any real slot; letting it into
            // the tracker would truncate to a valid slot id in `take_due` and
            // apply the leave to the wrong player. Drop it here so it never
            // enters (defensive — the wire values are validated upstream, so
            // this shouldn't occur).
            tracing::warn!(
                slot = directive.slot,
                "leave directive names a slot id out of range; ignoring",
            );
            return;
        }
        if let Some(existing) = self
            .leaves
            .iter()
            .find(|l| l.directive.slot == directive.slot)
        {
            // Same slot already tracked: the relay's contract is that every
            // directive for a slot carries the same apply frame + reason, so a
            // disagreement is a relay bug. Either way we keep the first
            // (already possibly surfaced) — never re-open a slot; convergence
            // by single-sourcing (first copy seen wins, per slot) still holds
            // regardless of which client saw which conflicting copy. This is a
            // runtime check, not a `debug_assert!`: a contract violation this
            // serious must be observable in a release build, not silently
            // swallowed the moment debug assertions are compiled out.
            if existing.directive.apply_at_frame != directive.apply_at_frame
                || existing.directive.reason != directive.reason
                || existing.directive.final_turn_count != directive.final_turn_count
            {
                tracing::error!(
                    slot = directive.slot,
                    kept = ?existing.directive,
                    conflicting = ?directive,
                    "conflicting leave directives for the same slot; keeping the first, \
                     the session's authority relay violated its own single-copy-per-slot \
                     contract",
                );
            }
            return;
        }
        self.leaves.push(TrackedLeave {
            directive: *directive,
            surfaced: false,
        });
    }

    /// Whether a leave has been observed for this slot, applied or not.
    pub fn contains(&self, slot: u32) -> bool {
        self.leaves.iter().any(|l| l.directive.slot == slot)
    }

    /// Surfaces every not-yet-surfaced leave that has come due, as `(slot, reason)`
    /// pairs. Each slot's leave is returned at most once; the caller writes each
    /// slot's native `pending_leave_reason` and drops it from the readiness set,
    /// *before* the step's readiness check (a due leave is what unstalls a step
    /// blocked on the departing slot).
    ///
    /// A directive carrying `final_turn_count` is due once `consumed(slot)` — how
    /// many of that slot's turns this client has dispatched to its sim — reaches
    /// the count. Turn consumption is lockstep-deterministic (every client
    /// dispatches the identical relay-forwarded set, one turn per slot per step),
    /// so every client surfaces the leave at the same simulated step with no
    /// trust in anyone's frame stamps. The relay forwards nothing past the
    /// count, so consumption parks exactly there and the comparison holds from
    /// the right step onward.
    ///
    /// A directive without the count (a relay that predates it) falls back to
    /// `next_frame >= apply_at_frame` — the frame the game is about to simulate
    /// against the directive's scheduled frame. The relay's survivor-reachability
    /// clamp can place that frame at one this client has already passed, which
    /// this comparison then applies on arrival — late, and not necessarily at
    /// the same step as everyone else. That imprecision is what
    /// `final_turn_count` exists to remove; the frame path remains only for
    /// compatibility.
    ///
    /// Call this every step. Both comparisons are `>=` so a missed poll still
    /// applies the leave — failing toward "apply" rather than "never apply" is
    /// the safe direction.
    pub fn take_due(
        &mut self,
        next_frame: u32,
        consumed: impl Fn(SlotId) -> u64,
    ) -> Vec<(SlotId, u32)> {
        let mut due = Vec::new();
        for leave in &mut self.leaves {
            if leave.surfaced {
                continue;
            }
            // `observe` already rejected any directive whose slot doesn't fit
            // in a `u8`, so every tracked entry casts back losslessly.
            let slot = SlotId(leave.directive.slot as u8);
            let is_due = match leave.directive.final_turn_count {
                Some(count) => consumed(slot) >= count,
                None => next_frame >= leave.directive.apply_at_frame,
            };
            if is_due {
                leave.surfaced = true;
                due.push((slot, leave.directive.reason));
            }
        }
        due
    }
}

#[cfg(test)]
mod tests {
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

    fn counted_leave(
        slot: u32,
        reason: u32,
        final_turn_count: u64,
        leave_seq: u32,
    ) -> LeaveDirective {
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
}
