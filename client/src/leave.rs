//! Applying the relay's synced player-leave directives on the client.
//!
//! When a player leaves or drops, every remaining client must register the leave
//! at the *same* simulated step — in the same per-slot order, with the same
//! synced-RNG state — or lockstep desyncs. The authority relay carries that
//! agreement in a [`LeaveDirective`] it **pushes down each surviving client's
//! reliable control stream** (see `ControlFrame::leave_directive` in the wire
//! contract): it names the departing slot, the native leave reason, and the exact
//! future frame to apply at. It rides the reliable stream, not the turn envelope,
//! because a drop stalls every survivor and stops the turn stream — so the leave
//! that must unstall them can only arrive off the turns. The driver hands each one
//! to the game over the `leaves` channel; the game feeds them here.
//!
//! [`LeaveTracker`] is the client-side state machine that turns that stream of
//! stamps into at-most-one leave per slot, surfaced at its apply frame. It is
//! the sibling of [`DirectiveTracker`](crate::DirectiveTracker), with two
//! deliberate differences that fall out of what a leave *is*:
//!
//! - **Set-valued, not single-pending.** Several slots can be leaving at once,
//!   each at its own frame; the tracker holds one pending leave per slot and can
//!   surface several in the same step.
//! - **Dedup by *slot*, not by a sequence number — and no "moot / past-frame"
//!   case.** A slot leaves exactly once, permanently, so the first directive seen
//!   for a slot wins and every later directive for that slot (a redundant copy, a
//!   second mesh path, or an authority-handoff re-derivation with a fresh
//!   `leave_seq`) is ignored. Deduping by `leave_seq` would be *wrong*: a promoted
//!   authority re-broadcasts an unapplied slot's leave under a higher seq, and a
//!   client that had already applied it would then double-apply and desync.
//!   Deduping by slot makes the re-derivation a no-op for clients that already
//!   have it and the real thing for clients that missed the original. And unlike
//!   a buffer change, a leave can never arrive "too late": the departing slot
//!   gates the receive step until the leave clears it, so a client physically
//!   cannot advance past the apply frame without applying the leave — there is no
//!   moot directive to drop.
//!
//! **The relay's half of the contract:** every directive the relay ever emits for
//! a given slot must carry the *same* `apply_at_frame` and `reason`. That is what
//! makes "first copy seen wins, per slot" agree across clients regardless of which
//! copy each saw first — including across an authority handoff, where the promoted
//! relay must reproduce the same apply frame (from the same last-observed frame).
//! The tracker enforces "once per slot"; the relay enforces "consistent per slot".
//!
//! The driver surfaces relay-pushed leaves over the `leaves` channel, which the
//! game drains into this tracker; buffer directives still ride the turn envelope
//! and are observed separately:
//!
//! ```ignore
//! // at the TOP of each step, before the readiness check (a due leave unstalls it):
//! while let Ok(leave) = turns.leaves.try_recv() { tracker.observe(&leave); }
//! for (slot, reason) in tracker.take_due(frame) {
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
        if let Some(existing) = self
            .leaves
            .iter()
            .find(|l| l.directive.slot == directive.slot)
        {
            // Same slot already tracked: the relay's contract is that every
            // directive for a slot carries the same apply frame + reason, so a
            // disagreement is a relay bug worth catching in tests. Either way we
            // keep the first (already possibly surfaced) — never re-open a slot.
            debug_assert!(
                existing.directive.apply_at_frame == directive.apply_at_frame
                    && existing.directive.reason == directive.reason,
                "conflicting leave directives for slot {}: {:?} vs {:?}",
                directive.slot,
                existing.directive,
                directive,
            );
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

    /// Surfaces every not-yet-surfaced leave whose apply frame has been reached by
    /// `next_frame` — the frame the game is about to simulate — as `(slot, reason)`
    /// pairs. Each slot's leave is returned at most once; the caller writes each
    /// slot's native `pending_leave_reason` and drops it from the readiness set,
    /// *before* the step's readiness check (a due leave is what unstalls a step
    /// blocked on the departing slot).
    ///
    /// Call this every step. The comparison is `>=` so a missed poll still applies
    /// the leave (late is impossible in practice — the slot gates the step — but
    /// failing toward "apply" rather than "never apply" is the safe direction).
    pub fn take_due(&mut self, next_frame: u32) -> Vec<(SlotId, u32)> {
        let mut due = Vec::new();
        for leave in &mut self.leaves {
            if !leave.surfaced && next_frame >= leave.directive.apply_at_frame {
                leave.surfaced = true;
                due.push((SlotId(leave.directive.slot as u8), leave.directive.reason));
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
            slot,
            reason,
            apply_at_frame,
            leave_seq,
        }
    }

    const DROPPED: u32 = 0x4000_0006;
    const LEFT: u32 = 1;

    #[test]
    fn applies_exactly_at_the_apply_frame_and_only_once() {
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(2, DROPPED, 100, 1));

        for frame in 90..100 {
            assert!(
                tracker.take_due(frame).is_empty(),
                "applied early at {frame}"
            );
        }
        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);
        assert!(
            tracker.take_due(100).is_empty(),
            "a leave must surface once"
        );
        assert!(tracker.take_due(101).is_empty());
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

        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);
        assert!(tracker.take_due(100).is_empty());
    }

    #[test]
    fn a_handoff_rederivation_with_a_higher_seq_does_not_double_apply() {
        // The promoted authority re-broadcasts the same slot's leave under a fresh
        // leave_seq. A client that already applied it must NOT apply it again
        // (that would consume synced RNG twice and desync). Dedup is by slot, so
        // the higher-seq copy is a no-op here.
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(2, DROPPED, 100, 1));
        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);

        tracker.observe(&leave(2, DROPPED, 100, 7)); // re-derivation, higher seq
        assert!(
            tracker.take_due(200).is_empty(),
            "a slot's leave must apply exactly once across a handoff"
        );
    }

    #[test]
    fn a_handoff_rederivation_still_applies_for_a_client_that_missed_the_original() {
        // Same re-derivation, but this client never saw the original: it must
        // apply the re-derived copy (at the same frame the relay guarantees).
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(2, DROPPED, 100, 7));
        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);
    }

    #[test]
    fn several_slots_leave_each_at_its_own_frame() {
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(2, DROPPED, 100, 1));
        tracker.observe(&leave(3, LEFT, 150, 2));

        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);
        assert!(tracker.take_due(120).is_empty(), "slot 3 not due yet");
        assert_eq!(tracker.take_due(150), vec![(SlotId(3), LEFT)]);
    }

    #[test]
    fn simultaneous_leaves_at_one_frame_surface_together_in_slot_order() {
        // Two slots due at the same frame come out in one poll so the caller
        // writes both before the synced-leave pass drains them in slot order.
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(5, DROPPED, 100, 2));
        tracker.observe(&leave(1, DROPPED, 100, 1));

        let due = tracker.take_due(100);
        assert_eq!(due.len(), 2);
        assert!(due.contains(&(SlotId(5), DROPPED)));
        assert!(due.contains(&(SlotId(1), DROPPED)));
    }

    #[test]
    fn a_late_copy_after_apply_does_not_re_surface() {
        let mut tracker = LeaveTracker::new();
        let stamp = leave(2, DROPPED, 100, 1);
        tracker.observe(&stamp);
        assert_eq!(tracker.take_due(100), vec![(SlotId(2), DROPPED)]);
        // The relay keeps broadcasting until the session passes the apply frame,
        // so a copy can arrive after we already applied it.
        tracker.observe(&stamp);
        assert!(tracker.take_due(101).is_empty());
        assert!(tracker.take_due(200).is_empty());
    }

    #[test]
    fn a_leave_observed_after_its_frame_still_applies() {
        // Can't happen while the slot gates the step, but if it did, apply rather
        // than silently drop (the safe direction — everyone else applied it).
        let mut tracker = LeaveTracker::new();
        tracker.observe(&leave(2, DROPPED, 100, 1));
        assert_eq!(tracker.take_due(140), vec![(SlotId(2), DROPPED)]);
    }

    #[test]
    fn contains_reflects_tracked_slots_whether_or_not_theyve_surfaced() {
        let mut tracker = LeaveTracker::new();
        assert!(!tracker.contains(2), "nothing tracked yet");

        tracker.observe(&leave(2, DROPPED, 100, 1));
        assert!(tracker.contains(2), "tracked, even before its apply frame");
        assert!(!tracker.contains(3), "a different slot is untouched");

        tracker.take_due(100);
        assert!(tracker.contains(2), "still tracked once surfaced");
    }
}
