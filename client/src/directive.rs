//! Applying the relay's latency-buffer directives on the client.
//!
//! The authority relay resizes the lockstep latency buffer by stamping a
//! [`BufferDirective`] onto the envelope of turns it forwards (see
//! `Payload::buffer_directive` in the wire contract). Every client must apply
//! the same change at the same simulated step, or lockstep desyncs — so the
//! directive names the exact future frame to apply at, and a `decision_seq`
//! orders decisions within the session. The turn stream is out-of-order and
//! redundant by design, which means copies of a directive arrive many times
//! and copies of a superseded directive can interleave with its replacement's.
//!
//! [`DirectiveTracker`] is the client-side state machine that turns that
//! stream of stamps into at-most-one buffer change per decision, applied at
//! the right step. It is deliberately sans-IO and single-threaded: the game
//! loop owns one, feeds it stamps while draining received turns, and polls it
//! once per simulation step. The rules it enforces:
//!
//! - **Highest `decision_seq` wins.** A stamp at or below the highest seq seen
//!   is a redundant copy or a superseded decision; both are dropped. A newer
//!   decision replaces a still-pending older one — the superseded change must
//!   never apply, even if its apply frame comes first.
//! - **Apply exactly at `apply_at_frame`.** The change is held until the game
//!   reaches that step, then surfaced once.
//! - **A past frame applies nothing.** A directive that arrives with its apply
//!   frame already behind the game is moot — applying it late would move this
//!   client's buffer at a different step than everyone else's. Its seq is
//!   still recorded, so a stale copy of it can't resurface later.
//!
//! The driver hands payloads to the game with their envelope intact, so the
//! game seam's drain loop is where stamps are observed:
//!
//! ```ignore
//! // once per simulation step, before dispatching `frame`:
//! while let Ok(payload) = turns.inbound.try_recv() {
//!     if let Some(directive) = &payload.buffer_directive {
//!         tracker.observe(directive, frame);
//!     }
//!     // ... hand the turn's commands to the game ...
//! }
//! if let Some(directive) = tracker.take_due(frame) {
//!     // resize the latency buffer to directive.buffer_turns
//! }
//! ```

use rally_point_proto::messages::BufferDirective;

/// Client-side latency-buffer directive state: collapses the redundant,
/// out-of-order stream of envelope stamps into at-most-one pending buffer
/// change, surfaced at its apply frame.
///
/// Owned by the game loop (single-threaded, no IO). Feed every received stamp
/// to [`observe`](Self::observe); poll [`take_due`](Self::take_due) once per
/// simulation step. Both take the frame the game is *about to simulate* —
/// observe-then-poll within one step lets a directive naming the current step
/// still apply on time.
#[derive(Debug, Default)]
pub struct DirectiveTracker {
    /// The highest `decision_seq` seen. Anything at or below it is a redundant
    /// copy or a superseded decision. The authority numbers decisions from 1
    /// (and keeps the numbering continuous across an authority handoff), so 0
    /// means "nothing seen yet".
    highest_seq: u32,
    /// The winning decision whose apply frame is still ahead, if any. `None`
    /// almost always — buffer changes are rare and each is pending only for
    /// the short window between its arrival and its apply frame.
    pending: Option<BufferDirective>,
}

impl DirectiveTracker {
    /// A tracker that has seen no decisions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one received stamp in. `next_frame` is the frame the game is
    /// about to simulate; a directive whose apply frame is already behind it
    /// is moot and will never surface (applying it late would change the
    /// buffer at a different step than the other clients did).
    ///
    /// Copies are idempotent and ordering is by `decision_seq` alone, so this
    /// is safe to call with every stamp the redundant, out-of-order turn
    /// stream delivers, in whatever order they arrive.
    pub fn observe(&mut self, directive: &BufferDirective, next_frame: u32) {
        if directive.decision_seq <= self.highest_seq {
            return;
        }
        self.highest_seq = directive.decision_seq;
        // The newest decision always displaces the pending one — even when the
        // newcomer itself is moot, the decision it superseded must not apply.
        self.pending = (directive.apply_at_frame >= next_frame).then_some(*directive);
    }

    /// Surfaces the pending buffer change if `next_frame` — the frame the game
    /// is about to simulate — has reached its apply frame. Returns each
    /// decision at most once; the caller applies `buffer_turns` before
    /// dispatching the step.
    ///
    /// Call this every step. Lockstep advances one frame at a time, so with a
    /// per-step poll the change surfaces exactly at `apply_at_frame`; the
    /// comparison is `>=` only so a missed poll fails toward late application
    /// rather than never applying.
    pub fn take_due(&mut self, next_frame: u32) -> Option<BufferDirective> {
        if self.pending?.apply_at_frame <= next_frame {
            self.pending.take()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(buffer_turns: u32, apply_at_frame: u32, decision_seq: u32) -> BufferDirective {
        BufferDirective {
            buffer_turns,
            apply_at_frame,
            decision_seq,
        }
    }

    #[test]
    fn applies_exactly_at_the_apply_frame_and_only_once() {
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive(4, 100, 1), 90);

        for frame in 90..100 {
            assert_eq!(tracker.take_due(frame), None, "applied early at {frame}");
        }
        assert_eq!(tracker.take_due(100), Some(directive(4, 100, 1)));
        assert_eq!(tracker.take_due(100), None, "a decision must apply once");
        assert_eq!(tracker.take_due(101), None);
    }

    #[test]
    fn redundant_copies_are_idempotent() {
        let mut tracker = DirectiveTracker::new();
        let stamp = directive(4, 100, 1);
        // The same decision rides every forwarded turn until the session
        // passes the apply frame, so copies arrive constantly.
        tracker.observe(&stamp, 90);
        tracker.observe(&stamp, 91);
        tracker.observe(&stamp, 95);

        assert_eq!(tracker.take_due(100), Some(stamp));
        assert_eq!(tracker.take_due(100), None);
    }

    #[test]
    fn a_higher_seq_decision_replaces_a_pending_one() {
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive(4, 100, 1), 90);
        tracker.observe(&directive(6, 110, 2), 91);

        // The superseded decision must not fire at its own apply frame.
        assert_eq!(tracker.take_due(100), None);
        assert_eq!(tracker.take_due(110), Some(directive(6, 110, 2)));
    }

    #[test]
    fn a_late_copy_of_a_superseded_decision_is_ignored() {
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive(6, 110, 2), 90);
        // The out-of-order wire delivers a copy of the older decision after
        // its replacement — even one naming the same apply frame.
        tracker.observe(&directive(4, 110, 1), 91);

        assert_eq!(tracker.take_due(110), Some(directive(6, 110, 2)));
    }

    #[test]
    fn a_directive_for_a_past_frame_applies_nothing() {
        let mut tracker = DirectiveTracker::new();
        // Arrives with its apply frame already behind the game: moot.
        tracker.observe(&directive(4, 100, 1), 150);

        for frame in 150..300 {
            assert_eq!(tracker.take_due(frame), None);
        }
    }

    #[test]
    fn a_moot_directive_still_supersedes_the_pending_one() {
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive(4, 200, 1), 90);
        // A newer decision arrives too late to apply itself — but the decision
        // it replaced must not apply either.
        tracker.observe(&directive(6, 95, 2), 96);

        for frame in 96..300 {
            assert_eq!(tracker.take_due(frame), None);
        }
    }

    #[test]
    fn a_directive_naming_the_current_step_applies_this_step() {
        let mut tracker = DirectiveTracker::new();
        // The drain loop observes stamps just before the step is dispatched,
        // so "apply at the frame we're about to simulate" is still on time.
        tracker.observe(&directive(4, 100, 1), 100);
        assert_eq!(tracker.take_due(100), Some(directive(4, 100, 1)));
    }

    #[test]
    fn an_initial_equal_size_directive_surfaces_as_a_no_op_resize() {
        // The authority broadcasts one directive at the first framed turn carrying
        // the buffer the session already runs, so a client seeded differently is
        // corrected. A client already at that depth receives an "equal-size"
        // resize: the tracker ranks by `decision_seq` alone and never inspects
        // `buffer_turns`, so it surfaces the directive exactly like any other
        // (once, at its apply frame), and the caller resizes to the depth it is
        // already at — a no-op. Nothing here needs to special-case it.
        let mut tracker = DirectiveTracker::new();
        let current_depth = 3;
        tracker.observe(&directive(current_depth, 100, 1), 90);
        assert_eq!(
            tracker.take_due(100),
            Some(directive(current_depth, 100, 1))
        );
        assert_eq!(
            tracker.take_due(100),
            None,
            "surfaces once, like any decision"
        );

        // A later real change still ranks above it and applies normally.
        tracker.observe(&directive(6, 200, 2), 150);
        assert_eq!(tracker.take_due(200), Some(directive(6, 200, 2)));
    }

    #[test]
    fn a_stale_copy_of_a_moot_decision_cannot_resurface() {
        let mut tracker = DirectiveTracker::new();
        // Seen first while moot: recorded but never pending.
        tracker.observe(&directive(4, 100, 1), 150);
        // A redundant copy arrives again later; it must stay dead even though
        // nothing is pending.
        tracker.observe(&directive(4, 100, 1), 151);
        assert_eq!(tracker.take_due(151), None);
        assert_eq!(tracker.take_due(200), None);
    }
}
