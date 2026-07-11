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
//! - **Highest `decision_seq` wins.** A stamp below the highest seq seen is a
//!   superseded decision and is dropped. A strictly newer decision replaces a
//!   still-pending older one — the superseded change must never apply, even
//!   if its apply frame comes first.
//! - **An equal `decision_seq` breaks the tie by `authority_relay_id`.** Two
//!   relays can briefly both believe they hold buffer authority (an
//!   acknowledged staggered-handoff race), each minting its own
//!   `decision_seq` count from where it took authority — so two directives
//!   can collide on the same seq with different `buffer_turns`. An ordinary
//!   redundant copy of the current winner is also "equal seq" and is simply a
//!   no-op here. See [`observe`](DirectiveTracker::observe) for the exact
//!   rule and why `Option<u64>`'s own ordering is exactly the comparison this
//!   needs.
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
    /// The highest `decision_seq` seen. Anything below it is a superseded
    /// decision. The authority numbers decisions from 1 (and keeps the
    /// numbering continuous across an authority handoff), so 0 means "nothing
    /// seen yet".
    highest_seq: u32,
    /// The `authority_relay_id` of the winning decision at `highest_seq` —
    /// kept even after `pending` is cleared (surfaced at its apply frame, or
    /// moot on arrival), so a later-arriving colliding copy at the same seq
    /// is still compared against the right identity, not `None`.
    highest_seq_tiebreak: Option<u64>,
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
    /// A strictly higher `decision_seq` always displaces the current winner.
    /// An EQUAL `decision_seq` displaces it only when `authority_relay_id` is
    /// itself strictly greater than the current winner's — `Option<u64>`'s
    /// own derived ordering is exactly this rule already: `None < Some(_)`
    /// for any value, so a directive naming no relay id (a relay running code
    /// that predates the field) never displaces one that does, and two
    /// `None`s (an unfixed fleet, or the ordinary case of two copies of the
    /// same decision) never displace each other — the first one seen simply
    /// stays, same as before this tie-break existed. Two `Some` ids compare
    /// numerically; equal ids are the same relay's own redundant copy and
    /// don't displace either.
    ///
    /// Copies are idempotent, so this is safe to call with every stamp the
    /// redundant, out-of-order turn stream delivers, in whatever order they
    /// arrive.
    pub fn observe(&mut self, directive: &BufferDirective, next_frame: u32) {
        match directive.decision_seq.cmp(&self.highest_seq) {
            std::cmp::Ordering::Less => return,
            std::cmp::Ordering::Equal
                if directive.authority_relay_id <= self.highest_seq_tiebreak =>
            {
                return;
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
        }
        self.highest_seq = directive.decision_seq;
        self.highest_seq_tiebreak = directive.authority_relay_id;
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
        directive_from(buffer_turns, apply_at_frame, decision_seq, None)
    }

    /// [`directive`] with an explicit `authority_relay_id`, for the tie-break
    /// tests below.
    fn directive_from(
        buffer_turns: u32,
        apply_at_frame: u32,
        decision_seq: u32,
        authority_relay_id: Option<u64>,
    ) -> BufferDirective {
        BufferDirective {
            buffer_turns,
            apply_at_frame,
            decision_seq,
            authority_relay_id,
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

    /// The staggered-handoff collision this tie-break exists for: two
    /// directives share a `decision_seq` but carry different `buffer_turns`
    /// (each relay minted its own count independently). Every client must
    /// converge on the same winner regardless of which copy it happens to
    /// see first — the whole point of a deterministic tie-break instead of
    /// "whichever arrived first".
    #[test]
    fn equal_seq_directives_converge_on_the_higher_relay_id_regardless_of_arrival_order() {
        let low = directive_from(4, 100, 1, Some(10));
        let high = directive_from(8, 100, 1, Some(20));

        // low arrives first.
        let mut tracker_a = DirectiveTracker::new();
        tracker_a.observe(&low, 90);
        tracker_a.observe(&high, 91);
        assert_eq!(tracker_a.take_due(100), Some(high));

        // high arrives first -- same winner either way.
        let mut tracker_b = DirectiveTracker::new();
        tracker_b.observe(&high, 90);
        tracker_b.observe(&low, 91);
        assert_eq!(tracker_b.take_due(100), Some(high));
    }

    #[test]
    fn a_lower_relay_id_at_an_equal_seq_does_not_displace_the_higher_one() {
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive_from(8, 100, 1, Some(20)), 90);
        // A colliding copy from the losing relay, arriving after: no effect.
        tracker.observe(&directive_from(4, 100, 1, Some(10)), 91);
        assert_eq!(tracker.take_due(100), Some(directive_from(8, 100, 1, Some(20))));
    }

    #[test]
    fn a_directive_with_no_relay_id_never_displaces_one_that_has_it() {
        // A relay running code that predates the tie-break field stamps no
        // id at all -- it must never win a collision against one that does,
        // regardless of arrival order.
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive_from(8, 100, 1, Some(20)), 90);
        tracker.observe(&directive_from(4, 100, 1, None), 91);
        assert_eq!(tracker.take_due(100), Some(directive_from(8, 100, 1, Some(20))));

        // And the reverse: the id-less one arrives first, the identified one
        // still displaces it.
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive_from(4, 100, 1, None), 90);
        tracker.observe(&directive_from(8, 100, 1, Some(20)), 91);
        assert_eq!(tracker.take_due(100), Some(directive_from(8, 100, 1, Some(20))));
    }

    #[test]
    fn two_directives_with_no_relay_id_at_an_equal_seq_keep_the_first_arrival() {
        // An unfixed fleet (or two genuine copies of the same decision): with
        // neither directive naming a relay id, the tie-break can't order them,
        // so the tracker falls back to exactly its old behavior -- the first
        // one seen simply stays. This is not a regression: without the field,
        // clients could already disagree during the staggered-handoff window;
        // this tracker's job is only to converge them once the field is set.
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive_from(4, 100, 1, None), 90);
        tracker.observe(&directive_from(8, 100, 1, None), 91);
        assert_eq!(tracker.take_due(100), Some(directive_from(4, 100, 1, None)));
    }

    #[test]
    fn the_tie_break_identity_persists_after_the_winner_is_taken() {
        // A colliding copy of the losing directive can arrive AFTER the
        // winner has already been surfaced via take_due -- `pending` is gone
        // by then, so the tracker must still remember the winning relay id to
        // reject it correctly.
        let mut tracker = DirectiveTracker::new();
        tracker.observe(&directive_from(8, 100, 1, Some(20)), 90);
        assert_eq!(tracker.take_due(100), Some(directive_from(8, 100, 1, Some(20))));

        // The losing relay's copy arrives late, after the winner already
        // applied. It must not resurrect a (now-past) pending change.
        tracker.observe(&directive_from(4, 100, 1, Some(10)), 105);
        assert_eq!(tracker.take_due(105), None);

        // A later, genuinely higher seq still displaces normally.
        tracker.observe(&directive_from(6, 200, 2, Some(10)), 150);
        assert_eq!(tracker.take_due(200), Some(directive_from(6, 200, 2, Some(10))));
    }
}
