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

    /// Makes a tracked, not-yet-surfaced leave for `slot` due at the very next
    /// [`take_due`](Self::take_due), whatever coordinate it was scheduled at, and
    /// reports whether there was one. The directive's slot and reason are kept;
    /// only its schedule is discarded.
    ///
    /// A leave's apply coordinate exists so that every client applies it at the
    /// identical simulated step. A client that is leaving lockstep itself — its
    /// game ending locally, or the player quitting — has no one left to stay
    /// identical with, and a schedule it can no longer reach is a trap: a frame
    /// past the one it is stalled at, or a turn count that needs turns the
    /// departing peer will never send, would keep that peer required forever and
    /// the stalled step from ever assembling. Expediting the leave lets the next
    /// poll surface it with its real reason through the ordinary path.
    pub fn expedite(&mut self, slot: u32) -> bool {
        match self
            .leaves
            .iter_mut()
            .find(|l| l.directive.slot == slot && !l.surfaced)
        {
            Some(leave) => {
                leave.directive.apply_at_frame = 0;
                leave.directive.final_turn_count = None;
                true
            }
            None => false,
        }
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
mod tests;
