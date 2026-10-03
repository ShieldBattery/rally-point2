//! A rollback session's clock: when each turn is due at the relay, and how long the whole session
//! has spent stopped.
//!
//! The turn with seq `n` (a slot's `n`-th turn, which the game runs at step `n`) is due
//! [`STEP_DURATION_US`] after turn `n - 1`, from an anchor the authority sets when the session's
//! lockstep start ends, plus the time the clock has spent stopped. The clock stops when it would
//! get more than [`STALL_SLACK_STEPS`] past the newest turn the authority can confirm for every
//! player: past the game's prediction limit every player is stalled anyway, so time beyond that is
//! time the whole session spent waiting (on a dropped player, through an outage), which nobody
//! should be asked to make up afterwards. A player whose own turns run later than the slack still
//! measures that late, because only the time past the slack is taken up.
//!
//! Relays share no timebase. Each keeps its own copy: the authority's is the original, and every
//! other relay places the anchor from the authority's `SessionClock` frame, less half the mesh
//! round trip the frame took.

use super::*;

use rally_point_proto::rollback::STEP_DURATION_US;

/// How far the clock may run past the newest turn the authority can confirm before it stops: the
/// game client's prediction limit (8 steps) and a margin of 4.
pub(in crate::consensus) const STALL_SLACK_STEPS: u64 = 12;

/// When `steps` turns' worth of the clock has passed.
fn steps_duration(steps: u64) -> Duration {
    Duration::from_micros(STEP_DURATION_US.saturating_mul(steps))
}

/// One relay's copy of a rollback session's clock. Unanchored until the lockstep start ends (on
/// the authority) or the authority's frame arrives (elsewhere).
#[derive(Debug, Default)]
pub(in crate::consensus) struct SessionClock {
    /// The anchor turn and the instant it was due, not counting stopped time.
    anchor: Option<(u64, Instant)>,
    /// The time the clock has spent stopped.
    pause: Duration,
}

impl SessionClock {
    pub(in crate::consensus) fn is_anchored(&self) -> bool {
        self.anchor.is_some()
    }

    /// The time the clock has spent stopped.
    pub(in crate::consensus) fn pause(&self) -> Duration {
        self.pause
    }

    /// When the turn with seq `seq` is due, or `None` before the clock is anchored or for a turn
    /// of the lockstep start, which every client waits for and nobody is measured on.
    pub(in crate::consensus) fn due_at(&self, seq: u64) -> Option<Instant> {
        let (anchor_seq, at) = self.anchor?;
        let after = seq.checked_sub(anchor_seq)?;
        Some(at + self.pause + steps_duration(after))
    }

    /// How late the turn with seq `seq` was when it arrived at `arrived`, in microseconds
    /// (negative when early), or `None` when [`due_at`](Self::due_at) has no deadline for it.
    pub(in crate::consensus) fn lateness_us(&self, seq: u64, arrived: Instant) -> Option<i64> {
        let due = self.due_at(seq)?;
        Some(match arrived.checked_duration_since(due) {
            Some(late) => i64::try_from(late.as_micros()).unwrap_or(i64::MAX),
            None => -i64::try_from((due - arrived).as_micros()).unwrap_or(i64::MAX),
        })
    }

    /// Anchors the clock with the turn with seq `seq` due at `at`, unless it already is. Returns
    /// whether it anchored.
    pub(in crate::consensus) fn anchor(&mut self, seq: u64, at: Instant) -> bool {
        if self.anchor.is_some() {
            return false;
        }
        self.anchor = Some((seq, at));
        true
    }

    /// Notes, on the authority, that the newest turn it can confirm for every player advanced at
    /// `now`, from the turn with seq `newest_before`. Any time the clock ran past
    /// [`STALL_SLACK_STEPS`] beyond that turn is time the session spent stopped, and is added to
    /// [`pause`](Self::pause). Returns whether it was.
    pub(in crate::consensus) fn note_confirmable_advance(
        &mut self,
        newest_before: u64,
        now: Instant,
    ) -> bool {
        let Some(limit) = self.due_at(newest_before.saturating_add(STALL_SLACK_STEPS)) else {
            return false;
        };
        let Some(stopped) = now.checked_duration_since(limit).filter(|x| !x.is_zero()) else {
            return false;
        };
        self.pause += stopped;
        true
    }

    /// The clock as the authority sends it at `now`: the anchor turn, how long ago the anchor was
    /// set (stopped time not counted, since it travels separately), and the stopped time. `None`
    /// before the anchor.
    pub(in crate::consensus) fn to_frame(&self, now: Instant) -> Option<SessionClockFrame> {
        let (anchor_seq, at) = self.anchor?;
        Some(SessionClockFrame {
            anchor_step: anchor_seq,
            since_anchor_us: u64::try_from(now.saturating_duration_since(at).as_micros())
                .unwrap_or(u64::MAX),
            pause_us: u64::try_from(self.pause.as_micros()).unwrap_or(u64::MAX),
        })
    }

    /// Adopts the authority's clock on another relay, from a frame that arrived at `received_at`
    /// over a mesh link with a round trip of `mesh_rtt_us`. The anchor is set once, from the first
    /// frame, so later frames (which only carry a grown stopped time) don't move every deadline by
    /// the jitter of their own trip. Stopped time only ever grows. Returns whether anything
    /// changed.
    pub(in crate::consensus) fn adopt(
        &mut self,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> bool {
        let mut changed = false;
        if self.anchor.is_none() {
            let age = Duration::from_micros(frame.since_anchor_us)
                + Duration::from_micros(u64::from(mesh_rtt_us) / 2);
            let at = received_at.checked_sub(age).unwrap_or(received_at);
            self.anchor = Some((frame.anchor_step, at));
            changed = true;
        }
        let pause = Duration::from_micros(frame.pause_us);
        if pause > self.pause {
            self.pause = pause;
            changed = true;
        }
        changed
    }
}
