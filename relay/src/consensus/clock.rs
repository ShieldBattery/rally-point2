//! A rollback session's clock: when each turn is due at the relay, and where the clock stood still.
//!
//! The turn with seq `n` (a slot's `n`-th turn, which the game runs at step `n`) is due
//! [`STEP_DURATION_US`] after turn `n - 1`, from an anchor the authority sets when the session's
//! lockstep start ends, plus every time the clock stood still before step `n`. The clock may not
//! run more than [`STALL_SLACK_STEPS`] past the newest step the authority can confirm for every
//! player: that step is its *limit*, and when the clock reaches the limit's deadline before the
//! next step becomes confirmable, it stands still there until one does. Past the slack every
//! client is stalled at its prediction limit, so that time is time the whole session spent waiting
//! (on a dropped player, through an outage), which nobody should be asked to make up afterwards. A
//! player whose own turns run later than the slack still measures about that late, because the
//! clock moves on as each of their turns arrives.
//!
//! A stop is kept by step: the limit the clock stood at, and for how long. It moves the deadline of
//! every later step and of no earlier one, whatever order a relay learns things in. And since the
//! clock only ever stops at its limit, and the limit only grows, every step up to the limit already
//! has its final deadline: a turn is measured only once its step is that far, so no measurement is
//! ever read against a deadline that moves afterwards.
//!
//! Relays share no timebase. Each keeps its own copy: the authority's is the original, and every
//! other relay adopts the authority's `SessionClock` frames whole, placing the anchor once, at the
//! first frame's receipt less the frame's age and half the mesh round trip it took.

use super::*;

use rally_point_proto::messages::ClockStop;
use rally_point_proto::rollback::STEP_DURATION_US;

/// How far the clock may run past the newest step the authority can confirm before it stops:
/// where clients stall. A client runs at most its prediction limit (8 steps) past the newest step
/// it knows every turn of, and steadily a couple of steps of rollback behind that, so it stalls
/// about 6 steps past what is confirmable.
pub(in crate::consensus) const STALL_SLACK_STEPS: u64 = 6;

/// How far behind its limit the clock keeps each stop by step. A relay measures a slot's turns up
/// to [`LEAD_SEEN_SEQS`] behind the slot's newest, and a player the session waits on is never more
/// than the slack behind the limit, so no such turn is older. Older stops are kept only as their
/// sum, which moves every turn still measured by all of them.
pub(in crate::consensus) const KEPT_STOP_STEPS: u64 = LEAD_SEEN_SEQS + STALL_SLACK_STEPS;

/// When `steps` turns' worth of the clock has passed.
fn steps_duration(steps: u64) -> Duration {
    Duration::from_micros(STEP_DURATION_US.saturating_mul(steps))
}

/// A duration in whole microseconds, saturating.
fn whole_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// One finished stop: the clock stood still at `step` for `pause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stop {
    step: u64,
    pause: Duration,
}

/// One relay's copy of a rollback session's clock. Unanchored until the lockstep start ends (on
/// the authority) or the authority's frame arrives (elsewhere).
#[derive(Debug, Default)]
pub(in crate::consensus) struct SessionClock {
    /// The anchor turn and the instant it was due.
    anchor: Option<(u64, Instant)>,
    /// The clock's limit: the newest step whose deadline is final.
    final_through: u64,
    /// Stops at steps before this one are kept only as their sum, `base_pause`.
    base_step: u64,
    base_pause: Duration,
    /// Every finished stop at or after `base_step`, by step.
    stops: VecDeque<Stop>,
}

impl SessionClock {
    pub(in crate::consensus) fn is_anchored(&self) -> bool {
        self.anchor.is_some()
    }

    /// The step due at the anchor, once the clock is anchored.
    pub(in crate::consensus) fn anchor_step(&self) -> Option<u64> {
        self.anchor.map(|(step, _)| step)
    }

    /// The newest step whose deadline is final, once the clock is anchored. A turn past it has no
    /// deadline yet: the clock may still stop before its step.
    pub(in crate::consensus) fn final_through(&self) -> Option<u64> {
        self.anchor.map(|_| self.final_through)
    }

    /// The time the clock has spent stopped, over every finished stop.
    pub(in crate::consensus) fn pause(&self) -> Duration {
        self.base_pause + self.stops.iter().map(|stop| stop.pause).sum::<Duration>()
    }

    /// When the turn with seq `seq` is due. `None` before the clock is anchored, for a turn of the
    /// lockstep start (which every client waits for and nobody is measured on), for a turn whose
    /// deadline isn't final yet, and for one so far behind that its stops are kept only as a sum.
    pub(in crate::consensus) fn due_at(&self, seq: u64) -> Option<Instant> {
        let (anchor_seq, at) = self.anchor?;
        let after = seq.checked_sub(anchor_seq)?;
        if seq > self.final_through || seq < self.base_step {
            return None;
        }
        let stopped = self
            .stops
            .iter()
            .filter(|stop| stop.step < seq)
            .map(|stop| stop.pause)
            .sum::<Duration>();
        Some(at + self.base_pause + stopped + steps_duration(after))
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
        self.final_through = seq.saturating_add(STALL_SLACK_STEPS);
        true
    }

    /// Notes, on the authority, that the newest step it can confirm for every player became
    /// `newest` at `now`, which moves the limit on to [`STALL_SLACK_STEPS`] past it. If the clock
    /// had already reached the old limit's deadline, it stood still there until now, and that
    /// stop is kept. Returns whether there was one.
    ///
    /// A limit that doesn't grow (a newly promoted authority confirming steps the former one
    /// already had) leaves the clock as it is, stopped or not.
    pub(in crate::consensus) fn note_confirmable(&mut self, newest: u64, now: Instant) -> bool {
        let limit = newest.saturating_add(STALL_SLACK_STEPS);
        if self.anchor.is_none() || limit <= self.final_through {
            return false;
        }
        let stop = self
            .due_at(self.final_through)
            .and_then(|due| now.checked_duration_since(due))
            .filter(|pause| !pause.is_zero())
            .map(|pause| Stop {
                step: self.final_through,
                pause,
            });
        self.stops.extend(stop);
        self.final_through = limit;
        let base = limit.saturating_sub(KEPT_STOP_STEPS);
        while let Some(stop) = self.stops.front().filter(|stop| stop.step < base) {
            self.base_pause += stop.pause;
            self.stops.pop_front();
        }
        self.base_step = self.base_step.max(base);
        stop.is_some()
    }

    /// The clock as the authority sends it at `now`: its whole state, with the anchor as its age.
    /// `None` before the anchor.
    pub(in crate::consensus) fn to_frame(&self, now: Instant) -> Option<SessionClockFrame> {
        let (anchor_step, at) = self.anchor?;
        Some(SessionClockFrame {
            anchor_step,
            since_anchor_us: whole_micros(now.saturating_duration_since(at)),
            final_through: self.final_through,
            base_step: self.base_step,
            base_pause_us: whole_micros(self.base_pause),
            stops: self
                .stops
                .iter()
                .map(|stop| ClockStop {
                    step: stop.step,
                    pause_us: whole_micros(stop.pause),
                })
                .collect(),
        })
    }

    /// Adopts the authority's clock on another relay, from a frame that arrived at `received_at`
    /// over a mesh link with a round trip of `mesh_rtt_us`. The anchor is placed once, from the
    /// first frame, so later frames don't move every deadline by the jitter of their own trip.
    /// The rest is taken whole from a frame newer than this copy: one whose limit is further on,
    /// or as far with more stopped time. An older frame (a duplicate, or one delayed across a
    /// reconnect) changes nothing. Returns whether anything changed.
    pub(in crate::consensus) fn adopt(
        &mut self,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> bool {
        let first = self.anchor.is_none();
        if first {
            let age = Duration::from_micros(frame.since_anchor_us)
                + Duration::from_micros(u64::from(mesh_rtt_us) / 2);
            let at = received_at.checked_sub(age).unwrap_or(received_at);
            self.anchor = Some((frame.anchor_step, at));
        }
        let base_pause = Duration::from_micros(frame.base_pause_us);
        let mut stops: Vec<Stop> = frame
            .stops
            .iter()
            .filter(|stop| stop.step >= frame.base_step && stop.step < frame.final_through)
            .map(|stop| Stop {
                step: stop.step,
                pause: Duration::from_micros(stop.pause_us),
            })
            .collect();
        stops.sort_unstable_by_key(|stop| stop.step);
        let pause = base_pause + stops.iter().map(|stop| stop.pause).sum::<Duration>();
        if !first && (frame.final_through, pause) <= (self.final_through, self.pause()) {
            return false;
        }
        self.final_through = frame.final_through;
        self.base_step = frame.base_step;
        self.base_pause = base_pause;
        self.stops = stops.into();
        true
    }
}
