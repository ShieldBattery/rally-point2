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
//! every later step and of no earlier one, whatever order a relay learns things in. The clock only
//! ever stops at its limit, and the limit only grows, so a relay treats every deadline up to its
//! limit as final: it measures a turn only once its step is that far, and never moves a deadline
//! it has made final, so no measurement is ever read against a deadline that moves afterwards.
//!
//! Relays share no timebase, and no relay's copy is the original. The authority makes the stops,
//! from what it can confirm; every relay sends its copy to the others on a heartbeat and merges
//! each copy it gets (see [`SessionClock::merge`]): the stopped time before each step is the most
//! any copy knows of, except that a deadline a relay already holds as final never moves. So a stop
//! isn't lost while any relay knows of it, the decisions of a new authority (or of two relays that
//! both believe they are the authority) fold in wherever they land, and every relay converges on
//! the same deadlines for the steps ahead. The authority's own record of a wait is folded in the
//! same way, as a least stopped time, so no wait is counted twice. There is one anchor: the relay
//! that saw the lockstep start completed sets it, and every other relay places it once, at the
//! first frame's receipt less the frame's age and half the mesh round trip it took.

use super::*;

use rally_point_proto::messages::ClockStop;
use rally_point_proto::rollback::{LOCKSTEP_START_STEPS, STEP_DURATION_US};

/// The step every relay anchors the clock at: the last of the lockstep start.
pub(in crate::consensus) const ANCHOR_STEP: u64 = LOCKSTEP_START_STEPS - 1;

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

/// The stops another relay's copy of the clock carries, to merge.
struct CopiedStops {
    base_step: u64,
    base_pause: Duration,
    /// By step, each at or after `base_step` and at or before the copy's limit (a stop at the
    /// limit is one a merge took in there).
    stops: Vec<Stop>,
}

impl CopiedStops {
    fn from_frame(frame: &SessionClockFrame) -> Self {
        let mut stops: Vec<Stop> = frame
            .stops
            .iter()
            .filter(|stop| stop.step >= frame.base_step && stop.step <= frame.final_through)
            .map(|stop| Stop {
                step: stop.step,
                pause: Duration::from_micros(stop.pause_us),
            })
            .collect();
        stops.sort_unstable_by_key(|stop| stop.step);
        Self {
            base_step: frame.base_step,
            base_pause: Duration::from_micros(frame.base_pause_us),
            stops,
        }
    }

    /// The stopped time this copy knows of before `step`: none before its base, where it only
    /// knows a sum.
    fn pause_before(&self, step: u64) -> Duration {
        if step < self.base_step {
            return Duration::ZERO;
        }
        self.base_pause
            + self
                .stops
                .iter()
                .take_while(|stop| stop.step < step)
                .map(|stop| stop.pause)
                .sum::<Duration>()
    }
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
    /// Every finished stop at or after `base_step`, by step, none past the limit.
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
        Some(at + self.pause_before(seq) + steps_duration(after))
    }

    /// The stopped time before step `step`, counting every stop kept only as the base's sum: what
    /// moves that step's deadline, final or not.
    pub(in crate::consensus) fn pause_before(&self, step: u64) -> Duration {
        self.base_pause
            + self
                .stops
                .iter()
                .filter(|stop| stop.step < step)
                .map(|stop| stop.pause)
                .sum::<Duration>()
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

    /// Anchors the clock, unless it already is, so that the turn with seq `newest` is due at `now`:
    /// the authority seeing the lockstep start become confirmable, with `newest` its newest
    /// confirmable step. Every relay anchors at [`ANCHOR_STEP`], so copies' stopped times line
    /// up, and only the relay that saw the start completed anchors from its own view, at the time
    /// that step corresponds to; the rest place that same anchor from its copies. Returns whether
    /// it anchored.
    pub(in crate::consensus) fn anchor(&mut self, newest: u64, now: Instant) -> bool {
        if self.anchor.is_some() {
            return false;
        }
        let since = steps_duration(newest.saturating_sub(ANCHOR_STEP));
        self.anchor = Some((ANCHOR_STEP, now.checked_sub(since).unwrap_or(now)));
        self.final_through = newest.max(ANCHOR_STEP).saturating_add(STALL_SLACK_STEPS);
        true
    }

    /// Notes, on the authority, that the newest step it can confirm for every player went from
    /// `newest_before` (`None` when nothing was) to `newest` at `now`, which moves the limit on to
    /// [`STALL_SLACK_STEPS`] past it. If the clock had already reached the deadline of the limit
    /// `newest_before` set, it stood still there until now, and the stop there is made at least
    /// that long (see [`stand_at_limit`](Self::stand_at_limit)). Returns whether it grew.
    ///
    /// The limit is first brought up to the slack past `newest_before`, with no stop. An authority
    /// that has held the clock all along already has it there, but a newly promoted one holds the
    /// limit of the last frame it heard, which can trail what it has confirmed itself: measuring a
    /// stop against that would stop the clock where the former authority never did. A limit that
    /// doesn't grow (a newly promoted authority confirming steps the former one already had) leaves
    /// the clock as it is, stopped or not.
    pub(in crate::consensus) fn note_confirmable(
        &mut self,
        newest_before: Option<u64>,
        newest: u64,
        now: Instant,
    ) -> bool {
        if self.anchor.is_none() {
            return false;
        }
        if let Some(before) = newest_before {
            self.final_through = self
                .final_through
                .max(before.saturating_add(STALL_SLACK_STEPS));
        }
        let limit = newest.saturating_add(STALL_SLACK_STEPS);
        if limit <= self.final_through {
            return false;
        }
        let stood = self
            .due_at(self.final_through)
            .and_then(|due| now.checked_duration_since(due))
            .unwrap_or_default();
        let stopped = self.stand_at_limit(stood);
        self.final_through = limit;
        self.fold();
        stopped
    }

    /// Notes that the clock stood still at its limit for `stood`: the stopped time past the limit
    /// becomes at least that much more than before it. Like a merge, this only ever raises the
    /// stopped time to a bound, never adds to it, so a stop a merge already took in at the limit
    /// (another relay's record of the same wait) isn't counted twice. Returns whether it grew.
    fn stand_at_limit(&mut self, stood: Duration) -> bool {
        let limit = self.final_through;
        let at_least = self.pause_before(limit) + stood;
        let past = self.pause_before(limit + 1);
        if at_least <= past {
            return false;
        }
        match self.stops.back_mut() {
            Some(stop) if stop.step == limit => stop.pause += at_least - past,
            _ => self.stops.push_back(Stop {
                step: limit,
                pause: at_least - past,
            }),
        }
        true
    }

    /// Keeps the stops too far behind the limit for any relay to measure a turn by them only as
    /// the base's sum.
    fn fold(&mut self) {
        let base = self.final_through.saturating_sub(KEPT_STOP_STEPS);
        while let Some(stop) = self.stops.front().filter(|stop| stop.step < base) {
            self.base_pause += stop.pause;
            self.stops.pop_front();
        }
        self.base_step = self.base_step.max(base);
    }

    /// This copy of the clock as it goes to the other relays at `now`: its whole state, with the
    /// anchor as its age. `None` before the anchor.
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

    /// Merges another relay's copy of the clock, `frame`, which arrived at `received_at` over a
    /// mesh link with a round trip of `mesh_rtt_us`. Returns whether this copy changed.
    ///
    /// Copies only ever gain stopped time, so of two copies, the one that knows of more stopped
    /// time before a step has that step's deadline right, and the merge takes, for each step, the
    /// later of the two deadlines. That makes merging order-free and repeatable: frames arriving
    /// late, twice, or from two relays both deciding the clock all converge on the same deadlines.
    /// Except that a deadline this copy already holds as final never moves, since a turn may have
    /// been measured against it: stopped time the other copy knows of before this copy's limit is
    /// taken in at the limit, moving only the steps past it. Then the limit becomes the further of
    /// the two.
    ///
    /// The anchor is placed once, from the first frame, so later frames don't move every deadline
    /// by the jitter of their own trip. A frame anchored at another step is ignored.
    pub(in crate::consensus) fn merge(
        &mut self,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> bool {
        let theirs = CopiedStops::from_frame(frame);
        let Some((anchor_step, _)) = self.anchor else {
            let age = Duration::from_micros(frame.since_anchor_us)
                + Duration::from_micros(u64::from(mesh_rtt_us) / 2);
            let at = received_at.checked_sub(age).unwrap_or(received_at);
            self.anchor = Some((frame.anchor_step, at));
            self.final_through = frame.final_through;
            self.base_step = theirs.base_step;
            self.base_pause = theirs.base_pause;
            self.stops = theirs.stops.into();
            return true;
        };
        if frame.anchor_step != anchor_step {
            return false;
        }
        let frontier = self.final_through;
        // The steps after which the merged stopped time can grow: the frontier itself (the other
        // copy may know of more stopped time before it than this one does), and every later step
        // after which either copy's grows.
        let mut steps: Vec<u64> = self
            .stops
            .iter()
            .chain(&theirs.stops)
            .map(|stop| stop.step)
            .chain(theirs.base_step.checked_sub(1))
            .chain([frontier])
            .filter(|&step| step >= frontier)
            .collect();
        steps.sort_unstable();
        steps.dedup();
        let mut merged: VecDeque<Stop> = self
            .stops
            .iter()
            .filter(|stop| stop.step < frontier)
            .copied()
            .collect();
        let mut before = self.pause_before(frontier);
        for step in steps {
            let after = self
                .pause_before(step + 1)
                .max(theirs.pause_before(step + 1));
            if after > before {
                merged.push_back(Stop {
                    step,
                    pause: after - before,
                });
                before = after;
            }
        }
        let changed = merged != self.stops || frame.final_through > frontier;
        self.stops = merged;
        self.final_through = frontier.max(frame.final_through);
        self.fold();
        changed
    }
}
