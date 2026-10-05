//! A rollback session's clock and the lead reports measured against it, with the fixtures every
//! topic shares: the authority's clock (`stopping`), home slots measured against it
//! (`measuring`), copies of it merged across relays (`copies`), and authority changes
//! (`handoff`).

mod copies;
mod handoff;
mod measuring;
mod stopping;

use super::*;

use rally_point_proto::messages::ClockStop;
use rally_point_proto::rollback::{LOCKSTEP_START_STEPS, STEP_DURATION_US};

const STEP: Duration = Duration::from_micros(STEP_DURATION_US);
const MS: Duration = Duration::from_millis(1);

/// `steps` steps of the session clock.
fn steps(steps: u64) -> Duration {
    STEP * u32::try_from(steps).unwrap()
}

/// `duration` in whole microseconds.
fn us(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap()
}

/// `maker` serving a rollback session of `slots`.
fn rollback(mut maker: DecisionMaker, slots: &[u8]) -> DecisionMaker {
    maker.latch_rollback(true);
    maker.set_expected_slots(slots.iter().map(|&x| SlotId(x)).collect());
    // Every slot shows up, which starts the session on the authority.
    for &slot in slots {
        let _ = maker.note_slot_present(SlotId(slot));
    }
    maker
}

/// This relay has forwarded `count` turns of every one of `slots`, as of `at`, returning the last
/// clock change that made.
fn forward(
    maker: &mut DecisionMaker,
    slots: &[u8],
    count: u64,
    at: Instant,
) -> Option<ClockUpdate> {
    let mut update = None;
    for &slot in slots {
        if let Some(change) = maker.note_forwarded_turns(SlotId(slot), count, at) {
            update = Some(change);
        }
    }
    update
}

/// The seq of the turn whose arrival completed the lockstep start: the clock's anchor.
const ANCHOR: u64 = LOCKSTEP_START_STEPS - 1;

/// When the turn with seq `seq` is due on a clock anchored at `start` that never stopped.
fn on_time(start: Instant, seq: u64) -> Instant {
    start + steps(seq - ANCHOR)
}

/// Plays the session on schedule: every one of `slots`' turns through count `through` arrives
/// exactly when it is due, after the lockstep start completed at `start`. Returns the last clock
/// change (the anchor, on an authority that wasn't anchored yet).
fn play_on_schedule(
    maker: &mut DecisionMaker,
    slots: &[u8],
    through: u64,
    start: Instant,
) -> Option<ClockUpdate> {
    let mut update = forward(maker, slots, LOCKSTEP_START_STEPS, start);
    for count in LOCKSTEP_START_STEPS + 1..=through {
        if let Some(change) = forward(maker, slots, count, on_time(start, count - 1)) {
            update = Some(change);
        }
    }
    update
}
