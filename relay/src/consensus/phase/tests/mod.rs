//! Shared fixtures for the phase-controller tests, split by topic:
//! [`alignment`] (correction mechanics, the command fence, cluster/dwell
//! bookkeeping) and [`health_and_stretch`] (the health gate, the give-up
//! latch, and the buffer-pressure stretch term).

use super::*;

pub(super) const TURN_US: u32 = 41_667;

/// Turns of steady flow a test feeds between evaluations. The longest
/// dwell an evaluation can set is one capped step's slew (8 ms at
/// [`SLEW_US_PER_S`]) plus the settle time -- around twelve seconds -- and
/// this many turns at the nominal period covers it half again over.
pub(super) const ROUND_TURNS: u64 = 400;

pub(super) fn slot(id: u8) -> SlotId {
    SlotId(id)
}

/// Feeds `controller` one arrival per slot for every seq in `seqs`, the
/// run's first turn landing at `first_at` and each one after it a
/// `period_us` later, with each slot offset inside the cycle by its entry
/// in `offsets_us`. A period other than [`TURN_US`] is how a test says the
/// session is stall-bound or catching up. Returns the last arrival instant.
pub(super) fn feed_at_cadence(
    controller: &mut PhaseController,
    first_at: Instant,
    offsets_us: &[(SlotId, i64)],
    seqs: std::ops::Range<u64>,
    period_us: i64,
) -> Instant {
    let first_seq = seqs.start;
    let mut last = first_at;
    for seq in seqs {
        for &(id, offset) in offsets_us {
            let step = (seq - first_seq) as i64;
            let at = first_at + Duration::from_micros((step * period_us + offset) as u64);
            controller.note_arrival(id, seq, at);
            last = last.max(at);
        }
    }
    last
}

/// The instant seq `seq` of a nominal-period run that began at `start`
/// lands on -- where a continuation of that run picks up.
pub(super) fn at_turn(start: Instant, seq: u64) -> Instant {
    start + Duration::from_micros(seq * u64::from(TURN_US))
}

/// [`feed_at_cadence`] at exactly the nominal period, for `turns` turns
/// from seq `first_seq`, on the timeline that began at `start`.
pub(super) fn feed_steady(
    controller: &mut PhaseController,
    start: Instant,
    offsets_us: &[(SlotId, i64)],
    first_seq: u64,
    turns: u64,
) -> Instant {
    feed_at_cadence(
        controller,
        at_turn(start, first_seq),
        offsets_us,
        first_seq..first_seq + turns,
        i64::from(TURN_US),
    )
}

/// Runs the controller past its first-evaluation delay on a steady stream
/// and returns the first evaluation's corrections.
pub(super) fn corrections_for(offsets_us: &[(SlotId, i64)]) -> Vec<(SlotId, u32)> {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    // 300 turns ≈ 12.5 s of flow: past FIRST_EVAL_DELAY and MIN_SAMPLES.
    let last = feed_steady(&mut controller, start, offsets_us, 0, 300);
    controller.evaluate(last + Duration::from_millis(1))
}

/// Simulates obedient clients against the controller: feeds steady turns,
/// evaluates, applies each round's corrections to the modeled offsets, and
/// repeats until an evaluation issues nothing. Returns the per-round
/// correction sets. Offsets model *natural* phases; a slot's effective
/// offset is natural + its currently commanded delay.
pub(super) fn run_to_convergence(
    natural_offsets: &[(SlotId, i64)],
    max_rounds: usize,
) -> Vec<Vec<(SlotId, u32)>> {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let mut commanded: HashMap<SlotId, i64> = HashMap::new();
    let mut seq = 0u64;
    let mut rounds = Vec::new();
    for _ in 0..max_rounds {
        let effective: Vec<(SlotId, i64)> = natural_offsets
            .iter()
            .map(|&(id, natural)| (id, natural + commanded.get(&id).copied().unwrap_or(0)))
            .collect();
        let clock = feed_at_cadence(
            &mut controller,
            at_turn(start, seq),
            &effective,
            seq..seq + ROUND_TURNS,
            turn,
        );
        seq += ROUND_TURNS;
        let corrections = controller.evaluate(clock + Duration::from_millis(1));
        if corrections.is_empty() {
            return rounds;
        }
        for &(id, delay) in &corrections {
            commanded.insert(id, i64::from(delay));
            // The modeled client both applies and acknowledges.
            controller.note_applied(id, delay, clock + Duration::from_millis(2));
        }
        rounds.push(corrections);
    }
    panic!("never converged: {rounds:?}");
}

mod alignment;
mod health_and_stretch;
