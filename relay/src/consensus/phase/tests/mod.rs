//! Shared fixtures for the phase-controller tests, split by topic:
//! [`alignment`] (correction mechanics, the command fence, cluster/dwell
//! bookkeeping) and [`health_and_stretch`] (the health gate, the give-up
//! latch, and the buffer-pressure stretch term).

use super::*;

pub(super) const TURN_US: u32 = 41_667;

pub(super) fn slot(id: u8) -> SlotId {
    SlotId(id)
}

/// Feeds `controller` a steady arrival stream: `turns` turns per slot
/// starting at seq `first_seq`, each slot offset within the cycle by its
/// entry in `offsets_us`, at exactly the nominal period. Returns the
/// instant just past the last arrival.
pub(super) fn feed_steady(
    controller: &mut PhaseController,
    start: Instant,
    offsets_us: &[(SlotId, i64)],
    first_seq: u64,
    turns: u64,
) -> Instant {
    let turn = i64::from(TURN_US);
    let mut last = start;
    for seq in first_seq..first_seq + turns {
        for &(id, offset) in offsets_us {
            let at = start + Duration::from_micros((seq as i64 * turn + offset) as u64);
            controller.note_arrival(id, seq, at);
            last = last.max(at);
        }
    }
    last
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
    let mut clock = start;
    let mut rounds = Vec::new();
    for _ in 0..max_rounds {
        // ~40 s of steady flow per round clears any slew+settle dwell.
        let effective: Vec<(SlotId, i64)> = natural_offsets
            .iter()
            .map(|&(id, natural)| (id, natural + commanded.get(&id).copied().unwrap_or(0)))
            .collect();
        let turns = 1_000u64;
        for s in seq..seq + turns {
            for &(id, offset) in &effective {
                let at = start + Duration::from_micros((s as i64 * turn + offset) as u64);
                controller.note_arrival(id, s, at);
                clock = clock.max(at);
            }
        }
        seq += turns;
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
