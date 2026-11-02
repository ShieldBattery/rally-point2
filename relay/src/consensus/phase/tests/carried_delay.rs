//! The delay slots carry from round to round: walks that take several capped
//! rounds to finish.

use super::*;

/// Obedient slots at natural arrival offsets that a test may move between
/// rounds (a route change). Each round feeds steady flow at every slot's
/// natural offset plus its commanded delay, evaluates once, and has every
/// corrected slot apply and acknowledge its new delay at once.
struct Population {
    controller: PhaseController,
    start: Instant,
    seq: u64,
    natural: Vec<(SlotId, i64)>,
}

impl Population {
    fn new(natural: &[(SlotId, i64)]) -> Self {
        Population {
            controller: PhaseController::new(TURN_US),
            start: Instant::now(),
            seq: 0,
            natural: natural.to_vec(),
        }
    }

    fn held(&self, id: SlotId) -> i64 {
        i64::from(self.controller.commanded(id).unwrap_or(0))
    }

    fn round(&mut self) -> Vec<(SlotId, u32)> {
        let effective: Vec<(SlotId, i64)> = self
            .natural
            .iter()
            .map(|&(id, natural)| (id, natural + self.held(id)))
            .collect();
        let clock = feed_at_cadence(
            &mut self.controller,
            at_turn(self.start, self.seq),
            &effective,
            self.seq..self.seq + ROUND_TURNS,
            i64::from(TURN_US),
        );
        self.seq += ROUND_TURNS;
        let corrections = self.controller.evaluate(clock + Duration::from_millis(1));
        for &(id, delay) in &corrections {
            self.controller
                .note_applied(id, delay, clock + Duration::from_millis(2));
        }
        corrections
    }
}

#[test]
fn a_slot_partway_through_a_walk_never_becomes_the_target() {
    // Slots 0 and 1 are aligned with no delay. Slot 2 carries 38 ms from
    // earlier alignment and arrives 5 ms ahead of them: following them
    // forward would carry its delay past a whole turn, so it walks ~36.7 ms
    // backward instead, in capped steps over five rounds. Partway through,
    // its phase sweeps past the middle of the cycle, where the tightest
    // cluster runs from slots 0 and 1 *to it* — but it is mid-walk, so the
    // aligned slots must be left alone while it finishes.
    let turn = i64::from(TURN_US);
    let mut population = Population::new(&[
        (slot(0), 10_000),
        (slot(1), 10_000),
        (slot(2), 10_000 - 5_000 - 38_000 + turn),
    ]);
    population.controller.commanded_us.insert(slot(2), 38_000);
    let mut rounds = 0;
    loop {
        let corrections = population.round();
        if corrections.is_empty() {
            break;
        }
        rounds += 1;
        assert!(
            corrections.iter().all(|&(id, _)| id == slot(2)),
            "round {rounds} moved an aligned slot: {corrections:?}"
        );
        assert!(rounds <= 5, "slot 2 still walking after {rounds} rounds");
    }
    assert!(!population.controller.is_disabled());
    assert!(
        population
            .controller
            .last_span_us()
            .is_some_and(|span| span <= SPAN_DEAD_BAND_US)
    );
    assert_eq!((population.held(slot(0)), population.held(slot(1))), (0, 0));
}
