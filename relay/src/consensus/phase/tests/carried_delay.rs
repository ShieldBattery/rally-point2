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

#[test]
fn a_walk_keeps_heading_for_the_delay_it_set_out_for() {
    // Slot 2 holds 30 ms and arrives 11.666 ms ahead of slots 0 and 1. The
    // forward walk onto them ends one microsecond short of a whole turn, so
    // it is the one taken, in capped steps. Its delay plus the forward walk
    // to the target stays that same sum all the way along -- but the
    // estimate of a phase that moved later settles a few microseconds short,
    // enough to tip the sum past the turn and flip the walk backward, after
    // which the estimate is exact again and flips it forward, round after
    // round. Once begun, a walk must keep heading where it set out for.
    let mut population =
        Population::new(&[(slot(0), 10_000), (slot(1), 10_000), (slot(2), 10_001)]);
    population.controller.commanded_us.insert(slot(2), 30_000);
    let mut walk = Vec::new();
    loop {
        let corrections = population.round();
        if corrections.is_empty() {
            break;
        }
        walk.push(corrections);
        assert!(walk.len() <= 2, "slot 2 still walking: {walk:?}");
    }
    assert!(!population.controller.is_disabled());
    assert_eq!(population.held(slot(2)), i64::from(TURN_US) - 1);
}

#[test]
fn a_slot_at_the_floor_measured_a_hair_late_is_not_walked_a_turn_forward() {
    // Slots 0 and 1 sit on the target with no delay; slot 3 trails by 6 ms,
    // so the round corrects. Slot 2 is finishing a walk down toward zero
    // delay and its last step left it 0.6 ms delayed but measured 0.8 ms
    // after the target. Its true correction is 0.8 ms backward, 0.2 ms more
    // than the floor allows: it stays where it is (well inside the
    // dead-band), rather than being walked forward nearly a whole turn.
    let mut controller = PhaseController::new(TURN_US);
    controller.commanded_us.insert(slot(2), 600);
    controller.walking.insert(slot(2), 0);
    let start = Instant::now();
    let offsets = [
        (slot(0), 20_000),
        (slot(1), 20_000),
        (slot(2), 20_800),
        (slot(3), 14_000),
    ];
    let last = feed_steady(&mut controller, start, &offsets, 0, 300);
    let corrections = controller.evaluate(last + Duration::from_millis(1));
    assert_eq!(corrections, vec![(slot(3), 6_000)]);
}
