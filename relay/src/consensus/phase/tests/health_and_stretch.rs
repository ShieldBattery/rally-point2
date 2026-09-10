//! The health gate, the give-up latch, and the buffer-pressure stretch term:
//! evaluation gated shut by a stretched or churning turn period, the latch
//! that disables a session that never settles under correction, and the
//! stretch term's sustain window and one-sided (slower-only) sensitivity.

use super::*;

#[test]
fn a_stretched_turn_period_gates_evaluation_shut() {
    // Arrivals at a 55 ms cadence against a ~41.7 ms nominal turn: the
    // session is stall-bound (period inflated), phases are not
    // quasi-static, and the controller must refuse to correct however
    // spread the (meaningless) phases look.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let stretched = 55_000i64;
    let mut last = start;
    for seq in 0..600u64 {
        for (id, offset) in [(slot(0), 0i64), (slot(1), 20_000)] {
            let at = start + Duration::from_micros((seq as i64 * stretched + offset) as u64);
            controller.note_arrival(id, seq, at);
            last = last.max(at);
        }
    }
    let corrections = controller.evaluate(last + Duration::from_millis(1));
    assert!(corrections.is_empty(), "got {corrections:?}");
}

#[test]
fn churn_after_a_correction_closes_the_gate_until_it_clears() {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let offsets = [(slot(0), 0i64), (slot(1), 16_000)];
    let last = feed_steady(&mut controller, start, &offsets, 0, 300);
    let first = controller.evaluate(last + Duration::from_millis(1));
    assert!(!first.is_empty(), "the 16 ms spread draws a correction");
    let applied: i64 = first
        .iter()
        .find(|&&(id, _)| id == slot(0))
        .map(|&(_, delay)| i64::from(delay))
        .expect("the early slot is corrected");
    for &(id, delay) in &first {
        controller.note_applied(id, delay, last + Duration::from_millis(2));
    }

    // The client applies the first (capped) correction, but the session
    // then kicks into churn: turns arrive at a stretched period. Once the
    // dwell passes, the health gate — not the dwell — must be what keeps
    // the controller silent, despite the still-open spread.
    let churn_start = last + Duration::from_secs(30);
    let stretched = 50_000i64;
    let mut clock = churn_start;
    for i in 0..300u64 {
        for (id, offset) in [(slot(0), applied), (slot(1), 16_000)] {
            let at = churn_start + Duration::from_micros((i as i64 * stretched + offset) as u64);
            controller.note_arrival(id, 300 + i, at);
            clock = clock.max(at);
        }
    }
    assert!(
        controller
            .evaluate(clock + Duration::from_millis(1))
            .is_empty(),
        "no corrections while the period is stretched"
    );

    // Churn clears: steady nominal-period flow resumes long enough for the
    // interval estimate to re-center, and evaluation may run again — the
    // applied first step released the response gate, so the remaining
    // spread draws the next correction.
    let resume = clock + Duration::from_secs(1);
    let mut clock2 = resume;
    let turn = i64::from(TURN_US);
    for i in 0..600u64 {
        for (id, offset) in [(slot(0), applied), (slot(1), 16_000)] {
            let at = resume + Duration::from_micros((i as i64 * turn + offset) as u64);
            controller.note_arrival(id, 600 + i, at);
            clock2 = clock2.max(at);
        }
    }
    // Drain the idle-reeval schedule: evaluate may need a couple of calls
    // spaced past IDLE_REEVAL before one actually runs.
    let mut corrected = false;
    for extra in 0..8u64 {
        let at = clock2 + Duration::from_secs(1 + extra * 6);
        if !controller.evaluate(at).is_empty() {
            corrected = true;
            break;
        }
    }
    assert!(corrected, "a healthy session is corrected again");
}

#[test]
fn a_plant_that_never_settles_trips_the_give_up_latch() {
    // Every round the population re-scrambles (natural phases jump around
    // as a churning game's would), so no evaluation ever measures inside
    // the dead-band. The controller must stop within the round budget and
    // stay stopped.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let mut seq = 0u64;
    let mut correcting_rounds = 0u32;
    for round in 0..20u64 {
        // A fresh scrambled offset pair each round, always ≥ 10 ms apart.
        let jitter = ((round * 7_919) % 20_000) as i64;
        let offsets = [(slot(0), jitter), (slot(1), jitter + 12_000)];
        let mut clock = start;
        for s in seq..seq + 1_000 {
            for &(id, offset) in &offsets {
                let at = start + Duration::from_micros((s as i64 * turn + offset) as u64);
                controller.note_arrival(id, s, at);
                clock = clock.max(at);
            }
        }
        seq += 1_000;
        if !controller
            .evaluate(clock + Duration::from_millis(1))
            .is_empty()
        {
            correcting_rounds += 1;
        }
    }
    assert!(
        correcting_rounds <= MAX_UNCONVERGED_ROUNDS,
        "the latch bounds correcting rounds, got {correcting_rounds}"
    );
}

#[test]
fn stretch_presses_only_after_the_sustain_window() {
    // A session stuck at a 50 ms cadence against the ~41.7 ms turn: the
    // first sighting latches the onset but must not press; once the
    // stretch has held past the sustain window it presses one turn.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let cadence = 50_000i64;
    let mut clock = start;
    for seq in 0..300u64 {
        let at = start + Duration::from_micros((seq as i64 * cadence) as u64);
        controller.note_arrival(slot(0), seq, at);
        clock = clock.max(at);
    }
    assert_eq!(
        controller.stretch_turns(clock),
        0,
        "first sighting only latches"
    );
    // The stretch persists: another 300 turns (~15 s) at the same cadence.
    for seq in 300..600u64 {
        let at = start + Duration::from_micros((seq as i64 * cadence) as u64);
        controller.note_arrival(slot(0), seq, at);
        clock = clock.max(at);
    }
    assert_eq!(
        controller.stretch_turns(clock),
        1,
        "sustained stretch presses"
    );
    // Recovery: the cadence returns to nominal long enough for the
    // interval estimate to re-center, and the pressure releases.
    let turn = i64::from(TURN_US);
    let resume = clock;
    for i in 0..200u64 {
        let at = resume + Duration::from_micros(((i + 1) as i64 * turn) as u64);
        controller.note_arrival(slot(0), 600 + i, at);
        clock = clock.max(at);
    }
    assert_eq!(
        controller.stretch_turns(clock),
        0,
        "recovered cadence releases"
    );
}

#[test]
fn fast_arrivals_never_press() {
    // Faster-than-nominal cadence is catch-up, not distress: one-sided.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let cadence = 35_000i64;
    let mut clock = start;
    for seq in 0..600u64 {
        let at = start + Duration::from_micros((seq as i64 * cadence) as u64);
        controller.note_arrival(slot(0), seq, at);
        clock = clock.max(at);
    }
    assert_eq!(controller.stretch_turns(clock), 0);
    assert_eq!(
        controller.stretch_turns(clock + Duration::from_millis(1)),
        0
    );
}

#[test]
fn a_single_long_gap_never_presses() {
    // One hiccup spikes the interval estimate, but the (clamped) sample
    // decays back inside tolerance well inside the sustain window, so
    // polling the pressure every turn across the episode never sees it
    // fire — including a multi-second pause that, folded unclamped, would
    // hold the estimate past tolerance for longer than the sustain.
    for gap_us in [500_000i64, 1_500_000, 4_000_000] {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let turn = i64::from(TURN_US);
        let mut clock = start;
        let at_of = |seq: u64, extra_us: i64| {
            start + Duration::from_micros((seq as i64 * turn + extra_us) as u64)
        };
        for seq in 0..200u64 {
            let at = at_of(seq, 0);
            controller.note_arrival(slot(0), seq, at);
            clock = clock.max(at);
            assert_eq!(controller.stretch_turns(clock), 0);
        }
        // The hiccup: turn 200 lands late, later turns shift with it (the
        // schedule slipped once, the cadence itself recovered).
        for seq in 200..500u64 {
            let at = at_of(seq, gap_us);
            controller.note_arrival(slot(0), seq, at);
            clock = clock.max(at);
            assert_eq!(
                controller.stretch_turns(clock),
                0,
                "gap {gap_us} at seq {seq}"
            );
        }
    }
}

#[test]
fn a_stale_out_of_order_delivery_is_ignored() {
    // The transport is unordered: an old turn can arrive after newer
    // ones, its timing describing the detour rather than the sender.
    // Folding it (or letting it regress the interval baseline) would
    // poison both estimators; it must change nothing at all.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let offsets = [(slot(0), 0i64), (slot(1), 1_500)];
    let mut clock = feed_steady(&mut controller, start, &offsets, 0, 300);
    // A delayed re-delivery of turn 100 lands now, 200 turns late.
    controller.note_arrival(slot(0), 100, clock + Duration::from_millis(5));
    // Steady flow resumes; the phases are aligned within the dead-band,
    // so a poisoned residual (shifted by the stale fold) or a poisoned
    // interval (differenced against the regressed baseline, closing the
    // health gate or faking stretch) would show up below.
    clock = feed_steady(&mut controller, start, &offsets, 300, 300);
    assert_eq!(controller.stretch_turns(clock), 0);
    let corrections = controller.evaluate(clock + Duration::from_millis(1));
    assert!(corrections.is_empty(), "got {corrections:?}");
    assert_eq!(controller.commanded(slot(0)), None);
    assert_eq!(controller.commanded(slot(1)), None);
}

#[test]
fn a_population_that_ignores_directives_still_trips_the_latch() {
    // Two slots 20 ms apart whose clients never apply any correction: the
    // response gate parks the command after a single cap step (an
    // unresponsive slot must never be ratcheted toward a near-full-turn
    // delay it might later apply all at once), the correction-free rounds
    // still walk to the give-up latch, and the latched controller stays
    // silent for good.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let offsets = [(slot(0), 0i64), (slot(1), 20_000)];
    let mut seq = 0u64;
    let mut clock = start;
    let mut correcting_rounds = 0u32;
    let mut last_commanded = 0u32;
    for _ in 0..30u32 {
        for s_ in seq..seq + 1_000 {
            for &(id, offset) in &offsets {
                let at = start + Duration::from_micros((s_ as i64 * turn + offset) as u64);
                controller.note_arrival(id, s_, at);
                clock = clock.max(at);
            }
        }
        seq += 1_000;
        let corrections = controller.evaluate(clock + Duration::from_millis(1));
        if !corrections.is_empty() {
            correcting_rounds += 1;
        }
        for &(id, delay) in &corrections {
            assert_eq!(id, slot(0), "only the early slot is corrected");
            last_commanded = delay;
        }
    }
    assert_eq!(
        correcting_rounds, 1,
        "an unresponsive slot is commanded exactly once"
    );
    assert!(
        i64::from(last_commanded) <= SLOT_MAX_CHANGE_US,
        "the command parks at one cap step, got {last_commanded}"
    );
    // The latch fired: even a later, larger misalignment draws nothing.
    let mut clock2 = clock;
    for s_ in seq..seq + 2_000 {
        let at = start + Duration::from_micros((s_ as i64 * turn) as u64);
        controller.note_arrival(slot(0), s_, at);
        let at1 = start + Duration::from_micros((s_ as i64 * turn + 15_000) as u64);
        controller.note_arrival(slot(1), s_, at1);
        clock2 = clock2.max(at1);
    }
    assert!(
        controller
            .evaluate(clock2 + Duration::from_millis(1))
            .is_empty(),
        "the latched controller stays silent"
    );
}

#[test]
fn a_latched_controller_still_presses() {
    // The give-up latch stops corrections, never the pressure term — the
    // latched sessions are exactly the ones the escape hatch exists for.
    let mut controller = PhaseController::new(TURN_US);
    controller.force_disable();
    let start = Instant::now();
    let cadence = 55_000i64;
    let mut clock = start;
    for seq in 0..600u64 {
        let at = start + Duration::from_micros((seq as i64 * cadence) as u64);
        controller.note_arrival(slot(0), seq, at);
        clock = clock.max(at);
        if seq == 300 {
            // Latch the onset partway through so the tail sustains it.
            let _ = controller.stretch_turns(clock);
        }
    }
    assert!(
        controller
            .evaluate(clock + Duration::from_millis(1))
            .is_empty()
    );
    assert_eq!(controller.stretch_turns(clock), 1);
}
