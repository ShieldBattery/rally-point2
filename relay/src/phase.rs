//! Per-session send-phase alignment for the client edge.
//!
//! Lockstep clients all send at the same *rate* — one turn per turn interval —
//! but at uncorrelated *phases* within the interval. At a one-turn latency
//! buffer there is zero slack, so each client micro-stalls on whichever peer's
//! turns arrive just after its own poll boundary: a rotating ring of small
//! stalls that per-slot arrival *pacing* can never reveal, because every slot's
//! pacing is individually clean. The buffer law is measuring the right thing
//! for its own decision (can the network sustain this depth?) and is blind to
//! this by design; phase alignment is a separate controller, not a law input.
//!
//! Why arrival phase *at the relay* is the right thing to align: client `C`
//! consuming at buffer one needs peer `P`'s turn `k` before its own boundary
//! `k+1`, which works out to `(t_P - t_C) + d_P_up + d_C_down <= T` per ordered
//! pair — send-phase offset plus the P→relay→C path must fit in one turn.
//! Rewriting against relay-observed arrival phases `a = t + d_up` collapses it
//! to `a_P - a_C + d_C_up + d_C_down <= T`; drive all arrival phases equal and
//! what remains is `d_C_up + d_C_down <= T` — each client's own relay round
//! trip under one turn interval, a per-client, phase-free condition that is
//! exactly the regime where the buffer law legitimately sits at depth one. So
//! minimizing the spread of arrival phases at the relay is not a proxy for the
//! objective; it *is* the objective, even with heterogeneous path delays, and
//! it needs no client-side measurement at all.
//!
//! Scope: each relay aligns only the slots homed on it, measured where their
//! datagrams actually arrive (the client edge — never mesh-forwarded copies,
//! whose extra hop would contaminate the phase). Controllers on different
//! relays touch disjoint slots and read disjoint sensors, so they cannot chase
//! each other. Cross-relay pairs stay unaligned by choice: comparing phases
//! across relays would need a shared clock, and mesh sessions carry a hop
//! cushion in their initial buffer depth that keeps them off depth one anyway.
//!
//! Security: corrections are computed from relay-side arrival timestamps only.
//! No client-asserted value (frame counts, stall telemetry) feeds a decision
//! that reaches other clients — a client can influence its peers' corrections
//! only as far as its *actual wire behavior* moves the shared target, and the
//! dead-band, the re-evaluation dwell, and the client-side slew cap each bound
//! how fast that influence can move anyone.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rally_point_proto::ids::SlotId;

/// Default rate at which a client moves its applied delay toward a newly
/// commanded one, in microseconds of delay change per second of wall clock.
/// Stamped on every directive. At 24 turns/s this stretches or squeezes each
/// inter-send gap by under 0.1 ms (~0.2% of the interval) while a shift is
/// underway — far below what the relay's pacing statistics register as jitter,
/// so the buffer law never sees the slew.
pub const SLEW_US_PER_S: u32 = 2_000;

/// No corrections are issued while the phase cluster's span is at or under
/// this. Network jitter wobbles the per-slot estimates by a millisecond or
/// two; correcting inside that band would chase noise (and hand a
/// phase-wobbling client a lever), while stall exposure this small is at worst
/// an occasional single render frame.
const SPAN_DEAD_BAND_US: i64 = 3_000;

/// A slot whose commanded delay would change by no more than this keeps its
/// current value, so near-converged slots are not churned with frames that
/// move them less than the estimate's own noise floor.
const SLOT_MIN_CHANGE_US: i64 = 1_000;

/// Samples a slot must accumulate before its estimate joins the phase
/// population. One second of turns at the nominal rate: enough for the
/// estimator to forget its first-sample bias.
const MIN_SAMPLES: u32 = 24;

/// A slot whose newest sample is older than this sits out evaluation — its
/// estimate describes where its phase *was* before it went quiet (a stall, a
/// dying link), and correcting from stale data would move it blindly. Its
/// commanded delay survives; only fresh evidence can change it.
const SAMPLE_MAX_AGE: Duration = Duration::from_secs(2);

/// Extra dwell after every commanded slew has had time to complete, before the
/// next evaluation. Covers the estimator re-converging on the shifted arrivals
/// (a couple of estimator time constants), so each control iteration measures
/// the settled result of the last one instead of its own transient.
const SETTLE: Duration = Duration::from_secs(8);

/// Delay from a session's first arrival sample to its first evaluation, so the
/// early estimates reflect steady turn flow rather than start-of-game churn.
const FIRST_EVAL_DELAY: Duration = Duration::from_secs(5);

/// Re-evaluation cadence while there is nothing to correct (aligned within the
/// dead-band, or too few measurable slots). Cheap — evaluation is a sort of at
/// most twelve phases — but there is no reason to run it per turn.
const IDLE_REEVAL: Duration = Duration::from_secs(5);

/// Denominator shift of the exponentially weighted residual average: each
/// sample moves the estimate by 1/32 of its deviation, a time constant of
/// about 1.3 s at the nominal turn rate. Slow enough to flatten jitter and a
/// stray delayed packet, fast enough to track the phase drift a client's own
/// stalls induce.
const EWMA_SHIFT: u32 = 5;

/// One slot's arrival-phase estimate.
struct SlotPhase {
    /// Exponentially weighted average of the arrival residual: arrival time
    /// minus `seq` turn intervals, both relative to the controller's epoch,
    /// in microseconds. Kept *unwrapped* — the residual is a continuous
    /// quantity that may sit anywhere on the number line (a slot's `seq`
    /// history from before the session started shifts it by whole turns) and
    /// drift slowly as the client's own stalls move its schedule. Averaging
    /// the wrapped phase instead would tear at the cycle boundary; the
    /// estimate is reduced modulo the turn interval only at evaluation time.
    residual_us: i64,
    /// Samples folded into `residual_us`, saturating; gates eligibility.
    samples: u32,
    /// When the newest sample arrived; gates out slots that went quiet.
    last_sample: Instant,
}

/// The per-session send-phase controller: folds client-edge arrival timestamps
/// into per-slot phase estimates and periodically issues per-slot delay
/// corrections that pull every measurable slot's arrival phase together.
///
/// Sans-IO. The caller feeds [`note_arrival`](Self::note_arrival) from the
/// client edge, asks [`evaluate`](Self::evaluate) on the same path (it
/// self-gates on its own schedule, so calling per packet is fine), delivers
/// whatever corrections come back, and re-pushes
/// [`commanded`](Self::commanded) to a slot that (re)connects.
pub struct PhaseController {
    /// One turn interval in microseconds — the cycle every phase lives within.
    turn_us: i64,
    /// The instant residuals are measured against, latched on the first
    /// sample. Only differences between slots matter, so any fixed epoch
    /// works; per-controller keeps the arithmetic near zero.
    epoch: Option<Instant>,
    slots: HashMap<SlotId, SlotPhase>,
    /// The delay each slot was last commanded, the baseline the next
    /// correction builds on. Survives slot removal (a reconnecting slot picks
    /// its delay back up via the connect-time re-push) for the session's life.
    commanded_us: HashMap<SlotId, u32>,
    /// The next instant `evaluate` will actually evaluate. Holds the
    /// first-evaluation delay, the idle cadence, and — after corrections — the
    /// slew-plus-settle dwell that keeps each iteration from measuring the
    /// previous one's transient.
    next_eval_at: Option<Instant>,
    /// Total per-slot corrections issued, for the session stats line.
    corrections_issued: u64,
    /// The cluster span seen by the most recent full evaluation, for the
    /// session stats line. `None` until one has run.
    last_span_us: Option<i64>,
}

impl PhaseController {
    /// Builds a controller for a session whose turns are `turn_duration_us`
    /// apart (zero falls back to the nominal 24 turns/s interval).
    pub fn new(turn_duration_us: u32) -> Self {
        let turn_us = if turn_duration_us == 0 {
            1_000_000 / 24
        } else {
            i64::from(turn_duration_us)
        };
        PhaseController {
            turn_us,
            epoch: None,
            slots: HashMap::new(),
            commanded_us: HashMap::new(),
            next_eval_at: None,
            corrections_issued: 0,
            last_span_us: None,
        }
    }

    /// Folds one client-edge arrival into `slot`'s phase estimate: a packet
    /// carrying exactly one previously-unseen turn, `seq`, received at `now`.
    ///
    /// The caller must skip packets that first-deliver more than one turn — a
    /// post-loss catch-up burst times the recovery, not the sender's phase —
    /// and mesh-forwarded copies, whose extra hop is not this slot's uplink.
    pub fn note_arrival(&mut self, slot: SlotId, seq: u64, now: Instant) {
        let epoch = *self.epoch.get_or_insert(now);
        if self.next_eval_at.is_none() {
            self.next_eval_at = Some(now + FIRST_EVAL_DELAY);
        }
        let Ok(elapsed_us) = i64::try_from(now.duration_since(epoch).as_micros()) else {
            return;
        };
        let Some(expected_us) = i64::try_from(seq)
            .ok()
            .and_then(|s| s.checked_mul(self.turn_us))
        else {
            return;
        };
        let residual = elapsed_us - expected_us;
        self.slots
            .entry(slot)
            .and_modify(|estimate| {
                estimate.residual_us += (residual - estimate.residual_us) >> EWMA_SHIFT;
                estimate.samples = estimate.samples.saturating_add(1);
                estimate.last_sample = now;
            })
            .or_insert(SlotPhase {
                residual_us: residual,
                samples: 1,
                last_sample: now,
            });
    }

    /// Runs one control iteration if one is due, returning the slots whose
    /// commanded delay changed, with their new *absolute* delays. Self-gating:
    /// call it as often as convenient (per received packet is the intended
    /// cadence) and it evaluates only on its own schedule — after the
    /// first-evaluation delay, then per the idle cadence, and never inside the
    /// dwell that lets a previous correction's slew finish and the estimates
    /// settle before they are trusted again.
    ///
    /// The correction is closed-loop: measured phases already include whatever
    /// delay each client currently applies, so each iteration corrects the
    /// *observed* misalignment and convergence needs no knowledge of what a
    /// client actually applied (a client that ignored its directive simply
    /// keeps showing up misaligned, and only its own correction keeps moving).
    pub fn evaluate(&mut self, now: Instant) -> Vec<(SlotId, u32)> {
        match self.next_eval_at {
            None => return Vec::new(),
            Some(at) if now < at => return Vec::new(),
            Some(_) => {}
        }

        // The measurable population: enough samples to trust, fresh enough to
        // still describe the present.
        let mut phases: Vec<(SlotId, i64)> = self
            .slots
            .iter()
            .filter(|(_, estimate)| {
                estimate.samples >= MIN_SAMPLES
                    && now.duration_since(estimate.last_sample) <= SAMPLE_MAX_AGE
            })
            .map(|(slot, estimate)| (*slot, estimate.residual_us.rem_euclid(self.turn_us)))
            .collect();
        if phases.len() < 2 {
            // Nothing to align against; look again soon.
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return Vec::new();
        }

        // Phases are circular: sort them, find the largest gap between
        // circular neighbors, and the complement of that gap is the cluster.
        // Aligning everyone onto the cluster's *latest* phase minimizes the
        // largest delay any slot is asked to add (the span, which the
        // largest-gap choice minimizes), and — because delays only ever hold a
        // turn back — never asks any client to send earlier than its game
        // produced the data.
        phases.sort_by_key(|&(_, phase)| phase);
        let count = phases.len();
        let mut widest_gap = 0i64;
        let mut cluster_end = 0usize; // index of the cluster's latest phase
        for i in 0..count {
            let this = phases[i].1;
            let next = phases[(i + 1) % count].1;
            let gap = (next - this).rem_euclid(self.turn_us);
            if gap > widest_gap {
                widest_gap = gap;
                cluster_end = i;
            }
        }
        let span = self.turn_us - widest_gap;
        self.last_span_us = Some(span);
        if span <= SPAN_DEAD_BAND_US {
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return Vec::new();
        }

        let target = phases[cluster_end].1;
        let mut corrections = Vec::new();
        let mut widest_change = 0i64;
        for &(slot, phase) in &phases {
            // The extra delay that walks this slot's phase forward onto the
            // target, folded into its existing commanded delay modulo the turn
            // interval — the steady-state phase only cares about the delay
            // modulo one turn, and the reduction keeps the commanded value in
            // [0, turn) so the wire bound holds. The reduction also makes most
            // adjustments small: a nearly-full-turn walk forward becomes a
            // slight *reduction* of an existing delay rather than a long slew.
            let needed = (target - phase).rem_euclid(self.turn_us);
            let current = i64::from(self.commanded_us.get(&slot).copied().unwrap_or(0));
            let next = (current + needed).rem_euclid(self.turn_us);
            let change = next - current;
            if change.abs() <= SLOT_MIN_CHANGE_US {
                continue;
            }
            widest_change = widest_change.max(change.abs());
            // In [0, turn_us), which fits u32 comfortably.
            let next = u32::try_from(next).unwrap_or(0);
            self.commanded_us.insert(slot, next);
            corrections.push((slot, next));
        }

        if corrections.is_empty() {
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return corrections;
        }
        self.corrections_issued += corrections.len() as u64;
        // Dwell until the slowest slew could have finished, plus settle time
        // for the estimates to re-converge on the shifted arrivals.
        let slew = Duration::from_micros(
            (widest_change.unsigned_abs()).saturating_mul(1_000_000) / u64::from(SLEW_US_PER_S),
        );
        self.next_eval_at = Some(now + slew + SETTLE);
        corrections
    }

    /// The delay `slot` was last commanded, if any — the value to re-push when
    /// it (re)connects after corrections were already issued.
    pub fn commanded(&self, slot: SlotId) -> Option<u32> {
        self.commanded_us.get(&slot).copied()
    }

    /// Drops `slot`'s phase estimate on link teardown. Its history describes a
    /// connection that no longer exists; a replacement link re-measures from
    /// scratch. The commanded delay is deliberately kept — the reconnecting
    /// client still applies it, and the connect-time re-push restates it.
    pub fn remove_slot(&mut self, slot: SlotId) {
        self.slots.remove(&slot);
    }

    /// Total per-slot corrections issued over the session, for the stats line.
    pub fn corrections_issued(&self) -> u64 {
        self.corrections_issued
    }

    /// The phase-cluster span the most recent evaluation measured, in
    /// microseconds — the depth-one stall exposure across the population.
    /// `None` until a full evaluation has run.
    pub fn last_span_us(&self) -> Option<i64> {
        self.last_span_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TURN_US: u32 = 41_667;

    fn slot(id: u8) -> SlotId {
        SlotId(id)
    }

    /// Feeds `controller` a steady arrival stream: `turns` turns per slot, each
    /// slot offset within the cycle by its entry in `offsets_us`, starting at
    /// `start`. Returns the instant just past the last arrival.
    fn feed_steady(
        controller: &mut PhaseController,
        start: Instant,
        offsets_us: &[(SlotId, i64)],
        turns: u64,
    ) -> Instant {
        let turn = i64::from(TURN_US);
        let mut last = start;
        for seq in 0..turns {
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
    fn corrections_for(offsets_us: &[(SlotId, i64)]) -> Vec<(SlotId, u32)> {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        // 300 turns ≈ 12.5 s of flow: past FIRST_EVAL_DELAY and MIN_SAMPLES.
        let last = feed_steady(&mut controller, start, offsets_us, 300);
        controller.evaluate(last + Duration::from_millis(1))
    }

    #[test]
    fn aligned_slots_get_no_corrections() {
        // Two slots inside the dead-band: spread 2 ms.
        let corrections = corrections_for(&[(slot(0), 0), (slot(1), 2_000)]);
        assert!(corrections.is_empty(), "got {corrections:?}");
    }

    #[test]
    fn spread_slots_are_delayed_onto_the_latest_phase() {
        // Three slots at 0 / 10 / 20 ms: the cluster's latest phase is 20 ms,
        // so slot 2 stays put and the others are delayed onto it.
        let corrections = corrections_for(&[(slot(0), 0), (slot(1), 10_000), (slot(2), 20_000)]);
        let by_slot: HashMap<SlotId, u32> = corrections.into_iter().collect();
        assert_eq!(by_slot.get(&slot(2)), None, "the latest slot is the target");
        let d0 = *by_slot.get(&slot(0)).expect("slot 0 corrected");
        let d1 = *by_slot.get(&slot(1)).expect("slot 1 corrected");
        assert!(
            (19_000..=21_000).contains(&d0),
            "slot 0 delayed ~20 ms, got {d0}"
        );
        assert!(
            (9_000..=11_000).contains(&d1),
            "slot 1 delayed ~10 ms, got {d1}"
        );
    }

    #[test]
    fn the_cluster_is_found_across_the_cycle_wrap() {
        // Phases at 38 ms and 1 ms sit 4.667 ms apart *across* the wrap; the
        // naive linear reading (37 ms apart) would delay the late slot by most
        // of a turn. The circular gap search must instead nudge the 38 ms slot
        // forward onto 1 ms.
        let corrections = corrections_for(&[(slot(0), 38_000), (slot(1), 1_000 + 41_667)]);
        // Slot 1's arrivals ride the next cycle (offset past one turn), which
        // is exactly the mod-T ambiguity the controller must be blind to.
        let by_slot: HashMap<SlotId, u32> = corrections.into_iter().collect();
        let d0 = *by_slot.get(&slot(0)).expect("slot 0 corrected");
        assert!(
            (3_600..=5_800).contains(&d0),
            "slot 0 walks forward across the wrap (~4.7 ms), got {d0}"
        );
        assert_eq!(by_slot.get(&slot(1)), None, "the target slot stays put");
    }

    #[test]
    fn corrections_do_not_reissue_inside_the_dwell() {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let last = feed_steady(
            &mut controller,
            start,
            &[(slot(0), 0), (slot(1), 20_000)],
            300,
        );
        let first = controller.evaluate(last + Duration::from_millis(1));
        assert!(!first.is_empty());
        // Immediately after issuing, and well inside slew+settle, nothing new
        // is issued even though the (not yet moved) estimates still disagree.
        let again = controller.evaluate(last + Duration::from_secs(1));
        assert!(again.is_empty(), "got {again:?}");
    }

    #[test]
    fn the_loop_converges_once_clients_apply_their_delays() {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let offsets = [(slot(0), 0i64), (slot(1), 12_000), (slot(2), 30_000)];
        let mut fed_until = feed_steady(&mut controller, start, &offsets, 300);
        let corrections = controller.evaluate(fed_until + Duration::from_millis(1));
        assert!(!corrections.is_empty());
        let by_slot: HashMap<SlotId, u32> = corrections.into_iter().collect();

        // Model obedient clients: each slot's arrivals shift by its commanded
        // delay. Resume the same steady stream, offsets adjusted, from where
        // the first stream ended (seq continues), long enough to clear the
        // dwell (max slew 30 ms / 2 ms/s = 15 s, plus settle).
        let shifted: Vec<(SlotId, i64)> = offsets
            .iter()
            .map(|&(id, offset)| {
                (
                    id,
                    offset + i64::from(by_slot.get(&id).copied().unwrap_or(0)),
                )
            })
            .collect();
        let turn = i64::from(TURN_US);
        let resume_seq = 300u64;
        for seq in resume_seq..resume_seq + 800 {
            for &(id, offset) in &shifted {
                let at = start + Duration::from_micros((seq as i64 * turn + offset) as u64);
                controller.note_arrival(id, seq, at);
                fed_until = fed_until.max(at);
            }
        }
        let follow_up = controller.evaluate(fed_until + Duration::from_millis(1));
        assert!(
            follow_up.is_empty(),
            "aligned population needs no further corrections, got {follow_up:?}"
        );
        let span = controller.last_span_us().expect("a full evaluation ran");
        assert!(span <= SPAN_DEAD_BAND_US, "converged span {span}");
    }

    #[test]
    fn a_quiet_slot_sits_out_but_keeps_its_commanded_delay() {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let last = feed_steady(
            &mut controller,
            start,
            &[(slot(0), 0), (slot(1), 20_000)],
            300,
        );
        let first = controller.evaluate(last + Duration::from_millis(1));
        let commanded: HashMap<SlotId, u32> = first.into_iter().collect();
        let corrected = *commanded.keys().next().expect("one slot corrected");

        // Only the other slot keeps sending; the corrected one goes quiet past
        // SAMPLE_MAX_AGE. With one measurable slot there is nothing to align.
        controller.remove_slot(corrected);
        let quiet_until = last + Duration::from_secs(60);
        let other = if corrected == slot(0) {
            slot(1)
        } else {
            slot(0)
        };
        for seq in 300u64..320 {
            let at = quiet_until + Duration::from_micros((seq - 300) * u64::from(TURN_US));
            controller.note_arrival(other, seq, at);
        }
        let corrections = controller.evaluate(quiet_until + Duration::from_secs(2));
        assert!(corrections.is_empty());
        // The departed slot's delay survives for the reconnect re-push.
        assert_eq!(
            controller.commanded(corrected),
            commanded.get(&corrected).copied()
        );
    }

    #[test]
    fn fewer_than_two_measurable_slots_never_correct() {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let last = feed_steady(&mut controller, start, &[(slot(0), 0)], 300);
        assert!(
            controller
                .evaluate(last + Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(controller.commanded(slot(0)), None);
    }

    #[test]
    fn seq_history_from_before_measurement_does_not_skew_the_phase() {
        // Two slots at identical phases whose seq counters differ by hundreds
        // (pre-game traffic consumed seqs at a different cadence): the
        // unwrapped residuals differ by whole turns, the phases must not.
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let turn = i64::from(TURN_US);
        for i in 0..300u64 {
            let at = start + Duration::from_micros((i as i64 * turn) as u64);
            controller.note_arrival(slot(0), i, at);
            controller.note_arrival(slot(1), i + 700, at);
        }
        let last = start + Duration::from_micros((299 * turn) as u64);
        let corrections = controller.evaluate(last + Duration::from_millis(1));
        assert!(corrections.is_empty(), "same phase, got {corrections:?}");
    }
}
