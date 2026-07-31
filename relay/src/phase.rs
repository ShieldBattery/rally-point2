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
//! Stability — the part that is easy to get wrong: a phase is only a
//! well-defined, quasi-static quantity while the session's turn flow actually
//! runs at the nominal period. A game client's *production* schedule is
//! coupled to its peers' arrivals — a client that stalls waiting on a peer
//! produces (and therefore sends) its own next turns later — so the moment a
//! session is stall-bound, commanded delays feed straight into every peer's
//! production time, the effective turn period stretches past nominal, and
//! residuals measured against the nominal period turn into drifting noise. A
//! controller that keeps correcting in that state chases its own wake and
//! amplifies the stalls it was built to remove (observed live before these
//! guards existed: an aligned-then-churning session inflated ~42ms turns to
//! ~70ms with the sim stalled most of the time). Three guards make the loop
//! stable:
//!
//! - **A health gate.** Every slot's inter-arrival interval is tracked, and no
//!   evaluation happens while any active slot's interval deviates from the
//!   turn interval by more than a small tolerance. Corrections only ever issue
//!   into a session whose phases are anchored (clients ticking on their own
//!   timers); the moment churn appears — including churn a correction itself
//!   caused — the gate closes, outstanding slews complete, and the session
//!   relaxes before the controller may look again.
//! - **A per-round change cap, never a wrap.** Each round moves a slot's
//!   commanded delay by a bounded step toward the target (choosing the
//!   delay-*reducing* direction when the floor allows and it is shorter), so a
//!   large misalignment converges over several gated rounds instead of one
//!   long slew that drifts arrivals across every consumer's poll boundary for
//!   many seconds.
//! - **A give-up latch.** If repeated correcting rounds never measure the
//!   population inside the dead-band, the phases are not quasi-static (the
//!   plant is moving for reasons alignment cannot fix) and the controller
//!   disables itself for the session's remainder rather than stirring it.
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

/// The most a slot's commanded delay may change in one round. Capping the step
/// bounds every slew to a few seconds of gentle drift, and rules out the
/// wrap-around slews (most of a turn interval) that a naive modulo fold can
/// command — a large misalignment converges over several health-gated rounds
/// instead. At the default slew rate this step completes in four seconds.
const SLOT_MAX_CHANGE_US: i64 = 8_000;

/// How far a slot's inter-arrival interval may sit from the turn interval and
/// still count as healthy (~2% at 24 turns/s). Inside the band the population
/// is rate-locked to the nominal period and phases are meaningful; outside it
/// the session is churning (stalls, a mid-flight buffer change, a link
/// outage's catch-up) and evaluation waits. A client-side slew in progress
/// shifts intervals by well under a tenth of this, so a correction never
/// closes the gate on itself.
const INTERVAL_TOLERANCE_US: i64 = 800;

/// Correcting rounds allowed without ever measuring the population inside the
/// dead-band before the controller concludes the phases are not quasi-static
/// and disables itself for the session. A full-turn spread takes about three
/// capped rounds when the plant cooperates, so this leaves room for one
/// large initial alignment plus drift repair, while a plant that keeps moving
/// under correction is cut off within a couple of minutes.
const MAX_UNCONVERGED_ROUNDS: u32 = 8;

/// How long the population must sit continuously stretched before the
/// pressure term presses the buffer target (see
/// [`stretch_turns`](PhaseController::stretch_turns)). The interval estimate's
/// own time constant (~1.3 s) already flattens a single long gap back inside
/// tolerance well within this window, so an isolated hiccup never presses;
/// only a session that genuinely cannot hold the turn cadence does.
const STRETCH_SUSTAIN: Duration = Duration::from_secs(5);

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
/// dead-band, unhealthy intervals, or too few measurable slots). Cheap —
/// evaluation is a sort of at most twelve phases — but there is no reason to
/// run it per turn.
const IDLE_REEVAL: Duration = Duration::from_secs(5);

/// Denominator shift of the exponentially weighted residual and interval
/// averages: each sample moves an estimate by 1/32 of its deviation, a time
/// constant of about 1.3 s at the nominal turn rate. Slow enough to flatten
/// jitter and a stray delayed packet, fast enough to track real change within
/// a couple of seconds.
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
    /// Exponentially weighted average of the per-turn arrival interval, in
    /// microseconds — the health signal. `None` until a second sample exists
    /// to difference against.
    interval_us: Option<i64>,
    /// The newest sampled seq, for interval normalization across a skipped
    /// sample (a catch-up packet the caller filtered out).
    last_seq: u64,
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
    /// Correcting rounds since the population last measured inside the
    /// dead-band. Reaching [`MAX_UNCONVERGED_ROUNDS`] sets [`Self::disabled`].
    unconverged_rounds: u32,
    /// The give-up latch: the phases would not settle under correction, so the
    /// controller has stopped for the session's remainder. Never cleared, and
    /// deliberately gates only *corrections* — arrival estimates keep folding,
    /// because the stretch pressure term must keep watching exactly the
    /// sessions that latched.
    disabled: bool,
    /// When the population first showed a stretched arrival interval and has
    /// stayed stretched since; `None` while inside tolerance. The pressure
    /// term fires once this age passes `STRETCH_SUSTAIN`.
    stretch_since: Option<Instant>,
    /// Whether the pressure term is currently pressing, for edge-transition
    /// logging only.
    stretch_pressing: bool,
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
            unconverged_rounds: 0,
            disabled: false,
            stretch_since: None,
            stretch_pressing: false,
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
        // Deliberately not gated on the give-up latch: a latched session stops
        // being *corrected*, but its estimates keep folding so the stretch
        // pressure term still sees it.
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
                // The per-turn interval, normalized across a filtered-out
                // catch-up sample; a reordered or wildly-jumped seq
                // contributes no interval reading (the residual still folds —
                // its EWMA absorbs the noise the same as any other sample).
                let turns = seq.saturating_sub(estimate.last_seq);
                if (1..=4).contains(&turns)
                    && let Ok(gap_us) =
                        i64::try_from(now.duration_since(estimate.last_sample).as_micros())
                {
                    let interval = gap_us / turns as i64;
                    estimate.interval_us = Some(match estimate.interval_us {
                        Some(prior) => prior + ((interval - prior) >> EWMA_SHIFT),
                        None => interval,
                    });
                }
                estimate.samples = estimate.samples.saturating_add(1);
                estimate.last_sample = now;
                estimate.last_seq = seq;
            })
            .or_insert(SlotPhase {
                residual_us: residual,
                interval_us: None,
                last_seq: seq,
                samples: 1,
                last_sample: now,
            });
    }

    /// Runs one control iteration if one is due, returning the slots whose
    /// commanded delay changed, with their new *absolute* delays. Self-gating:
    /// call it as often as convenient (per received packet is the intended
    /// cadence) and it evaluates only on its own schedule — after the
    /// first-evaluation delay, then per the idle cadence, never inside the
    /// dwell that lets a previous correction's slew finish and the estimates
    /// settle, and never while any active slot's arrival interval says the
    /// session is churning rather than rate-locked to the turn period.
    ///
    /// The correction is closed-loop: measured phases already include whatever
    /// delay each client currently applies, so each iteration corrects the
    /// *observed* misalignment and convergence needs no knowledge of what a
    /// client actually applied (a client that ignored its directive simply
    /// keeps showing up misaligned, and only its own correction keeps moving).
    pub fn evaluate(&mut self, now: Instant) -> Vec<(SlotId, u32)> {
        if self.disabled {
            return Vec::new();
        }
        match self.next_eval_at {
            None => return Vec::new(),
            Some(at) if now < at => return Vec::new(),
            Some(_) => {}
        }

        // The health gate: every slot still supplying samples must be running
        // at the nominal turn period before phases mean anything. One churning
        // slot poisons the whole population (its peers' production couples to
        // its arrivals), so any unhealthy active slot pauses evaluation
        // entirely — including churn a previous correction caused, which is
        // what makes the control loop stable instead of self-amplifying.
        let active_unhealthy = self.slots.values().any(|estimate| {
            estimate.samples >= MIN_SAMPLES
                && now.duration_since(estimate.last_sample) <= SAMPLE_MAX_AGE
                && !estimate
                    .interval_us
                    .is_some_and(|iv| (iv - self.turn_us).abs() <= INTERVAL_TOLERANCE_US)
        });
        if active_unhealthy {
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return Vec::new();
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
        // largest delay any slot ends up carrying — and because delays only
        // ever hold a turn back, no client is ever asked to send earlier than
        // its game produced the data.
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
            // Converged: the plant is holding still under the current delays.
            self.unconverged_rounds = 0;
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return Vec::new();
        }

        let target = phases[cluster_end].1;
        let mut corrections = Vec::new();
        let mut widest_change = 0i64;
        for &(slot, phase) in &phases {
            // The forward walk that puts this slot's phase on the target, and
            // its backward (delay-reducing) equivalent one turn shorter. The
            // backward direction is preferred when the current delay can
            // absorb it and it is the shorter move — but never commanded
            // through the zero floor, so a slot is never asked to send before
            // its game produced the data. Each round's move is capped: a big
            // walk becomes several small, health-gated slews instead of one
            // long drift across every consumer's poll boundary.
            let forward = (target - phase).rem_euclid(self.turn_us);
            let backward = forward - self.turn_us;
            let current = i64::from(self.commanded_us.get(&slot).copied().unwrap_or(0));
            let change = if current + backward >= 0 && backward.abs() < forward {
                backward
            } else {
                forward
            };
            let change = change.clamp(-SLOT_MAX_CHANGE_US, SLOT_MAX_CHANGE_US);
            let next = (current + change).clamp(0, self.turn_us - 1);
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
        self.unconverged_rounds += 1;
        if self.unconverged_rounds >= MAX_UNCONVERGED_ROUNDS {
            // The phases never settled under correction: the plant is moving
            // for reasons alignment cannot fix. Stop for the session — a
            // controller that keeps stirring a churning session amplifies the
            // very stalls it exists to remove.
            self.disabled = true;
            tracing::warn!(
                rounds = self.unconverged_rounds,
                span_us = span,
                "send-phase alignment never converged; disabling for this session",
            );
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

    /// The buffer-pressure term, in turns: `1` while the session has sat
    /// continuously stretched — some active slot's arrival interval running
    /// slower than the turn interval beyond tolerance — for the sustain
    /// window (`STRETCH_SUSTAIN`), else `0`.
    ///
    /// This is the escape hatch for a session that keeps stalling and that
    /// phase alignment cannot fix. A stall-bound client produces (and sends)
    /// turns slower than the turn rate, so persistent client-side misery shows
    /// up relay-side as stretched arrival intervals — first-hand wire
    /// evidence, never client-asserted telemetry — whatever the cause: phase
    /// churn the controller latched off over, an overloaded CPU, conditions
    /// the RTT/loss inputs underweight. The buffer law folds this into its
    /// target exactly like the delivery cushion (an additive term, the law
    /// itself untouched), buying the session a turn of slack the way a player
    /// raising the in-game latency setting once did.
    ///
    /// Severity tiles with the alignment controller by construction: the
    /// stretch boundary is the same interval tolerance the health gate uses,
    /// so any session stretched enough to press is one the phase controller
    /// is already refusing to touch, and a session mild enough to correct
    /// never presses — the two can pull in opposite directions on no input.
    /// One-sided on purpose (only slower-than-nominal presses): fast arrivals
    /// are catch-up flushes, not distress. Capped at one turn on purpose: a
    /// client that fundamentally cannot produce at the turn rate is not fixed
    /// by any depth, so escalating with continued stretch would chase an
    /// unfixable client into unbounded latency; one turn is what breaks the
    /// stall-feedback amplification cases. Only slots homed on this relay are
    /// visible here, which covers the sessions that matter (single-relay
    /// sessions are the depth-one population; mesh sessions carry a hop
    /// cushion).
    pub fn stretch_turns(&mut self, now: Instant) -> u32 {
        let stretched = self.slots.values().any(|estimate| {
            estimate.samples >= MIN_SAMPLES
                && now.duration_since(estimate.last_sample) <= SAMPLE_MAX_AGE
                && estimate
                    .interval_us
                    .is_some_and(|iv| iv - self.turn_us > INTERVAL_TOLERANCE_US)
        });
        if !stretched {
            self.stretch_since = None;
            if self.stretch_pressing {
                self.stretch_pressing = false;
                tracing::info!("arrival-interval stretch cleared; releasing the buffer pressure");
            }
            return 0;
        }
        let since = *self.stretch_since.get_or_insert(now);
        if now.duration_since(since) < STRETCH_SUSTAIN {
            return 0;
        }
        if !self.stretch_pressing {
            self.stretch_pressing = true;
            tracing::info!(
                "sustained arrival-interval stretch; pressing the buffer target by one turn",
            );
        }
        1
    }

    /// Trips the give-up latch directly, for tests asserting latched-session
    /// behavior without replaying an unconverging session.
    #[cfg(test)]
    fn force_disable(&mut self) {
        self.disabled = true;
    }

    /// Moves the recorded stretch onset `by` further into the past, so a test
    /// can drive the sustain condition without waiting out real wall clock —
    /// the same trick [`DecisionMaker::backdate_session_start`] plays with the
    /// region-label gate. A no-op while nothing is stretched.
    ///
    /// [`DecisionMaker::backdate_session_start`]: crate::consensus::DecisionMaker
    #[cfg(test)]
    pub(crate) fn backdate_stretch(&mut self, by: Duration) {
        self.stretch_since = self.stretch_since.and_then(|at| at.checked_sub(by));
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

    /// Feeds `controller` a steady arrival stream: `turns` turns per slot
    /// starting at seq `first_seq`, each slot offset within the cycle by its
    /// entry in `offsets_us`, at exactly the nominal period. Returns the
    /// instant just past the last arrival.
    fn feed_steady(
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
    fn corrections_for(offsets_us: &[(SlotId, i64)]) -> Vec<(SlotId, u32)> {
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
    fn run_to_convergence(
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
            }
            rounds.push(corrections);
        }
        panic!("never converged: {rounds:?}");
    }

    #[test]
    fn aligned_slots_get_no_corrections() {
        // Two slots inside the dead-band: spread 2 ms.
        let corrections = corrections_for(&[(slot(0), 0), (slot(1), 2_000)]);
        assert!(corrections.is_empty(), "got {corrections:?}");
    }

    #[test]
    fn spread_slots_converge_in_capped_steps_onto_the_latest_phase() {
        // Three slots at 0 / 10 / 20 ms. The cluster's latest phase is 20 ms,
        // so slots 0 and 1 walk onto it — never more than the per-round cap at
        // a time — and slot 2 stays put throughout.
        let rounds = run_to_convergence(&[(slot(0), 0), (slot(1), 10_000), (slot(2), 20_000)], 8);
        assert!(!rounds.is_empty());
        let mut final_delay: HashMap<SlotId, u32> = HashMap::new();
        let mut prior: HashMap<SlotId, i64> = HashMap::new();
        for round in &rounds {
            for &(id, delay) in round {
                assert_ne!(id, slot(2), "the latest slot is never corrected");
                let before = prior.get(&id).copied().unwrap_or(0);
                assert!(
                    (i64::from(delay) - before).abs() <= SLOT_MAX_CHANGE_US,
                    "per-round change capped, got {before} -> {delay}"
                );
                prior.insert(id, i64::from(delay));
                final_delay.insert(id, delay);
            }
        }
        let d0 = *final_delay.get(&slot(0)).expect("slot 0 corrected");
        let d1 = *final_delay.get(&slot(1)).expect("slot 1 corrected");
        assert!(
            (17_000..=23_000).contains(&d0),
            "slot 0 ends ~20 ms, got {d0}"
        );
        assert!(
            (7_000..=13_000).contains(&d1),
            "slot 1 ends ~10 ms, got {d1}"
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
            &[(slot(0), 0), (slot(1), 6_000)],
            0,
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
        let offsets = [(slot(0), 0i64), (slot(1), 8_000)];
        let last = feed_steady(&mut controller, start, &offsets, 0, 300);
        let first = controller.evaluate(last + Duration::from_millis(1));
        assert!(!first.is_empty(), "the 8 ms spread draws a correction");

        // The correction kicks the session into churn: turns now arrive at a
        // stretched period. Once the dwell passes, the gate — not the dwell —
        // must be what keeps the controller silent.
        let churn_start = last + Duration::from_secs(30);
        let stretched = 50_000i64;
        let mut clock = churn_start;
        for i in 0..300u64 {
            for &(id, offset) in &offsets {
                let at =
                    churn_start + Duration::from_micros((i as i64 * stretched + offset) as u64);
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
        // interval estimate to re-center, and evaluation may run again.
        let resume = clock + Duration::from_secs(1);
        let mut clock2 = resume;
        let turn = i64::from(TURN_US);
        for i in 0..600u64 {
            for &(id, offset) in &offsets {
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
    fn a_quiet_slot_sits_out_but_keeps_its_commanded_delay() {
        let mut controller = PhaseController::new(TURN_US);
        let start = Instant::now();
        let last = feed_steady(
            &mut controller,
            start,
            &[(slot(0), 0), (slot(1), 7_000)],
            0,
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
        let last = feed_steady(&mut controller, start, &[(slot(0), 0)], 0, 300);
        assert!(
            controller
                .evaluate(last + Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(controller.commanded(slot(0)), None);
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
        // One 500 ms hiccup spikes the interval estimate, but the estimate
        // re-centers well inside the sustain window, so polling the pressure
        // every turn across the episode never sees it fire.
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
        // The hiccup: turn 200 lands half a second late, later turns shift
        // with it (the schedule slipped once, the cadence itself recovered).
        for seq in 200..500u64 {
            let at = at_of(seq, 500_000);
            controller.note_arrival(slot(0), seq, at);
            clock = clock.max(at);
            assert_eq!(controller.stretch_turns(clock), 0, "at seq {seq}");
        }
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
