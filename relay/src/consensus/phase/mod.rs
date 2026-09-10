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
//! - **A per-slot command fence.** A slot is never issued a further command
//!   while its previous one is unacknowledged (`PhaseApplied` from the
//!   client), so delayed, lost, or ignored directives park a slot after one
//!   bounded step instead of accumulating a large delay it might later apply
//!   all at once. The acknowledgement is explicit rather than inferred from
//!   measured movement — every inferable reference drifts, and a drifting
//!   reference can fake a response from a slot that never applied anything.
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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
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

/// Outside-dead-band evaluations allowed without ever measuring the
/// population inside the dead-band before the controller concludes it cannot
/// converge the session and disables itself. Counted whether or not the round
/// issued any correction — a client that ignores its directives saturates its
/// command at the clamp and stops producing changes, and its correction-free
/// rounds must still walk toward the latch or the controller would probe it
/// (with the command pinned high) forever. A full-turn spread takes about
/// three capped rounds when the plant cooperates, so this leaves room for one
/// large initial alignment plus drift repair, while a session that stays
/// spread is cut off within a couple of minutes.
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
    /// Slots whose newest command has not yet been acknowledged
    /// (`PhaseApplied`). While present here a slot gets no further command —
    /// a client whose directives are delayed, lost, or ignored must not have
    /// its command ratcheted round after round toward a near-full-turn delay
    /// it might then apply all at once. Released only by an acknowledgement
    /// matching the commanded delay (see [`note_applied`](Self::note_applied));
    /// it deliberately survives dead-band crossings and link teardowns, so
    /// neither span jitter nor reconnect cycles can re-open it unearned.
    awaiting_ack: HashSet<SlotId>,
    /// The next instant `evaluate` will actually evaluate. Holds the
    /// first-evaluation delay, the idle cadence, and — after corrections — the
    /// slew-plus-settle dwell that keeps each iteration from measuring the
    /// previous one's transient.
    next_eval_at: Option<Instant>,
    /// Outside-dead-band evaluations since the population last measured
    /// inside the dead-band, correcting or not. Reaching
    /// [`MAX_UNCONVERGED_ROUNDS`] sets [`Self::disabled`].
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
            awaiting_ack: HashSet::new(),
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
        match self.slots.entry(slot) {
            Entry::Occupied(mut occupied) => {
                let estimate = occupied.get_mut();
                // The transport is deliberately unordered, so an old turn can
                // arrive *after* newer ones. Its arrival time reflects the
                // detour, not the sender's phase, and letting it regress the
                // seq/time baseline would hand the next interval reading a
                // garbage difference on top of folding a meaningless residual.
                // The estimators consume only a monotonically advancing seq;
                // a stale delivery is skipped wholesale.
                if seq <= estimate.last_seq {
                    return;
                }
                estimate.residual_us += (residual - estimate.residual_us) >> EWMA_SHIFT;
                // The per-turn interval, normalized across a filtered-out
                // catch-up sample; a wildly-jumped seq contributes no interval
                // reading (the residual still folds — its EWMA absorbs the
                // noise the same as any other sample).
                let turns = seq - estimate.last_seq;
                if (1..=4).contains(&turns)
                    && let Ok(gap_us) =
                        i64::try_from(now.duration_since(estimate.last_sample).as_micros())
                {
                    // Clamped: one enormous gap (a long stall, a link outage)
                    // is real, but folded raw it would swamp the average so
                    // far past tolerance that a single pause impersonates many
                    // seconds of sustained stretch — the pressure term's
                    // sustain window assumes the estimate re-centers within a
                    // couple of seconds of the cadence recovering. A session
                    // that is *actually* stall-bound re-crosses tolerance on
                    // every turn, clamp or no clamp.
                    let interval = (gap_us / turns as i64).min(self.turn_us.saturating_mul(4));
                    estimate.interval_us = Some(match estimate.interval_us {
                        Some(prior) => prior + ((interval - prior) >> EWMA_SHIFT),
                        None => interval,
                    });
                }
                estimate.samples = estimate.samples.saturating_add(1);
                estimate.last_sample = now;
                estimate.last_seq = seq;
            }
            Entry::Vacant(vacant) => {
                vacant.insert(SlotPhase {
                    residual_us: residual,
                    interval_us: None,
                    last_seq: seq,
                    samples: 1,
                    last_sample: now,
                });
            }
        }
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
            // The command fences deliberately survive this: jitter walks the
            // span across the dead-band boundary, and a fence dropped on
            // every inward crossing would let each outward crossing re-command
            // a slot that never acknowledged anything — a slow ratchet no
            // round counter would ever catch (the counter resets here too).
            // A fence is released only by the matching acknowledgement; a
            // still-fenced slot in a converged population simply never
            // mattered.
            self.unconverged_rounds = 0;
            self.next_eval_at = Some(now + IDLE_REEVAL);
            return Vec::new();
        }

        // Outside the dead-band: this evaluation counts toward the give-up
        // latch whether or not any correction issues below (see
        // `MAX_UNCONVERGED_ROUNDS` for why correction-free rounds count).
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
            return Vec::new();
        }

        let target = phases[cluster_end].1;
        let mut corrections = Vec::new();
        let mut widest_change = 0i64;
        for &(slot, phase) in &phases {
            // A slot that has not acknowledged its previous command gets no
            // further one. The acknowledgement is explicit (`PhaseApplied`,
            // sent by the client as it adopts a directive) rather than
            // inferred from measured movement: every inferable reference
            // drifts with the session, and a drifting reference can fake a
            // response from a slot that never applied anything — re-opening
            // the ratchet this fence exists to stop (commands stepping round
            // after round toward a near-full-turn delay a lagging client
            // might then apply all at once). Under the fence, a client whose
            // directives are delayed, lost, ignored, or predate the frame
            // parks after one bounded step — the safe reading of silence.
            // The ack is client-asserted, and safely so: it releases only the
            // sender's own fence, and a client misrepresenting adoption can
            // only advance its own command — send timing it already controls
            // outright — never another slot's. Held rounds still count toward
            // the give-up latch above.
            if self.awaiting_ack.contains(&slot) {
                continue;
            }
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
            self.awaiting_ack.insert(slot);
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

    /// Releases `slot`'s command fence on the client's acknowledgement that it
    /// adopted `delay_us` as its slew target — but only when the echo matches
    /// the currently commanded delay, so a stale acknowledgement (an older
    /// directive's echo arriving after a newer command, or replayed across a
    /// reconnect) releases nothing it shouldn't. Deliberately not gated on
    /// the give-up latch: releasing a fence on a latched controller is
    /// harmless (nothing evaluates), and keeping the state coherent costs
    /// nothing.
    ///
    /// The echo says *adopted*, not *slewed*: the client sends it as it sets
    /// its new target, with the physical slew still ahead. The issue-time
    /// dwell normally covers that slew — but an echo delayed past the dwell
    /// (slow delivery, or the fresh adoption a reconnect re-push triggers)
    /// would otherwise release the fence straight into an evaluation of a
    /// barely-applied target, stacking another step onto a client mid-slew.
    /// So an actual release re-arms a conservative full-step-plus-settle
    /// dwell from receipt, only ever pushing the next evaluation later.
    pub fn note_applied(&mut self, slot: SlotId, delay_us: u32, now: Instant) {
        if self.commanded_us.get(&slot) == Some(&delay_us) && self.awaiting_ack.remove(&slot) {
            let slew = Duration::from_micros(
                (SLOT_MAX_CHANGE_US as u64).saturating_mul(1_000_000) / u64::from(SLEW_US_PER_S),
            );
            let deadline = now + slew + SETTLE;
            self.next_eval_at = Some(match self.next_eval_at {
                Some(at) => at.max(deadline),
                None => deadline,
            });
        }
    }

    /// Drops `slot`'s phase estimate on link teardown. Its history describes a
    /// connection that no longer exists; a replacement link re-measures from
    /// scratch. The commanded delay is deliberately kept — the reconnecting
    /// client still applies it, and the connect-time re-push restates it.
    pub fn remove_slot(&mut self, slot: SlotId) {
        self.slots.remove(&slot);
        // The command fence deliberately survives alongside the commanded
        // delay it guards: the reconnecting client is re-pushed that same
        // command and acknowledges it afresh, which releases the fence the
        // legitimate way — clearing here instead would let each reconnect of
        // a never-acknowledging client advance its command by another step.
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
mod tests;
