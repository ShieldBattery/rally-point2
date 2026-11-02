//! The buffer-pressure term: first-hand wire evidence that a session cannot
//! hold the turn cadence, folded into the buffer law's target.

use std::time::Instant;

use super::{INTERVAL_TOLERANCE_US, MIN_SAMPLES, PhaseController, SAMPLE_MAX_AGE, STRETCH_SUSTAIN};

impl PhaseController {
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
}
