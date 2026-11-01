//! Client-side actuation of relay send-phase directives.
//!
//! The relay measures each of its home slots' turn-arrival phase within the
//! turn cycle and pushes a `PhaseDirective` — "hold each outbound turn's wire
//! handoff by this total delay" — down the reliable control stream when a
//! client's phase should shift (see the message's wire docs for why). The
//! driver applies it here: the game's own local echo has already happened by
//! the time a turn reaches the driver, so a held wire handoff shifts *when the
//! turn leaves for the relay* and nothing about when the game runs.
//!
//! The applied delay never steps to a new command; it slews at a bounded rate
//! so inter-send gaps stay within a fraction of a percent of the turn interval
//! and the relay's pacing statistics never register the shift as jitter. Both
//! directions are legal — a command may lower the delay (the phase difference
//! is what matters, modulo the turn interval) — but the applied delay never
//! goes below zero, so a turn is never sent before the game produced it.

use tokio::time::Instant;

/// Slew rate used when a directive leaves the rate unset (zero).
const DEFAULT_SLEW_US_PER_S: u64 = 2_000;

/// Bounds on the relay-commanded slew rate. The floor keeps a nonsensical
/// crawl from pinning the applied delay mid-slew for minutes; the ceiling
/// bounds how quickly any directive can move our send timing, keeping the
/// per-turn gap distortion well under one percent at any realistic turn rate.
const MIN_SLEW_US_PER_S: u64 = 100;
const MAX_SLEW_US_PER_S: u64 = 10_000;

/// Hard ceiling on any commanded delay. The relay works modulo the turn
/// interval so real commands sit far below this; the clamp is defense against
/// a bad or hostile relay, bounding the added send latency to a small fraction
/// of a second no matter what arrives on the wire.
const MAX_DELAY_US: u32 = 100_000;

/// The driver's current send-phase state, published to the embedder over a
/// watch channel so it can display the shift (a netstat overlay) without
/// participating in it. `applied_us` is the delay currently added to each
/// outbound turn's wire handoff; `target_us` is where the newest directive is
/// slewing it. Equal once a slew completes; both zero when no directive has
/// ever arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhaseStatus {
    /// Microseconds of wire-handoff delay currently applied per outbound turn.
    pub applied_us: u32,
    /// Microseconds of delay the newest directive commanded.
    pub target_us: u32,
}

/// The slewing delay itself: tracks the newest commanded target and walks the
/// applied delay toward it at the commanded (bounded) rate as time passes.
#[derive(Debug)]
pub(crate) struct PhaseSlew {
    /// The applied delay in [`UNITS_PER_US`] units. A nanosecond of elapsed
    /// time at a rate in µs/s moves it a whole number of units, so every
    /// advance credits all of its elapsed time at the rate in force: no
    /// fraction of a microsecond is dropped (which would slow the slew below
    /// its commanded rate at fine poll cadences) or left pending to be
    /// credited later at a different rate.
    applied_units: u64,
    target_us: u64,
    rate_us_per_s: u64,
    /// When the applied delay was last walked forward.
    last_advance: Instant,
}

/// Resolution of the applied delay: units per microsecond, so that
/// `elapsed_ns × rate_us_per_s` is exactly the movement in units.
const UNITS_PER_US: u64 = 1_000_000_000;

impl PhaseSlew {
    pub(crate) fn new(now: Instant) -> Self {
        PhaseSlew {
            applied_units: 0,
            target_us: 0,
            rate_us_per_s: DEFAULT_SLEW_US_PER_S,
            last_advance: now,
        }
    }

    /// Adopts a newly arrived directive: the commanded delay (clamped) becomes
    /// the slew target and the commanded rate (defaulted when zero, bounded
    /// always) becomes the slew rate. The applied delay is walked forward
    /// under the *old* rate first, so a rate change never applies
    /// retroactively to time already elapsed.
    pub(crate) fn retarget(&mut self, delay_us: u32, slew_us_per_s: u32, now: Instant) {
        self.advance(now);
        self.target_us = u64::from(delay_us.min(MAX_DELAY_US));
        self.rate_us_per_s = match u64::from(slew_us_per_s) {
            0 => DEFAULT_SLEW_US_PER_S,
            rate => rate.clamp(MIN_SLEW_US_PER_S, MAX_SLEW_US_PER_S),
        };
    }

    /// Walks the applied delay toward the target by however much the elapsed
    /// time allows, returning the delay to hold the next outbound turn by.
    pub(crate) fn advance(&mut self, now: Instant) -> u64 {
        let elapsed_ns = now
            .saturating_duration_since(self.last_advance)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        self.last_advance = self.last_advance.max(now);
        // Elapsed time is bounded by session length and the rate by its clamp,
        // so the product stays far inside u64 (and saturates past it).
        let step = elapsed_ns.saturating_mul(self.rate_us_per_s);
        let target_units = self.target_us * UNITS_PER_US;
        self.applied_units = if self.applied_units < target_units {
            self.applied_units.saturating_add(step).min(target_units)
        } else {
            self.applied_units.saturating_sub(step).max(target_units)
        };
        self.applied_us()
    }

    /// The applied delay in whole microseconds.
    fn applied_us(&self) -> u64 {
        self.applied_units / UNITS_PER_US
    }

    /// The current state, for the embedder-facing watch channel.
    pub(crate) fn status(&self) -> PhaseStatus {
        PhaseStatus {
            applied_us: u32::try_from(self.applied_us()).unwrap_or(u32::MAX),
            target_us: u32::try_from(self.target_us).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn applies_nothing_until_directed() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        assert_eq!(slew.advance(start + Duration::from_secs(60)), 0);
        assert_eq!(slew.status(), PhaseStatus::default());
    }

    #[test]
    fn slews_up_at_the_commanded_rate_and_stops_at_the_target() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(10_000, 2_000, start);
        // 2 ms/s: after 1 s, 2 ms applied; after 5 s, capped at the target.
        assert_eq!(slew.advance(start + Duration::from_secs(1)), 2_000);
        assert_eq!(slew.advance(start + Duration::from_secs(5)), 10_000);
        assert_eq!(slew.advance(start + Duration::from_secs(60)), 10_000);
        assert_eq!(
            slew.status(),
            PhaseStatus {
                applied_us: 10_000,
                target_us: 10_000
            }
        );
    }

    #[test]
    fn slews_back_down_when_a_lower_delay_is_commanded() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(10_000, 10_000, start);
        assert_eq!(slew.advance(start + Duration::from_secs(1)), 10_000);
        slew.retarget(4_000, 2_000, start + Duration::from_secs(1));
        assert_eq!(slew.advance(start + Duration::from_secs(2)), 8_000);
        assert_eq!(slew.advance(start + Duration::from_secs(10)), 4_000);
    }

    #[test]
    fn frequent_small_advances_lose_no_progress() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(10_000, 2_000, start);
        // 10 ms of wall clock per call moves 20 us; a call cadence finer than
        // 500 us would round each step to zero if elapsed time were consumed
        // unconditionally. 2000 calls x 500 us = 1 s => 2 ms applied.
        let mut at = start;
        for _ in 0..2_000 {
            at += Duration::from_micros(500);
            slew.advance(at);
        }
        assert_eq!(slew.advance(at), 2_000);
    }

    #[test]
    fn hostile_values_are_clamped() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(u32::MAX, u32::MAX, start);
        assert_eq!(u64::from(slew.status().target_us), u64::from(MAX_DELAY_US));
        // One second at the clamped max rate moves exactly MAX_SLEW_US_PER_S.
        assert_eq!(
            slew.advance(start + Duration::from_secs(1)),
            MAX_SLEW_US_PER_S
        );
    }

    #[test]
    fn a_zero_rate_falls_back_to_the_default() {
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(10_000, 0, start);
        assert_eq!(slew.advance(start + Duration::from_secs(1)), 2_000);
    }

    #[test]
    fn polls_finer_than_a_microsecond_of_movement_keep_the_commanded_rate() {
        // At 2 ms/s, a poll every 999 us moves 1.998 us. Crediting only the
        // whole microsecond and discarding the rest of the elapsed time would
        // halve the slew rate; the full 999 ms must move 1998 us.
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(10_000, 2_000, start);
        let mut at = start;
        for _ in 0..1_000 {
            at += Duration::from_micros(999);
            slew.advance(at);
        }
        assert_eq!(slew.advance(at), 1_998);
    }

    #[test]
    fn time_before_a_retarget_is_never_credited_at_the_new_rate() {
        // 9 ms at the slowest rate is under one microsecond of movement. That
        // time belongs to the old directive (whose target, zero, it had
        // already reached); none of it may be walked at the new 10 ms/s rate.
        let start = Instant::now();
        let mut slew = PhaseSlew::new(start);
        slew.retarget(0, 100, start);
        let at = start + Duration::from_millis(9);
        slew.retarget(10_000, 10_000, at);
        assert_eq!(slew.advance(at), 0);
        assert_eq!(slew.advance(at + Duration::from_millis(1)), 10);
    }
}
