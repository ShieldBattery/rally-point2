//! The relay's two shared throttles: a power-of-two occurrence counter for
//! repeat anomalies, and a token bucket for per-key admission rate caps.
//!
//! The bucket is clock-explicit where it matters: the refill arithmetic lives
//! behind entry points that take the instant to evaluate at, so a cap measured
//! in seconds can be driven end to end in a test without sleeping it.

use std::time::{Duration, Instant};

/// A rate-limited occurrence counter: tracks how many times one anomaly class
/// has fired and says whether *this* occurrence is worth logging. Fires on
/// the first occurrence, then again at every power of two, so a persistent
/// anomaly's log volume grows as O(log n) instead of once per turn while
/// never going fully silent. The desync comparator keeps one of these per
/// anomaly class it distinguishes, replacing what would otherwise be a
/// `count += 1; if <threshold check> { warn!(...) }` triplet duplicated at
/// every call site.
///
/// Comparable directly against a `u64` (`counter == 1`, `counter >= 1`, …) so
/// call sites and tests can read the running total without an accessor; use
/// [`Self::count`] when the value needs to be handed to a `tracing` field.
///
/// `pub(crate)` (rather than private to this module) so every relay module
/// with a rate-limited-warn need — the desync comparator's anomaly classes,
/// `chat`'s size- and rate-cap warnings — reuses the one counter rather than
/// each growing its own copy of that triplet.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RateLimitedCounter(u64);

impl RateLimitedCounter {
    /// Records one occurrence and returns whether it should be logged: the
    /// first occurrence, then every power of two thereafter.
    pub(crate) fn observe(&mut self) -> bool {
        self.0 += 1;
        self.0 == 1 || self.0.is_power_of_two()
    }

    /// The total number of occurrences recorded so far.
    pub(crate) fn count(self) -> u64 {
        self.0
    }
}

impl PartialEq<u64> for RateLimitedCounter {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for RateLimitedCounter {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

/// A per-key token bucket for an admission rate cap. A whole-token counter
/// plus a last-refill instant, rather than a fractional accumulator -- integer
/// refill counts avoid floating-point drift across a long-running session, and
/// whole-token granularity costs nothing observable at the cadence these caps
/// run at. Every admission path with its own per-key rate need — chat, lobby
/// commands, skin changes, drop requests — shares this one tested
/// implementation instead of each growing its own copy, the same reason
/// [`RateLimitedCounter`] is shared.
pub(crate) struct TokenBucket {
    /// Tokens currently available, capped at `burst`.
    tokens: u32,
    /// The instant the tokens above were last refilled up to.
    last_refill: Instant,
    /// The bucket's capacity: how many admissions may burst back-to-back
    /// before refill catches up.
    burst: u32,
    /// How often one additional token is added, up to `burst`.
    refill_interval: Duration,
}

impl TokenBucket {
    /// A fresh bucket starts full — a key's first admissions after joining
    /// (or after this bucket is first created for it) are not penalized for
    /// a session it just started participating in.
    pub(crate) fn new(burst: u32, refill_interval: Duration) -> Self {
        Self::new_at(burst, refill_interval, Instant::now())
    }

    /// [`new`](Self::new) with the start of the first refill window given
    /// rather than read off the clock, so a test can put the bucket and its
    /// [`try_take_at`](Self::try_take_at) calls on one synthetic timeline.
    pub(crate) fn new_at(burst: u32, refill_interval: Duration, now: Instant) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
            burst,
            refill_interval,
        }
    }

    /// Refills whole elapsed `refill_interval`s since the last refill (capped
    /// at `burst`), then attempts to take one token. Returns `false` — taking
    /// nothing — when the bucket is still empty after refilling.
    pub(crate) fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    /// [`try_take`](Self::try_take) evaluated at `now` rather than off the
    /// wall clock. All the refill arithmetic lives here, so a cap whose window
    /// is seconds long is covered by advancing an `Instant` instead of
    /// sleeping. A `now` at or before the last refill simply refills nothing.
    pub(crate) fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let interval_ms = self.refill_interval.as_millis().max(1);
        let intervals = elapsed.as_millis() / interval_ms;
        if intervals > 0 {
            let intervals = u32::try_from(intervals).unwrap_or(self.burst);
            self.tokens = self.tokens.saturating_add(intervals).min(self.burst);
            self.last_refill += self.refill_interval * intervals;
        }
        if self.tokens == 0 {
            false
        } else {
            self.tokens -= 1;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counter_logs_the_first_occurrence_then_every_power_of_two() {
        let mut counter = RateLimitedCounter::default();
        let mut logged = Vec::new();
        for occurrence in 1..=16u64 {
            if counter.observe() {
                logged.push(occurrence);
            }
        }
        assert_eq!(
            logged,
            vec![1, 2, 4, 8, 16],
            "a persistent anomaly logs on a doubling schedule, never per occurrence",
        );
        assert_eq!(counter.count(), 16, "every occurrence still counts");
    }

    #[test]
    fn token_bucket_admits_a_full_burst_then_recovers_after_refill() {
        let burst = 4;
        let interval = Duration::from_millis(200);
        let start = Instant::now();
        let mut bucket = TokenBucket::new_at(burst, interval, start);

        for _ in 0..burst {
            assert!(bucket.try_take_at(start));
        }
        assert!(
            !bucket.try_take_at(start),
            "the burst is exhausted; the next admission is rejected",
        );

        assert!(
            bucket.try_take_at(start + interval),
            "one interval refilled one token",
        );
        assert!(
            !bucket.try_take_at(start + interval),
            "and exactly one — the refill does not reopen the whole burst",
        );
    }

    #[test]
    fn token_bucket_never_refills_past_its_burst_cap() {
        let burst = 2;
        let interval = Duration::from_millis(10);
        let start = Instant::now();
        let mut bucket = TokenBucket::new_at(burst, interval, start);

        // Idle far longer than many refill intervals: the bucket must still
        // cap at `burst`, not accumulate an unbounded backlog of tokens.
        let idle = start + interval * 50;
        let mut admitted = 0;
        while bucket.try_take_at(idle) {
            admitted += 1;
        }
        assert_eq!(admitted, burst as usize);
    }
}
