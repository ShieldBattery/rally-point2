//! The two throttles the desync comparator logs and notifies through: a
//! power-of-two occurrence counter for repeat anomalies and a token bucket
//! for bursts.

/// A rate-limited occurrence counter: tracks how many times one anomaly class
/// has fired and says whether *this* occurrence is worth logging. Fires on
/// the first occurrence, then again at every power of two, so a persistent
/// anomaly's log volume grows as O(log n) instead of once per turn while
/// never going fully silent. [`SyncTracker`] keeps one of these per anomaly
/// class it distinguishes, replacing what would otherwise be a `count += 1;
/// if <threshold check> { warn!(...) }` triplet duplicated at every call
/// site.
///
/// Comparable directly against a `u64` (`counter == 1`, `counter >= 1`, …) so
/// call sites and tests can read the running total without an accessor; use
/// [`Self::count`] when the value needs to be handed to a `tracing` field.
///
/// `pub(crate)` (rather than private to this module) so other relay modules
/// with their own rate-limited-warn needs — e.g. `chat`'s size- and rate-cap
/// warnings — reuse the one counter rather than each growing its own copy of
/// this `count += 1; if <threshold> { warn!(...) }` triplet.
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

/// A per-key token bucket for a per-slot admission rate cap. Generalizes the
/// chat rate cap's original shape (a whole-token counter plus a last-refill
/// instant, rather than a fractional accumulator -- integer refill counts
/// avoid floating-point drift across a long-running session, and whole-token
/// granularity costs nothing observable at the cadence these caps run at) so
/// every admission path with its own per-slot rate need — chat, and now
/// lobby commands — shares one tested implementation instead of each growing
/// its own copy, mirroring why [`RateLimitedCounter`] is `pub(crate)` here.
pub(crate) struct TokenBucket {
    /// Tokens currently available, capped at `burst`.
    pub(in crate::consensus) tokens: u32,
    /// The instant the tokens above were last refilled up to.
    pub(in crate::consensus) last_refill: std::time::Instant,
    /// The bucket's capacity: how many admissions may burst back-to-back
    /// before refill catches up.
    pub(in crate::consensus) burst: u32,
    /// How often one additional token is added, up to `burst`.
    pub(in crate::consensus) refill_interval: std::time::Duration,
}

impl TokenBucket {
    /// A fresh bucket starts full — a slot's first admissions after joining
    /// (or after this bucket is first created for it) are not penalized for
    /// a session it just started participating in.
    pub(crate) fn new(burst: u32, refill_interval: std::time::Duration) -> Self {
        Self {
            tokens: burst,
            last_refill: std::time::Instant::now(),
            burst,
            refill_interval,
        }
    }

    /// Refills whole elapsed `refill_interval`s since the last refill (capped
    /// at `burst`), then attempts to take one token. Returns `false` — taking
    /// nothing — when the bucket is still empty after refilling.
    pub(crate) fn try_take(&mut self) -> bool {
        let elapsed = self.last_refill.elapsed();
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
