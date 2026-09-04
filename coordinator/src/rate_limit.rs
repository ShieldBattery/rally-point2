//! The token-bucket rate limiter the coordinator's tenant-authenticated endpoints
//! share.
//!
//! Every limit here has the same shape: a burst a caller may spend back-to-back
//! and a steady-state refill, keyed on something the request *authenticated* as —
//! the tenant, or the tenant and the session it named — so one caller's
//! misbehaviour never starves another's. The limits exist to stop a misbehaving
//! caller from hammering an endpoint, not to enforce correctness, which is what
//! makes the in-memory, forgotten-on-restart storage adequate: a restart only ever
//! grants a fresh burst.
//!
//! The buckets live behind a plain (non-async) mutex; every critical section is a
//! short, await-free token check. Two bounds keep the map from growing without
//! limit under an authenticated caller spraying unique keys: idle buckets are
//! pruned lazily on access (a bucket untouched long enough to have refilled from
//! empty to full is indistinguishable from a never-seen key, so dropping it loses
//! no state), and a hard cardinality cap evicts the stalest buckets when an insert
//! would exceed it. A full map never refuses a check outright — that would turn the
//! limiter into a denial of service on the callers actually using the endpoint.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// A token bucket for one key.
struct Bucket {
    /// Tokens available now, fractional so a partial refill accrues between
    /// requests rather than being lost.
    tokens: f64,
    /// When the tokens were last refilled — the anchor the next check accrues from.
    last_refill: Instant,
}

/// A keyed token-bucket rate limiter. Clone it cheaply (the state is behind one
/// `Arc`) to hand a copy to a router state or a lifecycle that prunes it.
pub struct KeyedTokenBuckets<K> {
    buckets: Arc<Mutex<HashMap<K, Bucket>>>,
    burst: u32,
    refill_interval: Duration,
    /// Hard cap on live bucket count. When an insert would exceed it, the stalest
    /// bucket(s) are evicted to make room.
    bucket_cap: usize,
}

impl<K> Clone for KeyedTokenBuckets<K> {
    fn clone(&self) -> Self {
        Self {
            buckets: Arc::clone(&self.buckets),
            burst: self.burst,
            refill_interval: self.refill_interval,
            bucket_cap: self.bucket_cap,
        }
    }
}

impl<K: Eq + Hash + Clone> KeyedTokenBuckets<K> {
    /// Builds a limiter admitting `burst` requests back-to-back per key, refilling
    /// one token per `refill_interval`, holding at most `bucket_cap` live buckets.
    pub fn new(burst: u32, refill_interval: Duration, bucket_cap: usize) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            burst,
            refill_interval,
            bucket_cap: bucket_cap.max(1),
        }
    }

    /// Whether a request for `key` is admitted at `now`, consuming a token if so.
    /// A fresh key starts with a full burst; refills accrue at one token per
    /// refill interval up to that burst.
    pub fn check_at(&self, key: &K, now: Instant) -> bool {
        let refill_per_sec = 1.0 / self.refill_interval.as_secs_f64();
        let burst = f64::from(self.burst);
        let mut buckets = self.buckets.lock();
        // Prune idle buckets: one untouched long enough to have refilled from empty
        // all the way back to its full burst says exactly what a never-seen key
        // says, so dropping it loses no state and keeps the map bounded by the keys
        // actually in use. The threshold is (burst + 1) refill intervals — the time
        // to refill from empty to full, plus a one-interval margin. Running it on
        // every check is fine for a map bounded this way.
        let evict_after = self.refill_interval * self.burst.saturating_add(1);
        buckets.retain(|_, b| now.saturating_duration_since(b.last_refill) < evict_after);
        // Hard cardinality cap: if admitting a *new* key would exceed it (the idle
        // pass above didn't free enough — a high-rate spray of unique keys keeps
        // every bucket fresh), evict the stalest bucket(s) to make room. A stale
        // bucket has refilled toward full, so dropping it only grants a fresh burst,
        // never refuses a live caller; and a spray can never push an active key out,
        // because an active key's bucket is by definition newer than the sprayer's
        // oldest. The check itself is never refused outright — a full map must not
        // become a denial of service on the callers actually using the endpoint.
        if !buckets.contains_key(key) {
            while buckets.len() >= self.bucket_cap {
                let Some(stalest) = buckets
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last_refill)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                buckets.remove(&stalest);
            }
        }
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        // Accrue refill for the elapsed time, capped at the burst.
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops every bucket whose key `predicate` accepts — how a caller retires the
    /// buckets of something that no longer exists.
    pub fn retain_not(&self, predicate: impl Fn(&K) -> bool) {
        self.buckets.lock().retain(|key, _| !predicate(key));
    }

    /// The number of live buckets — the hook a test asserts the map's bounds with.
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }
}
