//! The two counting primitives every metric static in [`super`] is built from: a
//! label-keyed monotonic counter and a fixed-bucket histogram. Both store raw,
//! non-cumulative state and leave cumulation/formatting to
//! [`render`](super::render).
//!
//! `pub(super)`: the metric statics live in the parent `metrics` module, and the
//! render helpers live in the sibling `render` module — both need these types and
//! their methods, so nothing here can stay private to this file.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use super::render::{write_meta, write_series};

/// A monotonic counter split by a small, bounded set of label-value tuples.
///
/// Every increment is a low-frequency control-plane event, so a single mutex
/// around a map keyed by the label tuple is ample — no need for a per-key
/// atomic. The map is created on first use behind a `OnceLock`, so the counter
/// itself is a `const`-constructible static.
pub(super) struct LabeledCounter<K> {
    values: OnceLock<Mutex<HashMap<K, u64>>>,
}

impl<K> LabeledCounter<K>
where
    K: Eq + std::hash::Hash + Clone + Ord,
{
    pub(super) const fn new() -> Self {
        Self {
            values: OnceLock::new(),
        }
    }

    fn map(&self) -> &Mutex<HashMap<K, u64>> {
        self.values.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn incr(&self, key: K) {
        *self.map().lock().entry(key).or_insert(0) += 1;
    }

    /// The counter's current values, sorted by label tuple so the exposition
    /// order is deterministic.
    pub(super) fn sorted(&self) -> Vec<(K, u64)> {
        let mut rows: Vec<(K, u64)> = self
            .map()
            .lock()
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }
}

/// The number of finite cold-start buckets; the exposition adds one more for
/// the `+Inf` overflow bucket.
const COLD_START_BUCKET_BOUNDS: [u64; 9] = [5, 10, 15, 20, 30, 45, 60, 90, 120];

/// A fixed-bucket histogram for relay cold-start durations. Bucket counts are
/// stored non-cumulatively and cumulated at render, so `observe` is a single
/// atomic add to one bucket plus the sum and count.
pub(super) struct ColdStartHistogram {
    /// One non-cumulative count per finite bound, plus a trailing `+Inf` bucket.
    buckets: [AtomicU64; COLD_START_BUCKET_BOUNDS.len() + 1],
    /// The sum of all observed values, in whole seconds.
    sum: AtomicU64,
    /// The total number of observations.
    count: AtomicU64,
}

impl ColdStartHistogram {
    pub(super) const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; COLD_START_BUCKET_BOUNDS.len() + 1],
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub(super) fn observe(&self, seconds: u64) {
        let idx = COLD_START_BUCKET_BOUNDS
            .iter()
            .position(|&bound| seconds <= bound)
            .unwrap_or(COLD_START_BUCKET_BOUNDS.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(seconds, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn render(&self, out: &mut String, name: &str) {
        write_meta(
            out,
            name,
            "Seconds from a provisioned relay's launch to its first enroll.",
            "histogram",
        );
        let bucket_name = format!("{name}_bucket");
        let mut cumulative = 0u64;
        for (idx, bound) in COLD_START_BUCKET_BOUNDS.iter().enumerate() {
            cumulative += self.buckets[idx].load(Ordering::Relaxed);
            let le = bound.to_string();
            write_series(out, &bucket_name, &[("le", le.as_str())], cumulative);
        }
        cumulative += self.buckets[COLD_START_BUCKET_BOUNDS.len()].load(Ordering::Relaxed);
        write_series(out, &bucket_name, &[("le", "+Inf")], cumulative);
        write_series(
            out,
            &format!("{name}_sum"),
            &[],
            self.sum.load(Ordering::Relaxed),
        );
        write_series(out, &format!("{name}_count"), &[], cumulative);
    }
}

/// The finite bucket bounds, in whole milliseconds, for a control-connection
/// frame send. Sends are normally sub-millisecond, so the low end is dense; the
/// top bound reaches the liveness timeout, past which a send is treated as a
/// stall, so a stalled send lands in the overflow (`+Inf`) bucket.
const SEND_DURATION_BUCKET_BOUNDS_MS: [u64; 12] =
    [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 5000, 30000];

/// A fixed-bucket histogram for control-connection frame send durations, in
/// milliseconds. Shaped exactly like [`ColdStartHistogram`]: non-cumulative
/// bucket counts cumulated at render, so `observe` is one atomic add per field.
pub(super) struct SendDurationHistogram {
    /// One non-cumulative count per finite bound, plus a trailing `+Inf` bucket.
    buckets: [AtomicU64; SEND_DURATION_BUCKET_BOUNDS_MS.len() + 1],
    /// The sum of all observed values, in whole milliseconds.
    sum: AtomicU64,
    /// The total number of observations.
    count: AtomicU64,
}

impl SendDurationHistogram {
    pub(super) const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; SEND_DURATION_BUCKET_BOUNDS_MS.len() + 1],
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub(super) fn observe(&self, millis: u64) {
        let idx = SEND_DURATION_BUCKET_BOUNDS_MS
            .iter()
            .position(|&bound| millis <= bound)
            .unwrap_or(SEND_DURATION_BUCKET_BOUNDS_MS.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(millis, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn render(&self, out: &mut String, name: &str) {
        write_meta(
            out,
            name,
            "Duration of a coordinator control-connection frame send, in milliseconds.",
            "histogram",
        );
        let bucket_name = format!("{name}_bucket");
        let mut cumulative = 0u64;
        for (idx, bound) in SEND_DURATION_BUCKET_BOUNDS_MS.iter().enumerate() {
            cumulative += self.buckets[idx].load(Ordering::Relaxed);
            let le = bound.to_string();
            write_series(out, &bucket_name, &[("le", le.as_str())], cumulative);
        }
        cumulative += self.buckets[SEND_DURATION_BUCKET_BOUNDS_MS.len()].load(Ordering::Relaxed);
        write_series(out, &bucket_name, &[("le", "+Inf")], cumulative);
        write_series(
            out,
            &format!("{name}_sum"),
            &[],
            self.sum.load(Ordering::Relaxed),
        );
        write_series(out, &format!("{name}_count"), &[], cumulative);
    }
}
