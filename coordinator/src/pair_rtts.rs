//! The backbone-RTT pair table: the coordinator's aggregate of the region-to-region
//! round-trips relays measure and report on their heartbeats.
//!
//! Each relay pings the always-up ping beacons of the *other* regions the coordinator
//! told it about and reports its latest median round-trip to each on every heartbeat
//! (see [`rally_point_proto::control::RegionRttReport`]). The coordinator folds those
//! reports into this store — one value per unordered region pair — and serves the
//! aggregate on `GET /regions`, where a consumer reads it in place of a
//! hand-maintained latency table.
//!
//! # Canonical pairs, last write wins
//!
//! A pair is unordered: `(a, b)` and `(b, a)` are the same backbone link, and either
//! region's relay may measure it. Keys are canonicalized to `a <= b` by id string
//! ([`canonical_pair`]), so both directions collapse to one entry. Aggregation is
//! last-write-wins — the latest report for a pair replaces the stored value, with no
//! smoothing across the two directions, since measured medians are stable and a fresh
//! value is the more current one. A same-region report (`a == b`) is rejected: the
//! round-trip to a region's own beacon is zero by definition, and relays skip their
//! own region already, so the guard is defensive.
//!
//! # Concurrency
//!
//! A [`parking_lot::Mutex`] over the map, the same idiom as the presence and relay
//! registries: every critical section is a short, await-free map edit or scan, never
//! held across I/O. The handle clones cheaply (an `Arc`), so the HTTP state and every
//! relay control connection share one table.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::RegionId;
use serde::Serialize;

/// One region pair's measured backbone round-trip and when it was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PairRtt {
    /// The latest reported median round-trip across the pair, in milliseconds.
    rtt_ms: u32,
    /// When this value was recorded, in Unix seconds — stamped by the coordinator at
    /// ingest, not measured by the relay.
    measured_at: u64,
}

/// One canonically-ordered region pair (`a <= b`) and its measured round-trip — the
/// snapshot row the serve path returns and the seed row the startup load supplies.
///
/// Serializes as `{"a", "b", "rtt_ms", "measured_at"}`, the shape `GET /regions`
/// nests under `backbone_rtts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairRttEntry {
    /// The lexicographically-smaller region id of the pair.
    pub a: RegionId,
    /// The lexicographically-larger region id of the pair.
    pub b: RegionId,
    /// The latest reported median round-trip across the pair, in milliseconds.
    pub rtt_ms: u32,
    /// When the value was recorded, in Unix seconds — stamped by the coordinator at
    /// ingest. Informational: it exposes a value's age to consumers and operators, and
    /// is `0` when the coordinator's clock read pre-epoch at ingest (age is advisory,
    /// so an unusable clock degrades it rather than failing the record).
    pub measured_at: u64,
}

/// The map key: a region pair ordered `a <= b`, so either direction of a link maps to
/// one entry.
type PairKey = (RegionId, RegionId);

/// The coordinator's backbone-RTT table: canonical region pair -> its latest measured
/// round-trip. A plain (non-async) mutex, the same idiom as the presence store; the
/// handle clones cheaply so the HTTP state and every control connection share one map.
#[derive(Clone, Default)]
pub struct PairRttStore {
    pairs: Arc<Mutex<HashMap<PairKey, PairRtt>>>,
}

/// Creates an empty backbone-RTT table (a coordinator that has aggregated no
/// measurements yet).
pub fn new_store() -> PairRttStore {
    PairRttStore::default()
}

impl PairRttStore {
    /// Folds one relay's measured round-trip for a pair into the table, stamping it
    /// `now_unix`. The pair `(relay_region, reported_region)` is canonicalized, so the
    /// direction the relay measured from does not matter; the value is
    /// last-write-wins.
    ///
    /// Returns whether the stored `rtt_ms` *changed* — `true` for a new pair or a
    /// different value, `false` for a re-report of the same value (whose `measured_at`
    /// is still refreshed) — so the caller writes through to the ledger only when
    /// something actually changed, and a steady-state re-report every heartbeat costs
    /// no persistence. A same-region report (`relay_region == reported_region`) is
    /// rejected: nothing is stored and `false` is returned.
    pub fn record(
        &self,
        relay_region: &RegionId,
        reported_region: &RegionId,
        rtt_ms: u32,
        now_unix: u64,
    ) -> bool {
        if relay_region == reported_region {
            return false;
        }
        let (a, b) = canonical_pair(relay_region, reported_region);
        let key = (a.clone(), b.clone());
        let mut pairs = self.pairs.lock();
        match pairs.get_mut(&key) {
            Some(existing) => {
                let changed = existing.rtt_ms != rtt_ms;
                existing.rtt_ms = rtt_ms;
                existing.measured_at = now_unix;
                changed
            }
            None => {
                pairs.insert(
                    key,
                    PairRtt {
                        rtt_ms,
                        measured_at: now_unix,
                    },
                );
                true
            }
        }
    }

    /// The whole table as canonically-ordered rows, sorted by pair (`a` then `b`), so
    /// the serve path returns a deterministic order.
    pub fn snapshot(&self) -> Vec<PairRttEntry> {
        let mut entries: Vec<PairRttEntry> = {
            let pairs = self.pairs.lock();
            pairs
                .iter()
                .map(|((a, b), rtt)| PairRttEntry {
                    a: a.clone(),
                    b: b.clone(),
                    rtt_ms: rtt.rtt_ms,
                    measured_at: rtt.measured_at,
                })
                .collect()
        };
        entries.sort_by(|x, y| (x.a.as_ref(), x.b.as_ref()).cmp(&(y.a.as_ref(), y.b.as_ref())));
        entries
    }

    /// The set of region pairs that currently hold a value, as canonical keys
    /// (`a <= b`). The reconcile loop's coverage bootstrap diffs this against the
    /// configured region pairs to find backbone links still lacking a measurement;
    /// taking it in one locked pass keeps that check to a set lookup per pair.
    pub fn covered_pairs(&self) -> HashSet<PairKey> {
        self.pairs.lock().keys().cloned().collect()
    }

    /// Loads `entries` into the table, canonicalizing each pair — the startup load from
    /// the ledger, so last-known values survive a coordinator restart or a
    /// scale-to-zero. A later entry for a pair overwrites an earlier one.
    pub fn seed(&self, entries: impl IntoIterator<Item = PairRttEntry>) {
        let mut pairs = self.pairs.lock();
        for entry in entries {
            let (a, b) = canonical_pair(&entry.a, &entry.b);
            pairs.insert(
                (a.clone(), b.clone()),
                PairRtt {
                    rtt_ms: entry.rtt_ms,
                    measured_at: entry.measured_at,
                },
            );
        }
    }
}

/// Orders a region pair canonically (`a <= b` by id string) — the ordering the store
/// keys on and the ledger stores, so either direction of a link resolves to one row.
pub fn canonical_pair<'a>(x: &'a RegionId, y: &'a RegionId) -> (&'a RegionId, &'a RegionId) {
    if x.as_ref() <= y.as_ref() {
        (x, y)
    } else {
        (y, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str) -> RegionId {
        RegionId(name.to_owned())
    }

    #[test]
    fn either_direction_of_a_pair_canonicalizes_to_one_entry() {
        // A relay in `us-east` reporting `eu-west` and a relay in `eu-west` reporting
        // `us-east` describe the same link — they must collapse to a single canonical
        // entry, not two.
        let store = new_store();
        assert!(store.record(&region("us-east"), &region("eu-west"), 87, 100));
        // The reverse direction, same link: already stored, same value -> unchanged.
        assert!(!store.record(&region("eu-west"), &region("us-east"), 87, 200));

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1, "the two directions collapse to one entry");
        assert_eq!(snap[0].a, region("eu-west"), "canonical order is a <= b");
        assert_eq!(snap[0].b, region("us-east"));
        assert_eq!(snap[0].rtt_ms, 87);
        assert_eq!(
            snap[0].measured_at, 200,
            "a same-value re-report refreshes the age"
        );
    }

    #[test]
    fn a_later_report_wins_and_its_change_is_signaled() {
        let store = new_store();
        assert!(
            store.record(&region("a"), &region("b"), 50, 10),
            "a new pair is a change",
        );
        assert!(
            store.record(&region("a"), &region("b"), 75, 20),
            "a different value is a change",
        );
        assert!(
            !store.record(&region("a"), &region("b"), 75, 30),
            "the same value is not a change",
        );

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].rtt_ms, 75, "last write wins");
        assert_eq!(
            snap[0].measured_at, 30,
            "even an unchanged re-report refreshes the age"
        );
    }

    #[test]
    fn covered_pairs_reports_stored_keys_canonically() {
        let store = new_store();
        assert!(
            store.covered_pairs().is_empty(),
            "an empty store covers no pairs",
        );
        // Either direction of a link registers the one canonical key.
        store.record(&region("us-east"), &region("eu-west"), 87, 100);
        let covered = store.covered_pairs();
        assert_eq!(covered.len(), 1);
        assert!(
            covered.contains(&(region("eu-west"), region("us-east"))),
            "the canonical (a <= b) key is present",
        );
    }

    #[test]
    fn a_same_region_report_is_rejected() {
        // A relay's round-trip to its own region's beacon is zero by definition and
        // must never enter the table.
        let store = new_store();
        assert!(!store.record(&region("us-east"), &region("us-east"), 0, 100));
        assert!(
            store.snapshot().is_empty(),
            "a same-region report stores nothing",
        );
    }

    #[test]
    fn snapshot_is_sorted_by_pair() {
        let store = new_store();
        store.record(&region("us-east"), &region("us-west"), 30, 100);
        store.record(&region("eu-west"), &region("us-east"), 87, 100);
        store.record(&region("ap-south"), &region("us-east"), 142, 100);

        let snap = store.snapshot();
        let ids: Vec<(&str, &str)> = snap.iter().map(|e| (e.a.as_ref(), e.b.as_ref())).collect();
        assert_eq!(
            ids,
            vec![
                ("ap-south", "us-east"),
                ("eu-west", "us-east"),
                ("us-east", "us-west"),
            ],
            "entries come out sorted by (a, b)",
        );
    }

    #[test]
    fn seed_canonicalizes_and_loads() {
        // The startup load: entries from the ledger populate the table, and a
        // non-canonical seed row is normalized to a <= b.
        let store = new_store();
        store.seed(vec![
            PairRttEntry {
                a: region("us-east"),
                b: region("eu-west"),
                rtt_ms: 87,
                measured_at: 5,
            },
            PairRttEntry {
                a: region("ap-south"),
                b: region("us-east"),
                rtt_ms: 142,
                measured_at: 6,
            },
        ]);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].a, region("ap-south"));
        assert_eq!(snap[0].b, region("us-east"));
        assert_eq!(
            snap[1].a,
            region("eu-west"),
            "a seeded pair is canonicalized"
        );
        assert_eq!(snap[1].b, region("us-east"));
        assert_eq!(snap[1].rtt_ms, 87);
    }
}
