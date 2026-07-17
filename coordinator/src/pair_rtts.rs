//! The backbone-RTT pair table: the coordinator's aggregate of the region-to-region
//! round-trips relays measure and report on their heartbeats.
//!
//! Each relay pings the always-up ping beacons of the *other* regions the coordinator
//! told it about and reports its latest median round-trip to each on every heartbeat
//! (see [`rally_point_proto::control::RegionRttReport`]). The coordinator folds those
//! reports into this store and serves the aggregate on `GET /regions`, where a
//! consumer reads it in place of a hand-maintained latency table.
//!
//! # Canonical pairs, per-direction storage
//!
//! A pair is unordered: `(a, b)` and `(b, a)` are the same backbone link, and both
//! ends measure it. Keys are canonicalized to `a <= b` by id string
//! ([`canonical_pair`]), so both ends collapse to one key — but the value keeps the
//! two ends apart, in two directional slots: the round-trip measured *from* `a` and
//! the one measured *from* `b`, each present once its end has reported.
//!
//! The two ends do not measure the same number. A backbone path is often
//! persistently asymmetric — the route `a → b` takes and the route `b → a` takes can
//! differ by more than measurement noise (tens of milliseconds on a real link), and
//! that difference does not average away over time; it is a property of the routing.
//! A single stored value per pair cannot hold both: the two ends' heartbeats would
//! overwrite each other every beat, each flip counting as a change and costing a log
//! line and a ledger write. A slot per direction makes a cross-direction overwrite
//! impossible by construction.
//!
//! Within one direction, aggregation is last-write-wins beyond a small dead-band
//! (`deadband_ms`): a direction's own reporters — the relays in its origin region —
//! measure independently and repeat their medians every heartbeat, agreeing only to
//! within noise, so a report within the band of the stored value keeps it (noise from
//! one origin does not thrash its slot or the ledger) while a real shift — a re-route
//! — passes through. The band absorbs same-origin noise; it is deliberately not asked
//! to absorb the cross-direction asymmetry, which the separate slots handle instead.
//!
//! The value served on `GET /regions` is the round-half-up average of the present
//! directions (a lone present direction serves as-is), stamped with the newer of the
//! two directions' ages. Averaging yields one representative number for the link
//! without biasing it toward either end: the mean is the honest midpoint for a
//! consumer sizing a jitter buffer, where neither direction's figure alone is more
//! correct than the other.
//!
//! A same-region report (`a == b`) is rejected: the round-trip to a region's own
//! beacon is zero by definition, and relays skip their own region already, so the
//! guard is defensive.
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

/// The floor of the measurement dead-band, in milliseconds — see [`deadband_ms`].
const RTT_DEADBAND_MIN_MS: u32 = 5;

/// How far a reported round-trip may sit from a direction's stored value and still
/// count as the same measurement: 5% of the stored value, floored at
/// [`RTT_DEADBAND_MIN_MS`]. One direction's reporters — the relays in its origin
/// region — measure it independently and repeat their medians on every heartbeat,
/// and medians of one backbone path agree only to within noise that scales loosely
/// with the path (single-digit milliseconds nearby, proportionally more
/// trans-oceanic). A real backbone shift — a re-route — moves that direction well
/// beyond the bound. The band absorbs the noise so a direction's alternating
/// heartbeats cannot thrash its slot or the ledger, and passes real shifts through
/// unchanged. It is not meant to absorb the difference *between* the two directions
/// — that asymmetry is real, and the separate slots keep it apart.
fn deadband_ms(stored_rtt_ms: u32) -> u32 {
    RTT_DEADBAND_MIN_MS.max(stored_rtt_ms / 20)
}

/// One direction of a pair's measured backbone round-trip: the latest median an
/// origin region reported, and when the coordinator recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectionRtt {
    /// The latest reported median round-trip for this direction, in milliseconds.
    rtt_ms: u32,
    /// When this value was recorded, in Unix seconds — stamped by the coordinator at
    /// ingest, not measured by the relay.
    measured_at: u64,
}

/// A canonical pair's two directional measurements, one per end. `from_a` is the
/// round-trip measured from region `a`, `from_b` the one measured from region `b`
/// (the pair's own `a <= b` ordering). Either is absent until its end has reported; a
/// stored pair always holds at least one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PairDirections {
    /// The round-trip measured from region `a`, once `a`'s relays have reported it.
    from_a: Option<DirectionRtt>,
    /// The round-trip measured from region `b`, once `b`'s relays have reported it.
    from_b: Option<DirectionRtt>,
}

impl PairDirections {
    /// The value to serve for this pair: the round-half-up average of the present
    /// directions, stamped with the newer of their ages; a lone present direction
    /// serves as-is. `None` only when neither direction is present, which a stored
    /// pair never is.
    fn served(&self) -> Option<DirectionRtt> {
        match (self.from_a, self.from_b) {
            (Some(a), Some(b)) => Some(DirectionRtt {
                // Round-half-up mean of two u32s, summed in u64 so it cannot overflow;
                // `div_ceil` rounds the exact half up. The mean never exceeds the larger
                // input, so the cast back to u32 is lossless.
                rtt_ms: (u64::from(a.rtt_ms) + u64::from(b.rtt_ms)).div_ceil(2) as u32,
                measured_at: a.measured_at.max(b.measured_at),
            }),
            (Some(one), None) | (None, Some(one)) => Some(one),
            (None, None) => None,
        }
    }
}

/// One canonically-ordered region pair (`a <= b`) and the round-trip served for it —
/// the snapshot row the serve path returns.
///
/// Serializes as `{"a", "b", "rtt_ms", "measured_at"}`, the shape `GET /regions`
/// nests under `backbone_rtts`. `rtt_ms` is the average of the pair's present
/// directions and `measured_at` the newer of their ages (see [`PairRttStore::snapshot`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairRttEntry {
    /// The lexicographically-smaller region id of the pair.
    pub a: RegionId,
    /// The lexicographically-larger region id of the pair.
    pub b: RegionId,
    /// The round-trip served across the pair, in milliseconds.
    pub rtt_ms: u32,
    /// When the served value was recorded, in Unix seconds — stamped by the
    /// coordinator at ingest. Informational: it exposes a value's age to consumers and
    /// operators, and is `0` when the coordinator's clock read pre-epoch at ingest
    /// (age is advisory, so an unusable clock degrades it rather than failing the
    /// record).
    pub measured_at: u64,
}

/// One direction of a canonical pair's measured backbone round-trip, tagged with the
/// origin region that measured it — the row the startup ledger load supplies to
/// [`PairRttStore::seed`], and the shape the ledger persists (one row per pair per
/// origin). `origin` is one of `a` or `b`; it selects which directional slot the row
/// fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectionRttRow {
    /// The lexicographically-smaller region id of the pair.
    pub a: RegionId,
    /// The lexicographically-larger region id of the pair.
    pub b: RegionId,
    /// The region that measured this direction — one of `a` or `b`.
    pub origin: RegionId,
    /// The latest reported median round-trip for this direction, in milliseconds.
    pub rtt_ms: u32,
    /// When this direction's value was recorded, in Unix seconds.
    pub measured_at: u64,
}

/// The map key: a region pair ordered `a <= b`, so either direction of a link maps to
/// one entry.
type PairKey = (RegionId, RegionId);

/// The coordinator's backbone-RTT table: canonical region pair -> its two directional
/// measurements. A plain (non-async) mutex, the same idiom as the presence store; the
/// handle clones cheaply so the HTTP state and every control connection share one map.
#[derive(Clone, Default)]
pub struct PairRttStore {
    pairs: Arc<Mutex<HashMap<PairKey, PairDirections>>>,
}

/// Creates an empty backbone-RTT table (a coordinator that has aggregated no
/// measurements yet).
pub fn new_store() -> PairRttStore {
    PairRttStore::default()
}

impl PairRttStore {
    /// Folds one relay's measured round-trip for a pair into the table, stamping it
    /// `now_unix`. The pair `(relay_region, reported_region)` is canonicalized; the
    /// relay's own region is the direction's origin, so the value lands in the
    /// `from_a` slot when the relay is the pair's `a` end and the `from_b` slot when
    /// it is the `b` end. Within that one slot the value is last-write-wins beyond a
    /// small dead-band; the other direction's slot is never touched.
    ///
    /// The dead-band exists because a direction's reporters — the relays in its origin
    /// region — measure it independently and repeat their own median on every
    /// heartbeat: two medians of one backbone path agree only to within noise, so
    /// without it the slot would flip between readings on every beat, each flip a
    /// change costing a ledger write. A report within `deadband_ms` of the slot's
    /// stored value therefore refreshes `measured_at` but keeps the stored round-trip;
    /// a real backbone shift (a re-route moves a path by tens of milliseconds) lands
    /// unchanged. The band is not asked to absorb the difference between the two
    /// directions — that asymmetry is real and lives in the separate slots.
    ///
    /// Returns whether *this direction's* stored `rtt_ms` changed — `true` for a
    /// direction's first report or a value beyond its dead-band, `false` otherwise
    /// (with `measured_at` still refreshed) — so the caller writes through to the
    /// ledger only when that direction actually changed, and steady-state re-reports
    /// every heartbeat cost no persistence. A same-region report
    /// (`relay_region == reported_region`) is rejected: nothing is stored and `false`
    /// is returned.
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
        // The reporting relay's own region is the origin, so the report fills the
        // `from_a` slot when the relay is the pair's `a` end, else the `from_b` slot.
        let origin_is_a = relay_region.as_ref() == a.as_ref();
        let mut pairs = self.pairs.lock();
        let directions = pairs.entry(key).or_default();
        let slot = if origin_is_a {
            &mut directions.from_a
        } else {
            &mut directions.from_b
        };
        match slot {
            Some(existing) => {
                if existing.rtt_ms.abs_diff(rtt_ms) <= deadband_ms(existing.rtt_ms) {
                    existing.measured_at = now_unix;
                    false
                } else {
                    existing.rtt_ms = rtt_ms;
                    existing.measured_at = now_unix;
                    true
                }
            }
            None => {
                *slot = Some(DirectionRtt {
                    rtt_ms,
                    measured_at: now_unix,
                });
                true
            }
        }
    }

    /// The whole table as canonically-ordered rows, sorted by pair (`a` then `b`), so
    /// the serve path returns a deterministic order. Each row's `rtt_ms` is the
    /// round-half-up average of the pair's present directions (a lone present
    /// direction serves as-is), and its `measured_at` is the newer of the two.
    pub fn snapshot(&self) -> Vec<PairRttEntry> {
        let mut entries: Vec<PairRttEntry> = {
            let pairs = self.pairs.lock();
            pairs
                .iter()
                .filter_map(|((a, b), directions)| {
                    directions.served().map(|served| PairRttEntry {
                        a: a.clone(),
                        b: b.clone(),
                        rtt_ms: served.rtt_ms,
                        measured_at: served.measured_at,
                    })
                })
                .collect()
        };
        entries.sort_by(|x, y| (x.a.as_ref(), x.b.as_ref()).cmp(&(y.a.as_ref(), y.b.as_ref())));
        entries
    }

    /// Every present direction of every stored pair as its own row, tagged with
    /// the origin region that measured it, in an unspecified order. Unlike
    /// [`snapshot`](Self::snapshot), which averages a pair's two directions into
    /// one served value, this keeps the directions apart — one row per measured
    /// direction — so a caller can expose each direction separately.
    pub fn direction_snapshot(&self) -> Vec<DirectionRttRow> {
        let pairs = self.pairs.lock();
        let mut rows = Vec::new();
        for ((a, b), directions) in pairs.iter() {
            if let Some(dir) = directions.from_a {
                rows.push(DirectionRttRow {
                    a: a.clone(),
                    b: b.clone(),
                    origin: a.clone(),
                    rtt_ms: dir.rtt_ms,
                    measured_at: dir.measured_at,
                });
            }
            if let Some(dir) = directions.from_b {
                rows.push(DirectionRttRow {
                    a: a.clone(),
                    b: b.clone(),
                    origin: b.clone(),
                    rtt_ms: dir.rtt_ms,
                    measured_at: dir.measured_at,
                });
            }
        }
        rows
    }

    /// The set of region pairs that currently hold a value in at least one direction,
    /// as canonical keys (`a <= b`). The reconcile loop's coverage bootstrap diffs
    /// this against the configured region pairs to find backbone links still lacking
    /// any measurement; taking it in one locked pass keeps that check to a set lookup
    /// per pair.
    pub fn covered_pairs(&self) -> HashSet<PairKey> {
        self.pairs
            .lock()
            .iter()
            .filter(|(_, directions)| directions.from_a.is_some() || directions.from_b.is_some())
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Loads directional `rows` into the table, canonicalizing each pair and filling
    /// the slot its `origin` selects — the startup load from the ledger, so
    /// last-known per-direction values survive a coordinator restart or a
    /// scale-to-zero. A later row for the same (pair, origin) overwrites an earlier
    /// one.
    pub fn seed(&self, rows: impl IntoIterator<Item = DirectionRttRow>) {
        let mut pairs = self.pairs.lock();
        for row in rows {
            let (a, b) = canonical_pair(&row.a, &row.b);
            let origin_is_a = row.origin.as_ref() == a.as_ref();
            // A row whose origin is neither end of its pair is corrupt — the ledger
            // only ever writes an origin that is one of the pair's regions — so skip it
            // rather than force it into an arbitrary slot.
            if !origin_is_a && row.origin.as_ref() != b.as_ref() {
                continue;
            }
            let key = (a.clone(), b.clone());
            let directions = pairs.entry(key).or_default();
            let slot = if origin_is_a {
                &mut directions.from_a
            } else {
                &mut directions.from_b
            };
            *slot = Some(DirectionRtt {
                rtt_ms: row.rtt_ms,
                measured_at: row.measured_at,
            });
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
    fn a_single_present_direction_serves_as_is() {
        // Only one end has reported this link, so the served row is that direction's
        // own value, not an average.
        let store = new_store();
        assert!(
            store.record(&region("us-east"), &region("eu-west"), 87, 100),
            "a direction's first report is a change",
        );
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].a, region("eu-west"), "canonical order is a <= b");
        assert_eq!(snap[0].b, region("us-east"));
        assert_eq!(snap[0].rtt_ms, 87, "a lone direction serves its own value");
        assert_eq!(snap[0].measured_at, 100);
    }

    #[test]
    fn direction_snapshot_keeps_the_two_directions_apart() {
        // The averaged snapshot collapses a pair to one row; the direction snapshot
        // keeps each measured direction as its own origin-tagged row.
        let store = new_store();
        let east = region("us-east");
        let west = region("us-west");
        store.record(&east, &west, 54, 10);
        store.record(&west, &east, 65, 11);

        let mut rows = store.direction_snapshot();
        rows.sort_by(|x, y| x.origin.as_ref().cmp(y.origin.as_ref()));
        assert_eq!(rows.len(), 2, "one row per present direction");
        // Origin us-east measured 54 toward us-west.
        assert_eq!(rows[0].origin, east);
        assert_eq!(rows[0].rtt_ms, 54);
        // Origin us-west measured 65 toward us-east.
        assert_eq!(rows[1].origin, west);
        assert_eq!(rows[1].rtt_ms, 65);
        // Both rows carry the canonical pair ordering (a <= b).
        assert_eq!(rows[0].a, east);
        assert_eq!(rows[0].b, west);
    }

    #[test]
    fn cross_direction_reports_never_overwrite_and_the_average_holds() {
        // The two ends of a link measure genuinely different paths — 54ms one way,
        // 65ms the other — a persistent asymmetry the dead-band cannot absorb.
        // Per-direction slots keep them apart: they never overwrite each other, and
        // the served value is their round-half-up average, steady across alternating
        // heartbeats.
        let store = new_store();
        let east = region("us-east");
        let west = region("us-west");
        // Canonical order: us-east <= us-west, so a = us-east, b = us-west. Each
        // direction's first report is a fresh slot, so each signals a change.
        assert!(
            store.record(&east, &west, 54, 10),
            "the a->b direction is a fresh slot",
        );
        assert!(
            store.record(&west, &east, 65, 11),
            "the b->a direction is a fresh slot",
        );

        // The served row averages the two present directions: (54 + 65) / 2 = 59.5,
        // rounded half up to 60, with the newer of the two ages.
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1, "the two directions serve one pair row");
        assert_eq!(snap[0].a, east);
        assert_eq!(snap[0].b, west);
        assert_eq!(
            snap[0].rtt_ms, 60,
            "the served value is the round-half-up average"
        );
        assert_eq!(
            snap[0].measured_at, 11,
            "measured_at is the newer of the two directions",
        );

        // Alternate the two directions across many beats: each lands in its own slot
        // and repeats the value already there, so neither signals a change and the
        // served average never moves.
        for beat in 0..8 {
            assert!(
                !store.record(&east, &west, 54, 100 + beat),
                "the a->b direction repeats its own value: no change",
            );
            assert!(
                !store.record(&west, &east, 65, 200 + beat),
                "the b->a direction repeats its own value: no change",
            );
        }
        assert_eq!(
            store.snapshot()[0].rtt_ms,
            60,
            "alternating cross-direction beats leave the served average stable",
        );
    }

    #[test]
    fn a_same_direction_report_within_the_dead_band_keeps_the_stored_value() {
        // One origin's noisy medians for the same direction: a report within the band
        // keeps the slot's value and signals nothing; one past the band is a real
        // shift that lands.
        let store = new_store();
        assert!(store.record(&region("a"), &region("b"), 87, 10));
        assert!(
            !store.record(&region("a"), &region("b"), 87 + RTT_DEADBAND_MIN_MS, 20),
            "a same-direction report inside the dead-band is not a change",
        );
        let snap = store.snapshot();
        assert_eq!(
            snap[0].rtt_ms, 87,
            "the stored direction is kept, not nudged"
        );
        assert_eq!(
            snap[0].measured_at, 20,
            "an in-band re-report still refreshes the age",
        );

        // One past the band is a real shift: it lands and signals.
        assert!(store.record(&region("a"), &region("b"), 87 + RTT_DEADBAND_MIN_MS + 1, 30));
        assert_eq!(store.snapshot()[0].rtt_ms, 87 + RTT_DEADBAND_MIN_MS + 1);

        // On a long path the band scales: 5% of the stored value once that exceeds the
        // floor. Stored 200 -> band 10: a report 10 away is absorbed, 11 lands.
        let long = new_store();
        assert!(long.record(&region("x"), &region("y"), 200, 10));
        assert!(
            !long.record(&region("x"), &region("y"), 210, 20),
            "within 5% of a long path is the same measurement",
        );
        assert_eq!(long.snapshot()[0].rtt_ms, 200);
        assert!(long.record(&region("x"), &region("y"), 211, 30));
        assert_eq!(long.snapshot()[0].rtt_ms, 211);
    }

    #[test]
    fn the_served_average_rounds_half_up() {
        // Feed each direction a value and check the mean's rounding. Origin `a` fills
        // the from_a slot, origin `b` the from_b slot.
        let cases = [
            ((54, 65), 60), // 59.5 -> 60
            ((50, 51), 51), // 50.5 -> 51
            ((50, 52), 51), // exactly 51
            ((10, 10), 10), // equal directions
        ];
        for ((from_a, from_b), expected) in cases {
            let store = new_store();
            let a = region("a");
            let b = region("b");
            assert!(
                store.record(&a, &b, from_a, 1),
                "origin a fills the from_a slot"
            );
            assert!(
                store.record(&b, &a, from_b, 2),
                "origin b fills the from_b slot"
            );
            assert_eq!(
                store.snapshot()[0].rtt_ms,
                expected,
                "the average of {from_a} and {from_b} rounds half up to {expected}",
            );
        }
    }

    #[test]
    fn covered_pairs_reports_a_pair_with_any_direction() {
        let store = new_store();
        assert!(
            store.covered_pairs().is_empty(),
            "an empty store covers no pairs",
        );
        // A single direction covers the canonical pair.
        store.record(&region("us-east"), &region("eu-west"), 87, 100);
        let covered = store.covered_pairs();
        assert_eq!(covered.len(), 1);
        assert!(
            covered.contains(&(region("eu-west"), region("us-east"))),
            "one direction covers the canonical (a <= b) key",
        );
        // The reverse direction is the same link, so coverage stays at one pair.
        store.record(&region("eu-west"), &region("us-east"), 91, 101);
        assert_eq!(
            store.covered_pairs().len(),
            1,
            "the second direction is the same pair",
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
    fn seed_loads_directional_rows_and_canonicalizes() {
        // The startup load: rows from the ledger populate the table by direction. A
        // non-canonical (a, b) is normalized, and two rows for one link — one per
        // origin — fill both slots, served as their average.
        let store = new_store();
        store.seed(vec![
            // A non-canonical pair (a > b) whose origin is the larger id.
            DirectionRttRow {
                a: region("us-east"),
                b: region("eu-west"),
                origin: region("us-east"),
                rtt_ms: 65,
                measured_at: 5,
            },
            // The other direction of the same link, canonically ordered.
            DirectionRttRow {
                a: region("eu-west"),
                b: region("us-east"),
                origin: region("eu-west"),
                rtt_ms: 55,
                measured_at: 6,
            },
            // A single-direction pair.
            DirectionRttRow {
                a: region("ap-south"),
                b: region("us-east"),
                origin: region("ap-south"),
                rtt_ms: 142,
                measured_at: 7,
            },
        ]);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 2, "two pairs seeded");
        assert_eq!(snap[0].a, region("ap-south"), "sorted by (a, b)");
        assert_eq!(snap[0].b, region("us-east"));
        assert_eq!(
            snap[0].rtt_ms, 142,
            "a single seeded direction serves as-is"
        );
        assert_eq!(
            snap[1].a,
            region("eu-west"),
            "a non-canonical seed row is canonicalized",
        );
        assert_eq!(snap[1].b, region("us-east"));
        assert_eq!(
            snap[1].rtt_ms, 60,
            "both seeded directions average: (55 + 65) / 2 = 60"
        );
        assert_eq!(
            snap[1].measured_at, 6,
            "the served age is the newer of the two seeded directions",
        );
    }
}
