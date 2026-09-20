use super::*;
use crate::test_support::region;

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
fn seed_loads_directional_rows_and_canonicalizes() {
    // The startup load: rows from the ledger populate the table by direction. A
    // non-canonical (a, b) is normalized, and two rows for one link — one per
    // origin — fill both slots, served as their average. The seeded pairs also
    // come back out sorted by (a, b) whatever order the ledger listed them in,
    // which is the order `GET /regions` serves.
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
        // A single-direction pair that sorts before both others.
        DirectionRttRow {
            a: region("ap-south"),
            b: region("us-east"),
            origin: region("ap-south"),
            rtt_ms: 142,
            measured_at: 7,
        },
        // A third pair, listed last but sorting last too — three pairs out of
        // order on the way in is what keeps the ordering assertion honest.
        DirectionRttRow {
            a: region("us-west"),
            b: region("us-east"),
            origin: region("us-west"),
            rtt_ms: 30,
            measured_at: 8,
        },
    ]);
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
    assert_eq!(
        snap[0].rtt_ms, 142,
        "a single seeded direction serves as-is"
    );
    assert_eq!(
        snap[1].a,
        region("eu-west"),
        "a non-canonical seed row is canonicalized",
    );
    assert_eq!(
        snap[1].rtt_ms, 60,
        "both seeded directions average: (55 + 65) / 2 = 60"
    );
    assert_eq!(
        snap[1].measured_at, 6,
        "the served age is the newer of the two seeded directions",
    );
}
