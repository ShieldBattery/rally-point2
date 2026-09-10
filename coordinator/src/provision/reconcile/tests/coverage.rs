//! Coverage-bootstrap demand tests: an empty pair table demanding one relay
//! per configured region, demand merging with warm targets by max not sum,
//! demand clearing once pairs arrive, and the backoff/escalation cycle for a
//! region whose measurements never show up.

use super::*;

#[tokio::test]
async fn an_empty_pair_table_bootstraps_every_configured_region() {
    let east = region("us-east");
    let west = region("us-west");
    let central = region("us-central");
    let mut h = Harness::new(
        vec![east.clone(), west.clone(), central.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );

    // No warm demand and an empty pair table: every region has an uncovered pair,
    // so every region bootstraps exactly one relay.
    h.provision.tick(1_000).await;

    assert_eq!(h.fake.launches().len(), 3, "one launch per region, no more");
    let bootstrapped: HashSet<RegionId> = h
        .fake
        .launches()
        .into_iter()
        .filter_map(|s| s.region)
        .collect();
    assert_eq!(
        bootstrapped,
        HashSet::from([east, west, central]),
        "each configured region gets a bootstrap launch",
    );
}

#[tokio::test]
async fn warm_and_coverage_demand_merge_by_max_not_sum() {
    let east = region("us-east");
    let west = region("us-west");
    let mut h = Harness::new(
        vec![east.clone(), west.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );

    // East is warm (target 1) and also lacks coverage (empty pair table). The two
    // demands merge by max, not sum: exactly one relay, not two.
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);
    h.provision.tick(1_000).await;

    assert_eq!(
        launches_for(&h, &east),
        1,
        "a warm region that also needs coverage bootstraps just once",
    );
}

#[tokio::test]
async fn coverage_demand_clears_when_a_regions_pairs_arrive() {
    let east = region("us-east");
    let west = region("us-west");
    // A short idle grace so the drain is reachable in a couple of ticks; a long
    // launch deadline so the seeded relay is not swept as an expired launch.
    let mut h = Harness::new(
        vec![east.clone(), west.clone()],
        Duration::from_secs(5),
        Duration::from_secs(3_600),
    );
    // A live relay in east, no warm demand. The empty pair table leaves east's one
    // pair uncovered, so coverage demand holds its target at 1.
    let (east_id, _gen) = h.seed_live_relay(&east, 1_000);

    // First tick starts the relay's idle timer; coverage keeps the target at 1, so
    // the relay is not yet a scale-down candidate.
    h.provision.tick(1_000).await;
    assert!(
        registry::is_available(&h.reg, east_id),
        "an uncovered region's relay is held up by coverage demand",
    );

    // Past the idle grace but still uncovered: coverage demand still shields the
    // idle relay from the scale-down.
    h.provision.tick(1_010).await;
    assert!(
        registry::is_available(&h.reg, east_id),
        "coverage demand keeps the relay from idle-draining while a pair is missing",
    );
    assert!(h.fake.stops().is_empty());

    // The relay's measurement lands: east's only pair now has a value, so coverage
    // demand clears. With no warm demand the target falls to 0 and the idle relay
    // drains by the normal path (whose mechanics are covered by other tests).
    h.pair_rtts.record(&east, &west, 87, 1_010);
    h.provision.tick(1_011).await;
    assert!(
        !registry::is_available(&h.reg, east_id),
        "once covered, the relay drops to the normal idle-drain path",
    );
    assert_eq!(
        h.fake.stops(),
        vec![format!("task-live-{}", east_id.0)],
        "the released relay's task is stopped",
    );
}

#[tokio::test]
async fn a_region_that_never_reports_backs_off_and_escalates() {
    let east = region("us-east");
    let west = region("us-west");
    let mut h = Harness::new(
        vec![east.clone(), west.clone()],
        Duration::from_secs(600),
        Duration::from_secs(3_600),
    );
    // Every bootstrap launch stops before enrolling, so nothing lingers as
    // "launching": each tick with live coverage demand produces exactly one launch
    // per region, giving a clean per-tick demand signal.
    h.fake.set_launch_state(TaskState::Stopped);

    // A fresh, uncovered region demands a bootstrap relay within the hold window.
    h.provision.tick(1_000).await;
    assert_eq!(launches_for(&h, &east), 1, "an uncovered region bootstraps");

    // The hold window elapses with no measurement: the region counts a failed
    // attempt and backs off, so this tick demands nothing more for it.
    let failed_at = 1_000 + COVERAGE_HOLD_SECS + 1;
    h.provision.tick(failed_at).await;
    assert_eq!(
        launches_for(&h, &east),
        1,
        "past the hold window with no report, the region backs off (no demand)",
    );

    // Deep into the first backoff (BASE seconds), still no demand.
    h.provision
        .tick(failed_at + COVERAGE_BACKOFF_BASE_SECS - 1)
        .await;
    assert_eq!(
        launches_for(&h, &east),
        1,
        "the region demands nothing while backing off",
    );

    // The first backoff expires: one fresh demanding tick.
    let second_try_at = failed_at + COVERAGE_BACKOFF_BASE_SECS;
    h.provision.tick(second_try_at).await;
    assert_eq!(
        launches_for(&h, &east),
        2,
        "when the backoff expires the region tries once more",
    );

    // That attempt's hold window elapses too: a second failure. The backoff has
    // doubled past BASE, so even BASE seconds after this failure it is still
    // backing off — proof the interval escalated.
    let second_failed_at = second_try_at + COVERAGE_HOLD_SECS + 1;
    h.provision.tick(second_failed_at).await;
    assert_eq!(
        launches_for(&h, &east),
        2,
        "the second failure backs off again"
    );
    h.provision
        .tick(second_failed_at + COVERAGE_BACKOFF_BASE_SECS + 1)
        .await;
    assert_eq!(
        launches_for(&h, &east),
        2,
        "the escalated backoff is longer than the first, so no retry yet",
    );
}

#[tokio::test]
async fn a_pair_value_resets_the_bootstrap_backoff() {
    let east = region("us-east");
    let west = region("us-west");
    let central = region("us-central");
    // Three regions so east has two pairs and a single value is partial progress.
    let mut h = Harness::new(
        vec![east.clone(), west.clone(), central.clone()],
        Duration::from_secs(600),
        Duration::from_secs(3_600),
    );
    h.fake.set_launch_state(TaskState::Stopped);

    // Drive east into a backoff: one attempt, then a failed hold window.
    h.provision.tick(1_000).await;
    let failed_at = 1_000 + COVERAGE_HOLD_SECS + 1;
    h.provision.tick(failed_at).await;
    assert_eq!(
        launches_for(&h, &east),
        1,
        "east backed off after its hold window elapsed with no report",
    );
    // Confirm it is genuinely backing off: a tick within the backoff demands
    // nothing.
    h.provision.tick(failed_at + 10).await;
    assert_eq!(
        launches_for(&h, &east),
        1,
        "east demands nothing while backing off",
    );

    // A value arrives for one of east's two pairs — partial coverage, but proof the
    // measurement path works. It resets the backoff: east demands a relay again on
    // the very next tick, without waiting out the backoff.
    h.pair_rtts.record(&east, &west, 87, failed_at + 20);
    h.provision.tick(failed_at + 20).await;
    assert_eq!(
        launches_for(&h, &east),
        2,
        "a pair value resets the backoff and east resumes demanding immediately",
    );

    // The reset also returned the attempt count to zero: the next failure backs
    // off by BASE again (not the escalated interval), so a retry lands exactly one
    // BASE window after this fresh failure.
    let refailed_at = failed_at + 20 + COVERAGE_HOLD_SECS + 1;
    h.provision.tick(refailed_at).await;
    assert_eq!(
        launches_for(&h, &east),
        2,
        "the fresh attempt fails and backs off",
    );
    h.provision
        .tick(refailed_at + COVERAGE_BACKOFF_BASE_SECS)
        .await;
    assert_eq!(
        launches_for(&h, &east),
        3,
        "the backoff is BASE again, confirming the attempt count reset",
    );
}

#[tokio::test]
async fn a_single_region_config_never_bootstraps() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );

    // A lone region has no pairs, so coverage never demands anything.
    h.provision.tick(1_000).await;
    assert!(
        h.fake.launches().is_empty(),
        "a single-region config has no pairs to bootstrap",
    );
}
