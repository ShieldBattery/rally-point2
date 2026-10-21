//! Max-age retirement tests: the per-relay jittered age limit, make-before-break
//! replacement, busy relays finishing their games before their task stops, a
//! reconnect losing the mark, and the off switch.

use super::super::retirement::age_limit_secs;
use super::*;
use crate::test_support::tid;

const MAX_AGE: Duration = Duration::from_secs(43_200);

/// A single-region rig with a 12h maximum relay age and the given idle grace.
fn with_max_age(idle_grace_secs: u64) -> (Harness, RegionId) {
    let east = region("us-east");
    let h = Harness::with_config(ProvisionConfig {
        regions: vec![east.clone()],
        tick_interval: Duration::from_secs(5),
        launch_deadline: Duration::from_secs(300),
        idle_grace: Duration::from_secs(idle_grace_secs),
        max_relay_age: Some(MAX_AGE),
    });
    (h, east)
}

/// The first instant at which a relay launched at `launched_at` is aged.
fn aged_at(id: RelayId, launched_at: u64) -> u64 {
    launched_at + age_limit_secs(MAX_AGE, id)
}

/// Enrolls the relay the loop launched `index`-th, as if its task had come up:
/// binds its id in the ledger with the launch's token (from the loopback address
/// the fake task reported) and enrolls it in `region`.
fn enroll_launched(h: &Harness, index: usize, region: &RegionId, now: u64) -> RelayId {
    let spec = h.fake.launches()[index].clone();
    h.ledger
        .authorize_enroll_at(
            now,
            spec.relay_id,
            [0x22; 32],
            Some(&spec.enroll_token),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .unwrap();
    registry::enroll(
        &h.reg,
        hello(spec.relay_id.0, 14_900 + spec.relay_id.0 as u16).with_region(region.clone()),
    );
    spec.relay_id
}

fn is_retired(h: &Harness, id: RelayId) -> bool {
    !h.ledger
        .bound_unretired()
        .unwrap()
        .iter()
        .any(|r| r.relay_id == id)
}

#[test]
fn age_limits_are_jittered_within_a_twelfth_and_stable() {
    let max = MAX_AGE.as_secs();
    let limits: Vec<u64> = (1..=500)
        .map(|id| age_limit_secs(MAX_AGE, RelayId(id)))
        .collect();
    for &limit in &limits {
        assert!(
            (max - max / 12..max + max / 12).contains(&limit),
            "limit {limit} is outside ±1/12 of {max}",
        );
    }
    assert_eq!(
        limits,
        (1..=500)
            .map(|id| age_limit_secs(MAX_AGE, RelayId(id)))
            .collect::<Vec<_>>(),
        "the limit is deterministic per relay",
    );
    let distinct: HashSet<u64> = limits.iter().copied().collect();
    assert!(
        distinct.len() > 400,
        "sequential ids spread across the window"
    );
    assert_eq!(
        age_limit_secs(Duration::from_secs(5), RelayId(7)),
        5,
        "a max age too short to jitter is used as-is",
    );
}

#[tokio::test]
async fn an_aged_relay_keeps_serving_until_its_replacement_enrolls() {
    let (mut h, east) = with_max_age(600);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(200_000), 1_000);

    h.provision.tick(1_000).await;
    assert!(
        h.fake.launches().is_empty(),
        "a young relay meets the target"
    );

    let t = aged_at(old, 1_000);
    h.provision.tick(t - 1).await;
    assert!(
        h.fake.launches().is_empty(),
        "nothing happens before the relay's own age limit",
    );

    // Aged: a replacement launches, but the old relay stays placeable — the
    // region has nowhere else to put a game yet.
    h.provision.tick(t).await;
    assert_eq!(h.fake.launches().len(), 1, "a replacement launches");
    assert!(registry::is_available(&h.reg, old));
    h.provision.tick(t + 5).await;
    assert_eq!(
        h.fake.launches().len(),
        1,
        "the in-flight replacement is credited, not doubled",
    );
    assert!(
        registry::is_available(&h.reg, old),
        "still placeable while the replacement is only launching",
    );

    // The replacement enrolls: the old relay drains, and being idle, stops.
    let new = enroll_launched(&h, 0, &east, t + 6);
    h.provision.tick(t + 10).await;
    assert!(!registry::is_available(&h.reg, old));
    assert_eq!(h.fake.stops(), vec![format!("task-live-{}", old.0)]);
    assert!(is_retired(&h, old));
    assert!(registry::is_available(&h.reg, new));
    assert_eq!(h.fake.launches().len(), 1, "no further launches");
}

#[tokio::test]
async fn an_idle_aged_relay_is_tombstoned_before_its_task_is_stopped() {
    let (mut h, east) = with_max_age(600);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(200_000), 1_000);
    let t = aged_at(old, 1_000);
    h.provision.tick(t).await;
    enroll_launched(&h, 0, &east, t + 1);

    let observed = h.observe_tombstone_at_next_stop();
    h.provision.tick(t + 5).await;
    assert_eq!(*observed.lock(), Some((old, true)));
}

#[tokio::test]
async fn a_busy_aged_relay_takes_no_new_sessions_and_stops_once_they_end() {
    let (mut h, east) = with_max_age(600);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(200_000), 1_000);
    let running = create_session(&h.setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(running.response.home_relay.relay_id, old);

    let t = aged_at(old, 1_000);
    h.provision.tick(t).await;
    let new = enroll_launched(&h, 0, &east, t + 1);
    h.provision.tick(t + 5).await;

    assert!(
        !registry::is_available(&h.reg, old),
        "the aged relay takes no new sessions",
    );
    assert!(
        h.fake.stops().is_empty(),
        "but keeps running for its game in progress",
    );
    assert!(!is_retired(&h, old));
    let next = create_session(&h.setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(
        next.response.home_relay.relay_id, new,
        "new games land on the replacement",
    );

    // Still busy on later ticks: left marked, not spared.
    h.provision.tick(t + 10).await;
    assert!(!registry::is_available(&h.reg, old));
    assert!(h.fake.stops().is_empty());

    // Its game ends: the next tick stops and retires it.
    h.setup.retire_session(&tid(), running.response.session);
    h.provision.tick(t + 15).await;
    assert_eq!(h.fake.stops(), vec![format!("task-live-{}", old.0)]);
    assert!(is_retired(&h, old));
    assert!(
        registry::is_available(&h.reg, new),
        "the replacement is untouched"
    );
}

#[tokio::test]
async fn a_reconnect_that_clears_the_retirement_mark_is_re_marked() {
    let (mut h, east) = with_max_age(600);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(200_000), 1_000);
    create_session(&h.setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();

    let t = aged_at(old, 1_000);
    h.provision.tick(t).await;
    enroll_launched(&h, 0, &east, t + 1);
    h.provision.tick(t + 5).await;
    assert!(!registry::is_available(&h.reg, old));

    // The relay reconnects; its fresh registry entry carries no draining mark.
    registry::enroll(
        &h.reg,
        hello(old.0, 14_900 + old.0 as u16).with_region(east.clone()),
    );
    assert!(registry::is_available(&h.reg, old));

    h.provision.tick(t + 10).await;
    assert!(
        !registry::is_available(&h.reg, old),
        "the next tick re-derives the retirement and re-marks it",
    );
    assert!(h.fake.stops().is_empty(), "still busy, so still running");
}

#[tokio::test]
async fn an_aged_relay_in_a_region_with_no_demand_drains_by_the_idle_path() {
    let (mut h, east) = with_max_age(5);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    let t = aged_at(old, 1_000);

    // No warm demand: no replacement is launched, and with none enrolled the
    // retirement leaves it alone — the ordinary idle scale-down owns it.
    h.provision.tick(t).await;
    assert!(h.fake.launches().is_empty());
    assert!(registry::is_available(&h.reg, old));

    h.provision.tick(t + 10).await;
    assert_eq!(h.fake.stops(), vec![format!("task-live-{}", old.0)]);
    assert!(is_retired(&h, old));
    assert!(h.fake.launches().is_empty());
}

#[tokio::test]
async fn without_a_max_age_an_old_busy_relay_is_left_alone() {
    let (mut h, east) = Harness::default_region();
    let (old, _) = h.seed_live_relay(&east, 1_000);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(10_000_000), 1_000);
    create_session(&h.setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();

    h.provision.tick(1_000 + 10 * MAX_AGE.as_secs()).await;
    assert!(h.fake.launches().is_empty());
    assert!(registry::is_available(&h.reg, old));
    assert!(h.fake.stops().is_empty());
}

/// Brings `old` (seeded at 1_000) to the point of retirement: aged, idle past
/// the rig's 5s grace, with a replacement launched and enrolled against a warm
/// target of one. Returns the replacement's id and the instant to act at.
/// Nothing is marked yet.
async fn aged_with_replacement(h: &mut Harness, east: &RegionId, old: RelayId) -> (RelayId, u64) {
    h.warm
        .warm_at(east.clone(), Duration::from_secs(200_000), 1_000);
    let t = aged_at(old, 1_000);
    h.provision.tick(t).await;
    let new = enroll_launched(h, 0, east, t + 1);
    assert!(registry::is_available(&h.reg, old), "not yet marked");
    (new, t + 10)
}

/// Runs a tick's retirement and scale-down phases for `east` over `enrolled`, a
/// snapshot the test has let go stale, exactly as `tick` sequences them.
async fn retire_then_scale_down(
    h: &mut Harness,
    east: &RegionId,
    mut enrolled: Vec<EnrolledRelay>,
    aged: &HashSet<RelayId>,
    now: u64,
) {
    h.provision.retire_aged(east, &mut enrolled, aged).await;
    let live = enrolled
        .iter()
        .filter(|r| !r.draining && r.region.as_ref() == Some(east))
        .count() as u32;
    h.provision.scale_down(east, &enrolled, live, 1, now).await;
}

#[tokio::test]
async fn a_replacement_that_begins_draining_after_the_snapshot_spares_the_old_relay() {
    let (mut h, east) = with_max_age(5);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    let (new, now) = aged_with_replacement(&mut h, &east, old).await;

    // The tick's snapshot still shows the replacement placeable; then it drains.
    let enrolled = registry::enrolled_relays(&h.reg);
    let aged = h.provision.aged_relays(&enrolled, now);
    let generation = enrolled
        .iter()
        .find(|r| r.relay_id == new)
        .unwrap()
        .generation;
    assert!(registry::mark_draining(&h.reg, new, generation));

    // Neither retirement nor the idle scale-down may drain the region's last
    // placeable relay, though the snapshot counts two against a target of one.
    retire_then_scale_down(&mut h, &east, enrolled, &aged, now).await;
    assert!(registry::is_available(&h.reg, old));
    assert!(h.fake.stops().is_empty());
}

#[tokio::test]
async fn a_replacement_that_disconnects_after_the_snapshot_spares_the_old_relay() {
    let (mut h, east) = with_max_age(5);
    let (old, _) = h.seed_live_relay(&east, 1_000);
    let (new, now) = aged_with_replacement(&mut h, &east, old).await;

    let enrolled = registry::enrolled_relays(&h.reg);
    let aged = h.provision.aged_relays(&enrolled, now);
    registry::remove(&h.reg, new);

    retire_then_scale_down(&mut h, &east, enrolled, &aged, now).await;
    assert!(registry::is_available(&h.reg, old));
    assert!(h.fake.stops().is_empty());
}
