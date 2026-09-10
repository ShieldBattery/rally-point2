//! Scale up/down tests: minting and launching relays to reach target, the
//! v6-only / public-IPv4-wait recording path, warm-target scale-back, and
//! drain-side races (a relay gaining a session, a stale drain generation).

use super::*;

#[tokio::test]
async fn scale_up_mints_launches_and_records_once_running() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;

    // Exactly one launch, tagged for the region.
    let launches = h.fake.launches();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].region.as_ref(), Some(&east));

    // The running task's address was recorded against the minted id.
    let minted_id = launches[0].relay_id;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
        "the launched task is recorded once it reports running",
    );
    // Still launching (unbound) — one in-flight launch credited against target.
    assert_eq!(h.ledger.count_launching(Some(&east), 1_000).unwrap(), 1);
}

#[tokio::test]
async fn launching_counts_against_target_so_no_double_launch() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    // A launch that stays Starting (its task never comes up this test).
    h.fake.set_launch_state(TaskState::Starting);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;
    assert_eq!(h.fake.launches().len(), 1, "the first tick launches one");

    // A second tick, the task still Starting: the in-flight launch counts
    // against the target, so no second task is launched.
    h.provision.tick(1_001).await;
    assert_eq!(
        h.fake.launches().len(),
        1,
        "a still-launching task is not double-launched",
    );
    // And the still-pending launch is spared the orphan sweep.
    assert_eq!(h.fake.stops(), Vec::<String>::new());
    assert_eq!(h.provision.pending.len(), 1);
}

#[tokio::test]
async fn a_starting_task_is_recorded_once_it_reports_running() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    h.fake.set_launch_state(TaskState::Starting);
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;
    let minted_id = h.fake.launches()[0].relay_id;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        None,
        "a still-starting task is not yet recorded",
    );

    // The task comes up; the next tick records it and clears it from pending.
    h.fake.set_task_state("task-0", running());
    h.provision.tick(1_005).await;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
    );
    assert!(
        h.provision.pending.is_empty(),
        "a recorded task leaves pending"
    );
}

#[tokio::test]
async fn a_v6_only_running_state_stays_pending_until_the_public_ipv4_appears() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    h.fake.set_expects_public_ipv4(true);
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let v6_addr: SocketAddr = "[2001:db8::1]:14900".parse().unwrap();
    h.fake.set_launch_state(TaskState::Running {
        expected_ips: vec![v6],
        addrs: vec![v6_addr],
    });
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;
    let minted_id = h.fake.launches()[0].relay_id;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        None,
        "a v6-only address set is not recorded while the public IPv4 may still appear",
    );
    assert_eq!(h.provision.pending.len(), 1);

    // The public IPv4 association appears: a later, still-within-window tick
    // records the full dual-stack set.
    let v4: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
    let v4_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 14_900));
    h.fake.set_task_state(
        "task-0",
        TaskState::Running {
            expected_ips: vec![v6, v4],
            addrs: vec![v6_addr, v4_addr],
        },
    );
    h.provision.tick(1_010).await;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
        "once the v4 association appears the dual-stack set is recorded",
    );
    assert!(
        h.provision.pending.is_empty(),
        "the now-recorded launch leaves pending"
    );
}

#[tokio::test]
async fn a_v6_only_running_state_is_recorded_once_the_wait_lapses() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(3_600),
    );
    h.fake.set_expects_public_ipv4(true);
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let v6_addr: SocketAddr = "[2001:db8::1]:14900".parse().unwrap();
    h.fake.set_launch_state(TaskState::Running {
        expected_ips: vec![v6],
        addrs: vec![v6_addr],
    });
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;
    let minted_id = h.fake.launches()[0].relay_id;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        None,
        "still within the wait, the v6-only set is not yet recorded",
    );

    // Past PUBLIC_IPV4_WAIT_SECS since launch, with the v4 association never
    // having appeared: the v6-only set is recorded as-is rather than held
    // forever.
    h.provision.tick(1_000 + PUBLIC_IPV4_WAIT_SECS + 1).await;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
        "past the wait the v6-only set is recorded rather than blocked forever",
    );
}

#[tokio::test]
async fn a_v6_only_running_state_is_recorded_immediately_when_ipv4_is_not_expected() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    // `expects_public_ipv4` stays at its default (false): a genuinely
    // v6-only deployment must not be held waiting for a v4 that never comes.
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let v6_addr: SocketAddr = "[2001:db8::1]:14900".parse().unwrap();
    h.fake.set_launch_state(TaskState::Running {
        expected_ips: vec![v6],
        addrs: vec![v6_addr],
    });
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    h.provision.tick(1_000).await;
    let minted_id = h.fake.launches()[0].relay_id;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
        "a v6-only deployment records immediately when no public IPv4 is expected",
    );
}

#[tokio::test]
async fn a_lapsed_warm_target_scales_back_to_zero() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    // Warm for 5s, then let it lapse.
    h.warm.warm_at(east.clone(), Duration::from_secs(5), 1_000);
    h.provision.tick(1_000).await;
    assert_eq!(h.fake.launches().len(), 1, "warm demand launched one");

    // Past the warm deadline (and no live relay ever enrolled): the target is 0,
    // so nothing new launches, and the never-enrolled launch stays launching
    // until its own deadline sweep — no runaway launching.
    h.provision.tick(1_010).await;
    assert_eq!(
        h.fake.launches().len(),
        1,
        "a lapsed warm target launches nothing more",
    );
}

#[tokio::test]
async fn a_draining_relay_does_not_suppress_scale_up() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    let (id, generation) = h.seed_live_relay(&east, 1_000);
    // The relay has asked to drain — placement can no longer land a session on
    // it (`registry::is_available` already excludes it) — but it is still
    // present in `enrolled_relays`.
    assert!(registry::mark_draining(&h.reg, id, generation));

    // Warm demand asks for one relay. The draining relay must not count toward
    // it: a live count that included it would read the target as already met
    // and launch nothing, stranding the region with zero placeable relays.
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);
    h.provision.tick(1_000).await;

    assert_eq!(
        h.fake.launches().len(),
        1,
        "a draining relay must not be counted as live, so scale-up still fires",
    );
}

#[tokio::test]
async fn scale_down_drains_only_idle_zero_session_relays_past_the_grace() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    // No warm demand: target is 0, so the single live relay is over target.
    let (id, _gen) = h.seed_live_relay(&east, 1_000);

    // First tick starts the idle timer; the relay is not yet idle past the grace.
    h.provision.tick(1_000).await;
    assert!(
        registry::is_available(&h.reg, id),
        "a relay under the idle grace is not drained",
    );
    assert!(h.fake.stops().is_empty());

    // Past the grace: the relay is drained — its task stopped and its id retired.
    h.provision.tick(1_010).await;
    assert_eq!(
        h.fake.stops(),
        vec![format!("task-live-{}", id.0)],
        "the idle relay's task is stopped",
    );
    assert!(
        !registry::is_available(&h.reg, id),
        "the drained relay is marked draining",
    );
    assert!(
        h.ledger.bound_unretired().unwrap().is_empty(),
        "the drained relay's id is retired",
    );
}

#[tokio::test]
async fn scale_down_spares_a_relay_that_gained_a_session_in_the_race() {
    let east = region("us-east");
    let h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    let (id, generation) = h.seed_live_relay(&east, 1_000);

    // A session lands on the relay (the only enrolled one).
    create_session(&h.setup, two_player_request(), ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(h.setup.session_count_for_relay(id), 1);

    // The drain sequence marks it, re-checks, sees the session, and spares it.
    let mut h = h;
    let drained = h.provision.try_drain_one(id, generation).await;
    assert!(!drained, "a relay that gained a session is spared");
    assert!(
        registry::is_available(&h.reg, id),
        "the spared relay is un-marked (draining cleared)",
    );
    assert!(
        h.fake.stops().is_empty(),
        "a spared relay's task is never stopped"
    );
    assert_eq!(
        h.ledger.bound_unretired().unwrap().len(),
        1,
        "the spared relay's id is not retired",
    );
}

#[tokio::test]
async fn a_stale_generation_drain_is_a_no_op() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    let (id, stale_generation) = h.seed_live_relay(&east, 1_000);
    // The relay reconnects: a newer generation supersedes the one selected.
    registry::enroll(&h.reg, hello_in_region(id.0, &east));

    let drained = h.provision.try_drain_one(id, stale_generation).await;
    assert!(!drained, "a stale-generation drain does not apply");
    assert!(
        registry::is_available(&h.reg, id),
        "the reconnected relay stays available",
    );
    assert!(h.fake.stops().is_empty());
}
