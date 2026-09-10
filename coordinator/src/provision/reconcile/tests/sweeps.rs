//! Sweep tests (launch-deadline, vanished-task, orphan) plus the
//! provisioner-error resilience tests: a failing launch/state/list/stop call
//! must not kill the loop, and repeated enroll/retire cycles must not leak
//! outbox state.

use super::*;

#[tokio::test]
async fn the_launch_deadline_sweep_stops_and_retires_a_never_enrolled_task() {
    let east = region("us-east");
    // A short launch deadline: the token expires quickly.
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(10),
    );
    h.fake.set_launch_state(TaskState::Starting);
    // Warm briefly, so a launch happens but the region is cold by the sweep.
    h.warm.warm_at(east.clone(), Duration::from_secs(5), 1_000);
    h.provision.tick(1_000).await;
    assert_eq!(h.fake.launches().len(), 1);
    let minted_id = h.fake.launches()[0].relay_id;

    // Past the token deadline (1_000 + 10) and the warm deadline: the launch is
    // swept — its task stopped, its id retired, its pending entry dropped.
    h.provision.tick(2_000).await;
    assert_eq!(
        h.fake.stops(),
        vec!["task-0".to_owned()],
        "the never-enrolled task is stopped",
    );
    assert_eq!(
        h.ledger.count_launching(Some(&east), 2_000).unwrap(),
        0,
        "the expired launch no longer counts as launching",
    );
    assert_eq!(
        h.ledger.expired_launching(2_000).unwrap().len(),
        0,
        "the expired launch was retired, so it is gone from the launching set",
    );
    assert!(
        h.provision.pending.is_empty(),
        "the swept launch left pending"
    );
    // A fresh mint after the retire gets a new id (the retired one is tombstoned).
    assert_ne!(
        h.ledger
            .mint_at(2_000, Some(&east), Duration::from_secs(10))
            .unwrap()
            .relay_id,
        minted_id,
    );
}

#[tokio::test]
async fn the_vanished_task_sweep_retires_a_bound_relay_whose_task_stopped() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    // A bound id, recorded task, but never enrolled in the registry and whose
    // task the provisioner reports stopped.
    let minted = h
        .ledger
        .mint_at(1_000, Some(&east), Duration::from_secs(3_600))
        .unwrap();
    h.ledger
        .authorize_enroll_at(
            1_000,
            minted.relay_id,
            [0x22; 32],
            Some(&minted.token),
            None,
        )
        .unwrap();
    h.ledger
        .record_task(minted.relay_id, "task-vanished", &[], &[])
        .unwrap();
    h.fake.set_task_state("task-vanished", TaskState::Stopped);

    h.provision.tick(2_000).await;
    assert!(
        h.ledger.bound_unretired().unwrap().is_empty(),
        "a bound relay whose task stopped and is not enrolled is retired",
    );
}

#[tokio::test]
async fn the_vanished_task_sweep_leaves_an_enrolled_relay_alone() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    let (id, _gen) = h.seed_live_relay(&east, 1_000);
    // Its task reports stopped, but it is still enrolled — a false alarm.
    h.fake
        .set_task_state(&format!("task-live-{}", id.0), TaskState::Stopped);

    h.provision.tick(1_001).await;
    assert_eq!(
        h.ledger.bound_unretired().unwrap().len(),
        1,
        "an enrolled relay is never vanished-swept, whatever its task reports",
    );
}

#[tokio::test]
async fn the_orphan_sweep_stops_an_unreferenced_task_and_spares_a_referenced_one() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );

    // A referenced task: a live relay's recorded task.
    let (id, _gen) = h.seed_live_relay(&east, 1_000);
    let referenced = format!("task-live-{}", id.0);
    h.fake.set_task_state(&referenced, running());

    // An orphan: a running task no ledger row references.
    h.fake.set_task_state("task-orphan", running());

    h.provision.tick(1_001).await;
    assert!(
        h.fake.stops().contains(&"task-orphan".to_owned()),
        "an unreferenced task is stopped",
    );
    assert!(
        !h.fake.stops().contains(&referenced),
        "a referenced task is spared",
    );
}

#[tokio::test]
async fn a_provisioner_launch_error_does_not_kill_the_loop_and_next_tick_retries() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    // First tick: launching fails. The tick completes (does not panic), and the
    // failed launch's minted id is retired, so nothing is left launching.
    h.fake.set_fail_launch(true);
    h.provision.tick(1_000).await;
    assert!(
        h.fake.launches().is_empty(),
        "the failed launch recorded no spec"
    );
    assert_eq!(
        h.ledger.count_launching(Some(&east), 1_000).unwrap(),
        0,
        "a failed launch's minted id is retired, not left launching",
    );

    // Next tick: launching succeeds — the loop retries the still-open gap.
    h.fake.set_fail_launch(false);
    h.provision.tick(1_001).await;
    assert_eq!(
        h.fake.launches().len(),
        1,
        "the next tick retries the launch"
    );
}

#[tokio::test]
async fn provisioner_state_and_list_errors_do_not_kill_the_loop() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(600),
        Duration::from_secs(300),
    );
    h.warm
        .warm_at(east.clone(), Duration::from_secs(600), 1_000);

    // Poll and list both fail this tick; the launch still records its spec, and
    // the tick completes without panicking.
    h.fake.set_fail_state(true);
    h.fake.set_fail_list(true);
    h.provision.tick(1_000).await;
    assert_eq!(h.fake.launches().len(), 1);
    // The task could not be polled, so it stays pending for a later tick.
    assert_eq!(h.provision.pending.len(), 1);

    // With polling restored, the next tick records the task.
    h.fake.set_fail_state(false);
    h.fake.set_fail_list(false);
    let minted_id = h.fake.launches()[0].relay_id;
    h.provision.tick(1_001).await;
    assert_eq!(
        h.ledger.task_arn(minted_id).unwrap(),
        Some("task-0".to_owned()),
        "the recovered poll records the task",
    );
}

#[tokio::test]
async fn a_stop_error_during_drain_still_retires_the_id() {
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    let (id, _gen) = h.seed_live_relay(&east, 1_000);
    h.fake.set_fail_stop(true);

    h.provision.tick(1_000).await; // start idle timer
    h.provision.tick(1_010).await; // past grace: drain
    assert!(
        h.ledger.bound_unretired().unwrap().is_empty(),
        "a stop failure does not stop the id from being retired",
    );
    assert!(
        !registry::is_available(&h.reg, id),
        "the relay is still marked draining despite the stop error",
    );
}

#[tokio::test]
async fn many_enroll_and_retire_cycles_do_not_grow_the_outbox_shells() {
    // Every launched task mints a fresh relay id (one-time ledger tokens, never
    // reused — `RelayLedger::mint_at` hands out the row's autoincrement rowid).
    // A coordinator with a long uptime under steady scale-to-zero churn runs
    // this cycle continuously, so the descriptor and reap outboxes must not
    // grow a permanent shell per id ever minted.
    let east = region("us-east");
    let mut h = Harness::new(
        vec![east.clone()],
        Duration::from_secs(5),
        Duration::from_secs(300),
    );

    let cycles = 50;
    let mut now = 1_000u64;
    for _ in 0..cycles {
        let (id, _gen) = h.seed_live_relay(&east, now);
        // A relay's control connection subscribes to both outboxes on enroll
        // (mirroring the real control-connection handler), which is what
        // creates each outbox's per-relay shell.
        drop(h.setup.descriptors().subscribe(id));
        drop(h.setup.reaps().subscribe(id));

        // First tick starts the idle timer; the second, past the grace, drains
        // and permanently retires the relay's id (no warm demand, so target 0
        // makes the freshly idle relay a drain candidate).
        h.provision.tick(now).await;
        now += 10;
        h.provision.tick(now).await;
        now += 1;
    }

    assert_eq!(
        h.setup.descriptors().relay_count(),
        0,
        "the descriptor outbox must not accumulate a shell per cycle across \
         {cycles} enroll/retire cycles",
    );
    assert_eq!(
        h.setup.reaps().relay_count(),
        0,
        "the reap outbox must not accumulate a shell per cycle across \
         {cycles} enroll/retire cycles",
    );
}
