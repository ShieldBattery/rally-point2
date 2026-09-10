//! The globally-empty reap: what counts as complete, fresh, same-epoch proof
//! that every serving relay holds an empty roster, and everything that resets
//! or supersedes that proof.

use super::*;

#[tokio::test]
async fn complete_empty_heartbeats_reap_a_started_session_and_release_membership() {
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::with_test_tunables(
        setup.clone(),
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    lc.on_relay_enrolled(RelayId(1), 7);
    lc.on_relay_heartbeat(
        RelayId(1),
        7,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(1), 7, &[], true, Instant::now());

    let census = lc.metrics_census();
    assert_eq!(census.sessions[&tid()].empty_grace, 1);
    assert!(
        !setup.serving_relays(&tid(), s).is_empty(),
        "membership remains protected during the grace",
    );
    tokio::time::sleep(SHORT / 2).await;
    assert!(lc.is_alive(&tid(), s), "nothing retires before the grace");

    timeout(SHORT * 5, async {
        while lc.contains_state(&tid(), s) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the continuously empty session is reaped");
    assert!(
        setup.serving_relays(&tid(), s).is_empty(),
        "the reap releases the scale-down membership blocker",
    );
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .all(|descriptor| descriptor.session != s),
        "the stale descriptor is retired with membership",
    );
}

#[tokio::test]
async fn an_entry_with_no_connected_slots_reaps_exactly_as_an_omission_does() {
    // A relay keeps a session on its beat after that session's last local slot
    // leaves, so it can go on restating the load state it retained. Such an
    // entry must say nothing about occupancy: the empty-session reap has to
    // read it as the relay reporting nobody, exactly as leaving the session out
    // of the roster does — otherwise a relay holding a finished session's
    // record would keep the session alive for as long as it ran.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::with_test_tunables(
        setup.clone(),
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    lc.on_relay_enrolled(RelayId(1), 7);
    lc.on_relay_heartbeat(
        RelayId(1),
        7,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );

    // The slot's link ends. The relay still names the session, now with no
    // connected slot and the facts it retained while the slot was here.
    let vacated = [heartbeat_load(s, &[], &[0], &[0], Some(1_700_000_000_000))];
    lc.on_relay_heartbeat(RelayId(1), 7, &vacated, true, Instant::now());
    lc.merge_load_state(&vacated);

    assert_eq!(
        lc.metrics_census().sessions[&tid()].empty_grace,
        1,
        "the entry is empty-roster evidence, exactly as an omission is",
    );
    let load = lc.load_state(&tid(), s).expect("created here");
    assert_eq!(
        (load.connected_slots, load.started_slots),
        (vec![SlotId(0)], vec![SlotId(0)]),
        "and its retained facts are still folded in",
    );

    timeout(SHORT * 5, async {
        while lc.contains_state(&tid(), s) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the vacated session is reaped on the same grace as an omitted one");
}

#[tokio::test]
async fn a_stale_empty_timer_cannot_consume_a_rearmed_timers_evidence() {
    let setup = bare_setup();
    let s = SessionId(89);
    stage_assignments(&setup, s, &[RelayId(1)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: HOUR,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 9);
    lc.on_relay_heartbeat(
        RelayId(1),
        9,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(1), 9, &[], true, Instant::now());
    let old_token = lc.inner.sessions.lock()[&(tid(), s)]
        .empty_timer
        .as_ref()
        .expect("first empty proof arms a timer")
        .token;

    // Occupancy cancels A, then a later empty roster establishes a fresh
    // proof and timer B.
    lc.on_relay_heartbeat(
        RelayId(1),
        9,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(1), 9, &[], true, Instant::now());
    let new_token = lc.inner.sessions.lock()[&(tid(), s)]
        .empty_timer
        .as_ref()
        .expect("the fresh empty proof arms a replacement timer")
        .token;
    assert_ne!(old_token, new_token);

    // Simulate A already having passed its sleep before its AbortHandle was
    // canceled. It may run, but cannot clear B or reap against B's evidence.
    lc.fire_empty_session(tid(), s, old_token);
    assert!(lc.contains_state(&tid(), s));
    assert_eq!(
        lc.inner.sessions.lock()[&(tid(), s)]
            .empty_timer
            .as_ref()
            .map(|timer| timer.token),
        Some(new_token),
    );

    // The matching callback still owns the slot and can retire the session.
    lc.fire_empty_session(tid(), s, new_token);
    assert!(!lc.contains_state(&tid(), s));
}

#[tokio::test]
async fn a_superseded_connection_cannot_restore_cleared_close_evidence() {
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(88);
    lc.inner
        .setup
        .set_session_membership_for_test(&tid(), s, vec![RelayId(1), RelayId(2)]);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 1);
    lc.on_relay_enrolled(RelayId(2), 2);
    lc.on_session_closed(tid(), s, RelayId(1), 1);

    // The replacement epoch reopens relay 1. A delayed terminal notice from
    // generation 1 arriving afterward must not restore the old mark.
    lc.on_relay_enrolled(RelayId(1), 3);
    lc.on_session_closed(tid(), s, RelayId(1), 1);
    lc.on_session_closed(tid(), s, RelayId(2), 2);
    assert!(lc.contains_state(&tid(), s));

    lc.on_session_closed(tid(), s, RelayId(1), 3);
    assert!(!lc.contains_state(&tid(), s));
}

#[tokio::test]
async fn an_empty_roster_that_stops_refreshing_cannot_reap_a_session() {
    let setup = bare_setup();
    let s = SessionId(90);
    stage_assignments(&setup, s, &[RelayId(1)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT * 2,
            freshness: SHORT / 2,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 10);
    lc.on_relay_heartbeat(
        RelayId(1),
        10,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(1), 10, &[], true, Instant::now());

    tokio::time::sleep(SHORT * 3).await;
    assert!(
        lc.contains_state(&tid(), s),
        "silence is unknown once the complete empty roster becomes stale",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);
}

#[tokio::test]
async fn every_assigned_relay_must_report_empty_before_the_grace_begins() {
    let setup = bare_setup();
    let s = SessionId(91);
    stage_assignments(&setup, s, &[RelayId(1), RelayId(2)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 11);
    lc.on_relay_enrolled(RelayId(2), 22);
    lc.on_relay_heartbeat(
        RelayId(1),
        11,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );

    lc.on_relay_heartbeat(RelayId(1), 11, &[], true, Instant::now());
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "one empty relay and one unknown relay cannot retire a session",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);

    lc.on_relay_heartbeat(RelayId(2), 22, &[], true, Instant::now());
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 1);
    timeout(SHORT * 5, async {
        while lc.contains_state(&tid(), s) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both complete empty rosters start and finish the grace");
}

#[tokio::test]
async fn positive_presence_reopens_a_relays_prior_close_evidence() {
    let setup = bare_setup();
    let s = SessionId(93);
    stage_assignments(&setup, s, &[RelayId(1), RelayId(2)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 41);
    lc.on_relay_enrolled(RelayId(2), 42);
    lc.on_relay_heartbeat(
        RelayId(1),
        41,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );

    close(&lc, tid(), s, RelayId(1));
    lc.on_relay_heartbeat(
        RelayId(1),
        41,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(2), 42, &[], true, Instant::now());
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a relay serving a reconnected player is no longer closed or empty",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);

    lc.on_relay_heartbeat(RelayId(1), 41, &[], true, Instant::now());
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 1);
    timeout(SHORT * 5, async {
        while lc.contains_state(&tid(), s) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a later live-to-empty transition may begin a fresh grace");
}

#[tokio::test]
async fn a_new_relay_enrollment_reopens_its_prior_close_evidence() {
    let setup = bare_setup();
    let s = SessionId(94);
    stage_assignments(&setup, s, &[RelayId(1), RelayId(2)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 51);
    lc.on_relay_enrolled(RelayId(2), 53);
    lc.on_relay_heartbeat(
        RelayId(1),
        51,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );
    close(&lc, tid(), s, RelayId(1));

    lc.on_relay_enrolled(RelayId(1), 52);
    lc.on_relay_heartbeat(RelayId(2), 53, &[], true, Instant::now());
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "the replacement process may reapply its descriptor and serve a reconnect",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);
}

#[tokio::test]
async fn partial_rosters_and_connection_changes_reset_empty_continuity() {
    let setup = bare_setup();
    let s = SessionId(92);
    stage_assignments(&setup, s, &[RelayId(1)]);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: SHORT,
            freshness: HOUR,
        },
    );
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 31);
    lc.on_relay_heartbeat(
        RelayId(1),
        31,
        &[heartbeat_session(s, &[0])],
        true,
        Instant::now(),
    );

    lc.on_relay_heartbeat(RelayId(1), 31, &[], true, Instant::now());
    lc.on_relay_heartbeat(RelayId(1), 31, &[], false, Instant::now());
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a legacy/partial roster turns omission into unknown",
    );

    lc.on_relay_heartbeat(RelayId(1), 31, &[], true, Instant::now());
    lc.on_relay_disconnected(RelayId(1), 31);
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a disconnect invalidates its heartbeat omission",
    );

    lc.on_relay_heartbeat(RelayId(1), 31, &[], true, Instant::now());
    lc.on_relay_enrolled(RelayId(1), 32);
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a reconnect invalidates the predecessor's empty proof",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);

    lc.on_relay_heartbeat(RelayId(1), 32, &[], true, Instant::now());
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 1);
    lc.prepare_rehome(&tid(), s);
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a re-home attempt cancels old-assignment empty evidence before mutation",
    );
    assert_eq!(lc.metrics_census().sessions[&tid()].empty_grace, 0);
}
