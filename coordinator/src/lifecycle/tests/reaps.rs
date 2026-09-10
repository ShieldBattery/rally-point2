//! The reap timers end to end: the holdout and linger closes, the
//! never-started bound, and the webhook-only state's idle reap.

use super::*;

#[tokio::test]
async fn holdout_reap_closes_the_silent_slot_after_grace_not_before() {
    let setup = bare_setup();
    let mut reaps = setup.reaps().subscribe(RelayId(1));
    let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    // Slot 0 accounts (departs); slot 1 is the lone holdout → holdout timer arms.
    lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped, None, false);
    assert!(reaps.try_recv().is_err(), "nothing closes before the grace");
    tokio::time::sleep(SHORT / 2).await;
    assert!(reaps.try_recv().is_err(), "still nothing mid-grace");

    let close = timeout(SHORT * 4, reaps.recv())
        .await
        .expect("the holdout is reaped after the grace")
        .unwrap();
    assert_eq!(close.session, s);
    assert_eq!(close.slots, vec![SlotId(1)], "only the holdout is closed");
}

#[tokio::test]
async fn holdout_reap_disarms_when_the_holdout_reports() {
    let setup = bare_setup();
    let mut reaps = setup.reaps().subscribe(RelayId(1));
    let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped, None, false); // arms holdout for slot 1
    lc.on_departure(tid(), s, SlotId(1), DepartureKind::Dropped, None, false); // the holdout reports → disarm

    // Past the holdout grace, nothing was reaped (the linger grace is an hour).
    tokio::time::sleep(SHORT * 2).await;
    assert!(
        reaps.try_recv().is_err(),
        "a holdout that reports before the grace is not reaped",
    );
}

#[tokio::test]
async fn linger_reap_closes_non_departed_slots_including_observers() {
    let setup = bare_setup();
    let mut r1 = setup.reaps().subscribe(RelayId(1));
    let mut r2 = setup.reaps().subscribe(RelayId(2));
    let lc = Lifecycle::with_graces(setup, HOUR, SHORT, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::from([SlotId(2)]),
    );

    // Both players report a result (accounted, but not departed) → linger arms.
    lc.on_result(tid(), s, SlotId(0));
    lc.on_result(tid(), s, SlotId(1));

    let close = timeout(SHORT * 4, r1.recv())
        .await
        .expect("the stragglers are reaped after the linger grace")
        .unwrap();
    let closed: HashSet<SlotId> = close.slots.into_iter().collect();
    assert_eq!(
        closed,
        HashSet::from([SlotId(0), SlotId(1), SlotId(2)]),
        "every non-departed slot, observer included, is closed",
    );
    // The reap fans out to every serving relay.
    let close2 = timeout(SHORT * 4, r2.recv())
        .await
        .expect("the second serving relay is reaped too")
        .unwrap();
    assert_eq!(close2.session, s);
}

#[tokio::test]
async fn a_never_started_session_reaps_while_a_started_one_does_not() {
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url);
    // Only the never-started grace is shrunk; every other grace stays at
    // production scale so nothing else in this test fires early.
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        SHORT,
        EmptyReapTunables {
            grace: HOUR,
            freshness: HOUR,
        },
    );

    // Session A: registered and never touched again -- no presence, no
    // accounting -- so it must reap once its grace lapses.
    let a = SessionId(1);
    lc.register_session(
        tid(),
        a,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // Session B: a departure arrives before the grace -- proof a real
    // client was there -- so it must NOT reap.
    let b = SessionId(2);
    lc.register_session(
        tid(),
        b,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_departure(tid(), b, SlotId(0), DepartureKind::Left, None, false);

    // A's sessionClosed fires once its never-started grace lapses, and its
    // lifecycle state (drain task included) is gone -- not left immortal.
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("session A's sessionClosed fires after its never-started grace")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
    assert!(
        !lc.contains_state(&tid(), a),
        "session A's lifecycle state is reaped, not left immortal",
    );

    // Session B is unaffected: still tracked, no second sessionClosed.
    assert!(
        lc.is_alive(&tid(), b),
        "session B started, so its never-started reap never fires",
    );
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "no second sessionClosed -- session B is still running",
    );
}

#[tokio::test]
async fn the_never_started_reaper_cancels_on_late_presence() {
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url);
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        NOTICE_QUEUE_CAPACITY,
        SHORT,
        EmptyReapTunables {
            grace: HOUR,
            freshness: HOUR,
        },
    );
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // A relay heartbeat reports the slot connected -- mirroring
    // `on_presence_seen`'s real caller -- before the grace lapses.
    lc.on_presence_seen(tid(), s);

    // Wait comfortably past the (short) grace: nothing fires, the session
    // stays tracked and alive.
    tokio::time::sleep(SHORT * 3).await;
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "no sessionClosed: presence cancelled the never-started reap",
    );
    assert!(lc.is_alive(&tid(), s));
    assert!(lc.contains_state(&tid(), s));
}

#[tokio::test]
async fn a_webhook_only_state_is_reaped_and_prunes_its_dedup_after_the_idle_grace() {
    // A departure/result webhook for a session this lifetime never registered
    // (restart amnesia) lazily creates a webhook-only state — no serving relays,
    // so it never receives a `SessionClosed` and the all-relays-closed removal
    // never fires. Its own idle reap must remove it (ending its drain task) and
    // prune its dedup entries, else it leaks for the process lifetime.
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url.clone());
    // Only the webhook-only idle grace is short; the others don't apply here.
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, SHORT);
    let dedup = notify::new_dedup();
    lc.attach_dedup(dedup.clone());
    let s = SessionId(1);

    // Seed a dedup entry for this session, as the notice handler would have.
    dedup.departures.lock().insert((tid(), s, SlotId(0)));

    lc.enqueue_webhook(
        tid(),
        s,
        NotifyConfig { url },
        bytes::Bytes::from_static(br#"{"event":"departure"}"#),
        "departure",
    );
    assert!(
        lc.contains_state(&tid(), s),
        "the webhook-only state exists after the lazy insert",
    );

    // Its queued webhook still delivers before the state is reaped.
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the webhook-only queue delivers its job")
        .unwrap();
    assert_eq!(got.event, "departure");

    // After the idle grace with no further webhooks, the state is removed and
    // its dedup entry pruned.
    timeout(SHORT * 20, async {
        loop {
            if !lc.contains_state(&tid(), s) {
                break;
            }
            tokio::time::sleep(SHORT / 4).await;
        }
    })
    .await
    .expect("the webhook-only state is reaped after its idle grace");
    assert!(
        !dedup.departures.lock().contains(&(tid(), s, SlotId(0))),
        "the reaped session's dedup entry was pruned",
    );
}

#[tokio::test]
async fn a_fresh_webhook_re_arms_the_idle_reap() {
    // The idle reap measures from the last webhook, so a later webhook pushes
    // it out — a game's tail notices keep the webhook-only state alive until
    // they stop arriving, rather than a fixed window from the first one.
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url.clone());
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, SHORT * 4);
    let s = SessionId(1);

    let enqueue = |lc: &Lifecycle| {
        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url: url.clone() },
            bytes::Bytes::from_static(br#"{"event":"departure"}"#),
            "departure",
        );
    };

    enqueue(&lc);
    // Half a grace later, a second webhook re-arms the timer.
    tokio::time::sleep(SHORT * 2).await;
    enqueue(&lc);
    // Past the *original* grace but inside the re-armed one: still present.
    tokio::time::sleep(SHORT * 3).await;
    assert!(
        lc.contains_state(&tid(), s),
        "a fresh webhook re-armed the idle reap, so the state is still held",
    );

    // Drain the two delivered webhooks so the receiver doesn't wedge on drop.
    let _ = timeout(Duration::from_secs(1), rx.recv()).await;
    let _ = timeout(Duration::from_secs(1), rx.recv()).await;

    // Eventually, with no more webhooks, it is reaped.
    timeout(SHORT * 20, async {
        loop {
            if !lc.contains_state(&tid(), s) {
                break;
            }
            tokio::time::sleep(SHORT / 4).await;
        }
    })
    .await
    .expect("the state is reaped once the idle grace elapses with no new webhook");
}
