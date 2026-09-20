//! The reap timers end to end: the holdout and linger closes, the
//! never-started bound, and the webhook-only state's idle reap.

use super::*;

/// The task id of the armed webhook-only reap timer, if any. A re-arm aborts
/// the old timer and spawns a replacement, so a changed id is proof the
/// deadline moved — observable the moment it happens, rather than inferred from
/// where the state still is once some later instant arrives.
fn webhook_timer_id(lc: &Lifecycle, session: SessionId) -> Option<tokio::task::Id> {
    lc.inner.sessions.lock()[&(tid(), session)]
        .webhook_timer
        .as_ref()
        .map(|timer| timer.id())
}

#[tokio::test(start_paused = true)]
async fn holdout_reap_closes_the_silent_slot_after_grace_not_before() {
    // The clock is paused so the mid-grace instant is reached exactly: the
    // "not before" half is otherwise a wall-clock margin a stalled runner eats.
    let setup = bare_setup();
    let mut reaps = setup.reaps().subscribe(RelayId(1));
    let lc = Lifecycle::with_tunables(
        setup,
        LifecycleTunables {
            holdout_grace: SHORT,
            ..Default::default()
        },
    );
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
    tokio::time::advance(SHORT / 2).await;
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
    let lc = Lifecycle::with_tunables(
        setup,
        LifecycleTunables {
            holdout_grace: SHORT,
            ..Default::default()
        },
    );
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
    let lc = Lifecycle::with_tunables(
        setup,
        LifecycleTunables {
            linger_grace: SHORT,
            ..Default::default()
        },
    );
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
async fn a_never_started_session_reaps_only_when_no_client_was_ever_seen() {
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let setup = setup_with_notify(url);
    // Only the never-started grace is shrunk; every other grace stays at
    // production scale so nothing else in this test fires early.
    let lc = Lifecycle::with_tunables(
        setup,
        LifecycleTunables {
            never_started_grace: SHORT,
            ..Default::default()
        },
    );
    let register = |session: SessionId, slots: HashSet<SlotId>| {
        lc.register_session(tid(), session, vec![RelayId(1)], slots, HashSet::new());
    };

    // Session A: registered and never touched again -- no presence, no
    // accounting -- so it must reap once its grace lapses.
    let a = SessionId(1);
    register(a, HashSet::from([SlotId(0)]));

    // Session B: a departure arrives before the grace -- proof a real client
    // was there -- so it must NOT reap.
    let b = SessionId(2);
    register(b, HashSet::from([SlotId(0), SlotId(1)]));
    lc.on_departure(tid(), b, SlotId(0), DepartureKind::Left, None, false);

    // Session C: a relay heartbeat reports the slot connected -- the other way
    // a client proves it arrived, and the one that reaches no accounting at all.
    let c = SessionId(3);
    register(c, HashSet::from([SlotId(0)]));
    lc.on_presence_seen(tid(), c);

    // A's sessionClosed fires once its never-started grace lapses, and its
    // lifecycle state (drain task included) is gone -- not left immortal.
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("session A's sessionClosed fires after its never-started grace")
        .unwrap();
    assert_eq!(got.event(), "sessionClosed");
    assert!(
        !lc.contains_state(&tid(), a),
        "session A's lifecycle state is reaped, not left immortal",
    );

    // B and C share A's grace, so it has lapsed for them too by now: that they
    // are still tracked and alive is the whole disarm guarantee, and reads off
    // the map rather than out of a wait for a webhook that must never come.
    for (session, disarmed_by) in [(b, "a departure"), (c, "presence")] {
        assert!(
            lc.is_alive(&tid(), session) && lc.contains_state(&tid(), session),
            "{disarmed_by} before the grace cancels the never-started reap",
        );
    }
}

#[tokio::test]
async fn a_webhook_only_state_is_reaped_and_prunes_its_dedup_after_the_idle_grace() {
    // A departure/result webhook for a session this lifetime never registered
    // (restart amnesia) lazily creates a webhook-only state — no serving relays,
    // so it never receives a `SessionClosed` and the all-relays-closed removal
    // never fires. Its own idle reap must remove it (ending its drain task),
    // prune its dedup entries, and run the same membership retirement a normal
    // close does — harmlessly, since there was never any membership to retire.
    use crate::session::{self, RehomeOutcome};

    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let setup = setup_with_notify(url.clone());
    // Only the webhook-only idle grace is short; the others don't apply here.
    let lc = Lifecycle::with_tunables(
        setup.clone(),
        LifecycleTunables {
            webhook_grace: SHORT,
            ..Default::default()
        },
    );
    let dedup = lc.notice_dedup().clone();
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
    assert!(
        setup.serving_relays(&tid(), s).is_empty(),
        "a webhook-only session never had membership",
    );

    // Its queued webhook still delivers before the state is reaped.
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the webhook-only queue delivers its job")
        .unwrap();
    assert_eq!(got.event(), "departure");

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
    assert!(setup.serving_relays(&tid(), s).is_empty());
    assert_eq!(
        session::rehome(&setup, &tid(), s, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
        "still unavailable after the no-op membership retirement",
    );
}

#[tokio::test]
async fn a_fresh_webhook_re_arms_the_idle_reap() {
    // The idle reap measures from the last webhook, so a later webhook pushes
    // it out — a game's tail notices keep the webhook-only state alive until
    // they stop arriving, rather than a fixed window from the first one. The
    // re-arm is read off the armed timer's identity, so nothing here races a
    // deadline.
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let setup = setup_with_notify(url.clone());
    let lc = Lifecycle::with_tunables(
        setup,
        LifecycleTunables {
            webhook_grace: SHORT,
            ..Default::default()
        },
    );
    let s = SessionId(1);

    let enqueue = || {
        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url: url.clone() },
            bytes::Bytes::from_static(br#"{"event":"departure"}"#),
            "departure",
        );
    };

    enqueue();
    let first = webhook_timer_id(&lc, s).expect("the first webhook arms the idle reap");
    enqueue();
    let rearmed = webhook_timer_id(&lc, s).expect("the state is still held");
    assert_ne!(
        first, rearmed,
        "a fresh webhook replaces the armed timer rather than leaving the first deadline standing",
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
