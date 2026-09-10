//! Retiring a closed session's state: its pending reap directives, dedup
//! entries, membership and limiter bucket, and per-relay descriptors.

use super::*;

#[tokio::test]
async fn closing_a_session_retires_its_pending_reap_directives() {
    // A reap armed for a session must not linger in the reap outbox after the
    // session fully closes: a relay reconnecting afterward would otherwise be
    // re-synced with a stale close for a session it no longer serves.
    let setup = bare_setup();
    let reaps = setup.reaps().clone();
    let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    // Arm and fire the holdout reap so a directive is pending for relay 1.
    lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped, None, false);
    let mut rx = reaps.subscribe(RelayId(1));
    let directive = timeout(SHORT * 4, rx.recv())
        .await
        .expect("the holdout is reaped")
        .unwrap();
    assert_eq!(directive.slots, vec![SlotId(1)]);

    // The session fully closes → its pending reap is retired. A relay
    // reconnecting after the close gets no stale directive replayed.
    close(&lc, tid(), s, RelayId(1));
    let mut reconnect = reaps.subscribe(RelayId(1));
    assert!(
        reconnect.try_recv().is_err(),
        "a closed session's reap is not replayed to a reconnecting relay",
    );
}

#[tokio::test]
async fn closing_a_session_prunes_its_dedup_entries_only() {
    // The normal all-relays-closed removal must also prune the session's dedup
    // entries (across all three sets), without touching another session's.
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let dedup = notify::new_dedup();
    lc.attach_dedup(dedup.clone());
    let s = SessionId(1);
    let other = SessionId(2);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    dedup.departures.lock().insert((tid(), s, SlotId(0)));
    dedup.results.lock().insert((tid(), s, SlotId(0)));
    dedup.desyncs.lock().insert((tid(), s, 7));
    // A different session's entry, which must survive.
    dedup.departures.lock().insert((tid(), other, SlotId(0)));

    close(&lc, tid(), s, RelayId(1));

    assert!(!dedup.departures.lock().contains(&(tid(), s, SlotId(0))));
    assert!(!dedup.results.lock().contains(&(tid(), s, SlotId(0))));
    assert!(!dedup.desyncs.lock().contains(&(tid(), s, 7)));
    assert!(
        dedup.departures.lock().contains(&(tid(), other, SlotId(0))),
        "another session's dedup entry is untouched",
    );
}

#[tokio::test]
async fn closing_a_session_retires_membership_and_limiter_bucket() {
    // A full close must retire the session's relay membership and drop its
    // rate-limit bucket, so a straggler cannot re-home (and thus resurrect) a
    // dead session and the bucket map stays bounded.
    use crate::rehome::REHOME_BURST;
    use crate::session::{self, RehomeOutcome};

    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    // Membership is recorded; exhaust the session's limiter bucket so its later
    // reset is observable.
    assert!(
        !setup.serving_relays(&tid(), s).is_empty(),
        "membership is recorded before close",
    );
    for _ in 0..REHOME_BURST {
        assert!(setup.rehome_limiter().check(&tid(), s));
    }
    assert!(
        !setup.rehome_limiter().check(&tid(), s),
        "the bucket is exhausted before close",
    );

    // The single serving relay reports closed → full close.
    close(&lc, tid(), s, RelayId(1));

    assert!(
        setup.serving_relays(&tid(), s).is_empty(),
        "close retired the session→relay membership",
    );
    // Relay 1 is still enrolled, yet the closed session's empty serving set trips
    // the guard: the honest terminal answer is Unavailable, not a resurrection.
    assert_eq!(
        session::rehome(&setup, &tid(), s, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
        "a closed session refuses re-home even while a relay is live",
    );
    assert!(
        setup.rehome_limiter().check(&tid(), s),
        "close dropped the limiter bucket, so a fresh burst is available",
    );
}

#[tokio::test]
async fn closing_a_session_removes_its_descriptor_from_each_serving_relay() {
    // A full close must drop the session's descriptor from every serving relay's
    // latest-wins outbox. Otherwise a relay reconnecting after the close is
    // re-synced the stale descriptor and re-applies the dead session (its
    // reconciler only leaves sessions absent from the pushed set).
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    // create_session staged a descriptor for the sole serving relay.
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .any(|d| d.session == s),
        "the session's descriptor is staged before the close",
    );

    close(&lc, tid(), s, RelayId(1));

    // A relay reconnecting after the close subscribes to a set that no longer
    // carries the closed session's descriptor.
    let rx = setup.descriptors().subscribe(RelayId(1));
    assert!(
        !rx.borrow().iter().any(|d| d.session == s),
        "the closed session's descriptor is gone from the serving relay's outbox",
    );
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .all(|d| d.session != s),
    );
}
