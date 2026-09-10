//! Connection epochs: reconnect admission, epoch-fenced departures, and the reinstate ordering.

use super::*;

/// A replacement connection is a fresh RTT/counter namespace but not a new
/// game participant. Its activation resets only link observations, keeps the
/// validated frame, and permanently rejects a delayed sidecar from the old
/// epoch even when that stale sidecar carries much larger counters.
#[test]
fn reconnect_epoch_resets_link_conditions_and_rejects_the_old_sidecar() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.observe_frame(SlotId(0), GameFrameCount(77));
    maker.ingest_local(&epoch_conditions(0, 11, 150_000, 0, 100));
    maker.ingest_local(&epoch_conditions(0, 11, 160_000, 10, 120));
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5));

    maker.ingest_local(&epoch_conditions(0, 22, 50_000, 0, 3));
    let replacement = &maker.slots[&SlotId(0)];
    assert_eq!(replacement.frame, Some(GameFrameCount(77)));
    assert_eq!((replacement.curr_sent, replacement.curr_lost), (3, 0));
    assert_eq!(slot_loss_rate(&maker, 0), None);
    let replacement = &maker.slots[&SlotId(0)];
    assert_eq!(replacement.rtt(), 50_000);

    maker.ingest_remote(&epoch_conditions(0, 11, 900_000, 900, 10_000), 80_000);
    let still_replacement = &maker.slots[&SlotId(0)];
    assert_eq!(
        (still_replacement.curr_sent, still_replacement.curr_lost),
        (3, 0)
    );
    assert_eq!(still_replacement.rtt(), 50_000);
    assert_eq!(still_replacement.mesh_rtt_us, 0);

    maker.ingest_local(&epoch_conditions(0, 22, 60_000, 1, 13));
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (13, 1));
    assert!((slot_loss_rate(&maker, 0).expect("replacement window") - 0.1).abs() < f64::EPSILON);
}

/// Epoch absence is rolling-upgrade compatibility only. Once a present
/// epoch has fenced the slot, a delayed sample from an older binary cannot
/// downgrade it back to the unfenced counter namespace.
#[test]
fn epoch_aware_slot_rejects_a_later_epochless_sidecar() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&epoch_conditions(0, 44, 40_000, 0, 5));
    maker.ingest_remote(&conditions(0, 800_000, 100, 1_000), 90_000);

    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (5, 0));
    assert_eq!(state.rtt(), 40_000);
    assert_eq!(state.mesh_rtt_us, 0);
}

/// Both destructive lifecycle operations use the same generation tombstone:
/// an old teardown can neither record a departure nor erase the replacement's
/// live state, while the current epoch still can.
#[test]
fn stale_epoch_cannot_depart_or_remove_a_reconnected_slot() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&epoch_conditions(0, 1, 70_000, 0, 10));
    maker.ingest_local(&epoch_conditions(0, 2, 30_000, 0, 1));

    assert!(!maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(1)
    ));
    assert!(!maker.remove_slot_for_epoch(SlotId(0), Some(1)));
    assert!(maker.slots.contains_key(&SlotId(0)));
    assert!(!maker.has_departure(SlotId(0)));

    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(2)
    ));
    assert!(maker.has_departure(SlotId(0)));
    assert!(!maker.slots.contains_key(&SlotId(0)));
}

#[test]
fn down_epoch_is_terminal_until_a_distinct_generation_is_reinstated() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&epoch_conditions(0, 11, 70_000, 0, 10));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(11)
    ));

    assert_eq!(
        maker.connection_activation(SlotId(0), Some(11)),
        ConnectionActivation::Rejected,
    );
    assert!(!maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
    maker.ingest_local(&epoch_conditions(0, 11, 900_000, 100, 1_000));
    assert!(!maker.slots.contains_key(&SlotId(0)));
    assert!(
        !maker.activate_connection_epoch(SlotId(0), 22, Instant::now()),
        "a new generation cannot bypass the pending departure",
    );

    assert!(maker.reinstate_slot(SlotId(0)));
    assert!(maker.activate_connection_epoch(SlotId(0), 22, Instant::now()));
    maker.ingest_remote(&epoch_conditions(0, 22, 30_000, 0, 1), 10_000);
    assert_eq!(maker.slots[&SlotId(0)].rtt(), 30_000);

    // Retention is a set for the whole maker lifetime, not just the one
    // immediately previous generation.
    assert!(maker.mark_connection_down(SlotId(0), Some(22)));
    assert!(maker.activate_connection_epoch(SlotId(0), 33, Instant::now()));
    for retired in [11, 22] {
        assert_eq!(
            maker.connection_activation(SlotId(0), Some(retired)),
            ConnectionActivation::Rejected,
        );
        assert!(!maker.activate_connection_epoch(SlotId(0), retired, Instant::now()));
    }
    assert_eq!(
        maker.connection_states.get(&SlotId(0)),
        Some(&ConnectionState::Up(33)),
    );
}

#[test]
fn delayed_retired_true_cannot_replace_the_live_relay_epoch() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    assert!(maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
    assert!(maker.mark_connection_down(SlotId(0), Some(11)));
    assert!(maker.activate_connection_epoch(SlotId(0), 22, Instant::now()));

    assert_eq!(
        maker.connection_activation(SlotId(0), Some(11)),
        ConnectionActivation::Rejected,
        "a delayed true(E1) is stale after E2 supersedes Down(E1)",
    );
    assert!(!maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
    assert_eq!(
        maker.connection_states.get(&SlotId(0)),
        Some(&ConnectionState::Up(22)),
        "rejecting E1 must leave E2 current",
    );

    assert_eq!(
        maker.connection_activation(SlotId(0), Some(22)),
        ConnectionActivation::Current,
    );
    assert!(maker.activate_connection_epoch(SlotId(0), 22, Instant::now()));
    maker.ingest_remote(&epoch_conditions(0, 22, 30_000, 0, 1), 10_000);
    assert_eq!(maker.slots[&SlotId(0)].rtt(), 30_000);
}

#[test]
fn decided_departure_rejects_reinstate_activation() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&epoch_conditions(0, 11, 70_000, 0, 10));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(11)
    ));
    assert!(maker.force_decide_leave(SlotId(0), DROPPED).is_some());

    assert!(!maker.reinstate_slot(SlotId(0)));
    assert!(!maker.activate_connection_epoch(SlotId(0), 22, Instant::now()));
}

#[test]
fn legacy_departure_requires_reinstate_before_legacy_true() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&conditions(0, 70_000, 0, 10));
    maker.record_departure(SlotId(0), DepartureStamps::default(), DROPPED);

    assert_eq!(
        maker.connection_activation(SlotId(0), None),
        ConnectionActivation::Replacement,
    );
    assert!(!maker.admit_connection_up(SlotId(0), None, Instant::now()));
    assert!(maker.reinstate_slot(SlotId(0)));
    assert!(maker.admit_connection_up(SlotId(0), None, Instant::now()));
    maker.ingest_remote(&conditions(0, 30_000, 0, 1), 10_000);
    assert_eq!(maker.slots[&SlotId(0)].rtt(), 30_000);
}

#[test]
fn remote_epoch_sidecar_waits_for_reliable_generation_activation() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_remote(&epoch_conditions(0, 22, 30_000, 0, 1), 10_000);
    assert!(!maker.slots.contains_key(&SlotId(0)));

    assert!(maker.activate_connection_epoch(SlotId(0), 22, Instant::now()));
    maker.ingest_remote(&epoch_conditions(0, 22, 30_000, 0, 1), 10_000);
    assert!(maker.slots.contains_key(&SlotId(0)));
}

#[test]
fn departure_reconcile_uses_the_epoch_stored_on_the_departure() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&epoch_conditions(0, 11, 70_000, 0, 10));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(11)
    ));
    // Model unrelated mutable lifecycle state changing after the record was
    // authored. Reconcile must still stamp the record's original E1.
    maker
        .connection_states
        .insert(SlotId(0), ConnectionState::Up(22));

    let (departures, _) = maker.leave_reconcile();
    assert_eq!(departures[0].3, Some(11));
}

#[test]
fn reconnect_restores_frame_history_and_immediate_redrop_keeps_apply_basis() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    assert!(maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
    feed_turns(&mut maker, 0, 0..=15);
    maker.ingest_local(&epoch_conditions(0, 11, 150_000, 3, 20));
    let history = maker.slots[&SlotId(0)].frame_history.clone();
    let last = maker.slot_frame(SlotId(0));
    assert_eq!(last, Some(GameFrameCount(115)));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps {
            last_frame: last,
            ..Default::default()
        },
        DROPPED,
        Some(11),
    ));

    let transition = maker.resolve_reconnect(SlotId(0), Some(22), true);
    assert_eq!(
        transition.admission,
        ReconnectAdmission::Admitted { reinstated: true }
    );
    let restored = &maker.slots[&SlotId(0)];
    assert_eq!(restored.frame, last);
    assert_eq!(restored.frame_history, history);
    assert_eq!(restored.rtt(), 0, "new physical link has fresh RTT state");
    assert!(!restored.seen, "new physical link has fresh counters");

    // E2 dies before producing another framed turn. Its departure and final
    // leave must still use the E1 progress basis rather than falling back to
    // an unframed/late apply point.
    let redrop_last = maker.slot_frame(SlotId(0));
    assert_eq!(redrop_last, Some(GameFrameCount(115)));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps {
            last_frame: redrop_last,
            ..Default::default()
        },
        DROPPED,
        Some(22),
    ));
    let leave = maker
        .decide_leave(SlotId(0), DROPPED)
        .expect("authority decides the immediate redrop");
    assert_eq!(leave.apply_at_frame, 116);
}

#[test]
fn dropped_departure_and_reconnect_have_two_safe_linearizations() {
    let makers = Arc::new(new_decision_makers());
    let session = key();
    makers.lock().insert(
        session.clone(),
        DecisionMaker::new(
            session.clone(),
            bounds(0, 20),
            law(),
            Authority::Peer,
            HashSet::new(),
        ),
    );
    let holds = crate::session::drop_hold::DropHolds::new(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
    );
    assert!(activate_connection_epoch(&makers, &session, SlotId(0), 11));

    // The old departure linearizes first: reconnect observes and claims the
    // complete departure+hold transition, restores state, and opens E2.
    assert!(holds.record_and_maybe_hold(&session, SlotId(0), || {
        let recorded = record_departure_for_epoch(
            &makers,
            &session,
            SlotId(0),
            DepartureStamps::default(),
            DROPPED,
            Some(11),
        );
        (recorded, recorded)
    }));
    assert_eq!(
        admit_reconnect(&makers, &holds, &session, SlotId(0), Some(22)),
        ReconnectAdmission::Admitted { reinstated: true }
    );
    assert!(!holds.is_pending(&session, SlotId(0)));
    assert!(!slot_departed(&makers, &session, SlotId(0)));

    // The reconnect linearizes first: a later E1 record is stale and cannot
    // install either a departure or an orphan hold against live E3.
    assert_eq!(
        admit_reconnect(&makers, &holds, &session, SlotId(0), Some(33)),
        ReconnectAdmission::Admitted { reinstated: false }
    );
    assert!(!holds.record_and_maybe_hold(&session, SlotId(0), || {
        let recorded = record_departure_for_epoch(
            &makers,
            &session,
            SlotId(0),
            DepartureStamps::default(),
            DROPPED,
            Some(22),
        );
        (recorded, recorded)
    }));
    assert!(!holds.is_pending(&session, SlotId(0)));
    assert!(!slot_departed(&makers, &session, SlotId(0)));
    assert!(connection_epoch_matches(
        &makers,
        &session,
        SlotId(0),
        Some(33)
    ));
}

#[test]
fn stale_departure_cannot_interleave_between_reinstate_and_activation() {
    let makers = Arc::new(new_decision_makers());
    let session = key();
    let mut maker = DecisionMaker::new(
        session.clone(),
        bounds(0, 20),
        law(),
        Authority::Peer,
        HashSet::new(),
    );
    assert!(maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
    assert!(maker.record_departure_for_epoch(
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
        Some(11)
    ));
    makers.lock().insert(session.clone(), maker);
    let holds = crate::session::drop_hold::DropHolds::new(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(1),
    );
    holds.hold(session.clone(), SlotId(0));

    let (inside_tx, inside_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let reconnect_makers = Arc::clone(&makers);
    let reconnect_holds = holds.clone();
    let reconnect_key = session.clone();
    let reconnect = std::thread::spawn(move || {
        admit_reconnect_with(
            &reconnect_makers,
            &reconnect_holds,
            &reconnect_key,
            SlotId(0),
            Some(22),
            || {
                inside_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            },
        )
    });
    inside_rx
        .recv()
        .expect("reconnect paused after restore with maker lock held");

    let stale_makers = Arc::clone(&makers);
    let stale_key = session.clone();
    let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
    let (stale_tx, stale_rx) = std::sync::mpsc::channel();
    let stale = std::thread::spawn(move || {
        attempting_tx.send(()).unwrap();
        let recorded = record_departure_for_epoch(
            &stale_makers,
            &stale_key,
            SlotId(0),
            DepartureStamps::default(),
            DROPPED,
            Some(11),
        );
        stale_tx.send(recorded).unwrap();
    });
    attempting_rx.recv().expect("stale teardown started");
    assert!(
        stale_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err(),
        "stale teardown must wait for the reconnect's maker critical section"
    );
    resume_tx.send(()).unwrap();

    assert_eq!(
        reconnect.join().unwrap(),
        ReconnectAdmission::Admitted { reinstated: true }
    );
    assert!(!stale_rx.recv().expect("stale teardown completed"));
    stale.join().unwrap();
    assert!(!slot_departed(&makers, &session, SlotId(0)));
    assert!(connection_epoch_matches(
        &makers,
        &session,
        SlotId(0),
        Some(22)
    ));
}
