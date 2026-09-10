//! Folding a peer authority's leave and a peer's `SlotDeparted` into our own record.

use super::*;

/// `observe_leave` caches a peer authority's directive and advances
/// `next_leave_seq` past it, so this relay's own later numbering never
/// collides. A conflicting duplicate keeps the first (and warns).
#[test]
fn observe_leave_caches_and_advances_the_seq() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let observed = LeaveDirective {
        finalized: false,
        slot: 2,
        reason: DROPPED,
        apply_at_frame: 88,
        leave_seq: 7,
        final_turn_count: None,
    };
    assert!(maker.observe_leave(&observed), "first insert for the slot");
    assert_eq!(maker.decided_leaves.get(&SlotId(2)), Some(&observed));
    assert_eq!(
        maker.next_leave_seq, 7,
        "seq kept at least the observed seq"
    );

    // A conflicting duplicate for the same slot keeps the first.
    let conflicting = LeaveDirective {
        apply_at_frame: 999,
        ..observed
    };
    assert!(
        !maker.observe_leave(&conflicting),
        "a conflicting duplicate is not a first insert",
    );
    assert_eq!(
        maker.decided_leaves.get(&SlotId(2)),
        Some(&observed),
        "the first cached leave wins a conflict",
    );

    // Promoted, its own first leave numbers above the observed seq.
    maker.observe_frame(SlotId(0), GameFrameCount(100));
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    let own = maker.decide_leave(SlotId(0), DROPPED).unwrap();
    assert!(
        own.leave_seq > 7,
        "own numbering continues above the observed seq"
    );
}

#[test]
fn final_leave_is_terminal_across_true_and_departure_orderings() {
    for true_before_leave in [false, true] {
        let mut maker =
            DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
        assert!(maker.activate_connection_epoch(SlotId(0), 11, Instant::now()));
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        let _ = maker.note_slot_present(SlotId(0));
        let retained_result = ResultEcho {
            payload: vec![0xAA],
            arrival_ms: 7,
            session_frame: Some(40),
            slot_frame: Some(40),
        };
        assert!(maker.record_result(SlotId(0), retained_result.clone()));

        if true_before_leave {
            assert_eq!(
                maker
                    .resolve_reconnect(SlotId(0), Some(22), false)
                    .admission,
                ReconnectAdmission::Admitted { reinstated: false }
            );
        }

        let leave = LeaveDirective {
            finalized: false,
            slot: 0,
            reason: DROPPED,
            apply_at_frame: 41,
            leave_seq: 1,
            final_turn_count: None,
        };
        assert!(maker.observe_leave(&leave));

        if !true_before_leave {
            assert_eq!(
                maker
                    .resolve_reconnect(SlotId(0), Some(22), false)
                    .admission,
                ReconnectAdmission::Rejected,
                "Leave(E1) must make a later true(E2) terminal"
            );
        }
        let stale_departure = maker.record_departure_for_epoch(
            SlotId(0),
            DepartureStamps {
                last_frame: Some(GameFrameCount(40)),
                ..Default::default()
            },
            DROPPED,
            Some(11),
        );
        assert_eq!(stale_departure, !true_before_leave);

        assert!(maker.has_departure(SlotId(0)));
        assert_eq!(
            maker.departures[&SlotId(0)].result,
            Some(retained_result),
            "a leave-first terminal notice retains the home-authored result"
        );
        assert!(!maker.slots.contains_key(&SlotId(0)));
        assert!(!maker.live_slots.contains(&SlotId(0)));
        assert!(!maker.note_slot_present(SlotId(0)));
        assert!(!maker.live_slots.contains(&SlotId(0)));
        assert!(!maker.activate_connection_epoch(SlotId(0), 33, Instant::now()));
        maker.ingest_local(&epoch_conditions(0, 33, 10_000, 0, 1));
        assert!(
            !maker.slots.contains_key(&SlotId(0)),
            "conditions cannot recreate a finally-left slot"
        );
    }
}

#[test]
fn terminal_departure_metadata_merges_without_weakening_the_epoch_fence() {
    let makers = new_decision_makers();
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
    assert!(activate_connection_epoch(&makers, &session, SlotId(0), 11,));
    assert!(activate_connection_epoch(&makers, &session, SlotId(0), 22,));
    assert!(observe_leave(
        &makers,
        &session,
        &LeaveDirective {
            finalized: false,
            slot: 0,
            reason: DROPPED,
            apply_at_frame: 41,
            leave_seq: 1,
            final_turn_count: None,
        },
    ));

    let result = ResultEcho {
        payload: vec![0xAA],
        arrival_ms: 7,
        session_frame: Some(40),
        slot_frame: Some(40),
    };
    assert_eq!(
        record_departure_for_epoch_outcome(
            &makers,
            &session,
            SlotId(0),
            DepartureStamps {
                last_frame: Some(GameFrameCount(40)),
                reachable_frame: Some(39),
                result: Some(result.clone()),
                ..Default::default()
            },
            DROPPED,
            Some(11),
        ),
        DepartureRecordOutcome::Terminal,
        "a final leave still accepts late home-authored terminal metadata",
    );

    let makers_guard = makers.lock();
    let maker = &makers_guard[&session];
    assert_eq!(
        maker.connection_states.get(&SlotId(0)),
        Some(&ConnectionState::Down(22)),
        "the stale E1 departure cannot rewrite the current E2 tombstone",
    );
    let departure = &maker.departures[&SlotId(0)];
    assert_eq!(departure.last_frame, Some(GameFrameCount(40)));
    assert_eq!(departure.reachable_frame, Some(39));
    assert_eq!(departure.result, Some(result));
}

/// Two relays independently force-deciding the same fully-abandoned slot (see
/// `force_decide_leave`) agree on `reason` and `apply_at_frame` — the decision
/// itself — but assign `leave_seq` from their own local counters, so the two
/// directives can disagree on it alone. `leave_seq` is a per-relay ordinal, not
/// part of the decision the two relays must agree on, so a mismatch there is
/// not a genuine conflict and must not be logged as one; the outcome here is
/// identical to any other duplicate: the first cached directive wins and the
/// observation is not a fresh insert. This test can't assert the log level
/// directly (no tracing-capture harness in this crate), but pins the
/// behavioral half of that distinction.
#[test]
fn observe_leave_agreeing_on_substance_but_not_leave_seq_is_not_a_conflict() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let first = LeaveDirective {
        finalized: false,
        slot: 3,
        reason: DROPPED,
        apply_at_frame: 51,
        leave_seq: 4,
        final_turn_count: None,
    };
    assert!(maker.observe_leave(&first), "first insert for the slot");

    // A second relay's independent force-decide of the identical drop: same
    // slot, reason, and apply frame, but its own local leave_seq.
    let same_decision_different_seq = LeaveDirective {
        leave_seq: 9,
        ..first
    };
    assert!(
        !maker.observe_leave(&same_decision_different_seq),
        "agreeing on substance is still not a fresh insert",
    );
    assert_eq!(
        maker.decided_leaves.get(&SlotId(3)),
        Some(&first),
        "the first cached directive wins",
    );
    assert_eq!(
        maker.next_leave_seq, 9,
        "the higher observed seq is still adopted so this relay's own numbering \
         never collides, even though the directive itself wasn't cached",
    );
}

/// `final_turn_count` is part of the decision's substance: clients schedule
/// the leave's application by it, so two directives that agree on reason and
/// frame but not count would have survivors remove the slot at different
/// simulation steps — a genuine authority conflict, not a leave_seq-style
/// labeling difference. Behaviorally the first still wins (pinned here); the
/// classification difference is the warn-vs-debug log level, which this
/// crate has no tracing-capture harness to assert. Clean-leave reason: only
/// clean leaves carry counts at all (a dropped directive's count is
/// normalized away before comparison).
#[test]
fn observe_leave_treats_a_differing_final_turn_count_as_a_substance_conflict() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let first = LeaveDirective {
        finalized: false,
        slot: 3,
        reason: LEAVE_REASON_LEFT,
        apply_at_frame: 51,
        leave_seq: 4,
        final_turn_count: Some(120),
    };
    assert!(maker.observe_leave(&first), "first insert for the slot");

    let conflicting_count = LeaveDirective {
        leave_seq: 9,
        final_turn_count: Some(121),
        ..first
    };
    assert!(
        !maker.observe_leave(&conflicting_count),
        "a count conflict is still not a fresh insert",
    );
    assert_eq!(
        maker.decided_leaves.get(&SlotId(3)),
        Some(&first),
        "the first cached directive wins a count conflict",
    );
}

/// A dropped directive arriving with a count was authored by code that
/// predates the clean-leaves-only rule. The count is stripped before the
/// directive is compared or cached — because a `LeaveDirective` can outrun
/// its matching `SlotDeparted`, this ingress is the only sanitizer that
/// ever sees it — and a peer's already-sanitized copy of the same decision
/// then reads as a plain duplicate, not a substance conflict.
#[test]
fn observe_leave_strips_a_legacy_dropped_count() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let legacy = LeaveDirective {
        finalized: false,
        slot: 3,
        reason: DROPPED,
        apply_at_frame: 51,
        leave_seq: 4,
        final_turn_count: Some(120),
    };
    assert!(maker.observe_leave(&legacy), "first insert for the slot");
    assert_eq!(
        maker.decided_leaves[&SlotId(3)].final_turn_count,
        None,
        "the legacy count never enters the cache",
    );

    let sanitized = LeaveDirective {
        final_turn_count: None,
        ..legacy
    };
    assert!(
        !maker.observe_leave(&sanitized),
        "a peer's sanitized copy is a plain duplicate",
    );
}

/// The authority's inbound `SlotDeparted` path — record the departure (which
/// max-merges the carried frame with our own observation), then decide —
/// schedules from the carried frame when our own observation lags it.
#[test]
fn slot_departed_ingest_uses_the_carried_frame_when_our_observation_lags() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Our own view of the departing slot lags (frame 30); a survivor is at 45.
    maker.observe_frame(SlotId(0), GameFrameCount(45));
    maker.observe_frame(SlotId(1), GameFrameCount(30));

    // The peer's SlotDeparted carries the home relay's fuller view (60): the
    // departure record max-merges it over our lagging 30.
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(60)),
            ..Default::default()
        },
        DROPPED,
    );
    let leave = maker.decide_leave(SlotId(1), DROPPED).unwrap();
    assert_eq!(
        leave.apply_at_frame, 61,
        "one past the carried last frame, not our lagging observation",
    );
}

/// When the carried frame is *lower* than our own observation of the slot,
/// the max-merge keeps our higher value, so the apply frame reflects it.
#[test]
fn slot_departed_ingest_keeps_a_higher_own_frame_over_a_lower_carried_one() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.observe_frame(SlotId(1), GameFrameCount(70)); // our fuller view
    maker.observe_frame(SlotId(0), GameFrameCount(80));

    // A stale SlotDeparted carries a lower frame (55): the merge keeps 70.
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(55)),
            ..Default::default()
        },
        DROPPED,
    );
    let leave = maker.decide_leave(SlotId(1), DROPPED).unwrap();
    assert_eq!(
        leave.apply_at_frame, 71,
        "one past our higher observed frame"
    );
}

/// A non-authority relay records a departure but decides nothing.
#[test]
fn slot_departed_ingest_records_without_deciding_on_a_non_authority() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );
    assert_eq!(
        maker.decide_leave(SlotId(1), DROPPED),
        None,
        "no decision as a peer"
    );
    // But the departure is recorded, so a later promotion re-derives it.
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].apply_at_frame, 51);
    assert_eq!(fresh, leaves, "re-derived on promotion — a fresh insert");
}

// -- Home-relay binding: `slot_homed` gates client admission --
