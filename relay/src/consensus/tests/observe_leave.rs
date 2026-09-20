//! Folding a peer authority's leave and a peer's `SlotDeparted` into our own record.

use super::*;

/// `observe_leave` caches a peer authority's directive and advances
/// `next_leave_seq` past it, so this relay's own later numbering never
/// collides. Any second directive for the slot -- whether it disagrees on
/// the decision's substance or only on the per-relay `leave_seq` ordinal
/// two relays force-deciding the same abandoned departure would each mint
/// on their own -- keeps the first cached copy and is not a fresh insert.
/// The seq still advances past it, so this relay's numbering cannot
/// collide with a directive it declined to cache.
#[test]
fn observe_leave_caches_and_advances_the_seq() {
    let mut maker = peer_maker();
    let observed = leave(2, LEAVE_REASON_DROPPED, 88, 7);
    assert!(maker.observe_leave(&observed), "first insert for the slot");
    assert_eq!(maker.decided_leaves.get(&SlotId(2)), Some(&observed));
    assert_eq!(
        maker.next_leave_seq, 7,
        "seq kept at least the observed seq"
    );

    // A duplicate disagreeing on the decision's substance keeps the first,
    // and its higher ordinal is still adopted.
    let conflicting = LeaveDirective {
        apply_at_frame: 999,
        leave_seq: 9,
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
    assert_eq!(
        maker.next_leave_seq, 9,
        "the higher observed seq is adopted even though the directive was \
         not cached, so this relay's own numbering cannot collide with it",
    );

    // A duplicate agreeing on every substantive field and differing only in
    // the ordinal is the same outcome: the first still wins.
    let same_decision_different_seq = LeaveDirective {
        leave_seq: 11,
        ..observed
    };
    assert!(
        !maker.observe_leave(&same_decision_different_seq),
        "agreeing on substance is still not a fresh insert",
    );
    assert_eq!(maker.decided_leaves.get(&SlotId(2)), Some(&observed));

    // Promoted, its own first leave numbers above the observed seq.
    maker.observe_frame(SlotId(0), GameFrameCount(100));
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    let own = maker.decide_leave(SlotId(0), LEAVE_REASON_DROPPED).unwrap();
    assert!(
        own.leave_seq > 11,
        "own numbering continues above every observed seq"
    );
}

#[test]
fn final_leave_is_terminal_across_true_and_departure_orderings() {
    for true_before_leave in [false, true] {
        let mut maker = peer_maker();
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
                    .resolve_reconnect_with(SlotId(0), Some(22), false, || {})
                    .admission,
                ReconnectAdmission::Admitted { reinstated: false }
            );
        }

        let leave = leave(0, LEAVE_REASON_DROPPED, 41, 1);
        assert!(maker.observe_leave(&leave));

        if !true_before_leave {
            assert_eq!(
                maker
                    .resolve_reconnect_with(SlotId(0), Some(22), false, || {})
                    .admission,
                ReconnectAdmission::Rejected,
                "Leave(E1) must make a later true(E2) terminal"
            );
        }
        let stale_departure =
            maker.record_departure_for_epoch(SlotId(0), framed(40), LEAVE_REASON_DROPPED, Some(11));
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
    makers.lock().insert(session.clone(), peer_maker());
    assert!(makers.activate_connection_epoch(&session, SlotId(0), 11));
    assert!(makers.activate_connection_epoch(&session, SlotId(0), 22));
    assert!(makers.observe_leave(&session, &leave(0, LEAVE_REASON_DROPPED, 41, 1)));

    let result = ResultEcho {
        payload: vec![0xAA],
        arrival_ms: 7,
        session_frame: Some(40),
        slot_frame: Some(40),
    };
    assert_eq!(
        makers.record_departure_for_epoch_outcome(
            &session,
            SlotId(0),
            DepartureStamps {
                last_frame: Some(GameFrameCount(40)),
                reachable_frame: Some(39),
                result: Some(result.clone()),
                ..Default::default()
            },
            LEAVE_REASON_DROPPED,
            Some(11)
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
/// A dropped directive arriving with a count was authored by code that
/// predates the clean-leaves-only rule. The count is stripped before the
/// directive is compared or cached — because a `LeaveDirective` can outrun
/// its matching `SlotDeparted`, this ingress is the only sanitizer that
/// ever sees it — and a peer's already-sanitized copy of the same decision
/// then reads as a plain duplicate, not a substance conflict.
#[test]
fn observe_leave_strips_a_legacy_dropped_count() {
    let mut maker = peer_maker();
    let legacy = LeaveDirective {
        finalized: false,
        slot: 3,
        reason: LEAVE_REASON_DROPPED,
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

/// The authority's inbound `SlotDeparted` path — record the departure
/// (which max-merges the carried frame with our own observation), then
/// decide — schedules from whichever view is fuller: a carried frame that
/// leads our own lagging observation, and our own when a stale carried
/// frame trails it.
#[test]
fn slot_departed_ingest_max_merges_the_carried_frame_with_our_own() {
    // `(own view, carried frame, apply frame)`, with a survivor kept clear
    // of the answer so only the merge can produce it.
    for (own, carried, apply_at) in [(30u32, 60u32, 61u32), (70, 55, 71)] {
        let mut maker = maker();
        maker.observe_frame(SlotId(0), GameFrameCount(85)); // a survivor
        maker.observe_frame(SlotId(1), GameFrameCount(own));
        maker.record_departure(SlotId(1), framed(carried), LEAVE_REASON_DROPPED);
        let leave = maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED).unwrap();
        assert_eq!(
            leave.apply_at_frame, apply_at,
            "one past the fuller of our {own} and the carried {carried}",
        );
    }
}

// -- Home-relay binding: `slot_homed` gates client admission --
