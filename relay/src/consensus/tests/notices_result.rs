//! End-of-game result echoes: admission bounds, notices, and the fold into a departure.

use super::*;

/// A slot's first end-of-game result fires exactly one result notice, stamped
/// with the reporting slot, the opaque payload, and the relay's own frame
/// view (the session's slowest-slot frame and the reporting slot's own newest
/// frame). A second report from the same slot records nothing and fires no
/// second notice — the one-report-per-slot dedup.
#[test]
fn record_result_fires_one_notice_per_slot() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    // Framed turns give the notice a session/slot frame basis: the session
    // coordinate is the slowest slot's frame (40), the reporting slot's own
    // is its newest (52).
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    observe_frame(&registry, &k, SlotId(1), GameFrameCount(52));

    record_result(&registry, &k, SlotId(1), vec![0xDE, 0xAD]);
    let notice = recv_result(&mut rx);
    assert_eq!(notice.tenant, k.tenant);
    assert_eq!(notice.session, k.session);
    assert_eq!(notice.slot, SlotId(1));
    assert_eq!(notice.payload, vec![0xDE, 0xAD]);
    assert_eq!(notice.session_frame, Some(40), "the slowest slot's frame");
    assert_eq!(
        notice.slot_frame,
        Some(52),
        "the reporting slot's own frame"
    );
    assert!(notice.arrival_ms > 0, "a wall-clock arrival stamp is set");
    assert!(rx.try_recv().is_err(), "just the one");

    // A second report from the same slot records nothing (first-writer-wins)
    // and so fires no second notice.
    record_result(&registry, &k, SlotId(1), vec![0xBE, 0xEF]);
    assert!(
        rx.try_recv().is_err(),
        "no re-fire for an already-reported slot",
    );
}

/// A result notice stamps the session's correlation ids the same way a
/// departure does, so it is self-describing across a coordinator restart.
#[test]
fn record_result_stamps_session_refs_into_the_notice() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    registry.set_session_refs(
        &k,
        Some("game-3".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-5".to_owned())]),
    );

    record_result(&registry, &k, SlotId(1), vec![0x01]);
    let notice = recv_result(&mut rx);
    assert_eq!(notice.external_id, Some("game-3".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-5".to_owned()));
}

/// A result for a session this relay does not serve (no maker) records
/// nothing and fires no notice, rather than erroring.
#[test]
fn record_result_on_a_relay_without_a_maker_is_a_no_op() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    record_result(&registry, &k, SlotId(0), vec![0x01]);
    assert!(rx.try_recv().is_err(), "no maker, so no notice");
}

/// An empty payload is the wire sentinel `SlotDeparted` uses for "no result
/// reported" -- see `wire.proto` -- so a real report can never be zero
/// bytes. `record_result` rejects it: nothing is retained and no notice
/// fires, the same outcome as a duplicate report.
#[test]
fn record_result_rejects_an_empty_payload() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    record_result(&registry, &k, SlotId(0), Vec::new());
    assert!(rx.try_recv().is_err(), "an empty payload fires no notice");
    assert!(
        result_for(&registry, &k, SlotId(0)).is_none(),
        "an empty payload is never retained",
    );
}

/// A payload over [`MAX_GAME_RESULT_PAYLOAD_LEN`] is an ill-formed report.
/// `record_result` rejects it the same way as an empty one.
#[test]
fn record_result_rejects_an_oversize_payload() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    let oversize = vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN + 1];
    record_result(&registry, &k, SlotId(0), oversize);
    assert!(
        rx.try_recv().is_err(),
        "an oversize payload fires no notice"
    );
    assert!(
        result_for(&registry, &k, SlotId(0)).is_none(),
        "an oversize payload is never retained",
    );
}

/// A peer relay's `SlotDeparted` can carry a payload up to the control
/// stream's 64 KiB frame cap -- far past `MAX_GAME_RESULT_PAYLOAD_LEN` --
/// since nothing on the wire enforces the per-result cap between relays.
/// `record_departure` rejects an over-cap folded-in result the same way
/// `record_result` rejects one reported directly: it never enters the
/// decision-maker's retained state, so the slot's later departure notice
/// embeds `None` rather than the oversize payload.
#[test]
fn record_departure_rejects_an_oversize_mesh_folded_result() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));

    let folded = ResultEcho {
        payload: vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN + 1],
        arrival_ms: 123,
        session_frame: Some(40),
        slot_frame: Some(40),
    };
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(40)),
            result: Some(folded),
            ..Default::default()
        },
        DROPPED,
    );

    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
    let departure = recv_departure(&mut rx);
    assert!(
        departure.result.is_none(),
        "the oversize folded-in result is never embedded",
    );
}

/// The retained result is embedded into the slot's departure notice: after a
/// slot reports, its later departure carries the same result (payload + stamps)
/// the standalone notice did, so the departure webhook is atomic terminal
/// truth. `result_for` exposes the retained echo for the home relay to seed the
/// departure record with.
#[test]
fn a_reported_result_is_embedded_into_the_slots_departure_notice() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    observe_frame(&registry, &k, SlotId(1), GameFrameCount(52));

    // Slot 1 reports its result: the standalone result notice fires, and the
    // echo is retained.
    record_result(&registry, &k, SlotId(1), vec![0xDE, 0xAD]);
    let result_notice = recv_result(&mut rx);
    assert_eq!(result_notice.payload, vec![0xDE, 0xAD]);

    // Slot 1 departs — the home relay seeds the departure record with its
    // retained result, exactly as `announce_departure` does.
    let retained = result_for(&registry, &k, SlotId(1)).expect("the result is retained");
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(52)),
            result: Some(retained),
            ..Default::default()
        },
        DROPPED,
    );
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

    let departure = recv_departure(&mut rx);
    let embedded = departure.result.expect("the departure carries the result");
    assert_eq!(embedded.payload, vec![0xDE, 0xAD]);
    assert_eq!(embedded.session_frame, Some(40));
    assert_eq!(embedded.slot_frame, Some(52));
    assert_eq!(embedded.arrival_ms, result_notice.arrival_ms);
}

/// A departure for a slot that never reported carries no embedded result —
/// `None` is the proof there provably never was one.
#[test]
fn a_departure_without_a_reported_result_embeds_none() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

    let departure = recv_departure(&mut rx);
    assert!(
        departure.result.is_none(),
        "a slot that never reported has no embedded result",
    );
}

/// The embedded result folds first-non-`None`-wins, exactly like the
/// reachability ceiling: whichever relay first seeds a result (the home) owns
/// it, and a later `record_departure` — a re-announce, or the home's own
/// `decide_leave` passing `None` — never clobbers it.
#[test]
fn an_embedded_result_folds_first_non_none_wins() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::Peer,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));

    // A peer's `SlotDeparted` carries the home-authored result first.
    let first = ResultEcho {
        payload: vec![0x01, 0x02],
        arrival_ms: 111,
        session_frame: Some(40),
        slot_frame: Some(50),
    };
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            result: Some(first.clone()),
            ..Default::default()
        },
        DROPPED,
    );

    // A later re-announce carrying a *different* result must not overwrite it.
    let second = ResultEcho {
        payload: vec![0x09],
        arrival_ms: 222,
        session_frame: Some(41),
        slot_frame: Some(51),
    };
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            result: Some(second),
            ..Default::default()
        },
        DROPPED,
    );

    // A `None`-carrying re-record (the home's own `decide_leave`) preserves it.
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );

    let kept = registry
        .lock()
        .get(&k)
        .unwrap()
        .departures
        .get(&SlotId(1))
        .unwrap()
        .result
        .clone();
    assert_eq!(kept, Some(first), "the first-seeded result wins");
}
