//! The departure notices the coordinator connection carries.

use super::*;

/// Deciding a leave on the authority fires exactly one departure notice for
/// the slot, classified from the reason; a duplicate signal for the same slot
/// decides nothing and so fires no second notice.
#[test]
fn decide_leave_fires_one_departure_notice_on_the_authority() {
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

    // A framed turn from slot 0 gives decide_leave a basis to schedule.
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(50));

    let leave = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("a leave is decided");
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.tenant, k.tenant);
    assert_eq!(notice.session, k.session);
    assert_eq!(notice.slot, SlotId(1));
    assert_eq!(notice.kind, DepartureKind::Dropped, "0x40000006 is a drop");
    assert_eq!(notice.reason, DROPPED);
    assert_eq!(notice.leave_seq, leave.leave_seq);
    assert!(rx.try_recv().is_err(), "just the one");

    // A duplicate departure signal for the slot decides nothing (already
    // cached), so no second notice fires.
    assert_eq!(decide_leave(&registry, &k, SlotId(1), DROPPED), None);
    assert!(
        rx.try_recv().is_err(),
        "no re-fire for an already-decided slot",
    );
}

/// A non-authority relay observing a peer authority's leave off the mesh
/// fires exactly one notice on the first insert, classified "left" for a
/// non-drop reason; a redundant reconcile-on-join re-send fires nothing.
#[test]
fn observe_leave_fires_one_departure_notice_on_first_insert() {
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
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    let leave = LeaveDirective {
        finalized: false,
        slot: 2,
        reason: 3,
        apply_at_frame: 90,
        leave_seq: 7,
        final_turn_count: None,
    };
    assert!(
        observe_leave(&registry, &k, &leave),
        "first insert for the slot",
    );
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.slot, SlotId(2));
    assert_eq!(
        notice.kind,
        DepartureKind::Left,
        "reason 3 is a clean leave"
    );
    assert_eq!(notice.reason, 3);
    assert_eq!(notice.leave_seq, 7);
    assert!(rx.try_recv().is_err());

    // A redundant copy is not a first insert, so it fires nothing.
    assert!(
        !observe_leave(&registry, &k, &leave),
        "a redundant copy is not a first insert",
    );
    assert!(rx.try_recv().is_err(), "no re-fire for a redundant copy");
}

/// With no notifier installed (a standalone relay), the leave path still
/// works and firing is a silent no-op — nothing to send to.
#[test]
fn a_standalone_relay_decides_leaves_without_a_notifier() {
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
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(10));
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
}

/// Promotion re-derivation must ALSO fire a departure notice, not just
/// `decide_leave`/`observe_leave`. This is the case a 2-relay topology hits
/// when the authority dies: the *only* other relay recorded the departure
/// (off the mesh `SlotDeparted`) but, as a peer, never decided — so no
/// directive ever entered *any* relay's cache and no notice ever fired for
/// this slot anywhere. The freshly promoted relay's re-derivation is the
/// first (and only) time this slot's directive enters a cache, so it must
/// fire the one notice itself, with the recorded reason/kind — otherwise
/// the departure is silently lost end to end.
#[test]
fn promotion_re_derivation_fires_exactly_one_departure_notice() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    // Starts as a peer: it records a departure off a mesh `SlotDeparted` but
    // never decides (not the authority), so nothing is cached and nothing
    // fires yet.
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
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        3,
    );
    assert!(rx.try_recv().is_err(), "recording alone fires nothing");

    // Promoted (the dead authority was the only other relay in the
    // topology): the departure has no cached directive anywhere, so this
    // relay derives it fresh — a first insert into its cache — and must
    // fire the one notice for it.
    let leaves = set_authority(&registry, &k, Authority::SelfRelay, &HashSet::new());
    assert_eq!(leaves.len(), 1, "the re-derived leave still broadcasts");

    let notice = recv_departure(&mut rx);
    assert_eq!(notice.slot, SlotId(1));
    assert_eq!(
        notice.kind,
        DepartureKind::Left,
        "reason 3 is a clean leave"
    );
    assert_eq!(notice.reason, 3);
    assert_eq!(notice.leave_seq, leaves[0].leave_seq);
    assert!(rx.try_recv().is_err(), "just the one");
}

/// The verbatim-re-broadcast half of the same rule: a directive already in
/// the cache before promotion must NOT re-fire — the relay that cached it
/// first (via `decide_leave` or `observe_leave`) already reported it, so a
/// promotion re-announcing it verbatim would double-count the departure.
#[test]
fn promotion_does_not_refire_an_already_cached_directive() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    // Authored while the authority: decide_leave fires the one notice.
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
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    observe_frame(&registry, &k, SlotId(1), GameFrameCount(50));
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
    assert!(rx.try_recv().is_ok(), "decide_leave fires the one notice");

    // Demoted, then re-promoted: the cached directive re-broadcasts
    // verbatim, not fresh — no second notice.
    let _ = set_authority(&registry, &k, Authority::Peer, &HashSet::new());
    let _ = set_authority(&registry, &k, Authority::SelfRelay, &HashSet::new());
    assert!(
        rx.try_recv().is_err(),
        "a verbatim re-broadcast of an already-cached leave must not re-fire",
    );
}

// -- Departure notice correlation ids --

/// Once a coordinator descriptor's correlation ids are recorded
/// (`set_session_refs`, what `apply_descriptor` does in production), the
/// authoring relay's `decide_leave` stamps them into the notice.
#[test]
fn decide_leave_stamps_session_refs_into_the_notice() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);
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

    registry.set_session_refs(
        &k,
        Some("game-99".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-7".to_owned())]),
    );

    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

    let notice = recv_departure(&mut rx);
    assert_eq!(notice.external_id, Some("game-99".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-7".to_owned()));
}

/// `observe_leave` (the non-authority path) stamps the same way.
#[test]
fn observe_leave_stamps_session_refs_into_the_notice() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);
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

    registry.set_session_refs(
        &k,
        Some("game-1".to_owned()),
        HashMap::from([(SlotId(2), "sb-user-2".to_owned())]),
    );

    let leave = LeaveDirective {
        finalized: false,
        slot: 2,
        reason: DROPPED,
        apply_at_frame: 88,
        leave_seq: 7,
        final_turn_count: None,
    };
    assert!(observe_leave(&registry, &k, &leave), "first insert");

    let notice = recv_departure(&mut rx);
    assert_eq!(notice.external_id, Some("game-1".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-2".to_owned()));
}

/// Promotion re-derivation stamps refs too — the exact 2-relay case where
/// no relay ever cached the directive before, so this is the only notice
/// that will ever fire for it, and it must not be refless just because it
/// takes the re-derivation path rather than `decide_leave` directly.
#[test]
fn promotion_re_derivation_stamps_session_refs_into_the_notice() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

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
    registry.set_session_refs(
        &k,
        Some("game-2".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-9".to_owned())]),
    );
    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        3,
    );
    assert!(rx.try_recv().is_err(), "recording alone fires nothing");

    let _ = set_authority(&registry, &k, Authority::SelfRelay, &HashSet::new());
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.external_id, Some("game-2".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-9".to_owned()));
}

/// With no refs ever recorded for the session (a standalone relay, or a
/// coordinator that predates the fields), a notice simply carries `None` —
/// not an error, and the coordinator's own fallback then applies.
#[test]
fn a_notice_carries_no_refs_when_none_were_ever_recorded() {
    let registry = new_decision_makers();
    let k = key();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);
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

    observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
    assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

    let notice = recv_departure(&mut rx);
    assert!(notice.external_id.is_none());
    assert!(notice.external_ref.is_none());
}

// -- Result notifier --
