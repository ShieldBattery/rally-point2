//! The departure notices the coordinator connection carries.

use super::*;

/// Deciding a leave on the authority fires exactly one departure notice for
/// the slot, classified from the reason and stamped with the coordinator
/// descriptor's correlation ids (`set_session_refs`, what
/// `apply_descriptor` does in production); a duplicate signal for the same
/// slot decides nothing and so fires no second notice.
///
/// A session whose refs were never recorded — a standalone relay, or a
/// coordinator predating the fields — simply carries `None`, which is not
/// an error: the coordinator's own fallback applies.
#[test]
fn decide_leave_fires_one_departure_notice_on_the_authority() {
    let (registry, mut rx) = notifying_registry();
    let k = key();
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::SelfRelay);

    // A framed turn from slot 0 gives decide_leave a basis to schedule.
    registry.observe_frame(&k, SlotId(0), GameFrameCount(50));

    let leave = registry
        .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
        .expect("a leave is decided");
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.tenant, k.tenant);
    assert_eq!(notice.session, k.session);
    assert_eq!(notice.slot, SlotId(1));
    assert_eq!(notice.kind, DepartureKind::Dropped, "0x40000006 is a drop");
    assert_eq!(notice.reason, LEAVE_REASON_DROPPED);
    assert_eq!(notice.leave_seq, leave.leave_seq);
    assert!(notice.external_id.is_none(), "no refs were ever recorded");
    assert!(notice.external_ref.is_none());
    assert!(rx.try_recv().is_err(), "just the one");

    // A duplicate departure signal for the slot decides nothing (already
    // cached), so no second notice fires.
    assert_eq!(
        registry.decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED),
        None
    );
    assert!(
        rx.try_recv().is_err(),
        "no re-fire for an already-decided slot",
    );

    // With the session's refs recorded, the next slot's notice carries them.
    registry.set_session_refs(
        &k,
        Some("game-99".to_owned()),
        HashMap::from([(SlotId(2), "sb-user-7".to_owned())]),
    );
    assert!(
        registry
            .decide_leave(&k, SlotId(2), LEAVE_REASON_DROPPED)
            .is_some()
    );
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.external_id, Some("game-99".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-7".to_owned()));
}

/// A non-authority relay observing a peer authority's leave off the mesh
/// fires exactly one notice on the first insert, classified "left" for a
/// non-drop reason and carrying the session's correlation ids; a redundant
/// reconcile-on-join re-send fires nothing.
#[test]
fn observe_leave_fires_one_departure_notice_on_first_insert() {
    let (registry, mut rx) = notifying_registry();
    let k = key();
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::Peer);
    registry.set_session_refs(
        &k,
        Some("game-1".to_owned()),
        HashMap::from([(SlotId(2), "sb-user-2".to_owned())]),
    );

    let leave = leave(2, 3, 90, 7);
    assert!(
        registry.observe_leave(&k, &leave),
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
    assert_eq!(notice.external_id, Some("game-1".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-2".to_owned()));
    assert!(rx.try_recv().is_err());

    // A redundant copy is not a first insert, so it fires nothing.
    assert!(
        !registry.observe_leave(&k, &leave),
        "a redundant copy is not a first insert",
    );
    assert!(rx.try_recv().is_err(), "no re-fire for a redundant copy");
}

/// Promotion re-derivation must ALSO fire a departure notice, not just
/// `decide_leave`/`observe_leave`. This is the case a 2-relay topology hits
/// when the authority dies: the *only* other relay recorded the departure
/// (off the mesh `SlotDeparted`) but, as a peer, never decided — so no
/// directive ever entered *any* relay's cache and no notice ever fired for
/// this slot anywhere. The freshly promoted relay's re-derivation is the
/// first (and only) time this slot's directive enters a cache, so it must
/// fire the one notice itself, with the recorded reason/kind and the
/// session's correlation ids — otherwise the departure is silently lost
/// end to end, or arrives refless.
#[test]
fn promotion_re_derivation_fires_exactly_one_departure_notice() {
    let (registry, mut rx) = notifying_registry();
    let k = key();

    // Starts as a peer: it records a departure off a mesh `SlotDeparted` but
    // never decides (not the authority), so nothing is cached and nothing
    // fires yet.
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::Peer);
    registry.set_session_refs(
        &k,
        Some("game-2".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-9".to_owned())]),
    );
    registry.observe_frame(&k, SlotId(0), GameFrameCount(40));
    registry.record_departure(&k, SlotId(1), framed(50), 3);
    assert!(rx.try_recv().is_err(), "recording alone fires nothing");

    // Promoted (the dead authority was the only other relay in the
    // topology): the departure has no cached directive anywhere, so this
    // relay derives it fresh — a first insert into its cache — and must
    // fire the one notice for it.
    let leaves = registry.set_authority(&k, Authority::SelfRelay, &HashSet::new());
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
    assert_eq!(
        notice.external_id,
        Some("game-2".to_owned()),
        "a re-derived notice is no less self-describing than an authored one",
    );
    assert_eq!(notice.external_ref, Some("sb-user-9".to_owned()));
    assert!(rx.try_recv().is_err(), "just the one");
}

/// The verbatim-re-broadcast half of the same rule: a directive already in
/// the cache before promotion must NOT re-fire — the relay that cached it
/// first (via `decide_leave` or `observe_leave`) already reported it, so a
/// promotion re-announcing it verbatim would double-count the departure.
#[test]
fn promotion_does_not_refire_an_already_cached_directive() {
    let (registry, mut rx) = notifying_registry();
    let k = key();

    // Authored while the authority: decide_leave fires the one notice.
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::SelfRelay);
    registry.observe_frame(&k, SlotId(0), GameFrameCount(40));
    registry.observe_frame(&k, SlotId(1), GameFrameCount(50));
    assert!(
        registry
            .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
            .is_some()
    );
    assert!(rx.try_recv().is_ok(), "decide_leave fires the one notice");

    // Demoted, then re-promoted: the cached directive re-broadcasts
    // verbatim, not fresh — no second notice.
    let _ = registry.set_authority(&k, Authority::Peer, &HashSet::new());
    let _ = registry.set_authority(&k, Authority::SelfRelay, &HashSet::new());
    assert!(
        rx.try_recv().is_err(),
        "a verbatim re-broadcast of an already-cached leave must not re-fire",
    );
}

// -- Result notifier --
