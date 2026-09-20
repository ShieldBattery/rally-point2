//! Departures, the holds a drop leaves undecided, and the manual requests
//! that resolve them.

use super::*;

/// A dropped departure is never decided on its own: it marks an undecided hold
/// and no leave ever reaches survivors without an explicit request, no matter
/// how long passes. This is the no-auto-drop policy at the routing level.
#[tokio::test(start_paused = true)]
async fn a_dropped_departure_is_never_decided_on_its_own() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    // Even a zero unlock floor — "past the floor from the first instant" —
    // decides nothing without a request; only an honored `RequestDrop` does.
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    // The drop is held, and nothing has reached the survivor.
    assert!(holds.is_pending(&k, SlotId(1)), "the drop marked a hold");
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a drop is never decided on its own",
    );

    // An hour on — past every window a timer could conceivably have used —
    // still no leave: the survivor stays stalled but alive, waiting on a
    // human's decision. Paused time makes the wait free, so the claim is made
    // at a scale no real-clock sleep could reach.
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "no auto-drop ever fires",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the hold still stands, undecided",
    );
}

/// A clean leave (a client's announced intent) decides immediately — no hold —
/// so an F10 quit unstalls survivors at once.
#[tokio::test]
async fn a_clean_departure_decides_immediately() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );

    let leave = h
        .inbox
        .try_recv_leave()
        .expect("a clean leave fires without any hold");
    assert_eq!(leave.slot, 1);
    assert_eq!(leave.reason, LEAVE_REASON_LEFT);
    assert!(!holds.is_pending(&k, SlotId(1)), "no hold was marked");
}

/// A clean-leave intent arriving while a drop for the same slot is still held
/// releases the hold and decides immediately with the "left" reason — the
/// ordering where a client's clean quit races its own link-death observation.
#[tokio::test]
async fn a_clean_intent_during_a_drop_hold_releases_it_and_proceeds() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    // A drop marks the hold.
    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );
    assert!(holds.is_pending(&k, SlotId(1)));
    assert!(h.inbox.try_recv_leave().is_none(), "still held");

    // The clean intent arrives: it releases the hold and decides at once with
    // the "left" reason.
    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );
    assert!(
        !holds.is_pending(&k, SlotId(1)),
        "the clean intent released the hold"
    );
    let leave = h
        .inbox
        .try_recv_leave()
        .expect("the clean leave decided immediately");
    assert_eq!(leave.reason, LEAVE_REASON_LEFT, "the left outcome wins");
}

/// A `RequestDrop` before the unlock floor is refused: the target's drop has
/// not stood long enough, so no leave is decided and the hold still stands.
#[tokio::test]
async fn a_request_before_the_unlock_is_refused() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    // A request while the hold is fresh (well before the unreachable floor) is
    // refused: no leave, and the hold is untouched.
    honor_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(1), 0);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a pre-unlock request decides no leave",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the refused request left the hold standing",
    );
}

/// A `RequestDrop` past the unlock floor decides the leave exactly once with the
/// DROPPED reason, and further requests — however many, through whichever
/// entry point — find the hold already gone.
#[tokio::test]
async fn a_request_past_the_unlock_decides_once_then_dedups() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    honor_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(1), 0);
    let leave = h
        .inbox
        .try_recv_leave()
        .expect("the request past the unlock decides the leave");
    assert_eq!(leave.slot, 1);
    assert_eq!(
        leave.reason, LEAVE_REASON_DROPPED,
        "a manual drop uses the dropped reason",
    );
    assert!(
        !holds.is_pending(&k, SlotId(1)),
        "honoring the request released the hold",
    );

    // A duplicate honor after the decide does nothing — the hold is gone and
    // the decision dedups.
    honor_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(1), 0);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a duplicate request after the decide is a no-op",
    );

    // And so does a whole double-click storm arriving the way a client's
    // really does, through the edge-validating entry point: whether each one
    // is rate-admitted or not, every one of them finds the hold already
    // claimed, so the slot is removed at most once.
    for _ in 0..8 {
        handle_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(0), 1);
    }
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a burst decides the leave at most once",
    );
}

/// The client-edge validation refuses a `RequestDrop` this relay has no reason
/// to honor, without a decide — the cheap sanity check before spending a mesh
/// broadcast. Three ways a request can be nonsense, all of them a no-op.
#[tokio::test]
async fn a_request_for_a_decided_self_or_connected_slot_is_a_no_op() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

    // A request naming a slot that is fully connected — no departure, no hold
    // — is nonsense and is dropped at the edge.
    handle_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(0), 1);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a request for a connected slot decides nothing",
    );

    // A request naming the requester itself is rejected before any hold check
    // or fan-out — the survivor (slot 0) here is not disconnected.
    handle_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(0), 0);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a self-targeting request is rejected, deciding nothing",
    );

    // Slot 1 leaves cleanly: decided immediately, no hold left behind.
    hold_or_decide_leave(
        &holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );
    let _ = h.inbox.try_recv_leave().expect("the clean leave decided");

    // A drop request for that already-decided slot finds no hold: no-op.
    honor_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(1), 0);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "a request for an already-decided slot decides nothing further",
    );
}
