//! Departures, the holds a drop leaves undecided, and the manual requests
//! that resolve them.

use super::*;

/// A dropped departure is never decided on its own: it marks an undecided hold
/// and no leave ever reaches survivors without an explicit request, no matter
/// how long passes. This is the no-auto-drop policy at the routing level.
#[tokio::test]
async fn a_dropped_departure_is_never_decided_on_its_own() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    // Even a zero unlock floor — "past the floor from the first instant" —
    // decides nothing without a request; only an honored `RequestDrop` does.
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    // The drop is held, and nothing has reached the survivor.
    assert!(holds.is_pending(&k, SlotId(1)), "the drop marked a hold");
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a drop is never decided on its own",
    );

    // Well past any window a timer could ever have used, still no leave — the
    // survivor stays stalled but alive, waiting on a human's decision.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
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
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );

    let leave = inbox
        .leave_push_rx
        .try_recv()
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
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    // A drop marks the hold.
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );
    assert!(holds.is_pending(&k, SlotId(1)));
    assert!(inbox.leave_push_rx.try_recv().is_err(), "still held");

    // The clean intent arrives: it releases the hold and decides at once with
    // the "left" reason.
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );
    assert!(
        !holds.is_pending(&k, SlotId(1)),
        "the clean intent released the hold"
    );
    let leave = inbox
        .leave_push_rx
        .try_recv()
        .expect("the clean leave decided immediately");
    assert_eq!(leave.reason, LEAVE_REASON_LEFT, "the left outcome wins");
}

/// A `RequestDrop` before the unlock floor is refused: the target's drop has
/// not stood long enough, so no leave is decided and the hold still stands.
#[tokio::test]
async fn a_request_before_the_unlock_is_refused() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    // A request while the hold is fresh (well before the unreachable floor) is
    // refused: no leave, and the hold is untouched.
    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a pre-unlock request decides no leave",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the refused request left the hold standing",
    );
}

/// A `RequestDrop` past the unlock floor decides the leave exactly once with the
/// DROPPED reason, and a duplicate request after the decide is a harmless no-op.
#[tokio::test]
async fn a_request_past_the_unlock_decides_once_then_dedups() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };
    let leave = inbox
        .leave_push_rx
        .try_recv()
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

    // A duplicate request after the decide does nothing — the hold is gone and
    // the decision dedups.
    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a duplicate request after the decide is a no-op",
    );
}

/// A `RequestDrop` targeting a slot that already left cleanly (decided, no hold)
/// is a no-op, and one targeting the requester itself is rejected at the edge.
#[tokio::test]
async fn a_request_for_a_decided_or_self_slot_is_a_no_op() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

    // Slot 1 leaves cleanly: decided immediately, no hold left behind.
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_LEFT,
    );
    let _ = inbox
        .leave_push_rx
        .try_recv()
        .expect("the clean leave decided");

    // A drop request for that already-decided slot finds no hold: no-op.
    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a request for an already-decided slot decides nothing further",
    );

    // A request naming the requester itself is rejected at the edge before any
    // hold check or fan-out — the survivor (slot 0) here is not disconnected.
    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        handle_drop_request(&sessions, &test_state, &k, SlotId(0), 0);
    };
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a self-targeting request is rejected, deciding nothing",
    );
}

/// The client-edge validation rejects a request for a slot this relay has no
/// reason to believe is disconnected (neither held nor departed), without a
/// decide — the cheap sanity check before spending a mesh broadcast.
#[tokio::test]
async fn a_request_for_a_connected_slot_is_rejected_at_the_edge() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

    // Slot 1 is fully connected (no departure, no hold). A request to drop it is
    // nonsense and is dropped at the edge.
    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        handle_drop_request(&sessions, &test_state, &k, SlotId(0), 1);
    };
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "a request for a connected slot decides nothing",
    );
}

/// The per-requester rate cap bounds how many requests one requester can spend a
/// mesh broadcast on, and — crucially — an over-limit burst never multi-decides:
/// the decision dedups regardless, so a double-click storm removes the slot at
/// most once.
#[tokio::test]
async fn a_burst_of_requests_decides_at_most_once() {
    let k = key();
    let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
    hold_or_decide_leave(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );

    // A burst of requests from the same survivor: the first decides, and every
    // later one — whether rate-admitted or not — finds the hold already gone.
    for _ in 0..8 {
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            handle_drop_request(&sessions, &test_state, &k, SlotId(0), 1);
        };
    }
    let leave = inbox
        .leave_push_rx
        .try_recv()
        .expect("the burst decided the leave once");
    assert_eq!(leave.slot, 1);
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "the burst decided the leave at most once",
    );
}
