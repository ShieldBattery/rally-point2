//! Honoring a manual drop in a session that runs the home-side finalization
//! handshake: locally homed, homed by a peer, and with no sealable cursor.

use super::*;

/// An honored drop in a finalized-drops session whose target this relay
/// strictly homes: the finalization runs inline, the hold is claimed, and
/// the decided leave carries the sealed count with its proof.
#[tokio::test]
async fn an_honored_drop_finalizes_at_the_local_home() {
    let k = key();
    let (sessions, mesh_links, makers, seen, mut inbox) =
        finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0, 1]);
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
    // Three of the departed slot's turns were forwarded before it died.
    for seq in 0..3 {
        let _ = crate::mesh::mark_seen(&seen, &k, SlotId(1), seq);
    }

    {
        let mut test_state = crate::mesh::new_mesh_state();
        test_state.drop_holds = holds.clone();
        test_state.decision_makers = makers.clone();
        test_state.links = mesh_links.clone();
        test_state.seen = seen.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };

    let leave = inbox
        .leave_push_rx
        .try_recv()
        .expect("the finalized drop's leave reaches the survivor");
    assert_eq!(leave.reason, LEAVE_REASON_DROPPED);
    assert_eq!(
        leave.final_turn_count,
        Some(3),
        "the leave carries the home's sealed gap-free count",
    );
    assert!(leave.finalized, "with its proof");
    assert!(!holds.is_pending(&k, SlotId(1)), "the hold was claimed");
}

/// The same honor with no gap-free cursor fails closed: no leave, and the
/// hold stays for a retry — never a frame-scheduled fallback.
#[tokio::test]
async fn an_honored_drop_without_a_cursor_stays_undecided() {
    let k = key();
    let (sessions, mesh_links, makers, seen, mut inbox) =
        finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0, 1]);
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
        test_state.seen = seen.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };

    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "no leave is decided without a sealable cursor",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the hold stays for a retry (or a reconnect)",
    );
}

/// An honored drop whose target a peer homes asks that home over the mesh
/// instead of deciding anything locally.
#[tokio::test]
async fn an_honored_drop_with_a_remote_home_asks_over_the_mesh() {
    let k = key();
    // Non-empty homed set that does NOT contain the target: a peer's job.
    let (sessions, mesh_links, makers, seen, mut inbox) =
        finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0]);
    let (fwd_tx, _fwd_rx) = tokio::sync::mpsc::channel(FORWARD_CAPACITY);
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let _link = crate::mesh::register_mesh_link(
        &mesh_links,
        k.clone(),
        fwd_tx,
        ctl_tx,
        Arc::new(tokio::sync::Notify::new()),
    );
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
        test_state.seen = seen.clone();
        honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
    };

    let frame = ctl_rx.try_recv().expect("a FinalizeDrop went to the mesh");
    assert!(
        matches!(
            frame.kind,
            Some(rally_point_proto::messages::mesh_control_frame::Kind::FinalizeDrop(ref f))
                if f.slot == 1
        ),
        "the home is asked to finalize; got {:?}",
        frame.kind,
    );
    assert!(
        inbox.leave_push_rx.try_recv().is_err(),
        "nothing is decided until the home answers",
    );
    assert!(holds.is_pending(&k, SlotId(1)), "the hold stays meanwhile");
}
