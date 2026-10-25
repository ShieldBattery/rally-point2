//! Honoring a manual drop in a session that runs the home-side finalization
//! handshake: locally homed, homed by a peer, and with no sealable cursor.

use super::*;

/// An honored drop in a finalized-drops session whose target this relay
/// strictly homes: the finalization runs inline, the hold is claimed, and
/// the decided leave carries the sealed count with its proof.
#[tokio::test]
async fn an_honored_drop_finalizes_at_the_local_home() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
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
    // Three of the departed slot's turns were forwarded before it died.
    for seq in 0..3 {
        let _ = crate::mesh::mark_seen(&h.seen, &k, SlotId(1), seq);
    }

    honor_drop_request(&h.sessions, &h.mesh(&holds), &k, SlotId(1), 0);

    let leave = h
        .inbox
        .try_recv_leave()
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
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
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

    assert!(
        h.inbox.try_recv_leave().is_none(),
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
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0]));
    let (fwd_tx, _fwd_rx) = tokio::sync::mpsc::channel(FORWARD_CAPACITY);
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let _link = crate::mesh::register_mesh_link(
        &h.mesh_links,
        k.clone(),
        fwd_tx,
        ctl_tx,
        Arc::new(tokio::sync::Notify::new()),
    );
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
        h.inbox.try_recv_leave().is_none(),
        "nothing is decided until the home answers",
    );
    assert!(holds.is_pending(&k, SlotId(1)), "the hold stays meanwhile");
}

/// The production shape of a slot that died before its first turn: a single
/// relay homing both slots, the survivor's game loop running and its pipe
/// seeds forwarded (none framed), the departed slot's gate empty. The honored
/// drop seals a count of zero, and the survivor receives a leave it applies
/// before consuming any of the departed slot's turns.
#[tokio::test]
async fn an_honored_drop_of_a_slot_that_never_sent_a_turn_finalizes_at_zero() {
    let k = key();
    let mut h = unframed_drop_hold_harness(&k, SlotId(0), Some(&[0, 1]));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
    h.makers.note_slot_started(&k, SlotId(0));
    for seq in 0..5 {
        let _ = crate::mesh::mark_seen(&h.seen, &k, SlotId(0), seq);
    }
    // The link's end records the departure before holding it.
    h.makers.record_departure(
        &k,
        SlotId(1),
        crate::consensus::DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
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
        .expect("the zero-count leave reaches the survivor");
    assert_eq!(leave.final_turn_count, Some(0));
    assert!(leave.finalized);
    assert_eq!(leave.apply_at_frame, 0);
    assert!(!holds.is_pending(&k, SlotId(1)), "the hold was claimed");
}

/// The same drop before any game loop runs is left alone, as a lobby drop
/// is: no leave, the hold kept, and no seal against the slot rejoining.
#[tokio::test]
async fn an_honored_drop_before_any_game_loop_runs_stays_undecided() {
    let k = key();
    let mut h = unframed_drop_hold_harness(&k, SlotId(0), Some(&[0, 1]));
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
    h.makers.record_departure(
        &k,
        SlotId(1),
        crate::consensus::DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
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

    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)));
    assert_eq!(
        h.makers.finalize_drop(&k, SlotId(1), None, || {
            crate::consensus::ForwardGateReading::NeverForwarded
        }),
        crate::consensus::FinalizeOutcome::RejectedNoCursor,
        "and a repeat is refused the same way, sealing nothing",
    );
}
