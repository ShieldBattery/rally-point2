//! The drop-finalization handshake: the home sealing a count, and the
//! authority deciding — or refusing — on the result it answers with.

use super::*;

const SUBJECT: SlotId = SlotId(FINALIZE_SUBJECT_SLOT);

/// The strict home answers a `FinalizeDrop`: it seals the slot, snapshots
/// its gap-free forwarded count, and broadcasts the result.
#[test]
fn the_home_answers_finalize_drop_with_the_sealed_count() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::Peer,
        &[FINALIZE_SUBJECT_SLOT],
        PeerDrop::Untouched,
    );
    fixture.mesh.session.decision_makers.record_departure(
        &fixture.key,
        SUBJECT,
        crate::consensus::DepartureStamps {
            // A framed departure: finalization refuses a pre-frame
            // (lobby) drop outright, so the record must show the slot
            // actually played.
            last_frame: Some(rally_point_proto::ids::GameFrameCount(40)),
            ..crate::consensus::DepartureStamps::default()
        },
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    // Three of the slot's turns were forwarded before it died.
    for seq in 0..3 {
        let _ = mark_seen(&fixture.mesh.seen, &fixture.key, SUBJECT, seq);
    }
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&fixture.mesh.links, &fixture.key);

    fixture.dispatch(MeshControlFrame {
        session: fixture.key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDrop(FinalizeDrop {
            slot: u32::from(FINALIZE_SUBJECT_SLOT),
            connection_epoch: None,
        })),
    });

    let frame = ctl_rx.try_recv().expect("the home broadcast its answer");
    match frame.kind {
        Some(mesh_control_frame::Kind::FinalizeDropResult(result)) => {
            assert_eq!(result.slot, u32::from(FINALIZE_SUBJECT_SLOT));
            assert_eq!(result.outcome, FINALIZE_OUTCOME_FINALIZED);
            assert_eq!(result.final_turn_count, Some(3));
        }
        other => panic!("expected a FinalizeDropResult, got {other:?}"),
    }
}

/// The authority receiving a FINALIZED result stamps the proof, claims the
/// hold, and decides the leave — which reaches local survivors carrying
/// the sealed count.
#[test]
fn the_authority_decides_on_a_finalized_result() {
    let fixture = finalize_fixture(crate::consensus::Authority::SelfRelay, &[0], PeerDrop::Held);
    fixture.mesh.session.decision_makers.observe_frame(
        &fixture.key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    fixture.mesh.session.decision_makers.observe_frame(
        &fixture.key,
        SUBJECT,
        rally_point_proto::ids::GameFrameCount(50),
    );
    let (_reg, mut survivor) = fixture.survivor();

    fixture.dispatch(finalized_result(&fixture, None, 5));

    let leave = survivor
        .try_recv_leave()
        .expect("the decided leave reaches the survivor");
    assert_eq!(leave.reason, crate::consensus::LEAVE_REASON_DROPPED);
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(leave.finalized);
    assert!(
        !fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold was claimed by the decide",
    );
}

/// A `FinalizeDropResult` naming a connection generation other than the
/// one the authority's departure record currently holds is ignored: a
/// delayed answer that survived a partition must not decide a newer
/// drop with a count sealed for an older generation. The matching
/// generation's answer then completes normally.
#[test]
fn the_authority_ignores_a_stale_generation_finalize_result() {
    // The peer-homed slot's drop was recorded for generation 7.
    let fixture = finalize_fixture(
        crate::consensus::Authority::SelfRelay,
        &[0],
        PeerDrop::Recorded(Some(7)),
    );
    fixture.mesh.session.decision_makers.observe_frame(
        &fixture.key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    let (_reg, mut survivor) = fixture.survivor();

    fixture.dispatch(finalized_result(&fixture, None, 5));
    assert!(
        survivor.try_recv_leave().is_none(),
        "a stale-generation result decides nothing",
    );
    assert!(
        fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold survives a stale-generation result",
    );

    fixture.dispatch(finalized_result(&fixture, Some(7), 5));
    let leave = survivor
        .try_recv_leave()
        .expect("the matching generation's result decides");
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(
        !fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT)
    );
}

/// A FINALIZED result whose sealed count the authority's own forwarded
/// prefix already exceeds is refused: the longer prefix is local proof
/// that turns past the count entered the mesh after the seal (the slot
/// reconnected elsewhere and played on while the answer was in flight),
/// even when the epoch check cannot see it yet. A count matching the
/// prefix completes normally.
#[test]
fn the_authority_refuses_a_finalized_count_its_own_prefix_exceeds() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::SelfRelay,
        &[0],
        PeerDrop::Recorded(None),
    );
    fixture.mesh.session.decision_makers.observe_frame(
        &fixture.key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    let (_reg, mut survivor) = fixture.survivor();
    // This relay has already forwarded eight of the slot's turns toward
    // its locals — a prefix past the stale count below.
    for seq in 0..8 {
        let _ = mark_seen(&fixture.mesh.seen, &fixture.key, SUBJECT, seq);
    }

    fixture.dispatch(finalized_result(&fixture, None, 5));
    assert!(
        survivor.try_recv_leave().is_none(),
        "a count the local prefix exceeds decides nothing",
    );
    assert!(
        fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold survives the stale count",
    );

    fixture.dispatch(finalized_result(&fixture, None, 8));
    let leave = survivor
        .try_recv_leave()
        .expect("a count matching the prefix completes");
    assert_eq!(leave.final_turn_count, Some(8));
}

/// A FINALIZED result arriving before any scheduling basis exists (no game
/// loop running, no framed turn) keeps the hold instead of releasing it into
/// a decide that silently short-circuits — the departure would otherwise be
/// stranded with no leave, no hold, and (behind the home's seal) no
/// reconnect path. Once a frame exists, a re-sent result completes normally.
#[test]
fn a_pre_frame_finalized_result_keeps_the_hold_for_a_retry() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::SelfRelay,
        &[0],
        PeerDrop::Recorded(None),
    );
    let (_reg, mut survivor) = fixture.survivor();

    fixture.dispatch(finalized_result(&fixture, None, 5));
    assert!(
        survivor.try_recv_leave().is_none(),
        "no leave commits without a framed basis",
    );
    assert!(
        fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold is kept for a later retry",
    );

    fixture.mesh.session.decision_makers.observe_frame(
        &fixture.key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    fixture.dispatch(finalized_result(&fixture, None, 5));
    let leave = survivor
        .try_recv_leave()
        .expect("the re-sent result completes once a frame exists");
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(
        !fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT)
    );
}

/// The home of a slot that departed before its first turn, once a survivor's
/// game loop runs: no framed turn exists anywhere (the survivors' pipe seeds
/// carry none), and its forward gate has the survivors' seeds but nothing
/// from the subject, so it seals a count of zero.
#[test]
fn the_home_seals_zero_for_a_slot_that_never_sent_a_turn() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::Peer,
        &[FINALIZE_SUBJECT_SLOT],
        PeerDrop::Untouched,
    );
    fixture.mesh.session.decision_makers.record_departure(
        &fixture.key,
        SUBJECT,
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    for seq in 0..5 {
        let _ = mark_seen(&fixture.mesh.seen, &fixture.key, SlotId(0), seq);
    }
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&fixture.mesh.links, &fixture.key);

    fixture.dispatch(finalize_request(&fixture));
    assert_eq!(
        home_answer(&mut ctl_rx),
        (FINALIZE_OUTCOME_REJECTED_NO_CURSOR, None),
        "before any game loop runs nothing is stalled, so nothing is sealed",
    );

    fixture
        .mesh
        .session
        .decision_makers
        .note_peer_slot_started(&fixture.key, SlotId(0));
    fixture.dispatch(finalize_request(&fixture));
    assert_eq!(
        home_answer(&mut ctl_rx),
        (FINALIZE_OUTCOME_FINALIZED, Some(0)),
    );
}

/// The authority deciding on the home's zero count with no framed turn
/// anywhere, once a game loop runs: the leave reaches the survivor carrying
/// the count, which is what unstalls it, and the hold is claimed.
#[test]
fn the_authority_decides_a_zero_count_before_any_framed_turn() {
    let fixture = finalize_fixture(crate::consensus::Authority::SelfRelay, &[0], PeerDrop::Held);
    fixture
        .mesh
        .session
        .decision_makers
        .note_slot_started(&fixture.key, SlotId(0));
    let (_reg, mut survivor) = fixture.survivor();

    fixture.dispatch(finalized_result(&fixture, None, 0));

    let leave = survivor
        .try_recv_leave()
        .expect("the zero-count leave reaches the survivor");
    assert_eq!(leave.final_turn_count, Some(0));
    assert!(leave.finalized);
    assert_eq!(leave.apply_at_frame, 0);
    assert!(
        !fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold was claimed by the decide",
    );
}

/// A slot whose turns its home forwarded just before it died, while those
/// turns are still crossing the mesh: only the home answers a `FinalizeDrop`,
/// a relay whose gate has not seen the turns yet stays silent, and the home
/// seals what it forwarded, never zero. The authority decides on that count
/// although its own gate is still empty, so its survivors wait for the turns.
#[test]
fn turns_in_flight_on_the_mesh_never_finalize_as_zero() {
    // A relay that does not home the subject, with an empty gate for it.
    let bystander = finalize_fixture(crate::consensus::Authority::Peer, &[0], PeerDrop::Untouched);
    bystander
        .mesh
        .session
        .decision_makers
        .note_peer_slot_started(&bystander.key, SlotId(0));
    bystander.mesh.session.decision_makers.record_departure(
        &bystander.key,
        SUBJECT,
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    let (_bystander_fwd, mut bystander_ctl) =
        register_link_channels(&bystander.mesh.links, &bystander.key);
    bystander.dispatch(finalize_request(&bystander));
    assert!(
        bystander_ctl.try_recv().is_err(),
        "a relay off the slot's home never answers from its own gate",
    );

    // The home forwarded three unframed turns (its pipe seeds) before the
    // link died.
    let home = finalize_fixture(
        crate::consensus::Authority::Peer,
        &[FINALIZE_SUBJECT_SLOT],
        PeerDrop::Untouched,
    );
    home.mesh
        .session
        .decision_makers
        .note_peer_slot_started(&home.key, SlotId(0));
    home.mesh.session.decision_makers.record_departure(
        &home.key,
        SUBJECT,
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    for seq in 0..3 {
        let _ = mark_seen(&home.mesh.seen, &home.key, SUBJECT, seq);
    }
    let (_home_fwd, mut home_ctl) = register_link_channels(&home.mesh.links, &home.key);
    home.dispatch(finalize_request(&home));
    assert_eq!(
        home_answer(&mut home_ctl),
        (FINALIZE_OUTCOME_FINALIZED, Some(3)),
    );

    // The authority has none of the three yet.
    let authority = finalize_fixture(crate::consensus::Authority::SelfRelay, &[0], PeerDrop::Held);
    authority
        .mesh
        .session
        .decision_makers
        .note_slot_started(&authority.key, SlotId(0));
    let (_reg, mut survivor) = authority.survivor();
    authority.dispatch(finalized_result(&authority, None, 3));
    let leave = survivor
        .try_recv_leave()
        .expect("the authority decides on the home's count");
    assert_eq!(leave.final_turn_count, Some(3));
}

/// The authority refuses the home's zero count once one of the slot's turns
/// has reached it: its own gate is then proof that the count is stale.
#[test]
fn the_authority_refuses_zero_once_a_turn_of_the_slot_reached_it() {
    let fixture = finalize_fixture(crate::consensus::Authority::SelfRelay, &[0], PeerDrop::Held);
    fixture
        .mesh
        .session
        .decision_makers
        .note_slot_started(&fixture.key, SlotId(0));
    let (_reg, mut survivor) = fixture.survivor();
    let _ = mark_seen(&fixture.mesh.seen, &fixture.key, SUBJECT, 0);

    fixture.dispatch(finalized_result(&fixture, None, 0));
    assert!(survivor.try_recv_leave().is_none());
    assert!(
        fixture
            .mesh
            .session
            .drop_holds
            .is_pending(&fixture.key, SUBJECT),
        "the hold survives the stale count",
    );
}

/// The authority's `FinalizeDrop` for the subject slot, epoch-less.
fn finalize_request(fixture: &FinalizeFixture) -> MeshControlFrame {
    MeshControlFrame {
        session: fixture.key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDrop(FinalizeDrop {
            slot: u32::from(FINALIZE_SUBJECT_SLOT),
            connection_epoch: None,
        })),
    }
}

/// The outcome and count of the `FinalizeDropResult` the home broadcast.
fn home_answer(
    ctl_rx: &mut tokio::sync::mpsc::UnboundedReceiver<MeshControlFrame>,
) -> (u32, Option<u64>) {
    match ctl_rx
        .try_recv()
        .expect("the home broadcast its answer")
        .kind
    {
        Some(mesh_control_frame::Kind::FinalizeDropResult(result)) => {
            assert_eq!(result.slot, u32::from(FINALIZE_SUBJECT_SLOT));
            (result.outcome, result.final_turn_count)
        }
        other => panic!("expected a FinalizeDropResult, got {other:?}"),
    }
}

/// The home's FINALIZED answer for the subject slot: sealed at `count`, under
/// connection generation `epoch`.
fn finalized_result(fixture: &FinalizeFixture, epoch: Option<u64>, count: u64) -> MeshControlFrame {
    MeshControlFrame {
        session: fixture.key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
            FinalizeDropResult {
                slot: u32::from(FINALIZE_SUBJECT_SLOT),
                connection_epoch: epoch,
                outcome: FINALIZE_OUTCOME_FINALIZED,
                final_turn_count: Some(count),
            },
        )),
    }
}
