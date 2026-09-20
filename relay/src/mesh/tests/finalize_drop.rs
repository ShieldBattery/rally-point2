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
    crate::consensus::record_departure(
        &fixture.mesh.session.decision_makers,
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

/// A FINALIZED result arriving before any framed scheduling basis exists
/// keeps the hold instead of releasing it into a decide that silently
/// short-circuits — the departure would otherwise be stranded with no
/// leave, no hold, and (behind the home's seal) no reconnect path. Once a
/// frame exists, a re-sent result completes normally.
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
