//! The drop-finalization handshake: the home sealing a count, the authority
//! deciding (or refusing) on the result, and the departure frame that carries
//! the proof.

use super::*;

/// The strict home answers a `FinalizeDrop`: it seals the slot, snapshots
/// its gap-free forwarded count, and broadcasts the result.
#[test]
fn the_home_answers_finalize_drop_with_the_sealed_count() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(1),
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
        let _ = mark_seen(&seen, &key, SlotId(1), seq);
    }
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&mesh_links, &key);

    let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::FinalizeDrop(FinalizeDrop {
                slot: 1,
                connection_epoch: None,
            })),
        },
        RelayId(9),
        &joined,
        &sessions,
        &mesh_state,
    );

    let frame = ctl_rx.try_recv().expect("the home broadcast its answer");
    match frame.kind {
        Some(mesh_control_frame::Kind::FinalizeDropResult(result)) => {
            assert_eq!(result.slot, 1);
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
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    crate::consensus::observe_frame(
        &makers,
        &key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    crate::consensus::observe_frame(
        &makers,
        &key,
        SlotId(1),
        rally_point_proto::ids::GameFrameCount(50),
    );
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(0), 1).expect("survivor registers");

    let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    // The peer-homed slot dropped: an undecided hold on this relay too.
    routing::hold_or_decide_leave(
        &mesh_state.drop_holds,
        &makers,
        &sessions,
        &mesh_links,
        &key,
        SlotId(1),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    assert!(mesh_state.drop_holds.is_pending(&key, SlotId(1)));

    dispatch_mesh_control(
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
                FinalizeDropResult {
                    slot: 1,
                    connection_epoch: None,
                    outcome: FINALIZE_OUTCOME_FINALIZED,
                    final_turn_count: Some(5),
                },
            )),
        },
        RelayId(9),
        &joined,
        &sessions,
        &mesh_state,
    );

    let leave = survivor
        .try_recv_leave()
        .expect("the decided leave reaches the survivor");
    assert_eq!(leave.reason, crate::consensus::LEAVE_REASON_DROPPED);
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(leave.finalized);
    assert!(
        !mesh_state.drop_holds.is_pending(&key, SlotId(1)),
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
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    crate::consensus::observe_frame(
        &makers,
        &key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(0), 1).expect("survivor registers");
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    // The peer-homed slot's drop was recorded for generation 7.
    assert!(crate::consensus::record_departure_for_epoch(
        &makers,
        &key,
        SlotId(1),
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
        Some(7),
    ));
    routing::hold_or_decide_leave(
        &mesh_state.drop_holds,
        &makers,
        &sessions,
        &mesh_links,
        &key,
        SlotId(1),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    assert!(mesh_state.drop_holds.is_pending(&key, SlotId(1)));

    let result_for = |epoch: Option<u64>| MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
            FinalizeDropResult {
                slot: 1,
                connection_epoch: epoch,
                outcome: FINALIZE_OUTCOME_FINALIZED,
                final_turn_count: Some(5),
            },
        )),
    };
    dispatch_mesh_control(
        result_for(None),
        RelayId(9),
        &joined,
        &sessions,
        &mesh_state,
    );
    assert!(
        survivor.try_recv_leave().is_none(),
        "a stale-generation result decides nothing",
    );
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(1)),
        "the hold survives a stale-generation result",
    );

    dispatch_mesh_control(
        result_for(Some(7)),
        RelayId(9),
        &joined,
        &sessions,
        &mesh_state,
    );
    let leave = survivor
        .try_recv_leave()
        .expect("the matching generation's result decides");
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(!mesh_state.drop_holds.is_pending(&key, SlotId(1)));
}

/// A FINALIZED result whose sealed count the authority's own forwarded
/// prefix already exceeds is refused: the longer prefix is local proof
/// that turns past the count entered the mesh after the seal (the slot
/// reconnected elsewhere and played on while the answer was in flight),
/// even when the epoch check cannot see it yet. A count matching the
/// prefix completes normally.
#[test]
fn the_authority_refuses_a_finalized_count_its_own_prefix_exceeds() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    crate::consensus::observe_frame(
        &makers,
        &key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(0), 1).expect("survivor registers");
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(1),
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    routing::hold_or_decide_leave(
        &mesh_state.drop_holds,
        &makers,
        &sessions,
        &mesh_links,
        &key,
        SlotId(1),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    // This relay has already forwarded eight of the slot's turns toward
    // its locals — a prefix past the stale count below.
    for seq in 0..8 {
        let _ = mark_seen(&mesh_state.seen, &key, SlotId(1), seq);
    }

    let result_for = |count: u64| MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
            FinalizeDropResult {
                slot: 1,
                connection_epoch: None,
                outcome: FINALIZE_OUTCOME_FINALIZED,
                final_turn_count: Some(count),
            },
        )),
    };
    dispatch_mesh_control(result_for(5), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(
        survivor.try_recv_leave().is_none(),
        "a count the local prefix exceeds decides nothing",
    );
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(1)),
        "the hold survives the stale count",
    );

    dispatch_mesh_control(result_for(8), RelayId(9), &joined, &sessions, &mesh_state);
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
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        true,
    );
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(0), 1).expect("survivor registers");
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: MeshLinkRegistration {
                links: mesh_links.clone(),
                key: key.clone(),
                id: next_mesh_link_id(),
            },
        },
    );
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(1),
        crate::consensus::DepartureStamps::default(),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    routing::hold_or_decide_leave(
        &mesh_state.drop_holds,
        &makers,
        &sessions,
        &mesh_links,
        &key,
        SlotId(1),
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    let result = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
            FinalizeDropResult {
                slot: 1,
                connection_epoch: None,
                outcome: FINALIZE_OUTCOME_FINALIZED,
                final_turn_count: Some(5),
            },
        )),
    };
    dispatch_mesh_control(result.clone(), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(
        survivor.try_recv_leave().is_none(),
        "no leave commits without a framed basis",
    );
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(1)),
        "the hold is kept for a later retry",
    );

    crate::consensus::observe_frame(
        &makers,
        &key,
        SlotId(0),
        rally_point_proto::ids::GameFrameCount(40),
    );
    dispatch_mesh_control(result, RelayId(9), &joined, &sessions, &mesh_state);
    let leave = survivor
        .try_recv_leave()
        .expect("the re-sent result completes once a frame exists");
    assert_eq!(leave.final_turn_count, Some(5));
    assert!(!mesh_state.drop_holds.is_pending(&key, SlotId(1)));
}

/// A `SlotDeparted` frame carries the record's finalization proof, so a
/// reconcile re-send of a home-finalized drop is not stripped back to a
/// frame fallback by the receiving sanitizer.
#[test]
fn a_slot_departed_frame_carries_the_finalization_proof() {
    let stamps = crate::consensus::DepartureStamps {
        final_turn_count: Some(9),
        finalized: true,
        ..crate::consensus::DepartureStamps::default()
    };
    let frame = slot_departed_frame(
        SessionId(4),
        SlotId(2),
        &stamps,
        crate::consensus::LEAVE_REASON_DROPPED,
        None,
    );
    match frame.kind {
        Some(mesh_control_frame::Kind::SlotDeparted(departed)) => {
            assert!(departed.finalized);
            assert_eq!(departed.final_turn_count, Some(9));
        }
        other => panic!("expected a SlotDeparted, got {other:?}"),
    }
}
