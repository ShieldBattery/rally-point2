//! Mesh control-frame dispatch: an oversize turn folded back onto the turn
//! path, a peer lobby command, and the ingress gate's fencing of retired
//! sessions and decided slots.

use super::*;

/// An oversize turn arriving over the mesh control stream folds back into
/// the normal receive path — its frame feeds the consensus coordinate and
/// the session-level gate marks it delivered (so reconnect, resume, or
/// re-home overlap is dropped) — and it is NOT re-broadcast to other mesh links:
/// the origin relay diverted a copy to every link itself, so re-flooding
/// would only echo. (Actual delivery to a local client link is covered by
/// the end-to-end mesh test; the slot inbox is private to `routing`.)
#[test]
fn an_oversize_turn_dispatch_marks_seen_observes_and_never_echoes() {
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    // A peer mesh link that must NOT hear an echo of the received turn.
    let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

    // The per-link joined state the dispatch resolves the bare session
    // id through, as the driver would hold it after a Join.
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

    let payload = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0xAB; 5000].into(),
        game_frame_count: Some(7),
        ..Default::default()
    };
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::OversizeTurn(payload)),
    };
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    // The remote slot's frame fed the consensus coordinate, exactly as a
    // datagram-delivered turn's would.
    assert_eq!(
        crate::consensus::slot_frame(&makers, &key, SlotId(0)),
        Some(GameFrameCount(7)),
    );
    // The turn was marked in the session-level gate: an overlapping copy is
    // a duplicate now.
    assert_eq!(
        mark_seen(&seen, &key, SlotId(0), 0).seen,
        Seen::Duplicate,
        "the dispatch delivered (and marked) the turn",
    );
    // No echo: neither a datagram forward nor a control frame went back out
    // to the mesh.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

/// A lobby command arriving over the mesh control stream is folded into this
/// relay's local delivery — appended to the replay log and fanned to local
/// members — and NOT re-broadcast to other mesh links: the origin relay
/// already sent a copy to every link serving the session, so re-flooding would
/// only echo. Mirrors the oversize-turn dispatch test.
#[test]
fn a_lobby_command_dispatch_delivers_locally_and_never_echoes() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();

    // A local member on this relay (slot 5) that must receive the mesh command.
    let mut member = crate::session::lobby::register_member(&lobby, &key, SlotId(5));
    // A peer mesh link that must NOT hear an echo of the received command.
    let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

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

    // A command a remote member (slot 0) authored, already slot-stamped.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::LobbyCommand(LobbyCommand {
            slot: 0,
            payload: vec![0xAB].into(),
        })),
    };
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    // The local member received the command with the origin's authoritative slot.
    let delivered = member.try_recv().expect("the local member received it");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.payload.as_ref(), &[0xAB]);
    // No echo back out to the mesh on either path.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

/// Retirement sweeps a session's state but only *queues* each link
/// driver's Leave, so a buffered mesh frame still passes the driver's
/// joined check in that window. The session gate must drop it there:
/// without the fence, a straggling `SlotDeparted` finds no maker, reads
/// as an undecided drop, and recreates a drop hold for a session that no
/// longer exists. A later descriptor naming the session (a genuine
/// re-serve, which reopens the gate in `apply_descriptor`) dispatches
/// again.
#[test]
fn a_slot_departed_after_retirement_recreates_no_drop_hold() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let serve = || {
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
    };
    serve();

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
    let departed = |slot: u32| MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            finalized: false,
            slot,
            last_frame: Some(10),
            reachable_frame: Some(10),
            reason: crate::consensus::LEAVE_REASON_DROPPED,
            result_payload: Vec::new().into(),
            result_arrival_ms: 0,
            result_session_frame: None,
            result_slot_frame: None,
            connection_epoch: Some(1),
            final_turn_count: None,
        })),
    };

    // Control: while the session is live, the same frame installs a hold.
    dispatch_mesh_control(departed(1), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(1)),
        "a live session's dropped SlotDeparted marks a hold",
    );

    // Retirement, as end_session performs it: close the gate first, then
    // the sweep — while this driver's joined map still lists the session.
    mesh_state.gates.retire(&key);
    crate::consensus::deregister_maker(&makers, &key);
    mesh_state.drop_holds.end_session_terminal(&key);

    dispatch_mesh_control(departed(2), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(
        !mesh_state.drop_holds.is_pending(&key, SlotId(2)),
        "a retired session's straggler frame resurrects nothing",
    );
    assert!(
        !mesh_state.drop_holds.is_pending(&key, SlotId(1)),
        "the swept hold stays swept",
    );

    // A genuine re-serve: apply_descriptor reopens the gate before it
    // syncs the maker; model both halves here.
    mesh_state.gates.reopen(&key);
    serve();
    dispatch_mesh_control(departed(3), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(3)),
        "a re-served session dispatches normally again",
    );
}

/// A slot whose synced leave is decided is terminal at its home ingress:
/// a turn it originates locally is dropped before it can reach local
/// survivors or enter the mesh. A mesh-delivered turn for the same slot
/// is NOT fenced — a peer home forwarded it before the decision reached
/// it, and local survivors may still need it to reach a clean leave's
/// exact count.
#[test]
fn a_decided_slots_client_turn_is_fenced_at_its_home_only() {
    let sessions = routing::Sessions::default();
    let key = control_key();
    let mesh_state = new_mesh_state();
    let makers = Arc::clone(&mesh_state.decision_makers);
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(1), 1).expect("survivor registers");
    let (mut peer_rx, _peer_ctl_rx) = register_link_channels(&mesh_state.links, &key);

    // Slot 0's leave is decided (a peer authority's directive observed).
    assert!(crate::consensus::observe_leave(
        &makers,
        &key,
        &LeaveDirective {
            finalized: false,
            slot: 0,
            reason: 0,
            apply_at_frame: 10,
            leave_seq: 1,
            final_turn_count: Some(9),
        },
    ));

    let turn = |seq: u64| Payload {
        seq,
        slot: 0,
        commands: vec![0x05].into(),
        ..Default::default()
    };
    forward_client_turn(&sessions, &mesh_state, &key, SlotId(0), turn(7));
    assert!(
        survivor.try_recv_forward().is_none(),
        "the decided slot's home-ingress turn never reaches a survivor",
    );
    assert!(
        peer_rx.try_recv().is_err(),
        "the decided slot's home-ingress turn never enters the mesh",
    );

    deliver_mesh_turn(&sessions, &mesh_state, &key, SlotId(0), turn(8), RelayId(2));
    assert!(
        survivor.try_recv_forward().is_some(),
        "a mesh-delivered turn for the decided slot still reaches survivors",
    );
}
