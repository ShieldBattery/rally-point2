//! Mesh control frames that fan out to this relay's own local members: chat,
//! cosmetic skins, and slot connectivity — none of which is ever echoed back
//! across the mesh.

use super::*;

/// A game-chat message arriving over the mesh control stream is folded into
/// this relay's local delivery — fanned to local members, no log to append
/// to — and NOT re-broadcast to other mesh links: the origin relay already
/// sent a copy to every link serving the session, so re-flooding would only
/// echo. Mirrors the lobby-command dispatch test.
#[test]
fn a_game_chat_dispatch_delivers_locally_and_never_echoes() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();

    // A local member on this relay (slot 5) that must receive the mesh message.
    let mut member = crate::session::chat::register_member(&chat, &key, SlotId(5));
    // A peer mesh link that must NOT hear an echo of the received message.
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

    // A message a remote member (slot 0) authored, already slot-stamped.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::GameChat(GameChat {
            slot: 0,
            target_kind: 2,
            target_slot: 0,
            text: "hi from relay A".to_owned(),
        })),
    };
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    // The local member received the message with the origin's authoritative
    // slot, and its scope fields intact — the relay never interprets them.
    let delivered = member.try_recv().expect("the local member received it");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.target_kind, 2);
    assert_eq!(delivered.text, "hi from relay A");
    // No echo back out to the mesh on either path.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

/// A cosmetic-skin blob arriving over the mesh control stream is folded into
/// this relay's local delivery — fanned to local members AND stored in the
/// latest-per-slot map so a later local joiner replays it — and NOT
/// re-broadcast to other mesh links: the origin relay already sent a copy to
/// every link serving the session, so re-flooding would only echo. Mirrors the
/// game-chat dispatch test, plus the store-and-replay the map adds over chat.
#[test]
fn a_player_skin_dispatch_delivers_locally_stores_and_never_echoes() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();

    // A local member on this relay (slot 5) that must receive the mesh blob.
    let mut member = crate::session::skin::register_member(&skins, &key, SlotId(5));
    // A peer mesh link that must NOT hear an echo of the received blob.
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

    // A blob a remote member (slot 0) authored, already slot-stamped.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::PlayerSkin(PlayerSkin {
            slot: 0,
            payload: vec![0xDE, 0xAD].into(),
        })),
    };
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    // The local member received the blob with the origin's authoritative slot.
    let delivered = member.try_recv().expect("the local member received it");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.payload.as_ref(), &[0xDE, 0xAD]);
    // It was also stored, so a local member joining afterwards replays it.
    let mut late = crate::session::skin::register_member(&skins, &key, SlotId(6));
    let replayed = late.try_recv().expect("the late joiner replayed the blob");
    assert_eq!(replayed.slot, 0);
    assert_eq!(replayed.payload.as_ref(), &[0xDE, 0xAD]);
    // No echo back out to the mesh on either path.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

/// A slot-connectivity change arriving over the mesh control stream is fanned
/// to this relay's local slots and NOT re-broadcast to other mesh links: the
/// origin relay already sent a copy to every peer, so re-flooding would only
/// echo. Mirrors the lobby/chat dispatch tests, but the local recipient is a
/// routing slot (connectivity is a client-edge concern, not a lobby/chat one).
#[test]
fn a_slot_connectivity_dispatch_fans_to_local_slots_and_never_echoes() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();

    // A local routing slot (slot 5) that must receive the fanned change.
    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("slot 5 registers");
    guard.disarm();
    // A peer mesh link that must NOT hear an echo of the received change.
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

    // A remote relay reports its home client (slot 0) lost its link.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 0,
                connected: false,
                connection_epoch: None,
            },
        )),
    };
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    // The local slot heard the change, naming the disconnected subject slot.
    assert_eq!(
        inbox.try_recv_connectivity(),
        Some((SlotId(0), false)),
        "the mesh connectivity change fanned to the local slot",
    );
    // No echo back out to the mesh on either path.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

#[test]
fn stale_mesh_teardown_cannot_regress_a_reconnected_slot() {
    use rally_point_proto::control::BufferBounds;

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
        BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let _ = crate::consensus::activate_connection_epoch(&makers, &key, SlotId(0), 22);

    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
    guard.disarm();
    let mut joined = HashMap::new();
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

    let stale_down = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 0,
                connected: false,
                connection_epoch: Some(11),
            },
        )),
    };
    dispatch_mesh_control(stale_down, RelayId(9), &joined, &sessions, &mesh_state);
    assert_eq!(inbox.try_recv_connectivity(), None);

    let stale_departure = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            finalized: false,
            slot: 0,
            last_frame: Some(10),
            reachable_frame: Some(9),
            reason: 0x4000_0006,
            result_payload: Vec::new().into(),
            result_arrival_ms: 0,
            result_session_frame: None,
            result_slot_frame: None,
            connection_epoch: Some(11),
            final_turn_count: None,
        })),
    };
    dispatch_mesh_control(stale_departure, RelayId(9), &joined, &sessions, &mesh_state);
    assert!(!crate::consensus::slot_departed(&makers, &key, SlotId(0),));
    assert!(!mesh_state.drop_holds.is_pending(&key, SlotId(0)));

    let current_down = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 0,
                connected: false,
                connection_epoch: Some(22),
            },
        )),
    };
    dispatch_mesh_control(current_down, RelayId(9), &joined, &sessions, &mesh_state);
    assert_eq!(inbox.try_recv_connectivity(), Some((SlotId(0), false)));
}
