//! Mesh control frames that fan out to this relay's own local members: lobby
//! commands, chat, cosmetic skins and slot connectivity — none of which is
//! ever echoed back across the mesh — and the connection-epoch fence that
//! keeps a stale teardown off a reconnected slot.

use super::*;

/// Every frame kind a peer relay's dispatch folds into this relay's own local
/// delivery behaves the same way: the origin member's authoritative slot is
/// preserved verbatim, the frame reaches whichever local registry owns that
/// kind, and nothing goes back out to the mesh on either path — the origin
/// relay already sent a copy to every link serving the session, so re-flooding
/// would only echo.
///
/// What differs per kind is only the recipient and the extra effect: a lobby
/// command is appended to the replay log, a chat message carries scope fields
/// the relay never interprets, a skin blob is stored so a member joining later
/// replays it, and a connectivity change reaches a routing slot rather than a
/// lobby/chat member (connectivity is a client-edge concern).
#[test]
fn a_peer_relays_local_fan_out_frames_deliver_locally_and_never_echo() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_state = test_mesh_state();
    let key = control_key();

    // One local member per registry a dispatch can fan to (slot 5), plus the
    // routing slot a connectivity change reaches.
    let mut lobby_member =
        crate::session::lobby::register_member(&mesh_state.session.lobby, &key, SlotId(5));
    let mut chat_member =
        crate::session::chat::register_member(&mesh_state.session.chat, &key, SlotId(5));
    let mut skin_member =
        crate::session::skin::register_member(&mesh_state.session.skins, &key, SlotId(5));
    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("slot 5 registers");
    guard.disarm();
    // A peer mesh link that must NOT hear an echo of anything received.
    let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_state.links, &key);
    let joined = joined_state(&mesh_state.links, &key);

    let dispatch = |kind| {
        dispatch_mesh_control(
            MeshControlFrame {
                session: key.session.0,
                kind: Some(kind),
            },
            RelayId(9),
            &joined,
            &sessions,
            &mesh_state,
        );
    };

    // A lobby command a remote member (slot 0) authored, already slot-stamped.
    dispatch(mesh_control_frame::Kind::LobbyCommand(LobbyCommand {
        slot: 0,
        payload: vec![0xAB].into(),
    }));
    let delivered = lobby_member
        .try_recv()
        .expect("the local member received the lobby command");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.payload.as_ref(), &[0xAB]);

    // A chat message, whose scope fields must arrive intact.
    dispatch(mesh_control_frame::Kind::GameChat(GameChat {
        slot: 0,
        target_kind: 2,
        target_slot: 0,
        text: "hi from relay A".to_owned(),
    }));
    let delivered = chat_member
        .try_recv()
        .expect("the local member received the chat message");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.target_kind, 2);
    assert_eq!(delivered.text, "hi from relay A");

    // A cosmetic skin blob, which is also stored per slot.
    dispatch(mesh_control_frame::Kind::PlayerSkin(PlayerSkin {
        slot: 0,
        payload: vec![0xDE, 0xAD].into(),
    }));
    let delivered = skin_member
        .try_recv()
        .expect("the local member received the skin blob");
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.payload.as_ref(), &[0xDE, 0xAD]);
    let mut late =
        crate::session::skin::register_member(&mesh_state.session.skins, &key, SlotId(6));
    let replayed = late
        .try_recv()
        .expect("a member joining afterwards replays the stored blob");
    assert_eq!(replayed.slot, 0);
    assert_eq!(replayed.payload.as_ref(), &[0xDE, 0xAD]);

    // A remote relay reporting that its home client (slot 0) lost its link.
    dispatch(mesh_control_frame::Kind::SlotConnectivity(
        SlotConnectivity {
            slot: 0,
            connected: false,
            connection_epoch: None,
        },
    ));
    assert_eq!(
        inbox.try_recv_connectivity(),
        Some((SlotId(0), false)),
        "the mesh connectivity change fanned to the local routing slot",
    );

    // Not one of the four went back out to the mesh.
    assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
    assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
}

#[test]
fn stale_mesh_teardown_cannot_regress_a_reconnected_slot() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_state = test_mesh_state();
    let makers = Arc::clone(&mesh_state.session.decision_makers);
    let key = control_key();
    test_maker(&makers, &key, crate::consensus::Authority::Peer);
    let _ = crate::consensus::activate_connection_epoch(&makers, &key, SlotId(0), 22);

    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
    guard.disarm();
    let joined = joined_state(&mesh_state.links, &key);

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
    assert!(!mesh_state.session.drop_holds.is_pending(&key, SlotId(0)));

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
