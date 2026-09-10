//! A peer member's manual drop request at the session authority and at a
//! relay that is not the authority.

use super::*;

/// A `RequestDrop` arriving over the mesh at the session authority, for a slot
/// whose drop is past the unlock floor, decides the leave: the hold is released
/// and a `LeaveDirective` for the target is broadcast to the peer links — and
/// the request itself is NOT re-broadcast (no echo).
#[tokio::test]
async fn a_mesh_request_drop_at_the_authority_decides_the_leave_and_never_echoes() {
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

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
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    // The target slot dropped: a frame basis for its leave, a recorded departure,
    // and a hold this relay marked. `test_mesh_state` uses a zero unlock floor,
    // so the hold is "past the floor" from the first instant.
    crate::consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(50));
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(0),
        crate::consensus::DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        0x4000_0006,
    );

    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    mesh_state.drop_holds.hold(key.clone(), SlotId(0));

    // A peer mesh link, to observe the decided leave broadcast and prove the
    // request was not re-broadcast.
    let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);
    let joined = joined_state(&mesh_links, &key);

    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
            slot: 0,
            requester: 3,
        })),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    assert!(
        !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
        "the honored request released the hold",
    );
    let mut saw_leave = false;
    while let Ok(frame) = echo_ctl_rx.try_recv() {
        match frame.kind {
            Some(mesh_control_frame::Kind::LeaveDirective(directive)) => {
                assert_eq!(directive.slot, 0);
                assert_eq!(
                    directive.reason, 0x4000_0006,
                    "a manual drop uses the dropped reason"
                );
                saw_leave = true;
            }
            Some(mesh_control_frame::Kind::RequestDrop(_)) => {
                panic!("the request must not be re-broadcast across the mesh")
            }
            other => panic!("unexpected mesh frame {other:?}"),
        }
    }
    assert!(saw_leave, "the authority decided and broadcast the leave");
}

/// A `RequestDrop` arriving over the mesh at a non-authority relay does nothing:
/// the hold stays, no leave is decided, and nothing is echoed back out — the
/// authority is a different relay among the broadcast's receivers.
#[tokio::test]
async fn a_mesh_request_drop_at_a_non_authority_does_nothing() {
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

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
    crate::consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(50));
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(0),
        crate::consensus::DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        0x4000_0006,
    );

    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    mesh_state.drop_holds.hold(key.clone(), SlotId(0));

    let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);
    let joined = joined_state(&mesh_links, &key);

    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
            slot: 0,
            requester: 3,
        })),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(0)),
        "a non-authority leaves the hold standing",
    );
    assert!(
        echo_ctl_rx.try_recv().is_err(),
        "a non-authority decides nothing and echoes nothing",
    );
}
