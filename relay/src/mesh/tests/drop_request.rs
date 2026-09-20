//! A peer member's manual drop request, at the session authority and at a
//! relay that is not the authority.

use super::*;

/// A `RequestDrop` arriving over the mesh for a slot whose drop is past the
/// unlock floor is acted on at the session authority and nowhere else: there
/// it decides the leave — releasing the hold and broadcasting a
/// `LeaveDirective` for the target — while every other relay leaves the hold
/// standing and decides nothing, the authority being a different relay among
/// the broadcast's receivers. The request itself is never re-broadcast in
/// either case.
#[tokio::test]
async fn a_mesh_request_drop_decides_the_leave_at_the_authority_only_and_never_echoes() {
    use rally_point_proto::ids::GameFrameCount;

    for (authority, decides) in [
        (crate::consensus::Authority::SelfRelay, true),
        (crate::consensus::Authority::Peer, false),
    ] {
        let sessions: routing::Sessions = Arc::default();
        let mesh_state = test_mesh_state();
        let makers = Arc::clone(&mesh_state.session.decision_makers);
        let key = control_key();
        test_maker(&makers, &key, authority);
        // The target slot dropped: a frame basis for its leave, a recorded
        // departure, and a hold this relay marked. `test_mesh_state` uses a
        // zero unlock floor, so the hold is "past the floor" from the first
        // instant.
        makers.observe_frame(&key, SlotId(0), GameFrameCount(50));
        makers.record_departure(
            &key,
            SlotId(0),
            crate::consensus::DepartureStamps {
                last_frame: Some(GameFrameCount(50)),
                ..Default::default()
            },
            0x4000_0006,
        );
        mesh_state.session.drop_holds.hold(key.clone(), SlotId(0));

        // A peer mesh link, to observe the decided leave broadcast and prove
        // the request was not re-broadcast.
        let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_state.links, &key);
        let joined = joined_state(&mesh_state.links, &key);

        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
                slot: 0,
                requester: 3,
            })),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        assert_eq!(
            mesh_state.session.drop_holds.is_pending(&key, SlotId(0)),
            !decides,
            "the honored request releases the hold; a non-authority leaves it standing",
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
        assert_eq!(
            saw_leave, decides,
            "only the authority decides and broadcasts the leave",
        );
    }
}
