//! Synced leaves arriving over the mesh: closing the subject, forwarding only
//! the accepted copy, releasing a local drop hold, and the orderings in which a
//! decided leave must refuse a slot's return.

use super::*;

/// A mesh-received `LeaveDirective` that this relay's own consensus state
/// accepts (a first insert for the slot) is fanned to local survivors; one
/// that conflicts with what this relay already cached (a different
/// reason or apply frame for the same slot -- an authority bug) is
/// dropped at this relay's own edge, never reaching local clients.
/// Forwarding a rejected directive would hand survivors a decision this
/// relay's own state just flagged as disagreeing with the one it already
/// holds.
#[tokio::test]
async fn a_leave_directive_dispatch_closes_subject_and_forwards_only_the_accepted_copy() {
    let sessions: routing::Sessions = Arc::default();
    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    // A maker for the session -- `observe_leave` (a Peer-relay concern:
    // only a non-authority relay observes a leave off the mesh) is a
    // no-op with no maker to cache into, so one must exist first.
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

    // A local survivor (slot 5) that must hear an accepted leave and must
    // NOT hear a rejected, conflicting one.
    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("slot 5 registers");
    guard.disarm();
    let (mut subject_guard, mut subject_inbox) =
        routing::register(&sessions, &key, SlotId(0), 1).expect("subject slot registers");
    subject_guard.disarm();
    let subject_shutdown = subject_inbox.shutdown_handle();

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

    let first = LeaveDirective {
        finalized: false,
        slot: 0,
        reason: 3,
        apply_at_frame: 90,
        leave_seq: 7,
        final_turn_count: None,
    };
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(first)),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        subject_shutdown.notified(),
    )
    .await
    .expect("the final leave closes a locally-live replacement subject");
    assert_eq!(
        subject_inbox.try_recv_leave(),
        None,
        "the subject closes; only survivors receive its leave directive"
    );
    assert_eq!(
        inbox.try_recv_leave(),
        Some(first),
        "the first, accepted copy is fanned to the local survivor",
    );

    // A second, CONFLICTING directive for the same slot -- a different
    // reason and apply frame, the authority-bug shape `observe_leave`
    // rejects. It must never reach the local survivor.
    let conflicting = LeaveDirective {
        finalized: false,
        slot: 0,
        reason: 6, // any reason differing from `first`'s -- the conflict is what matters
        apply_at_frame: 150,
        leave_seq: 8,
        final_turn_count: None,
    };
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(conflicting)),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
    assert_eq!(
        inbox.try_recv_leave(),
        None,
        "a rejected, conflicting directive must never be forwarded",
    );

    // An ordinary redundant copy of the FIRST directive is likewise not
    // re-forwarded (already delivered once) -- but this is the harmless
    // case, not the bug this test guards.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(first)),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
    assert_eq!(
        inbox.try_recv_leave(),
        None,
        "no re-forward of a redundant copy"
    );
    let events: Vec<_> = makers
        .flight_recorder()
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                crate::observability::flight_recorder::FlightEvent::LeaveMeshAccepted { .. }
            ))
            .count(),
        1,
        "only the first consensus-accepted mesh copy is recorded: {events:?}",
    );
    assert!(events.contains(
        &crate::observability::flight_recorder::FlightEvent::LeaveMeshAccepted {
            source_relay: 9,
            slot: 0,
            reason: first.reason,
            apply_frame: first.apply_at_frame,
            leave_seq: first.leave_seq,
            finalized: first.finalized,
            final_turn_count: first.final_turn_count,
        }
    ));
}

/// A `SlotConnectivity{connected: true}` arriving over the mesh is a slot coming
/// back: a client that re-registered on a peer relay while its drop was still
/// undecided. This relay marked its own hold on the earlier `SlotDeparted`, so
/// the "it's back" signal must release that hold — the symmetric mesh half of
/// the reconnect release, which is what stops a peer-homed authority from ever
/// honoring a drop for a slot that has already resumed elsewhere.
#[tokio::test]
async fn a_mesh_slot_connectivity_true_releases_a_local_drop_hold() {
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(0),
        crate::consensus::DepartureStamps::default(),
        0x4000_0006,
    );

    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);

    // This relay observed slot 0 drop and marked a hold on its leave. A hold
    // never fires on its own — the release is what clears it.
    mesh_state.drop_holds.hold(key.clone(), SlotId(0));
    assert!(
        mesh_state.drop_holds.is_pending(&key, SlotId(0)),
        "the drop marked a hold",
    );

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

    // The peer relay reports slot 0 back — it re-registered there while its drop
    // was still undecided.
    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 0,
                connected: true,
                connection_epoch: None,
            },
        )),
    };
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    assert!(
        !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
        "the it's-back signal released the held drop",
    );
}

#[tokio::test]
async fn terminal_or_decided_generation_true_never_activates_or_fans_out() {
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    assert!(crate::consensus::activate_connection_epoch(
        &makers,
        &key,
        SlotId(0),
        11,
    ));
    assert!(crate::consensus::record_departure_for_epoch(
        &makers,
        &key,
        SlotId(0),
        crate::consensus::DepartureStamps::default(),
        0x4000_0006,
        Some(11),
    ));

    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
    guard.disarm();
    let joined = joined_state(&mesh_links, &key);
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    mesh_state.drop_holds.hold(key.clone(), SlotId(0));

    let connected = |epoch| MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 0,
                connected: true,
                connection_epoch: Some(epoch),
            },
        )),
    };

    dispatch_mesh_control(connected(11), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(mesh_state.drop_holds.is_pending(&key, SlotId(0)));
    assert_eq!(inbox.try_recv_connectivity(), None);

    // A decided leave makes reinstate fail even for a distinct epoch. The
    // failed hold claim must stop both activation and local fan-out.
    let _ = makers
        .lock()
        .get_mut(&key)
        .expect("maker exists")
        .force_decide_leave(SlotId(0), 0x4000_0006);
    dispatch_mesh_control(connected(22), RelayId(9), &joined, &sessions, &mesh_state);
    assert!(!mesh_state.drop_holds.is_pending(&key, SlotId(0)));
    assert_eq!(inbox.try_recv_connectivity(), None);
    assert!(!crate::consensus::connection_epoch_matches(
        &makers,
        &key,
        SlotId(0),
        Some(22),
    ));
}

#[test]
fn final_leave_blocks_true_fanout_and_live_conditions_in_both_peer_orderings() {
    for true_before_leave in [false, true] {
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
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        assert!(crate::consensus::activate_connection_epoch(
            &makers,
            &key,
            SlotId(0),
            11,
        ));
        let (mut guard, mut inbox) =
            routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
        guard.disarm();
        let joined = joined_state(&mesh_links, &key);
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);

        let connected = |epoch| MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SlotConnectivity(
                SlotConnectivity {
                    slot: 0,
                    connected: true,
                    connection_epoch: Some(epoch),
                },
            )),
        };
        let leave = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::LeaveDirective(LeaveDirective {
                finalized: false,
                slot: 0,
                reason: crate::consensus::LEAVE_REASON_DROPPED,
                apply_at_frame: 41,
                leave_seq: 1,
                final_turn_count: None,
            })),
        };
        let departed = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
                finalized: false,
                slot: 0,
                last_frame: Some(40),
                reachable_frame: None,
                reason: crate::consensus::LEAVE_REASON_DROPPED,
                result_payload: Vec::new().into(),
                result_arrival_ms: 0,
                result_session_frame: None,
                result_slot_frame: None,
                connection_epoch: Some(11),
                final_turn_count: None,
            })),
        };

        if true_before_leave {
            dispatch_mesh_control(connected(22), RelayId(9), &joined, &sessions, &mesh_state);
            assert_eq!(
                inbox.try_recv_connectivity(),
                Some((SlotId(0), true)),
                "a replacement is live before any final leave"
            );
        }
        // Model a local E1 drop hold that the peer's final decision outran.
        // The final leave must retire it immediately in either ordering.
        mesh_state.drop_holds.hold(key.clone(), SlotId(0));
        dispatch_mesh_control(leave, RelayId(8), &joined, &sessions, &mesh_state);
        assert!(inbox.try_recv_leave().is_some());
        assert!(
            !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "a final peer leave clears an older local reconnect hold"
        );

        if !true_before_leave {
            dispatch_mesh_control(connected(22), RelayId(9), &joined, &sessions, &mesh_state);
            assert_eq!(
                inbox.try_recv_connectivity(),
                None,
                "Leave(E1) makes true(E2) terminal"
            );
        }
        dispatch_mesh_control(departed, RelayId(9), &joined, &sessions, &mesh_state);
        assert!(
            !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "a delayed departed frame may merge terminal metadata but cannot recreate a hold"
        );
        dispatch_mesh_control(connected(33), RelayId(9), &joined, &sessions, &mesh_state);
        assert_eq!(
            inbox.try_recv_connectivity(),
            None,
            "no true generation fans out after the final leave"
        );

        let mut guard = makers.lock();
        let maker = guard.get_mut(&key).expect("maker exists");
        maker.ingest_remote(
            &LinkConditions {
                slots: vec![SlotConditions {
                    slot: 0,
                    rtt_us: 10_000,
                    lost_packets: 0,
                    sent_packets: 1,
                    connection_epoch: Some(33),
                }],
            },
            5_000,
        );
        assert!(
            !maker.has_slot_state(SlotId(0)),
            "a sidecar cannot recreate conditions for the finally-left slot"
        );
    }
}
