//! Fan-out across a session's peer-relay links: per-link registration and
//! teardown, one turn reaching each link exactly once, the full-queue reset,
//! and control-frame delivery.

use super::*;

/// A synced leave's slot is a raw wire `u32`. A malformed one past `u8`
/// range must be dropped entirely -- neither pushed to local survivors nor
/// broadcast across the mesh -- rather than forwarded with a slot id that
/// can't name any real player. A well-formed leave in the same batch must
/// still go through normally.
#[test]
fn broadcast_leaves_drops_an_out_of_range_slot_and_still_delivers_the_rest() {
    let sessions = routing::Sessions::default();
    let mesh_links = new_mesh_links();
    let key = control_key();

    // Slot 0 is the one that actually left; slot 1 is the surviving peer
    // that should hear about it.
    let (_reg0, _inbox0) = routing::register(&sessions, &key, SlotId(0), 1).unwrap();
    let (_reg1, mut inbox1) = routing::register(&sessions, &key, SlotId(1), 1).unwrap();
    let (_forward_rx, mut control_rx) = register_link_channels(&mesh_links, &key);

    let real_leave = LeaveDirective {
        finalized: false,
        slot: 0,
        reason: 0,
        apply_at_frame: 10,
        leave_seq: 1,
        final_turn_count: None,
    };
    let malformed_leave = LeaveDirective {
        finalized: false,
        slot: 300,
        reason: 0,
        apply_at_frame: 10,
        leave_seq: 2,
        final_turn_count: None,
    };

    broadcast_leaves(
        &sessions,
        &mesh_links,
        &key,
        vec![real_leave, malformed_leave],
    );

    assert_eq!(
        inbox1.try_recv_leave(),
        Some(real_leave),
        "the well-formed departure still reaches the surviving slot"
    );
    assert_eq!(
        inbox1.try_recv_leave(),
        None,
        "the malformed leave was never pushed to any survivor"
    );
    let frame = control_rx
        .try_recv()
        .expect("the well-formed leave is still broadcast across the mesh");
    assert!(
        matches!(
            frame.kind,
            Some(mesh_control_frame::Kind::LeaveDirective(d)) if d == real_leave
        ),
        "the one mesh frame sent is the well-formed leave",
    );
    assert!(
        control_rx.try_recv().is_err(),
        "the malformed leave was never broadcast across the mesh"
    );
}

/// A peer relay's `SlotStarted` lands in this relay's maker — the slot has
/// left loading behind, which is what the silent-slot watch needs before it
/// may weigh that slot at all — and goes nowhere else: no coordinator notice
/// (the home already reported the load) and no echo back across the mesh.
#[test]
fn a_mesh_slot_started_marks_the_slot_without_notifying_or_echoing() {
    use rally_point_proto::control::BufferBounds;

    let mesh_links = new_mesh_links();
    let seen = new_seen_registries();
    let sessions = routing::Sessions::default();
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
    let (notice_tx, mut notice_rx) = mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    // A peer mesh link that must not hear the frame come back.
    let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

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

    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SlotStarted(SlotStarted {
            slot: 3,
        })),
    };
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat, &skins);
    dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

    assert!(
        crate::consensus::slot_has_started(&makers, &key, SlotId(3)),
        "the peer's report is recorded here",
    );
    assert!(
        crate::consensus::started_home_slots(&makers, &key).is_empty(),
        "a peer's slot is never re-shared as one of this relay's own",
    );
    assert!(
        notice_rx.try_recv().is_err(),
        "reporting the load stays the slot's home's job",
    );
    assert!(
        echo_ctl_rx.try_recv().is_err(),
        "and the frame is not re-broadcast across the mesh",
    );
}

/// Deregistering one peer relay's mesh link for a session must leave every
/// other peer's registration for that session intact. Regression: a session's
/// whole fan-out vec was once removed on any single link's teardown, so a
/// `Leave` to (or cancellation of) one peer's driver silently cut turns and
/// synced-leave frames to every *other* peer's clients.
#[test]
fn deregister_one_mesh_link_leaves_the_other_peers_registration() {
    let links = new_mesh_links();
    let key = control_key();

    // Two peer relays mesh the same session: each registers its own fan-out
    // entry, so the session's vec holds one element per peer.
    let (peer_b_fwd, mut peer_b_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    let (peer_b_ctl, _peer_b_ctl_rx) = mpsc::unbounded_channel();
    let reg_b = register_mesh_link(
        &links,
        key.clone(),
        peer_b_fwd,
        peer_b_ctl,
        Arc::new(Notify::new()),
    );

    let (peer_c_fwd, mut peer_c_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    let (peer_c_ctl, _peer_c_ctl_rx) = mpsc::unbounded_channel();
    let reg_c = register_mesh_link(
        &links,
        key.clone(),
        peer_c_fwd,
        peer_c_ctl,
        Arc::new(Notify::new()),
    );

    assert_eq!(
        links.lock().get(&key).map(Vec::len),
        Some(2),
        "both peers registered for the session",
    );

    // Peer B's driver winds down (a `Leave`, or the task being cancelled):
    // its RAII guard drops and deregisters — but only its own entry.
    drop(reg_b);
    assert_eq!(
        links.lock().get(&key).map(Vec::len),
        Some(1),
        "only peer B's entry was removed; peer C survives",
    );

    // Fan-out still reaches the surviving peer C, and not the removed peer B.
    let payload = Payload {
        seq: 7,
        slot: 1,
        ..Default::default()
    };
    fan_out_to_mesh(&links, &key, payload);
    let (session, got) = peer_c_rx.try_recv().expect("peer C is still reached");
    assert_eq!(session, key.session);
    assert_eq!(got.seq, 7);
    assert!(
        peer_b_rx.try_recv().is_err(),
        "peer B was deregistered and gets nothing",
    );

    // Dropping the last registration empties the key entirely — no stale
    // empty vec left behind.
    drop(reg_c);
    assert!(
        links.lock().get(&key).is_none(),
        "the session key is removed once its last link deregisters",
    );
}

#[test]
fn client_turn_enters_each_mesh_link_once() {
    let sessions = routing::Sessions::default();
    let links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let key = control_key();
    let (_registration, mut local) =
        routing::register(&sessions, &key, SlotId(1), 1).expect("local slot registers");
    let (mut peer_b_rx, _peer_b_control_rx) = register_link_channels(&links, &key);
    let (mut peer_c_rx, _peer_c_control_rx) = register_link_channels(&links, &key);
    let mut mesh_state = new_mesh_state();
    mesh_state.links = links.clone();
    mesh_state.seen = seen.clone();
    mesh_state.decision_makers = makers.clone();
    mesh_state.turn_ring = turn_ring.clone();

    forward_client_turn(
        &sessions,
        &mesh_state,
        &key,
        SlotId(0),
        Payload {
            seq: 7,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        },
    );

    assert_eq!(
        local
            .try_recv_forward()
            .expect("the local peer receives the turn")
            .seq,
        7,
    );
    for peer in [&mut peer_b_rx, &mut peer_c_rx] {
        let (session, payload) = peer
            .try_recv()
            .expect("each session peer receives one direct copy");
        assert_eq!(session, key.session);
        assert_eq!(payload.seq, 7);
        assert!(peer.try_recv().is_err(), "the peer receives only one copy");
    }
}

#[test]
fn mesh_turn_delivers_locally_and_never_reenters_the_mesh() {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let sessions = routing::Sessions::default();
    let links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let key = control_key();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (_registration, mut local) =
        routing::register(&sessions, &key, SlotId(1), 1).expect("local slot registers");
    let (mut peer_b_rx, mut peer_b_control_rx) = register_link_channels(&links, &key);
    let (mut peer_c_rx, mut peer_c_control_rx) = register_link_channels(&links, &key);
    let payload = Payload {
        seq: 9,
        slot: 0,
        commands: vec![0x05].into(),
        game_frame_count: Some(77),
        ..Default::default()
    };

    let mut mesh_state = new_mesh_state();
    mesh_state.seen = seen.clone();
    mesh_state.decision_makers = makers.clone();
    mesh_state.turn_ring = turn_ring.clone();
    deliver_mesh_turn(
        &sessions,
        &mesh_state,
        &key,
        SlotId(0),
        payload.clone(),
        RelayId(2),
    );

    let delivered = local
        .try_recv_forward()
        .expect("the peer turn reaches this relay's local player");
    assert_eq!(delivered.seq, payload.seq);
    assert_eq!(delivered.commands, payload.commands);
    assert_eq!(
        consensus::slot_frame(&makers, &key, SlotId(0)),
        Some(GameFrameCount(77)),
        "mesh ingress still feeds consensus",
    );
    assert_eq!(
        mark_seen(&seen, &key, SlotId(0), payload.seq).seen,
        Seen::Duplicate,
        "mesh ingress still passes the session-level dedup gate",
    );
    for peer in [&mut peer_b_rx, &mut peer_c_rx] {
        assert!(
            peer.try_recv().is_err(),
            "a peer-origin turn is never sent to any mesh link",
        );
    }
    assert!(peer_b_control_rx.try_recv().is_err());
    assert!(peer_c_control_rx.try_recv().is_err());

    // A redundant copy presented by a different peer during reconnect,
    // resume, or re-home overlap is dropped locally and still cannot enter
    // the mesh.
    deliver_mesh_turn(&sessions, &mesh_state, &key, SlotId(0), payload, RelayId(3));
    assert!(local.try_recv_forward().is_none());
    assert!(peer_b_rx.try_recv().is_err());
    assert!(peer_c_rx.try_recv().is_err());
}

/// The bug this guards: a full mesh forward queue used to just drop the fresh
/// turn (`let _ = tx.try_send(...)`) — a turn that never enters the link's
/// `AckManager` has nothing for that link's redundancy to re-carry, so the
/// peer relay's clients see a permanent per-(slot, seq) gap and stall in
/// lockstep forever. The fix mirrors `routing::fan_out`'s lagging-peer path:
/// a full queue resets the congested link (via its `Notify`) instead of
/// silently dropping into it, so the dial supervisor redials a fresh
/// connection. Also proves the reset is scoped to *only* the congested
/// link — a healthy sibling peer link serving the same session keeps
/// receiving every turn and is never signaled.
#[tokio::test]
async fn fan_out_to_mesh_resets_a_full_link_and_keeps_delivering_to_a_healthy_one() {
    let links = new_mesh_links();
    let key = control_key();

    // Peer B is drained every turn and so never fills; peer C is never
    // drained and fills.
    let (peer_b_fwd, mut peer_b_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    let (peer_b_ctl, _peer_b_ctl_rx) = mpsc::unbounded_channel();
    let peer_b_shutdown = Arc::new(Notify::new());
    let _reg_b = register_mesh_link(
        &links,
        key.clone(),
        peer_b_fwd,
        peer_b_ctl,
        Arc::clone(&peer_b_shutdown),
    );

    let (peer_c_fwd, _peer_c_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    let (peer_c_ctl, _peer_c_ctl_rx) = mpsc::unbounded_channel();
    let peer_c_shutdown = Arc::new(Notify::new());
    let _reg_c = register_mesh_link(
        &links,
        key.clone(),
        peer_c_fwd,
        peer_c_ctl,
        Arc::clone(&peer_c_shutdown),
    );

    // Fan out past peer C's capacity.
    let mut delivered_to_b = 0;
    for _ in 0..(routing::FORWARD_CAPACITY + 8) {
        fan_out_to_mesh(
            &links,
            &key,
            Payload {
                ..Default::default()
            },
        );
        if peer_b_rx.try_recv().is_ok() {
            delivered_to_b += 1;
        }
    }

    // The healthy peer received every turn — the congested one never
    // blocked it.
    assert_eq!(delivered_to_b, routing::FORWARD_CAPACITY + 8);

    // The congested peer's link was signaled to reset...
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        peer_c_shutdown.notified(),
    )
    .await
    .expect("peer C's full queue must signal its link to reset");
    // ...but peer B's link — never full — was never touched.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            peer_b_shutdown.notified(),
        )
        .await
        .is_err(),
        "a healthy sibling link must not be reset by another link's full queue",
    );
}

/// `fan_out_control` reaches every link serving the session (with the frame's
/// session stamped), and a link whose driver has exited (closed channel) is
/// tolerated without disturbing the healthy ones.
#[test]
fn fan_out_control_reaches_every_link_and_tolerates_a_closed_channel() {
    let links = new_mesh_links();
    let key = control_key();
    let (_fwd1, mut ctl1) = register_link_channels(&links, &key);
    let (_fwd2, mut ctl2) = register_link_channels(&links, &key);

    fan_out_slot_departed(
        &links,
        &key,
        SlotId(2),
        &crate::consensus::DepartureStamps {
            last_frame: Some(rally_point_proto::ids::GameFrameCount(41)),
            reachable_frame: Some(38),
            ..Default::default()
        },
        3,
        None,
    );
    for rx in [&mut ctl1, &mut ctl2] {
        let frame = rx.try_recv().expect("every link is told");
        assert_eq!(
            frame.session, 1,
            "the frame is stamped with the key's session"
        );
        match frame.kind {
            Some(mesh_control_frame::Kind::SlotDeparted(sd)) => {
                assert_eq!(sd.slot, 2);
                assert_eq!(sd.last_frame, Some(41));
                assert_eq!(sd.reason, 3);
            }
            other => panic!("expected SlotDeparted, got {other:?}"),
        }
    }

    // The second link's driver exits (receiver dropped): the next fan-out
    // tolerates the closed channel and still reaches the healthy first link.
    drop(ctl2);
    let leave = LeaveDirective {
        finalized: false,
        slot: 2,
        reason: 3,
        apply_at_frame: 42,
        leave_seq: 1,
        final_turn_count: None,
    };
    fan_out_leave_directive(&links, &key, leave);
    match ctl1.try_recv().expect("the live link still gets it").kind {
        Some(mesh_control_frame::Kind::LeaveDirective(got)) => assert_eq!(got, leave),
        other => panic!("expected LeaveDirective, got {other:?}"),
    }
}
