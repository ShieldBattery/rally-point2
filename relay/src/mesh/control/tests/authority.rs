//! Authority verdicts and resumed-descriptor sync: order-derived and
//! presence-driven authority, correlation-id stamping, and a rehomed
//! session's seeded departures/journaled provisional turns draining
//! through the ordinary paths once the maker exists.

use super::*;

#[test]
fn a_coordinator_assigned_order_overrides_id_order() {
    // our_id 1, peer 2. Id order would make us the authority; the
    // coordinator ranked relay 2 first (it is the session's home relay),
    // so relay 2 decides.
    let makers = Arc::new(consensus::new_decision_makers());
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
    control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
    assert!(
        !makers.lock().get(&key(1)).unwrap().is_authority(),
        "the assigned order outranks the id-order fallback",
    );

    // The same relay ranked first decides, whatever its id.
    let makers = Arc::new(consensus::new_decision_makers());
    let control = MeshControl::new(RelayId(3), makers.clone(), Arc::default());
    control.apply_descriptor(&descriptor_with_order(1, &[2], &[3, 2]));
    assert!(
        makers.lock().get(&key(1)).unwrap().is_authority(),
        "the first relay in the assigned order decides",
    );
}

#[test]
fn presence_hands_authority_off_between_descriptor_pushes() {
    // The handoff path with no coordinator involved: relay 2 heads the
    // order and decides; its players all leave; the presence report the
    // mesh driver records flips the verdict to us — no re-push needed.
    let makers = Arc::new(consensus::new_decision_makers());
    let presence_registry = Arc::new(presence::new_presence_registry());
    let control = MeshControl::new(RelayId(1), makers.clone(), presence_registry.clone());
    control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
    assert!(!makers.lock().get(&key(1)).unwrap().is_authority());

    // What the mesh-link driver does when relay 2's presence frame says
    // it no longer serves players.
    assert!(presence::record_peer(
        &presence_registry,
        &key(1),
        RelayId(2),
        0
    ));
    let _ = presence::recompute(
        &presence_registry,
        &makers,
        &key(1),
        &std::collections::HashSet::new(),
    );
    assert!(
        makers.lock().get(&key(1)).unwrap().is_authority(),
        "the authority's players leaving promotes the next relay in order",
    );

    // A later descriptor re-push must not resurrect relay 2's authority:
    // the verdict is recomputed against the *kept* presence reports.
    control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
    assert!(
        makers.lock().get(&key(1)).unwrap().is_authority(),
        "a re-push recomputes against known presence, not from scratch",
    );
}

#[test]
fn a_resumed_descriptor_latches_started_and_seeds_departures() {
    // A rehome descriptor: it resumes an already-running session onto this fresh
    // relay, expecting slots {0, 1} with slot 1 already departed. The relay must
    // latch the session started (never wait on the full expected set, which lists
    // the departed slot that will never dial) and record the departure as already
    // decided.
    let makers = Arc::new(consensus::new_decision_makers());
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1), SlotId(2)];
    desc.resumed = true;
    desc.departed_slots = vec![
        DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Left,
            final_turn_count: Some(240),
        },
        DepartedSlot {
            finalized: false,
            slot: SlotId(2),
            kind: DepartureKind::Dropped,
            // A drop count reaching a descriptor means the carrier ran code
            // predating the clean-leaves-only rule; the seed strips it.
            final_turn_count: Some(99),
        },
    ];
    control.apply_descriptor(&desc);

    {
        let registry = makers.lock();
        let maker = registry.get(&key(1)).expect("a maker was created");
        assert!(
            maker.is_authority(),
            "a single-relay rehome session is its own authority",
        );
        assert!(
            maker.is_started(),
            "a resumed descriptor latches the session started",
        );
        assert!(
            !maker.has_undecided_departure(),
            "the seeded departures are recorded as already decided",
        );
    }
    let (_, directives) = consensus::leave_reconcile(&makers, &key(1));
    assert!(
        directives
            .iter()
            .any(|l| l.slot == 1 && l.final_turn_count == Some(240)),
        "the seeded clean-leave directive a reconnecting survivor replays \
         carries the coordinator-retained count",
    );
    assert!(
        directives
            .iter()
            .any(|l| l.slot == 2 && l.final_turn_count.is_none()),
        "the seeded dropped directive's unsound count is stripped at ingress",
    );

    // Because the session is already started, a slot registering does not fire a
    // fresh session-wide start (the authority never re-covers the expected set).
    assert!(
        !consensus::note_slot_present(&makers, &key(1), SlotId(0)),
        "an already-started session fires no fresh session-wide start directive",
    );
}

/// A client admitted before its session's descriptor (provisional
/// admission) performs its one leave reconciliation at registration, when
/// there is nothing to reconcile. The resumed descriptor's seeded
/// departures must therefore be *pushed* to it when they are seeded —
/// otherwise it plays on forever, stalled on the departed slot's turns
/// that will never come.
#[tokio::test]
async fn a_resumed_descriptor_fans_seeded_leaves_to_already_connected_survivors() {
    let makers = Arc::new(consensus::new_decision_makers());
    let sessions = Sessions::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
        .with_broadcast(sessions.clone(), mesh_links.clone());

    // The survivor — and the departed subject itself — both admitted
    // before any descriptor arrived (provisional admission).
    let (_reg, mut inbox) = crate::routing::register(&sessions, &key(1), SlotId(0), 1).unwrap();
    let (_subject_reg, subject_inbox) =
        crate::routing::register(&sessions, &key(1), SlotId(1), 1).unwrap();
    let subject_shutdown = subject_inbox.shutdown_handle();

    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    desc.resumed = true;
    desc.departed_slots = vec![DepartedSlot {
        finalized: false,
        slot: SlotId(1),
        kind: DepartureKind::Left,
        final_turn_count: Some(64),
    }];
    control.apply_descriptor(&desc);

    let leave = inbox
        .try_recv_leave()
        .expect("the seeded leave is pushed to the already-connected survivor");
    assert_eq!(leave.slot, 1);
    assert_eq!(leave.final_turn_count, Some(64));
    // The subject's live provisional link is signaled closed: its leave is
    // decided, so nothing it sends is part of the game any more (and the
    // home-ingress turn fence drops whatever it manages to send first).
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        subject_shutdown.notified(),
    )
    .await
    .expect("the seeded departed subject's link is signaled to close");

    // The idempotent descriptor replay re-decides nothing, so nothing is
    // re-pushed either (the client would dedup it by slot regardless).
    control.apply_descriptor(&desc);
    assert_eq!(inbox.try_recv_leave(), None);
}

/// On a coordinator-managed relay (pen armed), a turn arriving before any
/// descriptor names its session is held, not fanned out — and descriptor
/// application drains it through the ordinary forward path, where a
/// current slot's turn reaches the survivors exactly as if it had arrived
/// a moment later.
#[test]
fn a_pre_descriptor_turn_is_held_and_drained_current_by_the_descriptor() {
    let makers = Arc::new(consensus::new_decision_makers());
    let sessions = Sessions::default();
    let mesh_state = crate::mesh::MeshState {
        decision_makers: makers.clone(),
        ..crate::mesh::new_mesh_state()
    };
    mesh_state.provisional_turns.arm();
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
        .with_broadcast(sessions.clone(), mesh_state.links.clone())
        .with_turn_path(mesh_state.clone());

    let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0), 1).unwrap();
    crate::mesh::forward_client_turn(
        &sessions,
        &mesh_state,
        &key(1),
        SlotId(1),
        rally_point_proto::messages::Payload {
            seq: 0,
            slot: 1,
            commands: vec![0x05].into(),
            ..Default::default()
        },
    );
    assert!(
        survivor.try_recv_forward().is_none(),
        "a pre-descriptor turn is held, not fanned out",
    );
    assert_eq!(mesh_state.provisional_turns.held(&key(1)), 1);

    control.apply_descriptor(&descriptor(1, &[]));
    assert!(
        survivor.try_recv_forward().is_some(),
        "the descriptor drains the held turn to the survivor",
    );
    assert_eq!(mesh_state.provisional_turns.held(&key(1)), 0);
}

/// The drain runs AFTER a resumed descriptor's departure seeding, so a
/// slot the descriptor reveals as already departed has its held turns die
/// at the decided-leave fence instead of reaching co-admitted survivors —
/// the exact post-count ingress the pen exists to close.
#[test]
fn a_seeded_departed_slots_held_turns_die_at_the_fence() {
    let makers = Arc::new(consensus::new_decision_makers());
    let sessions = Sessions::default();
    let mesh_state = crate::mesh::MeshState {
        decision_makers: makers.clone(),
        ..crate::mesh::new_mesh_state()
    };
    mesh_state.provisional_turns.arm();
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
        .with_broadcast(sessions.clone(), mesh_state.links.clone())
        .with_turn_path(mesh_state.clone());

    let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0), 1).unwrap();
    // The departed subject dials provisionally and originates a turn past
    // its sealed count before the descriptor lands.
    crate::mesh::forward_client_turn(
        &sessions,
        &mesh_state,
        &key(1),
        SlotId(1),
        rally_point_proto::messages::Payload {
            seq: 64,
            slot: 1,
            commands: vec![0x05].into(),
            ..Default::default()
        },
    );
    assert!(survivor.try_recv_forward().is_none());

    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    desc.resumed = true;
    desc.departed_slots = vec![DepartedSlot {
        finalized: false,
        slot: SlotId(1),
        kind: DepartureKind::Left,
        final_turn_count: Some(64),
    }];
    control.apply_descriptor(&desc);

    assert!(
        survivor.try_recv_leave().is_some(),
        "the seeded leave reaches the survivor",
    );
    assert!(
        survivor.try_recv_forward().is_none(),
        "the departed slot's held turn dies at the fence, never fanned",
    );
    assert_eq!(mesh_state.provisional_turns.held(&key(1)), 0);
}

/// A clean leave that lands before the session's descriptor is journaled,
/// not lost: the drain replays it into the freshly created maker, ordered
/// after the slot's own journaled turns, and derives the exact final turn
/// count over exactly those turns — so the departure is recorded, the
/// leave decided, and survivors never stall on an expected-but-absent
/// slot waiting for the coordinator's holdout reap.
#[test]
fn a_pre_descriptor_clean_leave_is_journaled_and_drained_with_its_count() {
    let makers = Arc::new(consensus::new_decision_makers());
    let sessions = Sessions::default();
    let mesh_state = crate::mesh::MeshState {
        decision_makers: makers.clone(),
        ..crate::mesh::new_mesh_state()
    };
    mesh_state.provisional_turns.arm();
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
        .with_broadcast(sessions.clone(), mesh_state.links.clone())
        .with_turn_path(mesh_state.clone());

    let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0), 1).unwrap();
    // The leaver plays two framed turns and cleanly leaves, all before the
    // descriptor arrives — everything lands in the journal.
    for seq in 0..2 {
        crate::mesh::forward_client_turn(
            &sessions,
            &mesh_state,
            &key(1),
            SlotId(1),
            rally_point_proto::messages::Payload {
                seq,
                slot: 1,
                game_frame_count: Some(40 + seq as u32),
                commands: vec![0x05].into(),
                ..Default::default()
            },
        );
    }
    let announced = mesh_state.gates.with_ingress(&key(1), || {
        crate::routing::announce_departure(
            &mesh_state.drop_holds,
            &makers,
            &sessions,
            &mesh_state.links,
            &mesh_state.provisional_turns,
            &key(1),
            SlotId(1),
            consensus::LEAVE_REASON_LEFT,
            // Deposit-time count: blind to the journaled turns; the drain
            // must recompute it, not trust this.
            None,
            Some(7),
        )
    });
    assert_eq!(
        announced,
        Some(true),
        "the pre-descriptor leave is journaled"
    );
    assert!(
        survivor.try_recv_forward().is_none(),
        "nothing fanned before the descriptor",
    );
    assert!(
        !consensus::slot_departed(&makers, &key(1), SlotId(1)),
        "nothing recorded before the descriptor",
    );

    control.apply_descriptor(&descriptor(1, &[]));

    assert!(survivor.try_recv_forward().is_some());
    assert!(
        survivor.try_recv_forward().is_some(),
        "both journaled turns reach the survivor",
    );
    let leave = survivor
        .try_recv_leave()
        .expect("the drained departure decides the leave");
    assert_eq!(leave.reason, consensus::LEAVE_REASON_LEFT);
    assert_eq!(
        leave.final_turn_count,
        Some(2),
        "the exact count is derived at the drain, over the drained turns",
    );
    assert!(consensus::slot_departed(&makers, &key(1), SlotId(1)));
}

/// A journaled clean leave whose link (the session's only local one) is
/// long gone still drains into a real recorded-and-decided leave when the
/// descriptor arrives — peer-homed survivors get their answer instead of
/// waiting forever on an expected slot with neither presence nor a
/// departure.
#[test]
fn a_journaled_leave_with_no_local_survivors_still_drains_and_decides() {
    let makers = Arc::new(consensus::new_decision_makers());
    let sessions = Sessions::default();
    let mesh_state = crate::mesh::MeshState {
        decision_makers: makers.clone(),
        ..crate::mesh::new_mesh_state()
    };
    mesh_state.provisional_turns.arm();
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
        .with_broadcast(sessions.clone(), mesh_state.links.clone())
        .with_turn_path(mesh_state.clone());

    // The leaver plays one framed turn and cleanly leaves; its link (and
    // with it the whole local roster) is gone before the descriptor.
    crate::mesh::forward_client_turn(
        &sessions,
        &mesh_state,
        &key(1),
        SlotId(1),
        rally_point_proto::messages::Payload {
            seq: 0,
            slot: 1,
            game_frame_count: Some(40),
            commands: vec![0x05].into(),
            ..Default::default()
        },
    );
    let announced = mesh_state.gates.with_ingress(&key(1), || {
        crate::routing::announce_departure(
            &mesh_state.drop_holds,
            &makers,
            &sessions,
            &mesh_state.links,
            &mesh_state.provisional_turns,
            &key(1),
            SlotId(1),
            consensus::LEAVE_REASON_LEFT,
            None,
            Some(7),
        )
    });
    assert_eq!(announced, Some(true));

    control.apply_descriptor(&descriptor(1, &[]));

    assert!(consensus::slot_departed(&makers, &key(1), SlotId(1)));
    let (_, directives) = consensus::leave_reconcile(&makers, &key(1));
    let leave = directives
        .iter()
        .find(|l| l.slot == 1)
        .expect("the drained leave is decided");
    assert_eq!(leave.reason, consensus::LEAVE_REASON_LEFT);
    assert_eq!(leave.final_turn_count, Some(1));
}

/// A descriptor push is routinely an idempotent replay (a coordinator
/// reconnect re-pushes every current descriptor), so it must NOT clear a
/// close seal: a closed-but-not-yet-retired session's seal is exactly what
/// keeps a straggling mesh event from conjuring an empty replacement
/// recording that would displace the real stored one.
#[test]
fn a_descriptor_replay_does_not_unseal_a_closed_flight_recording() {
    let makers = Arc::new(consensus::new_decision_makers());
    let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
    let desc = descriptor(1, &[]);
    control.apply_descriptor(&desc);

    let recorder = makers.flight_recorder();
    recorder.record(
        &key(1),
        crate::observability::flight_recorder::FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );
    // The session's close flush: removes the recording and seals the key
    // (outside a runtime the detached flush discards synchronously).
    recorder.flush_session_detached(&key(1), true);

    // The coordinator reconnects and replays the unchanged descriptor.
    control.apply_descriptor(&desc);

    // A straggling mesh event must still be dropped, not begin a
    // replacement recording.
    recorder.record(
        &key(1),
        crate::observability::flight_recorder::FlightEvent::DropHeld { slot: 1 },
    );
    assert!(
        recorder.recorded_sessions().is_empty(),
        "the replayed descriptor left the close seal in place",
    );

    // Retirement is what clears it; a genuine re-serve records again.
    control.end_session(&key(1));
    recorder.record(
        &key(1),
        crate::observability::flight_recorder::FlightEvent::SlotConnected {
            slot: 0,
            resumed: true,
        },
    );
    assert_eq!(recorder.recorded_sessions(), vec![key(1)]);
}
