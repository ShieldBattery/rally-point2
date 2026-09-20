//! End-of-life and observability: session-end sweeps (drop holds, replay
//! state), session-start/reconcile edge cases, flight-recorder events, and
//! the e2e delivery cushion and conditions-driven directive queuing.

use super::*;

/// Descriptor retirement is terminal for the session's drop bookkeeping:
/// held (undecided) drops and any armed abandon timer must be swept with
/// it, or they leak forever — the timer's expiry stands down on the
/// forgotten presence without releasing anything, and no owner remains to
/// clean the hold entries.
#[tokio::test]
async fn end_session_sweeps_undecided_holds_and_the_abandon_timer() {
    let mesh = crate::mesh::MeshState::new(crate::session::SessionState::with_tunables(
        crate::session::Tunables {
            drop_unlock: std::time::Duration::from_secs(3600),
            abandon_timeout: std::time::Duration::from_secs(3600),
            ..Default::default()
        },
    ));
    let holds = mesh.session.drop_holds.clone();
    let control = MeshControl::new(RelayId(1), &mesh, Sessions::default());
    control.apply_descriptor(&descriptor(1, &[]));

    holds.hold(key(1), SlotId(0));
    holds
        .arm_abandon(key(1), |_| {})
        .expect("the abandon timer arms");

    control.end_session(&key(1));

    assert!(
        !holds.is_pending(&key(1), SlotId(0)),
        "the undecided hold is swept by retirement",
    );
    assert!(
        !holds.abandon_armed(&key(1)),
        "the abandon timer is cancelled by retirement",
    );
}

/// Retirement is also the terminal sweep for the receipt (forward-once
/// seen) and replay (turn ring) stores: the session-emptied close retains
/// both while an undecided hold still promises a reconnect their receipts
/// would seed, and with the descriptor gone no admission path remains —
/// nothing else would ever clean a retained pair whose reconnect never
/// came.
#[tokio::test]
async fn end_session_sweeps_retained_receipts_and_replay_state() {
    let (control, mesh_state, _sessions) = control_over(1);
    control.apply_descriptor(&descriptor(1, &[]));

    crate::mesh::mark_seen(&mesh_state.seen, &key(1), SlotId(0), 0);
    mesh_state.session.turn_ring.record(
        &key(1),
        &rally_point_proto::messages::Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        2,
    );

    control.end_session(&key(1));

    assert!(
        !mesh_state.seen.lock().contains_key(&key(1)),
        "the seen receipts are swept by retirement",
    );
    assert_eq!(
        mesh_state.session.turn_ring.totals().sessions,
        0,
        "the replay ring is swept by retirement",
    );
}

#[test]
fn a_descriptor_reconciles_dials_that_raced_it_and_starts_the_session() {
    // Both of a two-player single-relay session's clients dial and register
    // before the coordinator's descriptor applies. Each slot's link task
    // announces its presence while the session has no maker yet, so the
    // announce finds nothing to record and the presence is dropped. The
    // descriptor must reconcile the roster it already holds into the maker it
    // creates, reach coverage, and deliver the start directive to the
    // connected clients.
    let (control, mesh, sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();

    // Seat slots {0, 1} in the roster, as registration does before a link
    // task runs — hold the guards and inboxes so the slots stay registered
    // and the delivered start directive can be observed.
    let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0), 1)
        .expect("slot 0 registers into an empty roster");
    let (_reg1, mut inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1), 1)
        .expect("slot 1 registers into an empty roster");

    // Each slot's announce raced ahead of the descriptor: with no maker yet,
    // `note_slot_present` takes its no-maker path and reports no start, so the
    // presence is dropped.
    assert!(
        !makers.note_slot_present(&key(1), SlotId(0)),
        "an announce with no maker yet drops the presence and fires no start",
    );
    assert!(
        !makers.note_slot_present(&key(1), SlotId(1)),
        "an announce with no maker yet drops the presence and fires no start",
    );

    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    control.apply_descriptor(&desc);

    assert!(
        makers.lock().get(&key(1)).unwrap().is_started(),
        "the descriptor reconciles the already-registered roster and covers the expected set",
    );
    // The start directive reached both connected clients, not merely the
    // maker's latch — the fix must fan the directive, not just flip the flag.
    assert!(
        inbox0.try_recv_start().is_some(),
        "slot 0's connected client receives the start directive",
    );
    assert!(
        inbox1.try_recv_start().is_some(),
        "slot 1's connected client receives the start directive",
    );
}

#[test]
fn a_reconcile_over_a_partial_roster_waits_for_the_late_slot() {
    // Only slot 0 raced the descriptor; slot 1 has not dialed yet. The
    // reconcile must not start the session on the partial roster — the
    // session starts only once slot 1 later announces. This is also the
    // ordinary (non-rehome) descriptor's own guarantee: without `resumed`,
    // nothing latches the session started ahead of coverage.
    let (control, mesh, sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();

    let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0), 1)
        .expect("slot 0 registers into an empty roster");
    assert!(
        !makers.note_slot_present(&key(1), SlotId(0)),
        "slot 0's announce with no maker yet drops the presence",
    );

    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    control.apply_descriptor(&desc);

    assert!(
        !makers.lock().get(&key(1)).unwrap().is_started(),
        "a reconcile over a partial roster does not start the session",
    );
    assert!(
        inbox0.try_recv_start().is_none(),
        "no start directive is delivered before the expected set is covered",
    );

    // Slot 1 dials and announces after the descriptor applied: this completes
    // the expected set and starts the session, exactly as the live announce
    // path does. No premature start came from the reconcile.
    let (_reg1, _inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1), 1)
        .expect("slot 1 registers after the descriptor applied");
    assert!(
        makers.note_slot_present(&key(1), SlotId(1)),
        "slot 1's announce completes the expected set and fires the start",
    );
    assert!(
        makers.lock().get(&key(1)).unwrap().is_started(),
        "the session is started once slot 1 arrives",
    );
}

#[test]
fn a_leave_decision_lands_in_the_flight_recorder() {
    // The consensus-side flight tap, through the production decide path: a
    // decided synced leave records its event (slot, kind, apply coordinates)
    // into the session's recording.
    let (control, mesh, _sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();
    control.apply_descriptor(&descriptor(1, &[])); // single relay: self-authority

    makers.observe_frame(
        &key(1),
        SlotId(1),
        rally_point_proto::ids::GameFrameCount(10),
    );
    assert!(
        makers
            .decide_leave(&key(1), SlotId(0), 0x4000_0006)
            .is_some()
    );

    let events: Vec<_> = makers
        .flight_recorder()
        .events(&key(1))
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(
        events.iter().any(|e| matches!(
            e,
            crate::observability::flight_recorder::FlightEvent::LeaveDecided {
                slot: 0,
                kind: DepartureKind::Dropped,
                ..
            }
        )),
        "the decided leave is recorded: {events:?}",
    );
}

#[test]
fn end_session_destroys_the_maker() {
    let (control, mesh, _sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();

    control.apply_descriptor(&descriptor(1, &[]));
    assert!(makers.lock().contains_key(&key(1)));

    control.end_session(&key(1));
    assert!(
        !makers.lock().contains_key(&key(1)),
        "ending the session drops its maker, even with no mesh peers",
    );
}

/// The whole relay-side buffer path at the registry level, from a descriptor
/// creating the maker to a directive queued off it: the 150ms baseline a
/// high-RTT sample alone produces, and what the cross-relay delivery inputs
/// may add on top of it — at most one extra-hop turn plus the capped lag term,
/// however absurd a destination's claimed lag, and never past the session's
/// own `BufferBounds`.
#[test]
fn e2e_delivery_inputs_add_at_most_the_capped_cushion_and_respect_bounds() {
    use crate::consensus::delivery::{
        DeliveryHome, E2E_LAG_CUSHION_CAP_TURNS, EXTRA_HOP_CUSHION_TURNS,
    };
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::{LinkConditions, SlotConditions};

    let conditions = LinkConditions {
        slots: vec![SlotConditions {
            slot: 0,
            rtt_us: 150_000,
            lost_packets: 0,
            sent_packets: 100,
            connection_epoch: None,
        }],
    };

    // The baseline, with no delivery inputs at all: a descriptor creates the
    // maker, a validated turn's frame and a high-RTT sample fed through the
    // same helpers the turn path uses make it decide, and the decision is
    // available to stamp onto the turns this relay forwards.
    {
        let (control, mesh, _sessions) = control_over(1);
        let makers = mesh.session.decision_makers.clone();
        control.apply_descriptor(&descriptor(1, &[])); // bounds (1, 6), SelfRelay

        makers.observe_frame(&key(1), SlotId(0), GameFrameCount(1));
        let decision = makers
            .ingest_local_conditions(&key(1), &conditions)
            .expect("a raise fires on the first high-RTT sample");
        assert_eq!(
            decision.buffer.0, 4,
            "150ms -> 4 turns, within bounds (1, 6)"
        );

        let directive = makers
            .active_directive(&key(1))
            .expect("a directive is queued");
        assert_eq!(directive.buffer_turns, 4);
        assert_eq!(directive.apply_at_frame, decision.applied_frame.0);
    }

    // Wide bounds so the cushion's own caps are what bounds the outcome.
    // The malicious case: a cross-relay destination understating its cursor
    // by miles. The delivery inputs may add AT MOST one hop turn plus the
    // capped lag term on top of that 4-turn baseline.
    let (control, mesh, _sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();
    let mut desc = descriptor(1, &[]);
    desc.bounds = BufferBounds::new(1, 20).unwrap();
    control.apply_descriptor(&desc);

    makers.observe_turn_frame(
        &key(1),
        SlotId(0),
        100_000, // the origin's newest seq, miles past the claimed cursor
        GameFrameCount(1),
        DeliveryHome::Local,
    );
    makers.observe_delivery(
        &key(1),
        SlotId(1),
        SlotId(0),
        0, // the wildly understated claim
        DeliveryHome::Peer(RelayId(9)),
    );

    let decision = makers
        .ingest_local_conditions(&key(1), &conditions)
        .expect("a raise fires on the first high-RTT sample");
    assert_eq!(
        decision.buffer.0,
        4 + EXTRA_HOP_CUSHION_TURNS + E2E_LAG_CUSHION_CAP_TURNS,
        "the cushion saturates at its caps, however large the claimed lag",
    );

    // The same inputs under tight bounds: the existing BufferBounds clamp
    // still has the last word.
    let (control, mesh, _sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();
    control.apply_descriptor(&descriptor(1, &[])); // bounds (1, 6)
    makers.observe_turn_frame(
        &key(1),
        SlotId(0),
        100_000,
        GameFrameCount(1),
        DeliveryHome::Local,
    );
    makers.observe_delivery(
        &key(1),
        SlotId(1),
        SlotId(0),
        0,
        DeliveryHome::Peer(RelayId(9)),
    );
    let decision = makers
        .ingest_local_conditions(&key(1), &conditions)
        .expect("a raise fires");
    assert_eq!(
        decision.buffer.0, 6,
        "the cushion never escapes the session's BufferBounds",
    );
}
