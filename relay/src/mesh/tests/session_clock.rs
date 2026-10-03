//! A rollback session's clock across the mesh: the authority's forward path anchors it and sends
//! it to every peer relay, and a peer relay that learns the clock stopped longer gives its own
//! measured players reports carrying the stop.

use super::*;

use rally_point_proto::messages::SessionClock;
use rally_point_proto::rollback::LOCKSTEP_START_STEPS;

/// A rollback session of slots 0 and 5, with slot 5 homed here and this relay's authority role
/// as given.
fn rollback_session(mesh: &MeshState, key: &SessionKey, authority: crate::consensus::Authority) {
    let _ = mesh.session.decision_makers.sync_maker(
        key,
        crate::consensus::MakerSync {
            expected_slots: [SlotId(0), SlotId(5)].into(),
            homed_slots: [SlotId(5)].into(),
            finalized_drops: true,
            rollback: true,
            ..crate::consensus::MakerSync::new(
                rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
                authority,
            )
        },
    );
}

fn session_clocks(control_rx: &mut mpsc::UnboundedReceiver<MeshControlFrame>) -> Vec<SessionClock> {
    std::iter::from_fn(|| control_rx.try_recv().ok())
        .filter_map(|frame| match frame.kind {
            Some(mesh_control_frame::Kind::SessionClock(clock)) => Some(clock),
            _ => None,
        })
        .collect()
}

#[test]
fn the_authority_sends_its_anchor_to_every_peer_relay_once_the_start_is_confirmable() {
    let sessions: routing::Sessions = Arc::default();
    let mesh = test_mesh_state();
    let key = control_key();
    rollback_session(&mesh, &key, crate::consensus::Authority::SelfRelay);
    let (_forward_rx, mut control_rx) = register_link_channels(&mesh.links, &key);

    let deliver = |slot: u8, seq: u64| {
        let payload = Payload {
            seq,
            slot: u32::from(slot),
            ..Default::default()
        };
        let home = if slot == 5 {
            crate::consensus::delivery::DeliveryHome::Local
        } else {
            crate::consensus::delivery::DeliveryHome::Peer(RelayId(9))
        };
        let _ = deliver_turn_to_locals(&sessions, &mesh, &key, SlotId(slot), payload, home);
    };
    for seq in 0..LOCKSTEP_START_STEPS - 1 {
        deliver(0, seq);
        deliver(5, seq);
    }
    deliver(0, LOCKSTEP_START_STEPS - 1);
    assert!(
        session_clocks(&mut control_rx).is_empty(),
        "nothing until every player's start is in",
    );
    deliver(5, LOCKSTEP_START_STEPS - 1);
    let clocks = session_clocks(&mut control_rx);
    assert_eq!(clocks.len(), 1, "the anchor goes out once: {clocks:?}");
    assert_eq!(clocks[0].anchor_step, LOCKSTEP_START_STEPS - 1);
    assert_eq!(clocks[0].pause_us, 0);

    // A relay joining after the anchor is sent the clock too.
    assert!(
        mesh.session
            .decision_makers
            .session_clock_frame(&key)
            .is_some()
    );
}

#[test]
fn a_stop_on_the_authority_reaches_this_relays_measured_players() {
    let sessions: routing::Sessions = Arc::default();
    let mesh = test_mesh_state();
    let key = control_key();
    rollback_session(&mesh, &key, crate::consensus::Authority::Peer);
    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("slot 5 registers");
    guard.disarm();
    let (mut echo_forward_rx, mut echo_control_rx) = register_link_channels(&mesh.links, &key);
    let joined = joined_state(&mesh.links, &key);
    let dispatch = |clock: SessionClock| {
        dispatch_mesh_control(
            MeshControlFrame {
                session: key.session.0,
                kind: Some(mesh_control_frame::Kind::SessionClock(clock)),
            },
            RelayId(9),
            20_000,
            &joined,
            &sessions,
            &mesh,
        );
    };

    let anchor = SessionClock {
        anchor_step: LOCKSTEP_START_STEPS - 1,
        since_anchor_us: 1_000_000,
        pause_us: 0,
    };
    dispatch(anchor);
    assert_eq!(
        inbox.try_recv_lead_report(),
        None,
        "nothing measured, nothing to send"
    );

    // Slot 5's turns are measured against the adopted clock.
    let first = mesh
        .session
        .decision_makers
        .note_lead_arrival(
            &key,
            SlotId(5),
            LOCKSTEP_START_STEPS,
            std::time::Instant::now(),
        )
        .expect("a slot's first measured turn reports");
    assert_eq!(first.pause_us, 0);

    dispatch(SessionClock {
        pause_us: 4_000_000,
        ..anchor
    });
    let report = inbox
        .try_recv_lead_report()
        .expect("the stop reaches the measured player at once");
    assert_eq!(report.pause_us, 4_000_000);
    assert_eq!(report.samples, 0, "the window starts over with the stop");
    assert!(
        echo_forward_rx.try_recv().is_err(),
        "never echoed to the mesh"
    );
    assert!(
        echo_control_rx.try_recv().is_err(),
        "never echoed to the mesh"
    );
}

/// A relay that adopted the authority's clock and is then promoted (the old authority failed)
/// announces the clock it holds to every peer relay: one that joined while it wasn't the
/// authority was never sent it, and during smooth play nothing else would.
#[test]
fn a_promoted_relay_announces_the_clock_it_already_holds() {
    let sessions: routing::Sessions = Arc::default();
    let mesh = test_mesh_state();
    let key = control_key();
    rollback_session(&mesh, &key, crate::consensus::Authority::Peer);
    let (_forward_rx, mut control_rx) = register_link_channels(&mesh.links, &key);
    let joined = joined_state(&mesh.links, &key);
    dispatch_mesh_control(
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SessionClock(SessionClock {
                anchor_step: LOCKSTEP_START_STEPS - 1,
                since_anchor_us: 1_000_000,
                pause_us: 250_000,
            })),
        },
        RelayId(9),
        0,
        &joined,
        &sessions,
        &mesh,
    );

    routing::after_authority_change(&sessions, &mesh.session.decision_makers, &mesh.links, &key);
    assert!(
        session_clocks(&mut control_rx).is_empty(),
        "a relay that isn't the authority announces nothing",
    );

    rollback_session(&mesh, &key, crate::consensus::Authority::SelfRelay);
    routing::after_authority_change(&sessions, &mesh.session.decision_makers, &mesh.links, &key);
    let clocks = session_clocks(&mut control_rx);
    assert_eq!(
        clocks.len(),
        1,
        "the promoted relay announces its clock: {clocks:?}"
    );
    assert_eq!(clocks[0].anchor_step, LOCKSTEP_START_STEPS - 1);
    assert_eq!(
        clocks[0].pause_us, 250_000,
        "with the stopped time it adopted"
    );
}
