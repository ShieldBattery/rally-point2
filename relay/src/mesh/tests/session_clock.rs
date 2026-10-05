//! A rollback session's clock across the mesh: the authority's forward path anchors it and sends
//! it to every peer relay, its heartbeat keeps sending it, and a peer relay that learns the clock
//! stopped longer gives its own measured players reports carrying the stop.

use super::*;

use rally_point_proto::messages::{ClockStop, SessionClock};
use rally_point_proto::rollback::LOCKSTEP_START_STEPS;

use super::super::clock_heartbeat::send_session_clocks;

/// The anchor step of a clock anchored once the lockstep start is in.
const ANCHOR: u64 = LOCKSTEP_START_STEPS - 1;

/// A clock as the authority sends it right after anchoring, a second ago, with a limit six steps
/// on.
fn anchored_clock() -> SessionClock {
    SessionClock {
        anchor_step: ANCHOR,
        since_anchor_us: 1_000_000,
        final_through: ANCHOR + 6,
        ..Default::default()
    }
}

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
    // Both slots show up, which starts the session on the authority.
    for slot in [SlotId(0), SlotId(5)] {
        let _ = mesh.session.decision_makers.note_slot_present(key, slot);
    }
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
    assert_eq!(clocks[0].anchor_step, ANCHOR);
    assert!(clocks[0].stops.is_empty());
    let anchored_limit = clocks[0].final_through;

    // Playing on moves the limit without a frame of its own; the heartbeat carries it.
    for seq in LOCKSTEP_START_STEPS..LOCKSTEP_START_STEPS + 3 {
        deliver(0, seq);
        deliver(5, seq);
    }
    assert!(session_clocks(&mut control_rx).is_empty());
    send_session_clocks(&mesh);
    let clocks = session_clocks(&mut control_rx);
    assert_eq!(clocks.len(), 1, "one heartbeat frame: {clocks:?}");
    assert_eq!(
        clocks[0].final_through,
        anchored_limit + 3,
        "the heartbeat carries the limit as it stands",
    );

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

    let anchor = anchored_clock();
    dispatch(anchor.clone());
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
        final_through: anchor.final_through + 1,
        stops: vec![ClockStop {
            step: anchor.final_through,
            pause_us: 4_000_000,
        }],
        ..anchor
    });
    let report = inbox
        .try_recv_lead_report()
        .expect("the stop reaches the measured player at once");
    assert_eq!(report.pause_us, 4_000_000);
    assert_eq!(report.samples, 1, "the window carries on through the stop");
    assert!(
        echo_forward_rx.try_recv().is_err(),
        "never echoed to the mesh"
    );
    assert!(
        echo_control_rx.try_recv().is_err(),
        "never echoed to the mesh"
    );
}

/// Every relay sends its copy of the clock to every peer relay, on the heartbeat and after an
/// authority change, and every relay merges the copies it gets, the authority included: a copy
/// can know of a stop a former authority made that never reached the relay now deciding.
#[test]
fn every_relay_sends_its_copy_and_every_relay_merges_them() {
    let sessions: routing::Sessions = Arc::default();
    let mesh = test_mesh_state();
    let key = control_key();
    rollback_session(&mesh, &key, crate::consensus::Authority::Peer);
    let (_forward_rx, mut control_rx) = register_link_channels(&mesh.links, &key);
    let joined = joined_state(&mesh.links, &key);
    let dispatch = |clock: SessionClock| {
        dispatch_mesh_control(
            MeshControlFrame {
                session: key.session.0,
                kind: Some(mesh_control_frame::Kind::SessionClock(clock)),
            },
            RelayId(9),
            0,
            &joined,
            &sessions,
            &mesh,
        );
    };
    let stopped_once = SessionClock {
        final_through: anchored_clock().final_through + 1,
        stops: vec![ClockStop {
            step: anchored_clock().final_through,
            pause_us: 250_000,
        }],
        ..anchored_clock()
    };
    dispatch(stopped_once.clone());

    // A relay that isn't the authority sends its copy too, on the heartbeat and after an
    // authority change.
    send_session_clocks(&mesh);
    routing::after_authority_change(&sessions, &mesh.session.decision_makers, &mesh.links, &key);
    let clocks = session_clocks(&mut control_rx);
    assert_eq!(clocks.len(), 2, "{clocks:?}");
    assert!(clocks.iter().all(|clock| clock.stops == stopped_once.stops));

    // Promoted, it merges another relay's copy that knows of a second stop.
    rollback_session(&mesh, &key, crate::consensus::Authority::SelfRelay);
    let mut stopped_twice = stopped_once.clone();
    stopped_twice.stops.push(ClockStop {
        step: stopped_once.final_through,
        pause_us: 500_000,
    });
    stopped_twice.final_through += 1;
    dispatch(stopped_twice.clone());
    send_session_clocks(&mesh);
    let clocks = session_clocks(&mut control_rx);
    assert_eq!(clocks.len(), 1, "{clocks:?}");
    assert_eq!(clocks[0].stops, stopped_twice.stops, "with both stops");
    assert_eq!(clocks[0].final_through, stopped_twice.final_through);
}
