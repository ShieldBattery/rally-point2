//! A redialed link's replay of the generations its own home slots departed on,
//! and what a peer that missed those generations makes of it.

use super::*;

const DROPPED: u32 = crate::consensus::LEAVE_REASON_DROPPED;

fn connectivity(key: &SessionKey, slot: u8, connected: bool, epoch: u64) -> MeshControlFrame {
    slot_connectivity_frame(key.session, SlotId(slot), connected, Some(epoch))
}

/// Records `slot`'s departure on connection generation `epoch`.
fn depart(makers: &crate::consensus::DecisionMakers, key: &SessionKey, slot: u8, epoch: u64) {
    assert!(makers.record_departure_for_epoch(
        key,
        SlotId(slot),
        crate::consensus::DepartureStamps::default(),
        DROPPED,
        Some(epoch),
    ));
}

/// Everything a Join's reconciles put on the link, in the order a Join sends
/// them: the local slots first, the leave state last.
fn join_frames(
    conditions: &ConditionsRegistry,
    makers: &crate::consensus::DecisionMakers,
    key: &SessionKey,
) -> Vec<MeshControlFrame> {
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_local_slots_on_join(conditions, makers, &control_tx, key);
    reconcile_leaves_on_join(makers, &control_tx, key);
    std::iter::from_fn(|| control_rx.try_recv().ok()).collect()
}

/// A peer relay homing slot 0, deciding the session, with a local survivor in
/// slot 0 and a mesh link registered for the frames it sends on.
struct Peer {
    sessions: routing::Sessions,
    mesh: MeshState,
    key: SessionKey,
    joined: HashMap<SessionId, JoinedSession>,
    _survivor: (routing::SlotRegistration, routing::SlotInbox),
}

impl Peer {
    fn new() -> Self {
        let key = control_key();
        let mesh = test_mesh_state();
        let _ = crate::test_support::seed_maker(
            &mesh.session.decision_makers,
            &key,
            crate::consensus::Authority::SelfRelay,
            &[0, 1],
            &[0],
        );
        let sessions: routing::Sessions = Arc::default();
        let survivor = routing::register(&sessions, &key, SlotId(0), 1).expect("survivor");
        let joined = joined_state(&mesh.links, &key);
        Self {
            sessions,
            mesh,
            key,
            joined,
            _survivor: survivor,
        }
    }

    fn dispatch(&self, frame: MeshControlFrame) {
        dispatch_mesh_control(
            frame,
            RelayId(2),
            0,
            &self.joined,
            &self.sessions,
            &self.mesh,
        );
    }
}

/// A home slot whose newest generation departed is replayed as that
/// generation's live history — connected, departed, then (for a drop)
/// disconnected — and nothing else is: not a departure this relay learned
/// from a peer, not one whose leave is already decided, not one with no
/// generation, and not a slot whose new generation is already active here.
#[test]
fn join_replays_each_departed_home_generation_before_its_departure() {
    let key = control_key();
    let makers = crate::consensus::new_decision_makers();
    let _ = crate::test_support::seed_maker(
        &makers,
        &key,
        crate::consensus::Authority::SelfRelay,
        &[],
        &[1, 2, 3, 4],
    );
    depart(&makers, &key, 1, 11);
    // Homed, departed on generation 22, and already active again on 23.
    depart(&makers, &key, 2, 22);
    let conditions = new_conditions_registry();
    activate_conditions(
        &conditions,
        &key,
        SlotId(2),
        SlotConditions {
            slot: 2,
            rtt_us: 20_000,
            lost_packets: 0,
            sent_packets: 1,
            connection_epoch: Some(23),
        },
    );
    // Homed, with its leave decided.
    makers.observe_frame(&key, SlotId(3), rally_point_proto::ids::GameFrameCount(9));
    depart(&makers, &key, 3, 33);
    assert!(makers.decide_leave(&key, SlotId(3), DROPPED).is_some());
    // Homed, departed with no generation.
    makers.record_departure(
        &key,
        SlotId(4),
        crate::consensus::DepartureStamps::default(),
        DROPPED,
    );
    // Learned from slot 5's home.
    depart(&makers, &key, 5, 55);

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_local_slots_on_join(&conditions, &makers, &control_tx, &key);
    let frames: Vec<_> = std::iter::from_fn(|| control_rx.try_recv().ok())
        .map(|frame| match frame.kind {
            Some(mesh_control_frame::Kind::SlotPresent(present)) => {
                format!("present {}", present.slot)
            }
            Some(mesh_control_frame::Kind::SlotConnectivity(change)) => format!(
                "connected {} {} {:?}",
                change.slot, change.connected, change.connection_epoch
            ),
            Some(mesh_control_frame::Kind::SlotDeparted(departed)) => {
                format!("departed {} {:?}", departed.slot, departed.connection_epoch)
            }
            other => panic!("unexpected reconcile frame {other:?}"),
        })
        .collect();
    assert_eq!(
        frames,
        [
            "present 2",
            "connected 2 true Some(23)",
            "connected 1 true Some(11)",
            "departed 1 Some(11)",
            "connected 1 false Some(11)",
        ]
    );
}

/// A peer whose link to slot 1's home died right after it learned the slot's
/// first generation missed the drop, the reconnect on a second generation and
/// that generation's drop. The redialed link's Join moves it onto the second
/// generation and records the departure with its drop hold, so a survivor's
/// drop request is honored there instead of the session stalling on a slot
/// that is gone.
#[test]
fn a_redialed_home_moves_a_peer_onto_a_departed_generation_it_never_saw() {
    let peer = Peer::new();
    let key = &peer.key;
    peer.dispatch(slot_present_frame(key.session, SlotId(1)));
    peer.dispatch(connectivity(key, 1, true, 1));

    let home = crate::consensus::new_decision_makers();
    let _ = crate::test_support::seed_maker(
        &home,
        key,
        crate::consensus::Authority::Peer,
        &[0, 1],
        &[1],
    );
    depart(&home, key, 1, 1);
    assert!(matches!(
        home.resolve_reconnect(key, SlotId(1), Some(2), true, || {})
            .admission,
        crate::consensus::ReconnectAdmission::Admitted { reinstated: true }
    ));
    depart(&home, key, 1, 2);
    for frame in join_frames(&new_conditions_registry(), &home, key) {
        peer.dispatch(frame);
    }

    let makers = &peer.mesh.session.decision_makers;
    assert!(makers.has_departure(key, SlotId(1)), "departure recorded");
    assert!(
        peer.mesh.session.drop_holds.is_pending(key, SlotId(1)),
        "drop held"
    );
    assert!(makers.connection_epoch_matches(key, SlotId(1), Some(2)));
    assert!(makers.connected_slots(key).is_empty());

    peer.dispatch(MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
            slot: 1,
            requester: 0,
        })),
    });
    assert!(
        !peer.mesh.session.drop_holds.is_pending(key, SlotId(1)),
        "the request decides the held drop"
    );
}

/// A relay that learned a departure from the slot's home restates only the
/// departure, never the generation's activation: it may have missed a newer
/// generation its peer holds live, and that generation must stay live there.
#[test]
fn a_second_hand_departure_never_retires_a_live_generation() {
    let peer = Peer::new();
    let key = &peer.key;
    peer.dispatch(slot_present_frame(key.session, SlotId(1)));
    peer.dispatch(connectivity(key, 1, true, 3));

    let bystander = crate::consensus::new_decision_makers();
    let _ = crate::test_support::seed_maker(
        &bystander,
        key,
        crate::consensus::Authority::Peer,
        &[0, 1],
        &[],
    );
    depart(&bystander, key, 1, 2);
    for frame in join_frames(&new_conditions_registry(), &bystander, key) {
        peer.dispatch(frame);
    }

    let makers = &peer.mesh.session.decision_makers;
    assert!(!makers.has_departure(key, SlotId(1)));
    assert!(!peer.mesh.session.drop_holds.is_pending(key, SlotId(1)));
    assert_eq!(makers.connected_slots(key), [(SlotId(1), 3)]);
}

/// A peer that already saw the departed generation live ends exactly where it
/// was: the restated activation is refused on its down generation, and the
/// departure and its hold stand.
#[test]
fn a_peer_that_saw_the_departure_live_keeps_its_hold() {
    let peer = Peer::new();
    let key = &peer.key;
    peer.dispatch(slot_present_frame(key.session, SlotId(1)));
    peer.dispatch(connectivity(key, 1, true, 1));

    let home = crate::consensus::new_decision_makers();
    let _ = crate::test_support::seed_maker(
        &home,
        key,
        crate::consensus::Authority::Peer,
        &[0, 1],
        &[1],
    );
    depart(&home, key, 1, 1);
    let frames = join_frames(&new_conditions_registry(), &home, key);
    // The live departure, then the redial's whole replay.
    let live = frames
        .iter()
        .find(|frame| matches!(frame.kind, Some(mesh_control_frame::Kind::SlotDeparted(_))))
        .cloned()
        .expect("a departure is replayed");
    peer.dispatch(live);
    for frame in frames {
        peer.dispatch(frame);
    }

    let makers = &peer.mesh.session.decision_makers;
    assert!(makers.has_departure(key, SlotId(1)));
    assert!(peer.mesh.session.drop_holds.is_pending(key, SlotId(1)));
    assert!(makers.connection_epoch_matches(key, SlotId(1), Some(1)));
}
