//! A reconnect racing its own link's teardown, and the connectivity fan-out
//! that tells survivors about the flap.

use super::*;

/// Guards against the stale-snapshot race the `serve_connection` admission fix
/// closes: if a reconnect for the same slot wins the roster race and registers
/// before this (now-stale) disconnect teardown reaches `announce_departure`,
/// the disconnect must not mark a hold or record a departure for it. Doing so
/// would orphan a hold against a connected player — a later `RequestDrop`
/// could honor a drop against them — and would leave a permanent departure
/// record with no hold to ever release it, wrongly refusing every later
/// reconnect for the slot.
#[tokio::test]
async fn a_disconnect_announcement_stands_down_when_the_slot_has_already_reconnected() {
    let k = key();
    let (sessions, mesh_links, makers, _inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    // Simulate a reconnect for slot 1 winning the roster race: it registers
    // before this (stale, racing) disconnect teardown reaches the
    // announcement below -- mirroring a concurrent `serve_connection`
    // acquiring the roster lock first.
    let (mut reconnect_guard, _reconnect_inbox) =
        register(&sessions, &k, SlotId(1), 1).expect("the reconnect claims the roster seat");
    reconnect_guard.disarm();

    // The disconnect's teardown -- unaware the seat was already reclaimed --
    // reaches its announcement.
    announce_departure(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &crate::session::provisional_turns::ProvisionalTurnPen::default(),
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
        None,
        None,
    );

    assert!(
        !holds.is_pending(&k, SlotId(1)),
        "no hold was marked against the already-reconnected slot",
    );
    assert!(
        !consensus::slot_departed(&makers, &k, SlotId(1)),
        "no departure record was written against the already-reconnected slot -- \
         an orphaned record would wrongly refuse every later reconnect for the slot",
    );
}

#[test]
fn old_link_teardown_cannot_erase_a_replacement_epoch() {
    use crate::consensus::Authority;
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::SlotConditions;

    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    let k = key();
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let replacement = SlotConditions {
        slot: 0,
        rtt_us: 30_000,
        lost_packets: 0,
        sent_packets: 1,
        connection_epoch: Some(22),
    };
    crate::mesh::activate_conditions(&mesh.conditions, &k, SlotId(0), replacement);
    let _ = consensus::ingest_local_condition(&mesh.decision_makers, &k, &replacement);
    consensus::observe_frame(&mesh.decision_makers, &k, SlotId(0), GameFrameCount(40));

    // The old task has already freed its roster seat and is finishing its
    // cleanup after the replacement published epoch 22.
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 11, false);

    let published = crate::mesh::snapshot_conditions(&mesh.conditions, &k)
        .expect("replacement conditions survive stale teardown");
    assert_eq!(published.slots[0].connection_epoch, Some(22));
    assert_eq!(
        consensus::slot_frame(&mesh.decision_makers, &k, SlotId(0)),
        Some(GameFrameCount(40)),
    );
    assert!(!consensus::slot_departed(
        &mesh.decision_makers,
        &k,
        SlotId(0),
    ));
    assert!(!mesh.drop_holds.is_pending(&k, SlotId(0)));
}

/// The reconnection race caught live: on a single relay, both clients' links
/// blip and both re-dial. As the roster empties and refills, presence flaps the
/// buffer authority to `Peer` and back — and the promotion on the way back must
/// not decide the leaves of slots whose drop is still held (away) or already
/// reinstated (returned). No leave is ever decided, and the game continues with
/// both slots back.
///
/// Removing either half of the fix breaks this: without the promotion's
/// held-slot skip, the still-away slot's leave fires; without the re-register's
/// departure reinstatement, the just-returned slot's does.
#[tokio::test]
async fn a_single_relay_flap_during_reconnect_decides_no_leave() {
    use crate::consensus::{self, Authority};
    use crate::session::presence::{self, Candidate};
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let makers = Arc::new(consensus::new_decision_makers());
    let presence = Arc::new(presence::new_presence_registry());
    // A hold never fires on its own; the re-registers release both holds
    // explicitly, exactly as the server's re-register path does.
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    // A started single-relay session of two framed slots, this relay authority.
    let _ = consensus::sync_maker(
        &makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::observe_frame(&makers, &k, SlotId(0), GameFrameCount(50));
    consensus::observe_frame(&makers, &k, SlotId(1), GameFrameCount(50));
    presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);

    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, _i1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    g0.disarm();
    g1.disarm();
    let _ = consensus::note_slot_present(&makers, &k, SlotId(0));
    let _ = consensus::note_slot_present(&makers, &k, SlotId(1));
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(
        makers.lock().get(&k).unwrap().is_authority(),
        "the relay starts as the session authority",
    );

    // Both links die: deregister, announce a dropped departure (marking a hold),
    // then report the changed roster — the end-of-link path, in order.
    deregister(&sessions, &k, SlotId(0));
    announce_departure(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &crate::session::provisional_turns::ProvisionalTurnPen::default(),
        &k,
        SlotId(0),
        LEAVE_REASON_DROPPED,
        None,
        None,
    );
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    deregister(&sessions, &k, SlotId(1));
    announce_departure(
        &holds,
        &makers,
        &sessions,
        &mesh_links,
        &crate::session::provisional_turns::ProvisionalTurnPen::default(),
        &k,
        SlotId(1),
        LEAVE_REASON_DROPPED,
        None,
        None,
    );
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );

    assert!(
        holds.is_pending(&k, SlotId(0)) && holds.is_pending(&k, SlotId(1)),
        "both drops marked a hold",
    );
    assert!(
        !makers.lock().get(&k).unwrap().is_authority(),
        "the emptied roster demoted the relay to a peer",
    );

    // Slot 0 re-registers while its drop is still held: register, then claim +
    // reinstate atomically as the server does, then report presence — which
    // re-promotes.
    let (mut r0, _ri0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 re-registers");
    r0.disarm();
    assert!(
        holds.take_if_pending(&k, SlotId(0), || consensus::reinstate_slot(
            &makers,
            &k,
            SlotId(0)
        )),
        "the hold was pending and reinstate succeeded",
    );
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(
        makers.lock().get(&k).unwrap().is_authority(),
        "the first return re-promoted the relay — the flap the fix must survive",
    );

    // Slot 1 re-registers too.
    let (mut r1, _ri1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 re-registers");
    r1.disarm();
    assert!(
        holds.take_if_pending(&k, SlotId(1), || consensus::reinstate_slot(
            &makers,
            &k,
            SlotId(1)
        )),
        "the hold was pending and reinstate succeeded",
    );
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );

    // The whole flap decided no leave, and the session continues with both slots.
    let (departures, directives) = consensus::leave_reconcile(&makers, &k);
    assert!(
        directives.is_empty(),
        "no leave was ever decided across the flap",
    );
    assert!(
        departures.is_empty(),
        "both departures were reinstated on reconnect",
    );
    let roster = sessions.lock();
    let slots = roster.get(&k).expect("the session still has its roster");
    assert!(
        slots.contains_key(&SlotId(0)) && slots.contains_key(&SlotId(1)),
        "both slots are back",
    );
}

/// A connectivity change fans to every currently-registered local slot, each
/// receiving `(subject, connected)` — the local half of a disconnect signal.
#[tokio::test]
async fn connectivity_fans_to_every_local_slot() {
    let k = key();
    let sessions: Sessions = Arc::default();
    let (mut g0, mut inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(3), 1).expect("slot 3 registers");
    g0.disarm();
    g1.disarm();

    fan_out_connectivity(&sessions, &k, SlotId(3), false, None);

    let a = inbox0.conn_push_rx.try_recv().expect("slot 0 hears it");
    assert_eq!(a, (SlotId(3), false, None));
    let b = inbox1.conn_push_rx.try_recv().expect("slot 3 hears it too");
    assert_eq!(b, (SlotId(3), false, None));
}
