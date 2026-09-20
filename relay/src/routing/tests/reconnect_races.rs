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
    let h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

    // Simulate a reconnect for slot 1 winning the roster race: it registers
    // before this (stale, racing) disconnect teardown reaches the
    // announcement below -- mirroring a concurrent `serve_connection`
    // acquiring the roster lock first.
    let _reconnect_inbox = registered(&h.sessions, &k, SlotId(1));

    // The disconnect's teardown -- unaware the seat was already reclaimed --
    // reaches its announcement.
    announce_departure(
        &h.sessions,
        &h.mesh(&holds),
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
        !h.makers.has_departure(&k, SlotId(1)),
        "no departure record was written against the already-reconnected slot -- \
         an orphaned record would wrongly refuse every later reconnect for the slot",
    );
}

#[test]
fn old_link_teardown_cannot_erase_a_replacement_epoch() {
    use crate::consensus::Authority;
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::SlotConditions;

    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::MeshState::default();
    let k = key();
    seed_maker(&mesh.session.decision_makers, &k, Authority::Peer, &[], &[]);
    let replacement = SlotConditions {
        slot: 0,
        rtt_us: 30_000,
        lost_packets: 0,
        sent_packets: 1,
        connection_epoch: Some(22),
    };
    crate::mesh::activate_conditions(&mesh.conditions, &k, SlotId(0), replacement);
    let _ = mesh
        .session
        .decision_makers
        .ingest_local_condition(&k, &replacement);
    mesh.session
        .decision_makers
        .observe_frame(&k, SlotId(0), GameFrameCount(40));

    // The old task has already freed its roster seat and is finishing its
    // cleanup after the replacement published epoch 22.
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 11, false);

    let published = crate::mesh::snapshot_conditions(&mesh.conditions, &k)
        .expect("replacement conditions survive stale teardown");
    assert_eq!(published.slots[0].connection_epoch, Some(22));
    assert_eq!(
        mesh.session.decision_makers.slot_frame(&k, SlotId(0)),
        Some(GameFrameCount(40)),
    );
    assert!(!mesh.session.decision_makers.has_departure(&k, SlotId(0)));
    assert!(!mesh.session.drop_holds.is_pending(&k, SlotId(0)));
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
    seed_maker(&makers, &k, Authority::SelfRelay, &[0, 1], &[]);
    makers.observe_frame(&k, SlotId(0), GameFrameCount(50));
    makers.observe_frame(&k, SlotId(1), GameFrameCount(50));
    presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);

    let _i0 = registered(&sessions, &k, SlotId(0));
    let _i1 = registered(&sessions, &k, SlotId(1));
    let _ = makers.note_slot_present(&k, SlotId(0));
    let _ = makers.note_slot_present(&k, SlotId(1));
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
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
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
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
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
    let _ri0 = registered(&sessions, &k, SlotId(0));
    assert!(
        holds.take_if_pending(&k, SlotId(0), || makers.reinstate_slot(&k, SlotId(0))),
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
    let _ri1 = registered(&sessions, &k, SlotId(1));
    assert!(
        holds.take_if_pending(&k, SlotId(1), || makers.reinstate_slot(&k, SlotId(1))),
        "the hold was pending and reinstate succeeded",
    );
    report_own_presence(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );

    // The whole flap decided no leave, and the session continues with both slots.
    let (departures, directives) = makers.leave_reconcile(&k);
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
    let mut inbox0 = registered(&sessions, &k, SlotId(0));
    let mut inbox1 = registered(&sessions, &k, SlotId(3));

    fan_out_connectivity(&sessions, &k, SlotId(3), false, None);

    assert_eq!(
        inbox0.try_recv_connectivity_change(),
        Some((SlotId(3), false, None)),
        "slot 0 hears it",
    );
    assert_eq!(
        inbox1.try_recv_connectivity_change(),
        Some((SlotId(3), false, None)),
        "and so does the subject slot itself",
    );
}
