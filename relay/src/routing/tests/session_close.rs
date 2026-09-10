//! Tearing a session's serving state down: what a refused admission leaves
//! behind, what the emptied-session close reports and erases, and the
//! reconnect promise that defers it.

use super::*;

/// A refused admission's light teardown removes exactly the scaffolding
/// the failed attempt created — the first-touch gate, the empty journal
/// reservation, any mark — and nothing anyone else owns: not a retired
/// tombstone, not an occupied session's gate, not a journal with
/// entries.
#[test]
fn a_refused_admission_leaves_no_scaffolding() {
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    mesh.provisional_turns.arm();
    let k = key();

    // The refusal path's residue: the register attempt touched the gate,
    // the reservation created the empty journal entry.
    let _ = mesh.gates.with_ingress(&k, || ());
    assert!(mesh.provisional_turns.reserve(&k));
    abandon_refused_admission(&sessions, &mesh, &k);
    assert_eq!(
        mesh.gates.tracked(),
        0,
        "the refused session's gate is gone"
    );
    assert!(
        mesh.provisional_turns.discard_if_empty(&k),
        "the empty reservation is gone too (an absent journal reads empty)",
    );

    // A retired gate is a tombstone: kept.
    mesh.gates.retire(&k);
    abandon_refused_admission(&sessions, &mesh, &k);
    assert_eq!(mesh.gates.tracked(), 1, "the tombstone stands");
    mesh.gates.reopen(&k);

    // An occupied roster owns the session's state: kept.
    let (_reg, _inbox) = register(&sessions, &k, SlotId(0), 1).expect("registers");
    assert!(mesh.provisional_turns.reserve(&k));
    abandon_refused_admission(&sessions, &mesh, &k);
    assert_eq!(
        mesh.gates.tracked(),
        1,
        "a live occupant's gate (and journal state) is untouched",
    );
}

/// The session's ONLY local link cleanly leaves before the descriptor: its
/// teardown empties the roster, but the emptied-session close must keep
/// the journal (and the gate) holding that departure — discarding it
/// would erase the only record of the leave, and the descriptor would
/// then drain nothing while peer-homed survivors wait forever on an
/// expected slot with neither presence nor a departure.
#[tokio::test]
async fn an_emptied_close_keeps_an_undrained_journal() {
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    mesh.provisional_turns.arm();
    let k = key();
    let (mut g1, _i1) = register(&sessions, &k, SlotId(1), 1).expect("the leaver registers");
    g1.disarm();
    // Admission marks the undescribed session for the provisional sweep.
    assert!(
        mesh.provisional
            .mark_if_undescribed(&mesh.decision_makers, &k)
    );

    // The clean-leave intent path: journal the departure, then the full
    // link teardown with the leave already announced.
    let announced = mesh.gates.with_ingress(&k, || {
        announce_departure(
            &mesh.drop_holds,
            &mesh.decision_makers,
            &sessions,
            &mesh.links,
            &mesh.provisional_turns,
            &k,
            SlotId(1),
            LEAVE_REASON_LEFT,
            None,
            Some(3),
        )
    });
    assert_eq!(announced, Some(true), "the pre-descriptor leave journals");
    end_slot_link(&sessions, &mesh, &k, SlotId(1), 3, true);

    assert!(
        mesh.provisional_turns.has_undrained(&k),
        "the emptied close keeps the journaled departure for the descriptor",
    );
    assert!(
        mesh.provisional_turns.slot_sealed(&k, SlotId(1)),
        "the clean leave's admission seal survives the emptied close",
    );
    assert!(
        mesh.provisional.is_marked(&k),
        "the sweep mark is retained WITH the journal — clearing it while \
         keeping the journal would leave the retained state immortal if \
         no descriptor ever comes",
    );
}

#[tokio::test]
async fn slot_teardown_records_flight_events_and_the_close_flushes() {
    // The real teardown flow, through `end_slot_link`: a dropped link records
    // its disconnect and the drop hold; the session-emptying teardown records
    // the close and flushes the recording (a logged discard — no sink here).
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    let k = key();
    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();
    let (mut g1, _i1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    g1.disarm();
    let flight = mesh.decision_makers.flight_recorder().clone();

    // Slot 1's link dies without a clean leave; slot 0 remains, so the
    // session stays open and the recording keeps accumulating.
    end_slot_link(&sessions, &mesh, &k, SlotId(1), 0, false);
    let events: Vec<_> = flight.events(&k).into_iter().map(|r| r.event).collect();
    assert!(
        events.contains(
            &crate::observability::flight_recorder::FlightEvent::SlotDisconnected { slot: 1 }
        ),
        "the dropped link's disconnect is recorded: {events:?}",
    );
    assert!(
        events.contains(&crate::observability::flight_recorder::FlightEvent::DropHeld { slot: 1 }),
        "the held drop decision is recorded: {events:?}",
    );

    // The last slot leaves: the close event seals the recording and the
    // detached flush retires it (discarded — no sink configured).
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);
    for _ in 0..100 {
        if flight.recorded_sessions().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        flight.recorded_sessions().is_empty(),
        "the session-emptying teardown flushed the recording",
    );
}

#[test]
fn session_emptying_teardown_drops_the_seen_registry_entry() {
    // `mesh.seen`'s entry for a session is created lazily on the first
    // turn forwarded (there is no explicit "join" to pair a deregister
    // with) and must be dropped once the relay's last local slot for the
    // session leaves -- otherwise it outlives every other per-session
    // registry the same teardown clears, leaking one `MeshSeen` per
    // session for the process lifetime.
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    let k = key();
    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();

    crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);
    assert!(
        mesh.seen.lock().contains_key(&k),
        "marking a turn forwarded creates the session's entry",
    );

    // The only local slot leaves: the session-emptying teardown fires.
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);
    assert!(
        !mesh.seen.lock().contains_key(&k),
        "the emptied session's seen-registry entry must not survive its teardown",
    );
}

/// A started session whose last local slot drops keeps its serving state and
/// defers the coordinator close while that drop is undecided: the hold is
/// the reconnect's admission token, and the retained registries (the seen
/// entry standing in for the lobby log and replay ring here) are what make
/// the resume whole. Deciding the departure is what runs the close.
#[tokio::test]
async fn an_undecided_drop_defers_the_emptied_session_close_until_decided() {
    use crate::consensus::{self, Authority, RelayNotice};
    use crate::session::presence::Candidate;
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    mesh.decision_makers.set_notice_notifier(tx);
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&mesh.decision_makers, &k);
    consensus::observe_frame(&mesh.decision_makers, &k, SlotId(0), GameFrameCount(50));
    crate::session::presence::set_order(&mesh.presence, &k, vec![Candidate::SelfRelay]);

    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();
    // The serve path reports own presence right after registering; without a
    // live report the session is never `ever_live` and the abandoned-expiry
    // recheck below would (correctly) refuse to treat it as abandoned.
    report_own_presence(&sessions, &mesh, &k);
    crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);

    // The only local slot's link dies without a clean leave — the emptying
    // that must NOT close the session while the drop is held.
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);

    assert!(
        mesh.drop_holds.is_pending(&k, SlotId(0)),
        "the drop marked a hold",
    );
    assert!(
        mesh.seen.lock().contains_key(&k),
        "the deferred close keeps the session's serving state",
    );
    while let Ok(notice) = rx.try_recv() {
        assert!(
            !matches!(notice, RelayNotice::SessionClosed { .. }),
            "no close is reported while the drop is undecided",
        );
    }

    // The abandoned-session force-decide (the expiry effect of the timer the
    // emptying armed) decides the held drop — which is what unblocks and
    // runs the deferred close. No close has been reported for the session:
    // the emptying above deferred it.
    decide_and_broadcast_abandoned(&sessions, &mesh, &k, false);

    assert!(
        !mesh.seen.lock().contains_key(&k),
        "the decided departure ran the close",
    );
    assert!(
        !mesh.drop_holds.is_pending(&k, SlotId(0)),
        "the decided hold was released and swept",
    );
    let mut saw_closed = false;
    while let Ok(notice) = rx.try_recv() {
        saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
    }
    assert!(saw_closed, "the close reported once the drop was decided");
}

/// The clean counterpart: a last local slot that leaves cleanly (its hold
/// released by the leave-intent, so no reconnect is promised) closes
/// immediately, exactly as an emptying with nothing held always has.
#[tokio::test]
async fn a_clean_leave_does_not_defer_the_emptied_session_close() {
    use crate::consensus::{self, Authority, RelayNotice};
    use rally_point_proto::control::BufferBounds;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    mesh.decision_makers.set_notice_notifier(tx);
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&mesh.decision_makers, &k);

    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();
    crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);

    // A clean leave, announced by the control-stream handler before the
    // link ends, so `end_slot_link` skips the drop announce. No framed turn
    // was observed, so the decide itself holds for a frame basis — but the
    // clean leave released any hold, and only a *held* departure promises a
    // reconnect, so the emptying still closes.
    hold_or_decide_leave(
        &mesh.drop_holds,
        &mesh.decision_makers,
        &sessions,
        &mesh.links,
        &k,
        SlotId(0),
        LEAVE_REASON_LEFT,
    );
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, true);

    assert!(
        !mesh.seen.lock().contains_key(&k),
        "a clean emptying closes at once",
    );
    let mut saw_closed = false;
    while let Ok(notice) = rx.try_recv() {
        saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
    }
    assert!(saw_closed, "the close reported on the emptying itself");
}

/// A NEVER-started session's emptying closes immediately — nothing defers
/// it — but the undecided held drop still survives as the
/// reconnect-admission token, and the receipts that reconnect's resume
/// depends on must survive exactly as long. The teardown erasing the seen
/// state while honoring the hold would admit a resume whose
/// transport-acked holes (a pre-start turn the forward gate recorded)
/// nothing could ever seed: the fresh window's prefix wedges permanently.
#[tokio::test]
async fn a_never_started_emptying_retains_receipts_while_the_hold_survives() {
    use crate::consensus::{self, Authority, RelayNotice};
    use rally_point_proto::control::BufferBounds;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    mesh.decision_makers.set_notice_notifier(tx);
    // Descriptor-backed (a maker exists, homing slot 0) but never started.
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (mut g0, _i0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();
    // A pre-start turn passed the forward gate: seq 1 was received and
    // transport-acked while seq 0 never arrived — the acked hole the
    // resume's anchor-0 seeding must close from these receipts.
    crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 1);

    // The only local slot's link dies without a clean leave.
    end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);

    assert!(
        mesh.drop_holds.is_pending(&k, SlotId(0)),
        "the drop marked a hold — the reconnect-admission token",
    );
    let mut saw_closed = false;
    while let Ok(notice) = rx.try_recv() {
        saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
    }
    assert!(
        saw_closed,
        "a never-started emptying still closes immediately",
    );
    let receipts = crate::mesh::slot_receipts(&mesh.seen, &k, SlotId(0));
    assert_eq!(
        receipts.ahead,
        vec![1],
        "the receipts survive the close for as long as the hold does",
    );
}
