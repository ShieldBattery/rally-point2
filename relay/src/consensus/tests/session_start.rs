//! Presence coverage, the start latch, and peer-shared start reports.

use super::*;

#[test]
fn session_start_fires_once_when_live_slots_cover_expected() {
    // A single-relay session: the descriptor lists three expected slots, the
    // relay is the authority, and slots register one at a time.
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(0), SlotId(1), SlotId(2)].into_iter().collect();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        expected,
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );

    // No directive until the last expected slot completes the set.
    assert!(!note_slot_present(&registry, &k, SlotId(0)));
    assert!(!note_slot_present(&registry, &k, SlotId(1)));
    assert!(
        !session_started(&registry, &k),
        "not yet — slot 2 is missing"
    );
    assert!(
        note_slot_present(&registry, &k, SlotId(2)),
        "the last expected slot fires the directive exactly once",
    );
    assert!(session_started(&registry, &k));

    // Churn after start never re-fires: a re-announce, or a slot not in the
    // expected set, returns false and the latch stays set.
    assert!(!note_slot_present(&registry, &k, SlotId(2)));
    assert!(!note_slot_present(&registry, &k, SlotId(5)));
    assert!(session_started(&registry, &k));
}

#[test]
fn empty_expected_slots_never_fires_session_start() {
    // A descriptor without an expected set (the feature off, or a coordinator
    // that predates it): no amount of presence triggers a directive.
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(!note_slot_present(&registry, &k, SlotId(0)));
    assert!(!note_slot_present(&registry, &k, SlotId(1)));
    assert!(!session_started(&registry, &k));
}

#[test]
fn a_non_authority_accumulates_presence_and_fires_on_promotion() {
    // A peer relay records presence but never decides; a promotion re-evaluates
    // and fires the directive the previous authority never got to (point:
    // authority churn during startup).
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(0), SlotId(1)].into_iter().collect();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::Peer,
        HashSet::new(),
        expected,
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );

    // Both expected slots register, but a peer relay never fires.
    assert!(!note_slot_present(&registry, &k, SlotId(0)));
    assert!(!note_slot_present(&registry, &k, SlotId(1)));
    assert!(!session_started(&registry, &k));

    // Promote it: the accumulated live slots already cover the expected set,
    // so the re-evaluation fires now — and only once.
    let _ = set_authority(&registry, &k, Authority::SelfRelay, &HashSet::new());
    assert!(reevaluate_session_start(&registry, &k));
    assert!(session_started(&registry, &k));
    assert!(!reevaluate_session_start(&registry, &k));
}

#[test]
fn a_departure_uncovers_a_not_yet_started_session() {
    // A slot that connects then leaves before everyone is present no longer
    // counts toward coverage; the start waits for the full set again.
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(0), SlotId(1)].into_iter().collect();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        expected,
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(!note_slot_present(&registry, &k, SlotId(0)));
    // Slot 0 departs, retiring it from the live-slot set.
    record_departure(
        &registry,
        &k,
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
    );
    // Slot 1 arrives: coverage is still incomplete (slot 0 left), so no fire.
    assert!(!note_slot_present(&registry, &k, SlotId(1)));
    assert!(!session_started(&registry, &k));
}

#[test]
fn mark_session_started_latches_without_firing() {
    // A non-authority relay that receives a peer's SessionStart latches the
    // session started (so its own late slots get re-pushed) without ever
    // deciding one itself.
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(0), SlotId(1)].into_iter().collect();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::Peer,
        HashSet::new(),
        expected,
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(!session_started(&registry, &k));
    mark_session_started(&registry, &k);
    assert!(session_started(&registry, &k));
    // Even a later promotion never re-fires: the latch is already set.
    let _ = set_authority(&registry, &k, Authority::SelfRelay, &HashSet::new());
    assert!(!reevaluate_session_start(&registry, &k));
}

/// A peer relay's shared game-started report is folded into the maker so the
/// silence watch can weigh that slot, and goes no further: the slot's home
/// already told the coordinator, and a second relay telling it again would
/// attribute one client's load twice. The heartbeat's own set stays
/// first-hand for the same reason.
#[test]
fn a_peer_shared_start_report_is_recorded_without_a_coordinator_notice() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::Peer,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    record_peer_slot_started(&registry, &k, SlotId(1));
    assert!(
        rx.try_recv().is_err(),
        "only the slot's home reports the load it watched",
    );
    assert!(
        registry.lock().get(&k).unwrap().has_started(SlotId(1)),
        "the maker knows the slot is simulating",
    );
    assert!(
        load_state_of(&registry, &k).started.is_empty(),
        "the heartbeat restates only this relay's own first-hand reports",
    );
    assert!(
        started_home_slots(&registry, &k).is_empty(),
        "and re-shares only its own, so a report never loops the mesh",
    );

    // This relay's own home client reporting does notify, and does join both
    // the heartbeat's set and what the mesh reconcile re-shares.
    record_slot_started(&registry, &k, SlotId(0));
    assert!(matches!(rx.try_recv(), Ok(RelayNotice::SlotStarted(_))));
    assert_eq!(load_state_of(&registry, &k).started, vec![SlotId(0)]);
    assert_eq!(started_home_slots(&registry, &k), vec![SlotId(0)]);

    // A crossed report for a slot this relay homes changes no answer.
    record_peer_slot_started(&registry, &k, SlotId(0));
    assert!(rx.try_recv().is_err());
    assert_eq!(started_home_slots(&registry, &k), vec![SlotId(0)]);
}
