//! The retained per-session load state the heartbeat restates.

use super::*;

#[test]
fn retained_load_state_outlives_the_links_it_was_recorded_from() {
    // The heartbeat's durability rests on this: the sets are cumulative, so a
    // slot that arrived, reported its game loop, and then lost its link is
    // still reported as having got there — which is exactly the evidence a
    // tenant needs to attribute a load nobody finished.
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(1), SlotId(2)].into_iter().collect();
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

    record_slot_connected(&registry, &k, SlotId(2), false);
    record_slot_connected(&registry, &k, SlotId(1), false);
    record_slot_started(&registry, &k, SlotId(2));
    assert!(!note_slot_present(&registry, &k, SlotId(1)));
    assert!(
        note_slot_present(&registry, &k, SlotId(2)),
        "the last expected slot fires the coverage latch",
    );
    let latched_at = load_state_of(&registry, &k).started_at_ms;
    assert!(
        latched_at.is_some(),
        "the relay whose own latch fired stamps the instant it reports",
    );

    // Both slots' links end.
    assert!(remove_slot_for_epoch(&registry, &k, SlotId(1), None));
    assert!(remove_slot_for_epoch(&registry, &k, SlotId(2), None));

    let load = load_state_of(&registry, &k);
    assert_eq!(
        load.ever_connected,
        vec![SlotId(1), SlotId(2)],
        "both arrivals survive their links, ascending",
    );
    assert_eq!(load.started, vec![SlotId(2)]);
    assert_eq!(
        load.started_at_ms, latched_at,
        "the latch instant is unmoved by anything after it",
    );

    // A reconnect re-reports an arrival; the union absorbs it unchanged.
    record_slot_connected(&registry, &k, SlotId(1), true);
    assert_eq!(
        load_state_of(&registry, &k).ever_connected,
        load.ever_connected
    );
}

#[test]
fn a_session_without_a_maker_retains_no_load_state() {
    // A session run without a descriptor has no maker to retain anything. It
    // still reports its facts as notices; the heartbeat simply carries empty
    // sets for it, which omits the fields from the wire entirely.
    let registry = new_decision_makers();
    let k = key();
    record_slot_connected(&registry, &k, SlotId(0), false);
    record_slot_started(&registry, &k, SlotId(0));
    assert_eq!(load_state_of(&registry, &k), RetainedLoadState::default());
}

#[test]
fn a_peer_adopting_the_start_directive_stands_in_its_own_start_instant() {
    // The authority's notice can be lost and the authority can die before its
    // next beat, leaving no relay to restate the start it decided. A peer that
    // adopted the directive stamps its own clock, so some relay always has an
    // instant to restate; the coordinator keeps the first it is told, so the
    // authority's earlier stamp still wins wherever it arrives.
    let registry = new_decision_makers();
    let k = key();
    let expected: HashSet<SlotId> = [SlotId(0)].into_iter().collect();
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
    let before = now_ms();
    adopt_session_start(&registry, &k, Some(4));
    assert!(session_started(&registry, &k));
    let adopted_at = load_state_of(&registry, &k)
        .started_at_ms
        .expect("the adopting peer stamps an instant of its own");
    assert!(adopted_at >= before, "stamped from this relay's own clock");

    // The directive is re-delivered (an authority handoff re-firing it, a
    // late slot's re-push) — the first instant stands.
    adopt_session_start(&registry, &k, Some(4));
    assert_eq!(load_state_of(&registry, &k).started_at_ms, Some(adopted_at));
}

// -- Initial buffer depth sized at the coverage latch --
