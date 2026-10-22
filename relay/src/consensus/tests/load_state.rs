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
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            expected_slots: expected,
            ..MakerSync::new(bounds(1, 6), Authority::SelfRelay)
        },
    );

    registry.note_slot_connected(&k, SlotId(2), false, None);
    registry.note_slot_connected(&k, SlotId(1), false, None);
    registry.note_slot_started(&k, SlotId(2));
    assert!(!registry.note_slot_present(&k, SlotId(1)));
    assert!(
        registry.note_slot_present(&k, SlotId(2)),
        "the last expected slot fires the coverage latch",
    );
    let latched_at = load_state_of(&registry, &k).started_at_ms;
    assert!(
        latched_at.is_some(),
        "the relay whose own latch fired stamps the instant it reports",
    );

    // Both slots' links end.
    assert!(registry.remove_slot_for_epoch(&k, SlotId(1), None));
    assert!(registry.remove_slot_for_epoch(&k, SlotId(2), None));

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
    registry.note_slot_connected(&k, SlotId(1), true, None);
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
    registry.note_slot_connected(&k, SlotId(0), false, None);
    registry.note_slot_started(&k, SlotId(0));
    assert_eq!(load_state_of(&registry, &k), RetainedLoadState::default());
}

#[test]
fn turn_evidence_is_home_first_hand_and_outlives_the_link() {
    // The relay's own record that a home client's turns got here. Kept apart from the client's start report so a slot can be forwarded
    // without having claimed anything, and claim without being forwarded.
    let registry = new_decision_makers();
    let k = key();
    let _ = registry.sync_maker(&k, MakerSync::new(bounds(1, 6), Authority::Peer));
    registry.note_slot_connected(&k, SlotId(1), false, None);
    registry.note_slot_connected(&k, SlotId(2), false, None);
    // Slot 1 claims its loop is running but no turn of its ever arrived.
    registry.note_slot_started(&k, SlotId(1));
    // Slot 2 never claimed anything, yet its seed and its loop's turns flow.
    registry.note_unframed_home_turn(&k, SlotId(2));
    registry.observe_turn_frame(
        &k,
        SlotId(2),
        3,
        GameFrameCount(0),
        crate::consensus::delivery::DeliveryHome::Local,
    );
    // Slot 3 is a peer's home client; this relay only carries its turns.
    registry.observe_turn_frame(
        &k,
        SlotId(3),
        3,
        GameFrameCount(0),
        crate::consensus::delivery::DeliveryHome::Peer(rally_point_proto::ids::RelayId(9)),
    );
    assert!(registry.remove_slot_for_epoch(&k, SlotId(2), None));

    let load = load_state_of(&registry, &k);
    assert_eq!(load.started, vec![SlotId(1)]);
    assert_eq!(
        load.forwarded,
        vec![SlotId(2)],
        "a start claim is not a forwarded turn, and a departed link keeps its record",
    );

    // Without a maker there is nowhere to retain the evidence.
    let other = SessionKey {
        session: SessionId(99),
        ..key()
    };
    registry.note_unframed_home_turn(&other, SlotId(1));
    assert_eq!(
        load_state_of(&registry, &other),
        RetainedLoadState::default()
    );
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
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            expected_slots: expected,
            ..MakerSync::new(bounds(1, 6), Authority::Peer)
        },
    );
    let before = unix_millis();
    registry.adopt_session_start(&k, Some(4));
    assert!(registry.is_started(&k));
    let adopted_at = load_state_of(&registry, &k)
        .started_at_ms
        .expect("the adopting peer stamps an instant of its own");
    assert!(adopted_at >= before, "stamped from this relay's own clock");

    // The directive is re-delivered (an authority handoff re-firing it, a
    // late slot's re-push) — the first instant stands.
    registry.adopt_session_start(&k, Some(4));
    assert_eq!(load_state_of(&registry, &k).started_at_ms, Some(adopted_at));
}

// -- Initial buffer depth sized at the coverage latch --
