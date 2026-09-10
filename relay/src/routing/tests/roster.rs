//! Claiming and freeing a slot in the roster, the snapshots taken off it,
//! and the epoch that makes a fence probe name one link rather than one seat.

use super::*;

#[test]
fn active_conditions_sampling_requires_a_fresh_delivery() {
    let ack_only = Received {
        fresh: Vec::new(),
        carried_payloads: false,
    };
    assert!(!should_sample_active_conditions(&ack_only));

    let all_redundant = Received {
        fresh: Vec::new(),
        carried_payloads: true,
    };
    assert!(!should_sample_active_conditions(&all_redundant));

    let fresh = Received {
        fresh: vec![payload()],
        carried_payloads: true,
    };
    assert!(should_sample_active_conditions(&fresh));
}

#[test]
fn an_occupied_slot_is_refused() {
    let sessions: Sessions = Arc::default();
    let (_guard, _inbox) = register(&sessions, &key(), SlotId(0), 1).expect("first registers");
    assert!(register(&sessions, &key(), SlotId(0), 1).is_none());
}

#[test]
fn dropping_an_armed_registration_frees_the_slot() {
    let sessions: Sessions = Arc::default();
    let (guard, _inbox) = register(&sessions, &key(), SlotId(0), 1).expect("first registers");
    drop(guard);
    // The slot — and the now-empty group — are gone, so it registers anew.
    assert!(register(&sessions, &key(), SlotId(0), 1).is_some());
}

#[test]
fn live_slots_snapshots_registered_slots_per_group() {
    let sessions: Sessions = Arc::default();
    assert!(live_slots(&sessions).is_empty(), "a fresh roster is empty");

    let (mut g1, _i1) = register(&sessions, &key(), SlotId(2), 1).expect("slot 2 registers");
    let (mut g0, _i0) = register(&sessions, &key(), SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();
    g1.disarm();

    let roster = live_slots(&sessions);
    assert_eq!(roster.len(), 1);
    assert_eq!(roster[0].0, key());
    assert_eq!(
        roster[0].1,
        vec![SlotId(0), SlotId(2)],
        "the group's connected slots, in sorted order",
    );
}

#[test]
fn a_fence_probe_reaches_only_the_link_generation_it_names() {
    // A slot read from the roster can be replaced by a reconnect before the
    // probe is delivered. The replacement is a different client stream with its
    // own queue of owed reports, so it must not receive — and therefore cannot
    // ack — a probe issued against the connection it displaced.
    let sessions: Sessions = Arc::default();
    let (registration, mut inbox) =
        register(&sessions, &key(), SlotId(0), 0x51).expect("slot 0 registers");

    assert!(deliver_load_state_probe_to_slot(
        &sessions,
        &key(),
        SlotId(0),
        0x51,
        7
    ));
    assert_eq!(inbox.try_recv_load_state_probe(), Some(7));

    // The link ends and the client dials back in on a fresh epoch.
    drop((registration, inbox));
    let (mut reconnect, mut reconnect_inbox) =
        register(&sessions, &key(), SlotId(0), 0x52).expect("the reconnect claims the seat");
    reconnect.disarm();

    assert!(
        !deliver_load_state_probe_to_slot(&sessions, &key(), SlotId(0), 0x51, 8),
        "the seat is occupied, but not by the connection the probe names",
    );
    assert_eq!(reconnect_inbox.try_recv_load_state_probe(), None);
    assert!(deliver_load_state_probe_to_slot(
        &sessions,
        &key(),
        SlotId(0),
        0x52,
        9
    ));
    assert_eq!(reconnect_inbox.try_recv_load_state_probe(), Some(9));
}

#[test]
fn holds_any_slots_tracks_registration_and_release() {
    // The drain-idle predicate: empty until a slot registers, empty again once it
    // is freed — so the coordinated-drain wait converges when the last slot leaves.
    let sessions: Sessions = Arc::default();
    assert!(!holds_any_slots(&sessions), "a fresh roster holds no slots");
    let (guard, _inbox) = register(&sessions, &key(), SlotId(0), 1).expect("slot 0 registers");
    assert!(holds_any_slots(&sessions), "a registered slot is held");
    drop(guard);
    assert!(
        !holds_any_slots(&sessions),
        "freeing the last slot drops the group, so nothing is held",
    );
}

#[test]
fn a_disarmed_registration_leaves_the_slot_held() {
    // disarm hands the slot's lifetime to the link task: dropping the guard must
    // not free it, so a concurrent reconnect is still refused.
    let sessions: Sessions = Arc::default();
    let (mut guard, _inbox) = register(&sessions, &key(), SlotId(0), 1).expect("first registers");
    guard.disarm();
    drop(guard);
    assert!(register(&sessions, &key(), SlotId(0), 1).is_none());
}

#[test]
fn freeing_one_slot_leaves_a_peer_in_the_same_group() {
    let sessions: Sessions = Arc::default();
    let (slot0, _inbox0) = register(&sessions, &key(), SlotId(0), 1).expect("slot 0 registers");
    let (_slot1, _inbox1) = register(&sessions, &key(), SlotId(1), 1).expect("slot 1 registers");
    drop(slot0);
    // Slot 0 is reclaimable; slot 1 is untouched.
    assert!(register(&sessions, &key(), SlotId(0), 1).is_some());
    assert!(register(&sessions, &key(), SlotId(1), 1).is_none());
}
