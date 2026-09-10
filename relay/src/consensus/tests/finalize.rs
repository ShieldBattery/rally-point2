//! The finalized-drop seal: what a finalize accepts, what it refuses, and the proven turn count it admits.

use super::*;

/// The full home-side finalization: the seal lands, the count stamps the
/// record with its proof, the decided leave carries both, and the sealed
/// slot refuses readmission.
#[test]
fn finalize_drop_seals_stamps_and_the_leave_carries_the_count() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );

    let outcome = finalize_drop(&registry, &k, SlotId(1), None, || Some(42));
    assert_eq!(
        outcome,
        FinalizeOutcome::Finalized {
            final_turn_count: 42
        },
    );
    assert!(
        registry
            .lock()
            .get(&k)
            .unwrap()
            .finalizing_drops
            .contains(&SlotId(1)),
        "the admission seal stays after a successful finalization",
    );

    let leave = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("the authority decides");
    assert_eq!(
        leave.final_turn_count,
        Some(42),
        "a finalized drop's leave carries the sealed count",
    );
    assert!(leave.finalized, "and the proof rides the directive");
}

/// A live (reconnected) generation rejects finalization: the game
/// continues with the slot present, and nothing is sealed.
#[test]
fn finalize_drop_rejects_a_live_generation() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    assert!(activate_connection_epoch(&registry, &k, SlotId(1), 7));

    let outcome = finalize_drop(&registry, &k, SlotId(1), None, || Some(42));
    assert_eq!(outcome, FinalizeOutcome::RejectedLive);
    assert!(
        !registry
            .lock()
            .get(&k)
            .unwrap()
            .finalizing_drops
            .contains(&SlotId(1)),
        "a rejected finalization seals nothing",
    );
}

/// No gap-free cursor fails closed — and lifts the admission seal again,
/// so a later reconnect (or a later finalization, once a cursor exists)
/// still works.
#[test]
fn finalize_drop_without_a_cursor_fails_closed_and_lifts_the_seal() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );

    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || None),
        FinalizeOutcome::RejectedNoCursor,
    );
    assert!(
        !registry
            .lock()
            .get(&k)
            .unwrap()
            .finalizing_drops
            .contains(&SlotId(1)),
        "a failed finalization lifts the seal",
    );
    // A retry with a cursor succeeds.
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(7)),
        FinalizeOutcome::Finalized {
            final_turn_count: 7
        },
    );
}

/// A re-request after the leave is decided is answered from the decided
/// directive — idempotent, never a second, different seal.
#[test]
fn finalize_drop_is_idempotent_after_the_decide() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );
    let _ = finalize_drop(&registry, &k, SlotId(1), None, || Some(42));
    let _ = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("decides");

    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(999)),
        FinalizeOutcome::Finalized {
            final_turn_count: 42
        },
        "the decided directive's count answers a replayed request",
    );
}

/// The normalization matrix for observed dropped counts: kept only with
/// the proof AND the session feature; stripped (flag included) otherwise.
#[test]
fn normalize_keeps_only_proven_counts_in_enabled_sessions() {
    let proven = LeaveDirective {
        finalized: true,
        slot: 3,
        reason: DROPPED,
        apply_at_frame: 51,
        leave_seq: 4,
        final_turn_count: Some(120),
    };
    assert_eq!(
        normalize_observed_leave(&proven, true),
        proven,
        "a proven count in an enabled session passes through",
    );

    let stripped = normalize_observed_leave(&proven, false);
    assert_eq!(stripped.final_turn_count, None);
    assert!(
        !stripped.finalized,
        "a disabled session strips the proof too"
    );

    let unproven = LeaveDirective {
        finalized: false,
        ..proven
    };
    let stripped = normalize_observed_leave(&unproven, true);
    assert_eq!(
        stripped.final_turn_count, None,
        "an unproven count is stripped even in an enabled session",
    );
}

/// A finalized dropped seed keeps its count in an enabled session, and is
/// stripped everywhere else.
#[test]
fn a_finalized_dropped_seed_keeps_its_count_only_when_enabled() {
    let mut enabled =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    enabled.finalized_drops_enabled = true;
    let seeded = enabled
        .seed_departed(SlotId(1), DepartureKind::Dropped, Some(9), true)
        .expect("newly decided");
    assert_eq!(seeded.final_turn_count, Some(9));
    assert!(seeded.finalized);

    let _ = enabled.seed_departed(SlotId(2), DepartureKind::Dropped, Some(9), false);
    assert_eq!(
        enabled.decided_leaves[&SlotId(2)].final_turn_count,
        None,
        "an unproven dropped seed is stripped even when enabled",
    );

    let mut disabled =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let _ = disabled.seed_departed(SlotId(1), DepartureKind::Dropped, Some(9), true);
    assert_eq!(
        disabled.decided_leaves[&SlotId(1)].final_turn_count,
        None,
        "a disabled session strips even a proven dropped seed",
    );
}

/// The `resumed` gate does not strip a finalized drop's count: its
/// soundness rests on the home's own gap-free cursor (a home without
/// cursor continuity cannot finalize at all), not on the pre-rehome
/// forwarding history the clean-leave gate protects.
#[test]
fn a_finalized_count_survives_a_resumed_session() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    registry.lock().get_mut(&k).unwrap().resumed = true;
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );
    let _ = finalize_drop(&registry, &k, SlotId(1), None, || Some(42));

    let leave = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("decides");
    assert_eq!(leave.final_turn_count, Some(42));
    assert!(leave.finalized);
}

/// A home gained mid-session (a rehome push added the slot to this
/// relay's homed set) refuses to finalize even with a non-`None` cursor —
/// an already-serving replacement's forwarded prefix can stop short of
/// turns other relays' clients consumed during a partition. A home held
/// continuously stays finalizable through the same resumed push.
#[test]
fn finalize_refuses_a_home_gained_by_a_rehome() {
    let registry = finalized_drop_registry(&key(), &[0]);
    let k = key();
    // The rehome push: slot 1's home moves onto this relay; slot 0's stays.
    let departed: [DepartedSlot; 0] = [];
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        Some(&departed),
        true,
    );
    let framed = DepartureStamps {
        last_frame: Some(GameFrameCount(40)),
        ..DepartureStamps::default()
    };
    record_departure(&registry, &k, SlotId(1), framed.clone(), DROPPED);
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(42)),
        FinalizeOutcome::RejectedNoCursor,
        "a rehome-gained home never seals a count, cursor or not",
    );
    record_departure(&registry, &k, SlotId(0), framed, DROPPED);
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(0), None, || Some(7)),
        FinalizeOutcome::Finalized {
            final_turn_count: 7
        },
        "the continuously-held home still finalizes after the rehome",
    );
}

/// A maker created BY a resumed descriptor (a fresh replacement relay, or
/// a restart-in-place) treats every home it starts with as cursor-broken:
/// whatever prefix a stale seen registry might answer with is not the
/// slot's whole ingress history.
#[test]
fn finalize_refuses_every_home_of_a_resumed_created_maker() {
    let registry = new_decision_makers();
    let k = key();
    let departed: [DepartedSlot; 0] = [];
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(1)].into_iter().collect(),
        HashSet::new(),
        Some(&departed),
        true,
    );
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(40)),
            ..DepartureStamps::default()
        },
        DROPPED,
    );
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(42)),
        FinalizeOutcome::RejectedNoCursor,
    );
}

/// The finalize request is generation-bound: a request naming a departed
/// generation other than the one this home recorded (the slot reconnected
/// and dropped again since the request was authored) is refused rather
/// than sealed against the wrong departure; the matching generation
/// finalizes normally.
#[test]
fn finalize_rejects_a_request_naming_a_stale_generation() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    assert!(record_departure_for_epoch(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(40)),
            ..DepartureStamps::default()
        },
        DROPPED,
        Some(7),
    ));
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(42)),
        FinalizeOutcome::RejectedLive,
        "an epoch-less request against an epoch-recorded departure is stale",
    );
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), Some(3), || Some(42)),
        FinalizeOutcome::RejectedLive,
        "a request naming an older generation is stale",
    );
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), Some(7), || Some(42)),
        FinalizeOutcome::Finalized {
            final_turn_count: 42
        },
    );
}

/// A pre-frame (lobby) drop is refused WITHOUT sealing admission: nothing
/// is stalled, the decide it would feed has no scheduling basis, and a
/// seal would lock the slot out of rejoining the lobby.
#[test]
fn finalize_refuses_a_pre_frame_drop_without_sealing() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(1)].into_iter().collect(),
        HashSet::new(),
        None,
        true,
    );
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );
    assert_eq!(
        finalize_drop(&registry, &k, SlotId(1), None, || Some(3)),
        FinalizeOutcome::RejectedNoCursor,
    );
    assert!(
        !registry
            .lock()
            .get(&k)
            .unwrap()
            .finalizing_drops
            .contains(&SlotId(1)),
        "a pre-frame refusal leaves no seal behind",
    );
}
