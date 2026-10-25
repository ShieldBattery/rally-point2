//! The finalized-drop seal: what a finalize accepts, what it refuses, and the proven turn count it admits.

use super::*;

/// The full home-side finalization: the seal lands, the count stamps the
/// record with its proof, the decided leave carries both, and the sealed
/// slot refuses readmission.
#[test]
fn finalize_drop_seals_stamps_and_the_leave_carries_the_count() {
    let registry = finalized_drop_registry(&key(), &[0, 1]);
    let k = key();
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );

    let outcome = registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42));
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

    let leave = registry
        .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
        .expect("the authority decides");
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
    assert!(registry.activate_connection_epoch(&k, SlotId(1), 7));

    let outcome = registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42));
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
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );

    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Unsound),
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
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(7)),
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
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    let _ = registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42));
    let _ = registry
        .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
        .expect("decides");

    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(999)),
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
        reason: LEAVE_REASON_DROPPED,
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
    let mut enabled = peer_maker();
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

    let mut disabled = peer_maker();
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
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    let _ = registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42));

    let leave = registry
        .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
        .expect("decides");
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
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            homed_slots: [SlotId(0), SlotId(1)].into_iter().collect(),
            resumed_departed: Some(&departed),
            finalized_drops: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    let stamps = framed(40);
    registry.record_departure(&k, SlotId(1), stamps.clone(), LEAVE_REASON_DROPPED);
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42)),
        FinalizeOutcome::RejectedNoCursor,
        "a rehome-gained home never seals a count, cursor or not",
    );
    registry.record_departure(&k, SlotId(0), stamps, LEAVE_REASON_DROPPED);
    assert_eq!(
        registry.finalize_drop(&k, SlotId(0), None, || ForwardGateReading::Count(7)),
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
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            homed_slots: [SlotId(1)].into_iter().collect(),
            resumed_departed: Some(&departed),
            finalized_drops: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    registry.record_departure(&k, SlotId(1), framed(40), LEAVE_REASON_DROPPED);
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42)),
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
    assert!(registry.record_departure_for_epoch(
        &k,
        SlotId(1),
        framed(40),
        LEAVE_REASON_DROPPED,
        Some(7)
    ));
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(42)),
        FinalizeOutcome::RejectedLive,
        "an epoch-less request against an epoch-recorded departure is stale",
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), Some(3), || ForwardGateReading::Count(42)),
        FinalizeOutcome::RejectedLive,
        "a request naming an older generation is stale",
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), Some(7), || ForwardGateReading::Count(42)),
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
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            homed_slots: [SlotId(1)].into_iter().collect(),
            finalized_drops: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Count(3)),
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

/// Whether `slot`'s drop is sealed against readmission on `k`'s maker.
fn sealed(registry: &DecisionMakers, k: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(k)
        .unwrap()
        .finalizing_drops
        .contains(&slot)
}

/// A slot that departed before its first turn, after another slot's game loop
/// started: the survivors are stalled in the game's first steps waiting on it,
/// before any turn carries a frame. Its home, the single ingress it has had
/// all session, has no record of a turn from it, so the count is zero: the
/// seal lands, and the decided leave carries the zero count with its proof
/// and the earliest apply frame.
#[test]
fn finalize_seals_zero_for_a_slot_that_never_forwarded_once_a_loop_runs() {
    let k = key();
    let registry = unframed_finalized_drop_registry(&k, &[0, 1]);
    registry.note_peer_slot_started(&k, SlotId(0));
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );

    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || {
            ForwardGateReading::NeverForwarded
        }),
        FinalizeOutcome::Finalized {
            final_turn_count: 0
        },
    );
    assert!(sealed(&registry, &k, SlotId(1)));

    let leave = registry
        .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
        .expect("a counted leave commits with no framed turn once a loop runs");
    assert_eq!(leave.final_turn_count, Some(0));
    assert!(leave.finalized);
    assert_eq!(leave.apply_at_frame, 0);
}

/// An empty forward gate is a zero count only where this relay knows it has
/// seen every turn the slot could have sent. Anywhere else it is ignorance,
/// so the finalization fails closed and lifts its seal.
#[test]
fn an_empty_forward_gate_is_no_count_without_first_hand_proof() {
    let k = key();
    let never = || ForwardGateReading::NeverForwarded;

    // The maker's own record says the home forwarded one of the slot's turns:
    // the gate's state for it is gone, not empty.
    let registry = unframed_finalized_drop_registry(&k, &[0, 1]);
    registry.note_peer_slot_started(&k, SlotId(0));
    registry
        .lock()
        .get_mut(&k)
        .unwrap()
        .note_home_turn_forwarded(SlotId(1));
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, never),
        FinalizeOutcome::RejectedNoCursor,
        "a slot the home recorded forwarding has no zero count",
    );
    assert!(!sealed(&registry, &k, SlotId(1)), "the seal is lifted");

    // The slot produced a framed turn, which it can only have done through
    // its home's gate.
    let registry = unframed_finalized_drop_registry(&k, &[0, 1]);
    registry.note_peer_slot_started(&k, SlotId(0));
    registry.record_departure(&k, SlotId(1), framed(40), LEAVE_REASON_DROPPED);
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, never),
        FinalizeOutcome::RejectedNoCursor,
        "a slot with framed history has no zero count",
    );

    // This relay does not strictly home the slot: another relay's gate is
    // where its turns enter.
    let registry = unframed_finalized_drop_registry(&k, &[0]);
    registry.note_peer_slot_started(&k, SlotId(0));
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, never),
        FinalizeOutcome::RejectedNoCursor,
        "an empty gate off the slot's home is no count",
    );

    // Turns recorded above a missing first one count nothing gap-free.
    let registry = unframed_finalized_drop_registry(&k, &[0, 1]);
    registry.note_peer_slot_started(&k, SlotId(0));
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || ForwardGateReading::Unsound),
        FinalizeOutcome::RejectedNoCursor,
    );
}

/// A home gained mid-session never proves a zero count from its empty gate:
/// the slot's earlier turns entered the game through another relay.
#[test]
fn a_rehome_gained_home_never_seals_zero() {
    let k = key();
    let registry = unframed_finalized_drop_registry(&k, &[0]);
    let departed: [DepartedSlot; 0] = [];
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            homed_slots: [SlotId(0), SlotId(1)].into_iter().collect(),
            resumed_departed: Some(&departed),
            finalized_drops: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    registry.note_peer_slot_started(&k, SlotId(0));
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || {
            ForwardGateReading::NeverForwarded
        }),
        FinalizeOutcome::RejectedNoCursor,
    );
}

/// Before any game loop runs, a never-forwarded slot is still refused without
/// a seal, exactly like a lobby drop with a cursor: nothing is stalled, and a
/// seal would lock the slot out of rejoining.
#[test]
fn a_never_forwarded_slot_before_any_loop_runs_is_refused_without_sealing() {
    let k = key();
    let registry = unframed_finalized_drop_registry(&k, &[0, 1]);
    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.finalize_drop(&k, SlotId(1), None, || {
            ForwardGateReading::NeverForwarded
        }),
        FinalizeOutcome::RejectedNoCursor,
    );
    assert!(!sealed(&registry, &k, SlotId(1)));
}

/// With a game loop running and no framed turn anywhere, a leave commits only
/// when it carries a count to apply by: a counted clean leave decides at the
/// earliest frame, while an unfinalized drop, which only a frame could
/// schedule, still holds.
#[test]
fn only_a_counted_leave_commits_before_any_framed_turn() {
    let k = key();
    let registry = unframed_finalized_drop_registry(&k, &[0, 1, 2]);
    registry.note_peer_slot_started(&k, SlotId(0));

    registry.record_departure(
        &k,
        SlotId(1),
        DepartureStamps::default(),
        LEAVE_REASON_DROPPED,
    );
    assert_eq!(
        registry.decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED),
        None,
        "an unfinalized drop has nothing to schedule by",
    );

    registry.record_departure(
        &k,
        SlotId(2),
        DepartureStamps {
            final_turn_count: Some(4),
            ..DepartureStamps::default()
        },
        LEAVE_REASON_LEFT,
    );
    let leave = registry
        .decide_leave(&k, SlotId(2), LEAVE_REASON_LEFT)
        .expect("a counted clean leave commits");
    assert_eq!(leave.final_turn_count, Some(4));
    assert_eq!(leave.apply_at_frame, 0);
}
