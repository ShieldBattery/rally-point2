//! Coordinator-seeded departures on a resumed or re-homed session.

use super::*;

#[test]
fn seed_departed_is_decided_and_re_broadcast_verbatim_on_promotion() {
    // A rehome-seeded departure on a non-authority relay is already decided (not
    // "undecided"), and a later promotion re-broadcasts it verbatim — firing no
    // fresh departure notice, since a fresh relay resuming a session must not
    // re-report a departure the mesh already reported.
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let _ = maker.seed_departed(SlotId(1), DepartureKind::Dropped, None, false);
    assert!(
        !maker.has_undecided_departure(),
        "a seeded departure is already decided, never left undecided",
    );

    let (all, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(
        all.iter()
            .any(|l| l.slot == 1 && l.reason == LEAVE_REASON_DROPPED),
        "the seeded dropped leave is re-broadcast verbatim on promotion",
    );
    assert!(
        fresh.is_empty(),
        "a seeded (already decided) leave fires no fresh departure notice",
    );
}

#[test]
fn seed_departed_maps_the_kind_to_the_native_reason() {
    // A left departure seeds the native "player left" reason, a dropped one the
    // dropped reason — so a promotion re-broadcast renders the correct wording.
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let _ = maker.seed_departed(SlotId(1), DepartureKind::Left, None, false);
    let _ = maker.seed_departed(SlotId(2), DepartureKind::Dropped, None, false);
    assert_eq!(maker.decided_leaves[&SlotId(1)].reason, LEAVE_REASON_LEFT);
    assert_eq!(
        maker.decided_leaves[&SlotId(2)].reason,
        LEAVE_REASON_DROPPED
    );
}

/// The coordinator-retained final turn count survives into the seeded
/// directive: a survivor that never received the original directive picks
/// the leave up from this seeded copy on reconnect (`leave_reconcile`), and
/// must schedule its application at the same consumption count every other
/// survivor used — the count is not cosmetic the way the seeded apply
/// frame is. A count-less seed stays count-less (frame fallback).
#[test]
fn seed_departed_carries_the_original_directives_final_turn_count() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let _ = maker.seed_departed(SlotId(1), DepartureKind::Left, Some(312), false);
    let _ = maker.seed_departed(SlotId(2), DepartureKind::Dropped, None, false);
    assert_eq!(maker.decided_leaves[&SlotId(1)].final_turn_count, Some(312),);
    assert_eq!(maker.decided_leaves[&SlotId(2)].final_turn_count, None);
    // A promotion re-broadcasts the seeded directive verbatim, count included.
    let (all, _) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(
        all.iter()
            .any(|l| l.slot == 1 && l.final_turn_count == Some(312)),
        "the re-broadcast seeded leave keeps the original count",
    );
}

/// A dropped seed's count is discarded at this ingress no matter what the
/// carrier holds: only clean leaves may carry counts, and the seed may
/// have travelled through a coordinator or peer running code that
/// predates that rule.
#[test]
fn seed_departed_strips_a_dropped_seeds_count() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let _ = maker.seed_departed(SlotId(1), DepartureKind::Dropped, Some(99), false);
    assert_eq!(maker.decided_leaves[&SlotId(1)].final_turn_count, None);
}

/// The first seed of a slot returns the newly decided directive — the copy
/// the descriptor path fans to already-connected local survivors — and a
/// repeat (an idempotent descriptor replay) returns nothing to deliver.
#[test]
fn seed_departed_returns_the_newly_decided_directive_exactly_once() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let first = maker.seed_departed(SlotId(1), DepartureKind::Left, Some(7), false);
    assert_eq!(
        first.map(|l| (l.slot, l.final_turn_count)),
        Some((1, Some(7)))
    );
    assert_eq!(
        maker.seed_departed(SlotId(1), DepartureKind::Left, Some(7), false),
        None,
        "a replayed seed decides nothing new",
    );
}

/// A resumed descriptor's latches and seeds install atomically with the
/// maker becoming visible in the registry: the instant `sync_maker`
/// returns, the maker is already resumed (so a racing clean-leave decide
/// can never stamp an exact count) and started, and the returned batch
/// carries the seeded directive for local fan-out — a client admitted
/// before the descriptor did its one leave reconciliation at registration
/// and would otherwise never hear of the seeded departure.
#[test]
fn a_resumed_sync_installs_the_latch_and_returns_the_seeds() {
    let registry = new_decision_makers();
    let k = key();
    let departed = [DepartedSlot {
        finalized: false,
        slot: SlotId(2),
        kind: DepartureKind::Left,
        final_turn_count: Some(41),
    }];
    let leaves = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        Some(&departed),
        false,
    );
    assert!(
        leaves
            .iter()
            .any(|l| l.slot == 2 && l.final_turn_count == Some(41)),
        "the seeded directive is in the broadcast batch",
    );
    {
        let makers = registry.lock();
        let maker = makers.get(&k).expect("maker created");
        assert!(maker.resumed, "the resumed latch is set before exposure");
        assert!(
            maker.is_started(),
            "the started latch is set before exposure"
        );
    }

    // A replayed resumed descriptor (an idempotent coordinator re-push)
    // reconciles the existing maker and has nothing new to broadcast.
    let replayed = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        Some(&departed),
        false,
    );
    assert!(
        replayed.iter().all(|l| l.slot != 2),
        "a replayed seed is not re-decided or re-delivered",
    );
}

/// A resumed re-push onto a relay that already holds the maker (it was
/// serving the session when the rehome happened) seeds any departure it
/// had not yet learned and returns it for broadcast, so survivors on this
/// relay hear of a leave that only the coordinator still knew.
#[test]
fn a_resumed_repush_seeds_into_an_existing_maker() {
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
    assert!(!registry.lock().get(&k).unwrap().resumed);

    let departed = [DepartedSlot {
        finalized: false,
        slot: SlotId(3),
        kind: DepartureKind::Dropped,
        final_turn_count: None,
    }];
    let leaves = sync_maker(
        &registry,
        &k,
        bounds(1, 6),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        Some(&departed),
        false,
    );
    assert!(
        leaves
            .iter()
            .any(|l| l.slot == 3 && l.reason == LEAVE_REASON_DROPPED),
        "the newly seeded dropped leave is in the broadcast batch",
    );
    assert!(registry.lock().get(&k).unwrap().resumed);
}
