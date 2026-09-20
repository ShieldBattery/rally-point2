//! Canonical-ordinal checksum comparison: anchoring, late reports, validation, and bounded state.

use super::*;

fn tracker_record(
    tracker: &mut SyncTracker,
    slot: u8,
    ordinal: u64,
    kind: u8,
    value: SyncValue,
) -> Option<SyncDivergence> {
    tracker.record(
        &key(),
        SlotId(slot),
        ordinal,
        SyncReport {
            kind,
            value,
            game_frame: u32::try_from(ordinal).ok(),
        },
        None,
        authority_margin(),
    )
}

fn tracker_feed(
    tracker: &mut SyncTracker,
    slot: u8,
    ordinal: u64,
    value: SyncValue,
) -> Option<SyncDivergence> {
    tracker_record(
        tracker,
        slot,
        ordinal,
        expected_kind_for_ordinal(ordinal),
        value,
    )
}

#[test]
fn first_huge_ordinal_anchors_the_reset_tracker_without_retiring_from_zero() {
    let mut tracker = SyncTracker::default();
    let first = u64::MAX - 32;

    assert_eq!(tracker_feed(&mut tracker, 0, first, SYNC_A), None);
    assert_eq!(tracker.base_ordinal, first);
    assert_eq!(tracker.members[&SlotId(0)].since, first);
    assert_eq!(tracker.members[&SlotId(0)].next_expected, first + 1);

    assert_eq!(tracker_feed(&mut tracker, 1, first, SYNC_A), None);
    for ordinal in first + 1..first + authority_margin() {
        assert_eq!(tracker_feed(&mut tracker, 0, ordinal, SYNC_A), None);
    }
    assert_eq!(
        tracker.base_ordinal,
        first + 1,
        "the first complete interval retires without a vacuous walk from ordinal zero",
    );
}

#[test]
fn a_late_older_report_is_dropped_without_corrupting_future_comparisons() {
    let mut tracker = SyncTracker::default();
    let base = 100;

    for slot in 0..3 {
        tracker_feed(&mut tracker, slot, base, SYNC_A);
    }
    tracker_feed(&mut tracker, 1, base - 1, SYNC_A);
    assert_eq!(
        tracker.members[&SlotId(1)].next_expected,
        base + 1,
        "a late older report cannot move a member backward",
    );
    assert!(
        !tracker.pending.contains_key(&(base - 1)),
        "a report below the anchored base is not compared later",
    );

    tracker_feed(&mut tracker, 0, base + 1, SYNC_A);
    tracker_feed(&mut tracker, 1, base + 1, SYNC_A);
    tracker_feed(&mut tracker, 2, base + 1, SYNC_B);
    let mut divergence = None;
    for ordinal in base + 2..=base + authority_margin() {
        divergence = divergence.or_else(|| tracker_feed(&mut tracker, 0, ordinal, SYNC_A));
    }
    assert_eq!(
        divergence,
        Some(SyncDivergence {
            sync_ordinal: base + 1,
            game_frame: u32::try_from(base + 1).ok(),
            no_majority: false,
            diverged: vec![SlotId(2)],
        }),
        "a later canonical interval still compares at its true ordinal",
    );
}

#[test]
fn malformed_kind_does_not_create_a_member_or_pending_report() {
    let mut tracker = SyncTracker::default();
    assert_eq!(
        tracker_record(&mut tracker, 0, 7, 0xF, SYNC_A),
        None,
        "a malformed hash-kind is skipped",
    );
    assert!(tracker.members.is_empty());
    assert!(tracker.pending.is_empty());
    assert!(
        !tracker.initialized,
        "no ordinal anchor from malformed input"
    );
}

#[test]
fn a_kind_parity_mismatch_is_excluded_from_an_otherwise_honest_interval() {
    let mut tracker = SyncTracker::default();
    tracker_feed(&mut tracker, 0, 0, SYNC_A);
    tracker_record(&mut tracker, 1, 0, SYNC_KIND_HEADER, SYNC_B);
    tracker_feed(&mut tracker, 2, 0, SYNC_A);

    for ordinal in 1..authority_margin() {
        assert_eq!(tracker_feed(&mut tracker, 0, ordinal, SYNC_A), None);
    }
    assert_eq!(tracker.base_ordinal, 1);
    assert!(tracker.kind_parity_warns > 0);
    assert!(!tracker.dormant, "a wrong-kind report is not a desync vote");
}

#[test]
fn same_ordinal_duplicate_keeps_the_first_value_and_progress() {
    let mut tracker = SyncTracker::default();
    tracker_feed(&mut tracker, 0, 7, SYNC_A);
    tracker_feed(&mut tracker, 0, 7, SYNC_B);

    assert_eq!(tracker.members[&SlotId(0)].next_expected, 8);
    assert!(matches!(
        tracker.pending[&7][&SlotId(0)],
        SyncObservation::Report(SyncReport { value: SYNC_A, .. })
    ));
    assert!(tracker.duplicate_warns > 0);
}

#[test]
fn departed_slot_is_no_longer_required_for_the_next_interval() {
    let mut tracker = SyncTracker::default();
    for slot in 0..3 {
        tracker_feed(&mut tracker, slot, 0, SYNC_A);
    }
    for ordinal in 1..authority_margin() {
        tracker_feed(&mut tracker, 0, ordinal, SYNC_A);
    }
    assert_eq!(tracker.base_ordinal, 1);

    tracker_feed(&mut tracker, 1, 1, SYNC_A);
    tracker.remove_member(SlotId(2));
    assert_eq!(
        tracker_feed(&mut tracker, 0, authority_margin(), SYNC_A),
        None
    );
    assert_eq!(tracker.base_ordinal, 2);
}

#[test]
fn the_in_flight_window_is_bounded_when_one_slot_stalls() {
    let mut tracker = SyncTracker::default();
    tracker_feed(&mut tracker, 1, 0, SYNC_A);
    for ordinal in 0..SYNC_WINDOW as u64 + 6 {
        tracker_feed(&mut tracker, 0, ordinal, SYNC_A);
    }
    assert!(tracker.evict_warns > 0, "a stalled slot triggered eviction");
    assert!(tracker.pending.len() <= SYNC_WINDOW);
}

#[test]
fn multiple_sync_commands_in_one_turn_advance_the_ordinal_by_one() {
    let mut m = authority_maker();
    let mut commands = sync_command(0, expected_kind_for_ordinal(0), SYNC_A);
    commands.extend(sync_command(1, expected_kind_for_ordinal(1), SYNC_A));
    commands.extend(sync_command(2, expected_kind_for_ordinal(2), SYNC_A));
    assert_eq!(
        m.observe_ordered_sync(SlotId(0), Some(1000), &commands),
        None
    );
    assert_eq!(m.sync.members[&SlotId(0)].next_expected, 1);
    assert_eq!(m.sync.multi_sync_warns, 1);
}

#[test]
fn a_one_turn_sync_flood_cannot_vault_the_eviction_window() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_A);

    let mut flood = Vec::new();
    for ring in 0..(SYNC_WINDOW as u8 + 4) {
        flood.extend(sync_command(
            ring % 16,
            expected_kind_for_ordinal(u64::from(ring % 16)),
            SYNC_B,
        ));
    }
    assert_eq!(m.observe_ordered_sync(SlotId(0), Some(2000), &flood), None);
    assert_eq!(m.sync.members[&SlotId(0)].next_expected, 1);
    assert_eq!(m.sync.base_ordinal, 0);
    assert!(
        m.sync
            .pending
            .get(&0)
            .is_some_and(|reports| reports.contains_key(&SlotId(1))),
    );
}
#[test]
fn a_confirmed_minority_cannot_rejoin_from_a_later_ordered_report() {
    let mut tracker = SyncTracker::default();
    for slot in 0..3 {
        tracker_feed(
            &mut tracker,
            slot,
            0,
            if slot == 2 { SYNC_B } else { SYNC_A },
        );
    }
    let divergence =
        (1..authority_margin()).find_map(|ordinal| tracker_feed(&mut tracker, 0, ordinal, SYNC_A));
    assert_eq!(divergence.unwrap().diverged, vec![SlotId(2)]);

    tracker_feed(&mut tracker, 2, authority_margin(), SYNC_B);
    assert!(tracker.excluded.contains(&SlotId(2)));
    assert!(!tracker.members.contains_key(&SlotId(2)));
    assert!(
        !tracker
            .pending
            .values()
            .any(|reports| reports.contains_key(&SlotId(2))),
        "a queued minority report cannot re-enter the survivor comparison",
    );
}
