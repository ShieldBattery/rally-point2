//! Sync comparison under delayed and recovered turns.

use super::*;

#[test]
fn a_delayed_run_does_not_compare_hashes_from_different_ring_cycles() {
    let mut maker = authority_maker();
    for ordinal in 0..100u16 {
        for slot in [0, 1] {
            assert!(ordered_feed(&mut maker, slot, ordinal).is_none());
        }
    }
    for ordinal in 100..132u16 {
        assert!(ordered_feed(&mut maker, 1, ordinal).is_none());
    }
    for ordinal in 109..132u16 {
        assert!(
            ordered_feed(&mut maker, 0, ordinal).is_none(),
            "equal simulations must not compare different ring cycles at {ordinal}"
        );
    }
    for ordinal in 100..109u16 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 124);
}

fn ordered_feed(maker: &mut DecisionMaker, slot: u8, ordinal: u16) -> Option<SyncDivergence> {
    maker.observe_sync(
        SlotId(slot),
        u64::from(ordinal),
        Some(u32::from(ordinal)),
        &sync_command(
            (ordinal % 16) as u8,
            expected_kind_for_ordinal(u64::from(ordinal)),
            ordinal.to_le_bytes(),
        ),
    )
}

#[test]
fn a_real_disagreement_is_detected_after_reordered_turns_recover() {
    let mut maker = authority_maker();
    for ordinal in 0..40 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
        assert!(ordered_feed(&mut maker, 1, ordinal).is_none());
    }
    for ordinal in 41..64 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    for ordinal in 40..64 {
        assert!(ordered_feed(&mut maker, 1, ordinal).is_none());
    }
    let divergence = maker
        .observe_sync(
            SlotId(0),
            40,
            Some(40),
            &sync_command(8, SYNC_KIND_UNITS, [0xFF, 0xFF]),
        )
        .expect("real mismatch");
    assert_eq!(divergence.sync_ordinal, 40);
    assert!(divergence.no_majority);
}

#[test]
fn a_turn_without_sync_closes_an_ordering_gap_without_advancing_the_sync_ring() {
    let mut maker = authority_maker();
    // Sequence 0 is a pre-sync turn; ring 0 begins at transport sequence 1.
    for slot in [0, 1] {
        for ordinal in 0..20u8 {
            let command = sync_command(
                ordinal % 16,
                expected_kind_for_ordinal(u64::from(ordinal)),
                [ordinal, 0],
            );
            assert!(
                maker
                    .observe_sync(
                        SlotId(slot),
                        u64::from(ordinal) + 1,
                        Some(u32::from(ordinal)),
                        &command
                    )
                    .is_none()
            );
        }
    }
    assert!(maker.sync.members.is_empty());
    for slot in [0, 1] {
        assert!(maker.observe_sync(SlotId(slot), 0, None, &[0x05]).is_none());
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 12);
}

#[test]
fn reordered_startup_duplicates_do_not_shift_the_sync_ordinal() {
    let mut maker = authority_maker();
    for slot in [0, 1] {
        for seq in [2, 0, 1] {
            assert!(
                maker
                    .observe_sync(
                        SlotId(slot),
                        seq,
                        Some(0),
                        &sync_command(1, SYNC_KIND_HEADER, [1, 0])
                    )
                    .is_none()
            );
        }
    }
    for ordinal in 2..24u8 {
        for slot in [0, 1] {
            assert!(
                maker
                    .observe_sync(
                        SlotId(slot),
                        u64::from(ordinal) + 1,
                        Some(u32::from(ordinal)),
                        &sync_command(
                            ordinal % 16,
                            expected_kind_for_ordinal(u64::from(ordinal)),
                            [ordinal, 0]
                        )
                    )
                    .is_none()
            );
        }
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 16);
}

#[test]
fn peer_ordering_survives_promotion_with_an_outstanding_gap() {
    let mut maker = authority_maker();
    let _ = maker.set_authority(Authority::Peer, &HashSet::new());
    for ordinal in 0..100 {
        for slot in [0, 1] {
            assert!(ordered_feed(&mut maker, slot, ordinal).is_none());
        }
    }
    for ordinal in 109..120 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    assert!(maker.sync.members.is_empty());
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    // Both members join the comparison before the recovered slot advances.
    assert!(ordered_feed(&mut maker, 1, 100).is_none());
    for ordinal in 100..109 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    for ordinal in 101..132 {
        assert!(ordered_feed(&mut maker, 1, ordinal).is_none());
    }
    for ordinal in 120..132 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 124);
}

#[test]
fn one_origins_failure_cannot_blind_the_remaining_players_even_after_promotion() {
    for ring_failure in [false, true] {
        for promote in [false, true] {
            let mut maker = authority_maker();
            if promote {
                let _ = maker.set_authority(Authority::Peer, &HashSet::new());
            }
            for slot in 0..4 {
                assert!(
                    maker
                        .observe_sync(
                            SlotId(slot),
                            0,
                            Some(0),
                            &sync_command(0, SYNC_KIND_UNITS, SYNC_A)
                        )
                        .is_none()
                );
            }
            let (seq, ring) = if ring_failure { (1, 2) } else { (4097, 1) };
            assert!(
                maker
                    .observe_sync(
                        SlotId(0),
                        seq,
                        Some(1),
                        &sync_command(ring, expected_kind_for_ordinal(u64::from(ring)), SYNC_A)
                    )
                    .is_none()
            );
            assert!(maker.sync_turns.unavailable(SlotId(0)));
            assert!(!maker.sync.dormant);
            assert!(!maker.sync.members.contains_key(&SlotId(0)));
            if promote {
                let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
            }

            // Repeated and ostensibly corrected reports cannot re-admit the
            // failed origin, but the three other origins still expose a desync.
            let mut verdicts = Vec::new();
            for ordinal in 1..20 {
                assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
                for slot in 1..4 {
                    if let Some(verdict) = maker.observe_sync(
                        SlotId(slot),
                        u64::from(ordinal),
                        Some(u32::from(ordinal)),
                        &sync_command(
                            (ordinal % 16) as u8,
                            expected_kind_for_ordinal(u64::from(ordinal)),
                            if slot == 3 { SYNC_B } else { SYNC_A },
                        ),
                    ) {
                        verdicts.push(verdict);
                    }
                }
            }
            assert_eq!(verdicts.len(), 1);
            assert_eq!(verdicts[0].sync_ordinal, 1);
            assert_eq!(verdicts[0].diverged, vec![SlotId(3)]);
            assert!(!verdicts[0].no_majority);
            assert!(!maker.sync.dormant);
            assert!(!maker.sync.members.contains_key(&SlotId(0)));
            assert!(maker.sync_turns.ordered(SlotId(1)));
            assert!(maker.sync_turns.ordered(SlotId(2)));
        }
    }
}

#[test]
fn promotion_never_aliases_a_recovered_backlog_with_a_newer_ring_cycle() {
    let mut maker = authority_maker();
    let _ = maker.set_authority(Authority::Peer, &HashSet::new());
    for ordinal in 0..100 {
        for slot in [0, 1] {
            assert!(ordered_feed(&mut maker, slot, ordinal).is_none());
        }
    }
    for ordinal in 109..132 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    for ordinal in 100..132 {
        assert!(ordered_feed(&mut maker, 1, ordinal).is_none());
    }
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    // 132 and the recovering slot's 100 have the same native ring nibble.
    assert!(ordered_feed(&mut maker, 1, 132).is_none());
    for ordinal in 100..109 {
        assert!(ordered_feed(&mut maker, 0, ordinal).is_none());
    }
    assert!(ordered_feed(&mut maker, 0, 132).is_none());
    for ordinal in 133..156 {
        for slot in [0, 1] {
            assert!(ordered_feed(&mut maker, slot, ordinal).is_none());
        }
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 148);
}

#[test]
fn turns_seen_during_an_undecided_departure_preserve_reconnect_ordering() {
    let mut maker = authority_maker();
    for slot in [0, 1] {
        assert!(ordered_feed(&mut maker, slot, 0).is_none());
    }
    maker.record_departure(SlotId(0), DepartureStamps::default(), DROPPED);
    assert!(ordered_feed(&mut maker, 0, 1).is_none());
    assert!(maker.reinstate_slot(SlotId(0)));
    assert!(ordered_feed(&mut maker, 1, 1).is_none());
    for ordinal in 2..20 {
        for slot in [0, 1] {
            assert!(ordered_feed(&mut maker, slot, ordinal).is_none());
        }
    }
    assert!(!maker.sync_turns.unavailable(SlotId(0)));
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 12);
}

#[test]
fn coverage_reports_missing_history_before_the_window_is_exhausted() {
    let mut maker = authority_maker();
    maker.expected_slots = [SlotId(0), SlotId(1), SlotId(2), SlotId(3)].into();
    maker.set_observers([SlotId(2)].into());
    maker.record_departure(SlotId(3), DepartureStamps::default(), DROPPED);
    let initial = maker.sync_coverage();
    assert_eq!(initial.expected_players, 2);
    assert_eq!(initial.waiting_slots, 2);
    assert_eq!(initial.ordered_slots, 0);

    // The mesh can attach after sequence zero, without replaying its prefix.
    ordered_feed(&mut maker, 0, 12);
    ordered_feed(&mut maker, 1, 0);
    let waiting = maker.sync_coverage();
    assert_eq!(waiting.waiting_slots, 1);
    assert_eq!(waiting.ordered_slots, 1);
    assert_eq!(waiting.unavailable_slots, 0);
    assert!(waiting.authority);
    assert!(!waiting.dormant);

    maker.observe_sync(
        SlotId(0),
        4096,
        Some(4096),
        &sync_command(0, SYNC_KIND_UNITS, SYNC_A),
    );
    let failed = maker.sync_coverage();
    assert_eq!(failed.unavailable_slots, 1);
    assert_eq!(failed.waiting_slots, 0);
    assert_eq!(failed.ordered_slots, 1);
    assert!(
        !failed.dormant,
        "one missing origin cannot disable the session comparator"
    );
    let _ = maker.set_authority(Authority::Peer, &HashSet::new());
    assert!(!maker.sync_coverage().authority);
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    let promoted = maker.sync_coverage();
    assert_eq!(promoted.unavailable_slots, failed.unavailable_slots);
    assert_eq!(promoted.ordered_slots, failed.ordered_slots);
    assert_eq!(
        promoted.comparable_slots, 0,
        "fresh authority waits for fresh votes"
    );
    assert!(promoted.authority);
}

#[test]
fn recovered_initial_history_restores_coverage_without_guessing() {
    let mut maker = authority_maker();
    ordered_feed(&mut maker, 0, 2);
    assert_eq!(maker.sync_coverage().waiting_slots, 1);
    ordered_feed(&mut maker, 0, 0);
    ordered_feed(&mut maker, 0, 1);
    assert_eq!(maker.sync_coverage().waiting_slots, 0);
    assert_eq!(maker.sync_coverage().ordered_slots, 1);
    assert_eq!(maker.sync_coverage().unavailable_slots, 0);
}

#[test]
fn ordering_failures_record_once_per_origin_without_a_desync_notice() {
    use crate::observability::flight_recorder::FlightEvent;

    for authority in [Authority::SelfRelay, Authority::Peer] {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(
            &registry,
            &k,
            bounds(0, 6),
            authority,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            None,
            false,
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);
        observe_sync(
            &registry,
            &k,
            SlotId(0),
            0,
            Some(0),
            &sync_command(0, SYNC_KIND_UNITS, SYNC_A),
        );
        // The malformed ring is queued before seq 1. Its diagnostic must name
        // seq 2, not the incoming seq 1 that finally permits it to be examined.
        observe_sync(
            &registry,
            &k,
            SlotId(0),
            2,
            Some(2),
            &sync_command(3, SYNC_KIND_HEADER, SYNC_A),
        );
        observe_sync(
            &registry,
            &k,
            SlotId(0),
            1,
            Some(1),
            &sync_command(1, SYNC_KIND_HEADER, SYNC_A),
        );
        {
            let mut makers = registry.lock();
            let maker = makers.get_mut(&k).unwrap();
            let _ = maker.set_authority(Authority::Peer, &HashSet::new());
            let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
        }
        for seq in 1..5 {
            observe_sync(
                &registry,
                &k,
                SlotId(0),
                seq,
                Some(seq as u32),
                &sync_command(2, SYNC_KIND_UNITS, SYNC_A),
            );
        }
        observe_sync(
            &registry,
            &k,
            SlotId(1),
            rally_point_transport::RECEIVE_WINDOW,
            Some(100),
            &sync_command(0, SYNC_KIND_UNITS, SYNC_A),
        );
        let events: Vec<_> = registry
            .flight_recorder()
            .events(&k)
            .into_iter()
            .filter_map(|record| match record.event {
                event @ FlightEvent::SyncOrderingUnavailable { .. } => Some(event),
                _ => None,
            })
            .collect();
        assert_eq!(
            events,
            vec![
                FlightEvent::SyncOrderingUnavailable {
                    slot: 0,
                    reason: "ring_discontinuity".to_owned(),
                    seq: 2,
                    missing_next: 2,
                    previous_ordinal: Some(1),
                    ring: Some(3),
                },
                FlightEvent::SyncOrderingUnavailable {
                    slot: 1,
                    reason: "sequence_gap".to_owned(),
                    seq: rally_point_transport::RECEIVE_WINDOW,
                    missing_next: 0,
                    previous_ordinal: None,
                    ring: Some(0),
                },
            ]
        );
        let serialized = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(serialized["event"], "sync_ordering_unavailable");
        let decoded: FlightEvent = serde_json::from_value(serialized).unwrap();
        assert_eq!(decoded, events[0]);
        assert!(
            rx.try_recv().is_err(),
            "unavailable history is not a desync verdict"
        );
    }
}
