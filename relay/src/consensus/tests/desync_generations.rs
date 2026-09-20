//! Explicit native checksum generations across repeats, omissions, and mixed clients.

use super::*;

#[test]
fn one_players_omission_does_not_hide_a_disagreement_among_other_players() {
    let mut maker = authority_maker();
    for slot in 0..4 {
        assert!(feed_generation(&mut maker, slot, 0, 0, SYNC_A).is_none());
    }
    for slot in 0..3 {
        let value = if slot == 2 { SYNC_B } else { SYNC_A };
        assert!(feed_generation(&mut maker, slot, 1, 1, value).is_none());
    }
    assert!(feed_generation(&mut maker, 3, 1, 2, SYNC_A).is_none());
    let mut verdict = None;
    for generation in 2..=1 + authority_margin() {
        if let Some(found) = feed_generation(&mut maker, 0, generation, generation, SYNC_A) {
            verdict = Some(found);
            break;
        }
    }
    let verdict = verdict.expect("three actual reports must still be compared");
    assert_eq!(verdict.sync_ordinal, 1);
    assert_eq!(verdict.diverged, vec![SlotId(2)]);
    assert!(!verdict.no_majority);
    assert!(maker.sync.members.contains_key(&SlotId(3)));
    assert_eq!(maker.sync.evict_warns, 0);
}

#[test]
fn repeated_resizes_and_ring_wraps_preserve_comparison_without_eviction() {
    let mut maker = authority_maker();
    let mut generation = 0_u64;
    for seq in 0..320 {
        if seq != 0 {
            generation += [0, 1, 2, 14, 1, 0, 3, 1][seq as usize % 8];
        }
        let value = (generation as u16).to_le_bytes();
        for slot in [0, 1] {
            assert!(feed_generation(&mut maker, slot, seq, generation, value).is_none());
            assert!(!maker.sync_turns.unavailable(SlotId(slot)));
        }
        assert!(maker.sync.pending.len() <= SYNC_WINDOW);
    }
    assert!(generation > 256);
    assert!(maker.sync.base_ordinal >= generation - authority_margin());
    assert!(!maker.sync.dormant);
    assert_eq!(maker.sync.evict_warns, 0);
}

#[test]
fn legacy_and_enhanced_origins_share_the_same_generation_coordinate() {
    let mut maker = authority_maker();
    for generation in 0..100_u64 {
        let command = sync_command(
            (generation % 16) as u8,
            expected_kind_for_ordinal(generation),
            (generation as u16).to_le_bytes(),
        );
        assert!(
            maker
                .observe_sync(SlotId(0), generation, Some(999), &command)
                .is_none()
        );
        assert!(
            maker
                .observe_sync_with_generation(
                    SlotId(1),
                    generation,
                    Some(1),
                    &command,
                    Some(generation),
                )
                .is_none()
        );
    }
    assert!(!maker.sync.dormant);
    assert!(maker.sync.base_ordinal >= 100 - authority_margin());
    assert_eq!(maker.sync.evict_warns, 0);
}

#[test]
fn invalid_generation_transitions_exclude_only_the_origin() {
    for (first, next, ring, expected) in [
        (1, 0, 0, "generation_regression"),
        (0, 2, 1, "generation_ring_mismatch"),
        (0, 15, 15, "generation_jump"),
        (0, 16, 0, "generation_jump"),
    ] {
        let mut maker = authority_maker();
        assert!(feed_generation(&mut maker, 0, 0, first, SYNC_A).is_none());
        assert!(feed_generation(&mut maker, 1, 0, first, SYNC_A).is_none());
        assert!(
            maker
                .observe_sync_with_generation(
                    SlotId(0),
                    1,
                    None,
                    &sync_command(ring, expected_kind_for_ordinal(next), SYNC_A),
                    Some(next),
                )
                .is_none()
        );
        assert_eq!(
            maker.sync_turns.failure(SlotId(0)).unwrap().reason,
            expected
        );
        assert!(!maker.sync_turns.unavailable(SlotId(1)));
        assert!(!maker.sync.members.contains_key(&SlotId(0)));
        assert!(maker.sync.members.contains_key(&SlotId(1)));
    }
}

/// The absolute sync ordinal an origin's history was recorded at survives
/// a promotion and out-of-order delivery -- and an omission that *both*
/// origins share does not strand the comparison: the next generation they
/// both reported is compared, at its true ordinal, with neither origin
/// going unavailable and nothing evicted.
///
/// The session opens with six checksum-less turns, so every origin's
/// transport sequence runs ahead of its native generation by an offset
/// nothing on the wire states. A comparator reading the ring nibble off
/// the sequence instead of the tagged generation lands on the wrong
/// epoch.
#[test]
fn enhanced_history_retains_its_ring_epoch_across_promotion_and_reordering() {
    let mut maker = authority_maker();
    let _ = maker.set_authority(Authority::Peer, &HashSet::new());
    for seq in 0..6 {
        for slot in [0, 1] {
            assert!(
                maker
                    .observe_sync_with_generation(SlotId(slot), seq, None, &[0x05], None)
                    .is_none()
            );
        }
    }
    for generation in 0..=34 {
        for slot in [0, 1] {
            assert!(
                feed_generation(&mut maker, slot, generation + 6, generation, SYNC_A).is_none()
            );
        }
    }
    // Generation 35 is omitted by both origins: their next turns carry 36
    // and 37. The later packet alone cannot establish that omission.
    assert!(feed_generation(&mut maker, 0, 42, 37, SYNC_A).is_none());
    let _ = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(feed_generation(&mut maker, 1, 41, 36, SYNC_A).is_none());
    assert!(feed_generation(&mut maker, 0, 41, 36, SYNC_B).is_none());
    let mut verdict = None;
    for generation in 38..=36 + authority_margin() {
        if let Some(found) = feed_generation(&mut maker, 0, generation + 5, generation, SYNC_A) {
            verdict = Some(found);
            break;
        }
    }
    let verdict = verdict.expect("the first checksum after the shared omission must be compared");
    assert_eq!(verdict.sync_ordinal, 36);
    assert!(verdict.no_majority, "one against one is undecidable");
    assert_eq!(maker.sync.evict_warns, 0);
    for slot in [0, 1] {
        assert!(!maker.sync_turns.unavailable(SlotId(slot)));
    }
}

#[test]
fn a_whole_ring_of_unreported_generations_is_rejected_instead_of_compared_at_the_wrong_epoch() {
    let mut tagged = authority_maker();
    let mut inferred = authority_maker();
    for generation in 0..=34 {
        for maker in [&mut tagged, &mut inferred] {
            for slot in [0, 1] {
                assert!(
                    feed_generation(
                        maker,
                        slot,
                        generation,
                        generation,
                        (generation as u16).to_le_bytes()
                    )
                    .is_none()
                );
            }
        }
    }
    // Complete transport history does not imply complete checksum history:
    // these valid turns still carry gameplay traffic while omitting 0x37.
    for generation in 35..=52 {
        for maker in [&mut tagged, &mut inferred] {
            assert!(
                feed_generation(
                    maker,
                    1,
                    generation,
                    generation,
                    (generation as u16).to_le_bytes()
                )
                .is_none()
            );
            if generation < 52 {
                assert!(
                    maker
                        .observe_sync_with_generation(
                            SlotId(0),
                            generation,
                            Some(generation as u32),
                            &[0x05],
                            None,
                        )
                        .is_none()
                );
            }
        }
    }
    let actual_generation = 52_u64;
    assert!(feed_generation(&mut tagged, 0, 52, actual_generation, 52_u16.to_le_bytes()).is_none());
    assert_eq!(
        tagged.sync_turns.failure(SlotId(0)).unwrap().reason,
        "generation_jump"
    );
    assert!(!tagged.sync_turns.unavailable(SlotId(1)));

    // Model a ring-only unwrap constrained to advances 0..=14. It accepts
    // the residue of a real +18 advance as +2, pairing different snapshots.
    let last_generation = 34;
    let delta = (actual_generation % 16 + 16 - last_generation % 16) % 16;
    assert_eq!(delta, 2);
    let guessed_generation = last_generation + delta;
    let false_verdict = feed_generation(
        &mut inferred,
        0,
        52,
        guessed_generation,
        52_u16.to_le_bytes(),
    )
    .expect("assuming the advance bound compares snapshots from different epochs");
    assert_eq!(false_verdict.sync_ordinal, 36);
    assert!(false_verdict.no_majority);
    assert_eq!(tagged.sync.evict_warns, 0);
    assert_eq!(inferred.sync.evict_warns, 0);
}
