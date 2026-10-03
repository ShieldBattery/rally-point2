//! Rollback sessions' state hash reports: judged once every report is in or the deadline passes,
//! naming the minority and any slot that kept playing without its report, and nobody when there
//! is nobody to trust. Every slot a verdict names (every player, when it names nobody) is queued
//! for eviction, claimed once, and refused readmission on its home.

use super::*;

const A: u64 = 0xaaaa;
const B: u64 = 0xbbbb;

/// An authority maker for a rollback session of `slots`.
fn rollback_maker(slots: &[u8]) -> DecisionMaker {
    let mut maker = maker();
    maker.latch_rollback(true);
    maker.set_expected_slots(slots.iter().map(|&x| SlotId(x)).collect());
    maker
}

/// This relay has forwarded `count` turns of every one of `slots`, as of `at`.
fn forward(maker: &mut DecisionMaker, slots: &[u8], count: u64, at: Instant) {
    for &slot in slots {
        maker.note_forwarded_turns(SlotId(slot), count, at);
    }
}

#[test]
fn reports_that_agree_retire_the_step_silently() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    assert!(m.observe_state_hash(SlotId(0), 8, A, start).is_empty());
    assert!(m.observe_state_hash(SlotId(1), 8, A, start).is_empty());
    // The deadline passing later finds nothing left to judge.
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE * 2)
            .is_empty()
    );
    assert!(!m.hashes.dormant);
}

#[test]
fn the_minority_is_named_when_the_rest_agree() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, B, start);
    let verdicts = m.observe_state_hash(SlotId(2), 8, A, start);
    assert_eq!(
        verdicts,
        vec![SyncDivergence {
            sync_ordinal: 8,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(1)],
            missing: Vec::new(),
        }]
    );
    assert!(!m.hashes.dormant, "the other two keep being compared");
    // The named slot takes no further part: the next step needs only the other two.
    forward(&mut m, &[0, 2], 2 * STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 16, A, start);
    assert!(m.observe_state_hash(SlotId(2), 16, A, start).is_empty());
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE * 2)
            .is_empty()
    );
}

#[test]
fn a_one_v_one_disagreement_names_nobody_and_goes_dormant() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    let verdicts = m.observe_state_hash(SlotId(1), 8, B, start);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
    assert!(verdicts[0].diverged.is_empty() && verdicts[0].missing.is_empty());
    assert!(m.hashes.dormant);
}

#[test]
fn a_slot_that_keeps_playing_without_its_report_is_named_at_the_deadline() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    // Slot 1 goes on sending turns well past the step, but never reports it.
    forward(&mut m, &[1], 8 + STATE_HASH_LIVE_TURNS, start);
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE - Duration::from_millis(1))
            .is_empty(),
        "nothing is judged before the deadline",
    );
    let verdicts = m.judge_state_hashes(start + STATE_HASH_DEADLINE);
    assert_eq!(
        verdicts,
        vec![SyncDivergence {
            sync_ordinal: 8,
            game_frame: None,
            no_majority: false,
            diverged: Vec::new(),
            missing: vec![SlotId(1)],
        }]
    );
}

#[test]
fn a_slot_whose_turns_stopped_is_left_to_the_leave_machinery() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    // Slot 1's turns stop just past the step: its link went quiet, it didn't withhold.
    forward(&mut m, &[0], 8 + STATE_HASH_LIVE_TURNS, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    assert!(!m.hashes.dormant);
}

#[test]
fn nobody_reporting_names_nobody() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], 8 + STATE_HASH_LIVE_TURNS, start);
    let verdicts = m.judge_state_hashes(start + STATE_HASH_DEADLINE);
    assert_eq!(
        verdicts.len(),
        1,
        "the first verdict leaves the comparator dormant"
    );
    assert!(verdicts[0].no_majority);
    assert_eq!(verdicts[0].missing, vec![SlotId(0), SlotId(1)]);
    assert!(m.hashes.dormant);
}

#[test]
fn reports_wait_until_the_step_is_confirmable_here() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    // Reports can reach this relay before the turns that make their step confirmable.
    m.observe_state_hash(SlotId(0), 8, A, start);
    assert!(m.observe_state_hash(SlotId(1), 8, B, start).is_empty());
    forward(&mut m, &[0], STATE_HASH_INTERVAL, start);
    assert!(
        m.judge_state_hashes(start).is_empty(),
        "slot 1's turn is still missing"
    );
    forward(&mut m, &[1], STATE_HASH_INTERVAL, start);
    let verdicts = m.judge_state_hashes(start);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
}

#[test]
fn only_the_authority_judges_but_every_relay_keeps_the_reports() {
    let start = Instant::now();
    let mut m = peer_maker();
    m.latch_rollback(true);
    m.set_expected_slots([SlotId(0), SlotId(1)].into());
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    assert!(m.observe_state_hash(SlotId(1), 8, B, start).is_empty());
    assert!(m.judge_state_hashes(start).is_empty());
    // Promoted, it judges the reports it already held.
    m.authority = Authority::SelfRelay;
    let verdicts = m.judge_state_hashes(start);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].sync_ordinal, 8);
}

#[test]
fn observers_are_neither_required_nor_compared() {
    let start = Instant::now();
    let mut m = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        [SlotId(2)].into(),
    );
    m.latch_rollback(true);
    m.set_expected_slots([SlotId(0), SlotId(1), SlotId(2)].into());
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(2), 8, B, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    assert!(m.observe_state_hash(SlotId(1), 8, A, start).is_empty());
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE * 2)
            .is_empty()
    );
}

#[test]
fn a_report_off_the_interval_is_ignored() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    for step in [0, 3] {
        m.observe_state_hash(SlotId(0), step, A, start);
        m.observe_state_hash(SlotId(1), step, B, start);
    }
    m.observe_state_hash(SlotId(0), 8, A, start);
    assert!(m.observe_state_hash(SlotId(1), 8, A, start).is_empty());
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
}

#[test]
fn a_rollback_session_ignores_native_sync_commands() {
    let mut m = rollback_maker(&[0, 1]);
    feed_auto_seq(&mut m, 1, 0, SYNC_B);
    assert_eq!(advance(&mut m, 0, SYNC_A, 20), None);
    assert!(
        m.sync.members.is_empty(),
        "the native comparator never saw them"
    );
}

#[test]
fn a_missing_report_reaches_the_coordinator_as_a_desync_notice() {
    let (registry, mut rx) = notifying_registry();
    let k = key();
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            rollback: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    let _ = registry.note_forward_advance(&k, SlotId(0), STATE_HASH_INTERVAL);
    let _ = registry.note_forward_advance(&k, SlotId(1), 8 + STATE_HASH_LIVE_TURNS);
    registry.observe_state_hash(&k, SlotId(0), 8, A);
    registry.judge_overdue_state_hashes(Instant::now() + STATE_HASH_DEADLINE);
    let notice = std::iter::from_fn(|| rx.try_recv().ok())
        .find_map(|notice| match notice {
            RelayNotice::Desync(notice) => Some(notice),
            _ => None,
        })
        .expect("the verdict is published");
    assert_eq!(notice.sync_ordinal, 8);
    assert!(!notice.no_majority);
    assert!(notice.diverged.is_empty());
    assert_eq!(
        notice.missing.iter().map(|x| x.slot).collect::<Vec<_>>(),
        vec![SlotId(1)]
    );
}

/// Slots 0 to 2 agree, slot 3 disagrees, and slot 4 keeps sending turns without ever reporting:
/// the verdict at the deadline names 3 as diverged and 4 as missing. This relay homes `homed`.
fn split_verdict(homed: &[u8]) -> (DecisionMaker, Vec<SyncDivergence>) {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3, 4]);
    m.set_homed_slots(homed.iter().map(|&x| SlotId(x)).collect());
    forward(&mut m, &[0, 1, 2, 3], STATE_HASH_INTERVAL, start);
    forward(&mut m, &[4], 8 + STATE_HASH_LIVE_TURNS, start);
    for slot in [0, 1, 2] {
        m.observe_state_hash(SlotId(slot), 8, A, start);
    }
    m.observe_state_hash(SlotId(3), 8, B, start);
    let verdicts = m.judge_state_hashes(start + STATE_HASH_DEADLINE);
    (m, verdicts)
}

#[test]
fn a_majority_verdict_queues_exactly_the_slots_it_names_for_eviction() {
    let (mut m, verdicts) = split_verdict(&[3]);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].diverged, vec![SlotId(3)]);
    assert_eq!(verdicts[0].missing, vec![SlotId(4)]);
    assert_eq!(
        m.claim_desync_evictions(),
        vec![
            DesyncEviction {
                slot: SlotId(3),
                sync_ordinal: 8,
                homed: true,
            },
            DesyncEviction {
                slot: SlotId(4),
                sync_ordinal: 8,
                homed: false,
            },
        ],
        "both named slots, and only they, are handed over",
    );
    assert_eq!(
        m.eviction(SlotId(3)),
        Some(EvictionCause::Desync),
        "the claim marks the slot this relay homes",
    );
    assert_eq!(
        m.eviction(SlotId(4)),
        None,
        "a slot homed elsewhere is that home's to mark",
    );
    for slot in [0, 1, 2] {
        assert_eq!(m.eviction(SlotId(slot)), None);
    }
}

#[test]
fn a_verdict_with_no_majority_queues_every_player() {
    let start = Instant::now();
    // Slots 0 and 1 split 2-2 against 2 and 3; slot 4 is an observer, which reports nothing.
    let mut m = rollback_maker(&[0, 1, 2, 3, 4]);
    m.set_observers([SlotId(4)].into());
    m.set_homed_slots([SlotId(0), SlotId(1), SlotId(2), SlotId(3), SlotId(4)].into());
    forward(&mut m, &[0, 1, 2, 3, 4], STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(0, A), (1, A), (2, B)] {
        m.observe_state_hash(SlotId(slot), 8, hash, start);
    }
    let verdicts = m.observe_state_hash(SlotId(3), 8, B, start);
    assert!(verdicts[0].no_majority);
    assert!(
        verdicts[0].diverged.is_empty() && verdicts[0].missing.is_empty(),
        "the verdict still names nobody at fault",
    );
    assert_eq!(
        m.claim_desync_evictions()
            .iter()
            .map(|x| x.slot)
            .collect::<Vec<_>>(),
        vec![SlotId(0), SlotId(1), SlotId(2), SlotId(3)],
        "every player's game ends, without the relay picking a side",
    );
    for slot in [0, 1, 2, 3] {
        assert_eq!(m.eviction(SlotId(slot)), Some(EvictionCause::Desync));
    }
    assert_eq!(m.eviction(SlotId(4)), None, "the observer watches on");
}

#[test]
fn a_named_slot_is_claimed_once() {
    let (mut m, _) = split_verdict(&[3, 4]);
    assert_eq!(m.claim_desync_evictions().len(), 2);
    assert!(
        m.claim_desync_evictions().is_empty(),
        "a second claim finds the queue drained",
    );
    // The comparator carries on between the survivors without the named slots, and a later
    // agreement queues nothing new.
    let later = Instant::now();
    forward(&mut m, &[0, 1, 2], 2 * STATE_HASH_INTERVAL, later);
    for slot in [0, 1, 2] {
        m.observe_state_hash(SlotId(slot), 16, A, later);
    }
    assert!(m.claim_desync_evictions().is_empty());
}

#[test]
fn only_the_strict_home_marks_a_desync_eviction() {
    let mut m = rollback_maker(&[0, 1]);
    assert!(
        !m.mark_desync_evicted(SlotId(1)),
        "an empty homed set admits every slot but homes none strictly",
    );
    m.set_homed_slots([SlotId(0)].into());
    assert!(!m.mark_desync_evicted(SlotId(1)));
    assert_eq!(m.eviction(SlotId(1)), None);
    assert!(m.mark_desync_evicted(SlotId(0)));
    assert_eq!(m.eviction(SlotId(0)), Some(EvictionCause::Desync));
}

#[test]
fn the_first_eviction_cause_stands() {
    let mut m = rollback_maker(&[0, 1]);
    m.set_homed_slots([SlotId(0)].into());
    m.mark_evicted(SlotId(0), EvictionCause::Silent);
    assert!(
        m.mark_desync_evicted(SlotId(0)),
        "the slot is still homed here"
    );
    assert_eq!(m.eviction(SlotId(0)), Some(EvictionCause::Silent));
}

#[test]
fn a_desync_evicted_slot_is_refused_readmission_without_taking_the_hold() {
    let (mut maker, _start) = silence_maker(&[0, 1], &[0, 1]);
    assert!(maker.mark_desync_evicted(SlotId(1)));
    drop_slot(&mut maker, 1);

    let transition = maker.resolve_reconnect_with(SlotId(1), Some(2), true, || {});
    assert_eq!(transition.admission, ReconnectAdmission::Rejected);
    assert!(
        !transition.consume_hold,
        "the hold is what the finalized drop is decided against; a redial must not clear it",
    );
    assert!(
        maker.has_departure(SlotId(1)),
        "the refused readmission leaves the departure standing",
    );
}

#[test]
fn a_desync_evicted_slot_is_never_named_by_the_silence_watch() {
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    assert!(maker.mark_desync_evicted(SlotId(1)));
    assert_eq!(
        maker.silent_slot(start + Duration::from_secs(20), Duration::from_secs(10)),
        None,
        "a slot whose link is already closing is not named again for another reason",
    );
}

#[test]
fn a_verdict_on_the_turn_path_is_claimed_through_the_registry() {
    let registry = new_decision_makers();
    let k = key();
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1), SlotId(2)].into(),
            homed_slots: [SlotId(1)].into(),
            rollback: true,
            ..MakerSync::new(bounds(0, 20), Authority::SelfRelay)
        },
    );
    for slot in [0, 1, 2] {
        let _ = registry.note_forward_advance(&k, SlotId(slot), STATE_HASH_INTERVAL);
    }
    registry.observe_state_hash(&k, SlotId(0), 8, A);
    registry.observe_state_hash(&k, SlotId(1), 8, B);
    registry.observe_state_hash(&k, SlotId(2), 8, A);

    assert_eq!(
        registry.claim_desync_evictions(),
        vec![(
            k.clone(),
            DesyncEviction {
                slot: SlotId(1),
                sync_ordinal: 8,
                homed: true,
            },
        )],
    );
    assert_eq!(
        registry.eviction(&k, SlotId(1)),
        Some(EvictionCause::Desync)
    );
    assert!(registry.claim_desync_evictions().is_empty());
}
