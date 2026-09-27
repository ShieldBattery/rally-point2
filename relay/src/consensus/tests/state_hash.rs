//! Rollback sessions' state hash reports: judged once every report is in or the deadline passes,
//! naming the minority and any slot that kept playing without its report, and nobody when there
//! is nobody to trust.

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
    registry.note_forward_advance(&k, SlotId(0), STATE_HASH_INTERVAL);
    registry.note_forward_advance(&k, SlotId(1), 8 + STATE_HASH_LIVE_TURNS);
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
