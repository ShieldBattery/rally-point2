//! Rollback sessions' state hash reports: judged once every report is in or the deadline passes,
//! naming the minority and any slot that kept playing without its report, and nobody when there
//! is nobody to trust. What the verdicts evict is in `state_hash_evictions`.

use super::*;

pub(super) const A: u64 = 0xaaaa;
pub(super) const B: u64 = 0xbbbb;

/// An authority maker for a rollback session of `slots`.
pub(super) fn rollback_maker(slots: &[u8]) -> DecisionMaker {
    let mut maker = maker();
    maker.latch_rollback(true);
    maker.set_expected_slots(slots.iter().map(|&x| SlotId(x)).collect());
    maker
}

/// This relay has forwarded `count` turns of every one of `slots`, as of `at`.
pub(super) fn forward(maker: &mut DecisionMaker, slots: &[u8], count: u64, at: Instant) {
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
fn a_report_after_the_deadline_is_still_compared() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], 2 * STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(0), 16, A, start);
    // Slot 1 lags: its reports arrive after the deadline judged both steps on slot 0's alone.
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    let later = start + STATE_HASH_DEADLINE * 2;
    assert!(m.observe_state_hash(SlotId(1), 8, A, later).is_empty());
    let verdicts = m.observe_state_hash(SlotId(1), 16, B, later);
    assert_eq!(
        verdicts,
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: true,
            diverged: Vec::new(),
            missing: Vec::new(),
        }]
    );
    assert!(m.hashes.dormant);
}

#[test]
fn a_late_report_that_disagrees_with_the_rest_is_named() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, A, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    let verdicts = m.observe_state_hash(SlotId(2), 8, B, start + STATE_HASH_DEADLINE * 2);
    assert_eq!(
        verdicts,
        vec![SyncDivergence {
            sync_ordinal: 8,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(2)],
            missing: Vec::new(),
        }]
    );
    assert!(!m.hashes.dormant);
}

/// A verdict naming only `slot` as diverged at step 8.
fn diverged_at_8(slot: u8) -> Vec<SyncDivergence> {
    vec![SyncDivergence {
        sync_ordinal: 8,
        game_frame: None,
        no_majority: false,
        diverged: vec![SlotId(slot)],
        missing: Vec::new(),
    }]
}

#[test]
fn late_reports_name_the_minority_in_either_order() {
    for late in [[(1, B), (2, A)], [(2, A), (1, B)]] {
        let start = Instant::now();
        let mut m = rollback_maker(&[0, 1, 2]);
        forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
        m.observe_state_hash(SlotId(0), 8, A, start);
        assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
        let later = start + STATE_HASH_DEADLINE + Duration::from_secs(1);
        let [(first, first_hash), (second, second_hash)] = late;
        assert!(
            m.observe_state_hash(SlotId(first), 8, first_hash, later)
                .is_empty(),
            "one of the two hashes holds a third of the slots, so slot {second} decides it",
        );
        let verdicts = m.observe_state_hash(SlotId(second), 8, second_hash, later);
        assert_eq!(verdicts, diverged_at_8(1));
        assert!(!m.hashes.dormant);
    }
}

#[test]
fn an_even_split_is_only_called_once_every_report_is_in() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3]);
    forward(&mut m, &[0, 1, 2, 3], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, A, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    let later = start + STATE_HASH_DEADLINE + Duration::from_secs(1);
    assert!(
        m.observe_state_hash(SlotId(2), 8, B, later).is_empty(),
        "slot 3 could still make it 3-1",
    );
    let verdicts = m.observe_state_hash(SlotId(3), 8, B, later);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
    assert!(m.hashes.dormant);
}

#[test]
fn a_disagreement_at_the_deadline_waits_for_the_report_that_decides_it() {
    for (third, expected) in [(Some(A), diverged_at_8(1)), (None, Vec::new())] {
        let start = Instant::now();
        let mut m = rollback_maker(&[0, 1, 2]);
        forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
        m.observe_state_hash(SlotId(0), 8, A, start);
        m.observe_state_hash(SlotId(1), 8, B, start);
        assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
        let settled = start + STATE_HASH_DEADLINE * 2;
        if let Some(hash) = third {
            let verdicts =
                m.observe_state_hash(SlotId(2), 8, hash, settled - Duration::from_millis(1));
            assert_eq!(verdicts, expected);
            assert!(m.judge_state_hashes(settled).is_empty());
        } else {
            assert!(
                m.judge_state_hashes(settled - Duration::from_millis(1))
                    .is_empty()
            );
            // Slot 2 never reports: the step is decided on the two reports it has.
            let verdicts = m.judge_state_hashes(settled);
            assert_eq!(verdicts.len(), 1);
            assert!(verdicts[0].no_majority);
        }
    }
}

#[test]
fn a_report_for_a_step_judged_too_long_ago_is_dropped() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    // Slot 2 drops after its first two steps' turns, and the game goes on without it for longer
    // than the judged steps held.
    forward(&mut m, &[0, 1, 2], 2 * STATE_HASH_INTERVAL, start);
    m.note_departure(SlotId(2), framed(1), 0, None);
    for step in 1..=STATE_HASH_WINDOW as u64 + 1 {
        forward(&mut m, &[0, 1], step * STATE_HASH_INTERVAL, start);
        m.observe_state_hash(SlotId(0), step * STATE_HASH_INTERVAL, A, start);
        m.observe_state_hash(SlotId(1), step * STATE_HASH_INTERVAL, A, start);
        assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    }
    // It comes back, and its reports of those two steps arrive. The oldest judged step is no
    // longer held; the next oldest still is.
    assert!(m.reinstate_slot(SlotId(2)));
    let later = start + STATE_HASH_DEADLINE * 2;
    assert!(
        m.observe_state_hash(SlotId(2), STATE_HASH_INTERVAL, B, later)
            .is_empty()
    );
    assert_eq!(
        m.observe_state_hash(SlotId(2), 2 * STATE_HASH_INTERVAL, B, later),
        vec![SyncDivergence {
            sync_ordinal: 2 * STATE_HASH_INTERVAL,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(2)],
            missing: Vec::new(),
        }]
    );
}

#[test]
fn a_slot_that_goes_on_playing_without_its_report_after_its_step_was_decided_is_named() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, A, start);
    // At the deadline slot 2's turns are short of what counts its missing report against it, so
    // the step is decided without naming it.
    forward(&mut m, &[2], 8 + STATE_HASH_LIVE_TURNS - 1, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    // Its turns go on, still without the report.
    let later = start + STATE_HASH_DEADLINE + Duration::from_secs(1);
    forward(&mut m, &[2], 8 + STATE_HASH_LIVE_TURNS, later);
    assert_eq!(
        m.judge_state_hashes(later),
        vec![SyncDivergence {
            sync_ordinal: 8,
            game_frame: None,
            no_majority: false,
            diverged: Vec::new(),
            missing: vec![SlotId(2)],
        }]
    );
}

#[test]
fn a_full_window_keeps_the_step_awaiting_its_verdict() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    // Fill the window past capacity with steps beyond what is confirmable before step 8's
    // remaining reports arrive.
    let horizon = STATE_HASH_INTERVAL * (1 + STATE_HASH_WINDOW as u64);
    for step in (2 * STATE_HASH_INTERVAL..=horizon).step_by(STATE_HASH_INTERVAL as usize) {
        assert!(m.observe_state_hash(SlotId(2), step, B, start).is_empty());
    }
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, A, start);
    assert_eq!(
        m.observe_state_hash(SlotId(2), 8, B, start),
        diverged_at_8(2),
        "step 8 is still judged",
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
fn the_last_slot_left_in_the_game_is_never_judged_alone() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1]);
    forward(&mut m, &[0, 1], STATE_HASH_INTERVAL, start);
    // Slot 1 leaves; slot 0 plays on well past the step without reporting it, with nobody left
    // to compare a hash with.
    m.note_departure(SlotId(1), framed(1), 0, None);
    forward(&mut m, &[0], 8 + STATE_HASH_LIVE_TURNS, start);
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE * 3)
            .is_empty()
    );
    assert!(m.claim_desync_evictions().is_empty());
    assert!(!m.hashes.dormant);
}

/// Slots 1 and 3 diverge at step 16 and slot 2 at step 24, and slot 0's report for 16 arrives
/// after step 24 is complete.
#[test]
fn a_later_step_judged_first_leaves_the_earlier_verdict_naming_its_minority() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3, 4]);
    forward(&mut m, &[0, 1, 2, 3, 4], 3 * STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(1, B), (3, B), (2, A), (4, A)] {
        assert!(
            m.observe_state_hash(SlotId(slot), 16, hash, start)
                .is_empty()
        );
    }
    for slot in [0, 1, 3, 4] {
        assert!(m.observe_state_hash(SlotId(slot), 24, A, start).is_empty());
    }
    assert_eq!(
        m.observe_state_hash(SlotId(2), 24, 0xcccc, start),
        vec![SyncDivergence {
            sync_ordinal: 24,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(2)],
            missing: Vec::new(),
        }]
    );
    // Its eviction ends its link, so it leaves; its report of step 16, where it agreed with slots
    // 0 and 4, still backs their hash there.
    m.note_departure(SlotId(2), framed(1), 0, None);
    assert_eq!(
        m.observe_state_hash(SlotId(0), 16, A, start),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(1), SlotId(3)],
            missing: Vec::new(),
        }]
    );
    assert!(!m.hashes.dormant);
}

#[test]
fn a_slot_named_at_a_later_step_never_splits_an_earlier_one() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3]);
    forward(&mut m, &[0, 1, 2, 3], 3 * STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(3), 16, B, start);
    for slot in [0, 1, 2] {
        m.observe_state_hash(SlotId(slot), 24, A, start);
    }
    assert_eq!(m.observe_state_hash(SlotId(3), 24, 0xcccc, start).len(), 1);
    // Slot 3's report of step 16 matches slot 2's, but a named slot's report only ever settles a
    // split; it never turns a majority into one.
    m.observe_state_hash(SlotId(0), 16, A, start);
    m.observe_state_hash(SlotId(1), 16, A, start);
    assert_eq!(
        m.observe_state_hash(SlotId(2), 16, B, start),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(2)],
            missing: Vec::new(),
        }]
    );
}

#[test]
fn a_relay_told_of_a_later_verdict_judges_an_earlier_step_like_the_authority_did() {
    let start = Instant::now();
    let mut m = peer_maker();
    m.latch_rollback(true);
    m.set_expected_slots((0..5).map(SlotId).collect());
    forward(&mut m, &[0, 1, 2, 3, 4], 3 * STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(1, B), (3, B), (2, A), (4, A)] {
        m.observe_state_hash(SlotId(slot), 16, hash, start);
    }
    for (slot, hash) in [(0, A), (1, A), (2, 0xcccc), (3, A), (4, A)] {
        m.observe_state_hash(SlotId(slot), 24, hash, start);
    }
    // The authority named slot 2 at step 24 and its eviction order reached this relay, then the
    // slot left. Promoted, this relay still has slot 2's report back slots 0 and 4 at step 16.
    m.exclude_from_state_hashes(SlotId(2), 24);
    m.note_departure(SlotId(2), framed(1), 0, None);
    m.authority = Authority::SelfRelay;
    assert!(m.judge_state_hashes(start).is_empty());
    assert_eq!(
        m.observe_state_hash(SlotId(0), 16, A, start),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(1), SlotId(3)],
            missing: Vec::new(),
        }]
    );
}

/// Slots 4 and 5 are named at step 24. At step 16 the rest split two and two, slot 4 reported
/// slot 0's hash, and slot 5's report is still on its way: it could leave the split even, so the
/// step waits for it rather than letting the order reports arrive in pick the verdict.
#[test]
fn a_split_waits_for_every_report_of_the_slots_named_later() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3, 4, 5]);
    forward(&mut m, &[0, 1, 2, 3, 4, 5], 3 * STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(0, A), (1, A), (2, B), (3, B), (4, A)] {
        assert!(
            m.observe_state_hash(SlotId(slot), 16, hash, start)
                .is_empty()
        );
    }
    for (slot, hash) in [(0, A), (1, A), (2, A), (3, A), (4, 0xcccc)] {
        assert!(
            m.observe_state_hash(SlotId(slot), 24, hash, start)
                .is_empty()
        );
    }
    assert_eq!(
        m.observe_state_hash(SlotId(5), 24, 0xdddd, start),
        vec![SyncDivergence {
            sync_ordinal: 24,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(4), SlotId(5)],
            missing: Vec::new(),
        }],
        "step 16 is not decided on slot 4's report alone",
    );
    assert_eq!(
        m.observe_state_hash(SlotId(5), 16, B, start),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: true,
            diverged: Vec::new(),
            missing: Vec::new(),
        }]
    );
}

/// The step-16 split above, judged by a relay promoted after slots 4 and 5 left. Only slot 4's
/// eviction order reached it, but each departure carries the step its slot was named at, so it
/// counts slot 5's report where the authority did and finds the same even split.
#[test]
fn a_departure_tells_a_relay_that_missed_the_order_which_step_named_the_slot() {
    let start = Instant::now();
    let mut m = peer_maker();
    m.latch_rollback(true);
    m.set_expected_slots((0..6).map(SlotId).collect());
    forward(&mut m, &[0, 1, 2, 3, 4, 5], 3 * STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(0, A), (1, A), (2, B), (3, B), (4, A), (5, B)] {
        m.observe_state_hash(SlotId(slot), 16, hash, start);
    }
    for (slot, hash) in [(0, A), (1, A), (2, A), (3, A), (4, 0xcccc), (5, 0xdddd)] {
        m.observe_state_hash(SlotId(slot), 24, hash, start);
    }
    m.exclude_from_state_hashes(SlotId(4), 24);
    for slot in [4, 5] {
        m.note_departure(
            SlotId(slot),
            DepartureStamps {
                evict_sync_ordinal: Some(24),
                ..framed(1)
            },
            0,
            None,
        );
    }
    m.authority = Authority::SelfRelay;
    assert_eq!(
        m.judge_state_hashes(start),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: true,
            diverged: Vec::new(),
            missing: Vec::new(),
        }]
    );
}

/// The same split with slot 5's report never arriving is decided on the reports present once the
/// step's hold runs out.
#[test]
fn a_split_awaiting_a_report_of_a_slot_named_later_is_settled_at_its_hold() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3, 4, 5]);
    forward(&mut m, &[0, 1, 2, 3, 4, 5], 3 * STATE_HASH_INTERVAL, start);
    for (slot, hash) in [(0, A), (1, A), (2, B), (3, B), (4, A)] {
        m.observe_state_hash(SlotId(slot), 16, hash, start);
    }
    for (slot, hash) in [(0, A), (1, A), (2, A), (3, A), (4, 0xcccc), (5, 0xdddd)] {
        m.observe_state_hash(SlotId(slot), 24, hash, start);
    }
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    assert_eq!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE * 2),
        vec![SyncDivergence {
            sync_ordinal: 16,
            game_frame: None,
            no_majority: false,
            diverged: vec![SlotId(2), SlotId(3)],
            missing: Vec::new(),
        }]
    );
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
fn a_missing_report_with_none_in_yet_waits_for_the_rest() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    // Slot 0 goes on sending turns without its report; 1 and 2 lag and haven't reported yet.
    forward(&mut m, &[0], 8 + STATE_HASH_LIVE_TURNS, start);
    assert!(
        m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty(),
        "slots 1 and 2 may yet report, so there is no telling there is no majority",
    );
    let later = start + STATE_HASH_DEADLINE + Duration::from_secs(1);
    assert_eq!(
        m.observe_state_hash(SlotId(1), 8, A, later),
        vec![SyncDivergence {
            sync_ordinal: 8,
            game_frame: None,
            no_majority: false,
            diverged: Vec::new(),
            missing: vec![SlotId(0)],
        }],
        "only the slot that withheld its report is named",
    );
    assert!(m.observe_state_hash(SlotId(2), 8, A, later).is_empty());
    assert!(!m.hashes.dormant);
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
fn a_promoted_relay_settles_a_held_step_when_the_authority_would_have() {
    let start = Instant::now();
    let mut m = peer_maker();
    m.latch_rollback(true);
    m.set_expected_slots([SlotId(0), SlotId(1), SlotId(2)].into());
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, B, start);
    // Promoted after the step's deadline and its hold have both run out, it decides at once.
    m.authority = Authority::SelfRelay;
    let verdicts = m.judge_state_hashes(start + STATE_HASH_DEADLINE * 2 + Duration::from_secs(1));
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
}

#[test]
fn an_undecided_step_is_decided_once_the_slot_it_waits_on_leaves() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2]);
    forward(&mut m, &[0, 1, 2], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    m.observe_state_hash(SlotId(1), 8, B, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    // Slot 2's report would have decided it; with slot 2 gone, nothing still to come can.
    m.note_departure(SlotId(2), framed(1), 0, None);
    let verdicts = m.judge_state_hashes(start + STATE_HASH_DEADLINE);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
}

#[test]
fn a_late_report_that_leaves_the_step_undecided_holds_it_from_its_arrival() {
    let start = Instant::now();
    let mut m = rollback_maker(&[0, 1, 2, 3]);
    forward(&mut m, &[0, 1, 2, 3], STATE_HASH_INTERVAL, start);
    m.observe_state_hash(SlotId(0), 8, A, start);
    assert!(m.judge_state_hashes(start + STATE_HASH_DEADLINE).is_empty());
    let arrived = start + STATE_HASH_DEADLINE * 2;
    assert!(m.observe_state_hash(SlotId(1), 8, B, arrived).is_empty());
    let settled = arrived + STATE_HASH_DEADLINE;
    assert!(
        m.judge_state_hashes(settled - Duration::from_millis(1))
            .is_empty()
    );
    let verdicts = m.judge_state_hashes(settled);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].no_majority);
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
    assert_eq!(advance(&mut m, &[0], SYNC_A, 0..20), None);
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
    let _ = registry.note_forwarded_turn(
        &k,
        SlotId(0),
        STATE_HASH_INTERVAL - 1,
        Some(STATE_HASH_INTERVAL),
    );
    let _ = registry.note_forwarded_turn(
        &k,
        SlotId(1),
        (8 + STATE_HASH_LIVE_TURNS) - 1,
        Some(8 + STATE_HASH_LIVE_TURNS),
    );
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
