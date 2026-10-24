//! Clock recovery must not turn missing history into delivery or enforcement evidence.

use super::*;

fn replacement() -> DecisionMaker {
    let mut replacement = rollback(peer_maker(), &[0, 1]);
    replacement.recover_clock();
    let _ = replacement.seed_resumed(&[]);
    let _ = replacement.set_authority(Authority::SelfRelay, &HashSet::new());
    replacement
}

fn inherited(start: Instant) -> SessionClockFrame {
    let mut original = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut original, &[0, 1], 100, start);
    original.session_clock_frame(on_time(start, 99)).unwrap()
}

fn turn(maker: &mut DecisionMaker, slot: u8, seq: u64, at: Instant) -> Option<ClockUpdate> {
    maker.note_forwarded_turn(SlotId(slot), seq, None, at)
}

#[test]
fn a_recovered_clock_waits_for_every_gap_above_the_peer_baseline() {
    let start = Instant::now();
    let mut m = replacement();
    let inherited = inherited(start);
    let at = on_time(start, 105);
    let _ = m.merge_session_clock(&inherited, on_time(start, 99), 0);
    let _ = turn(&mut m, 0, 101, at);
    let _ = turn(&mut m, 1, 100, at);
    let _ = turn(&mut m, 1, 101, at);
    assert_eq!(m.clock.final_through(), Some(inherited.final_through));
    let _ = turn(&mut m, 0, 100, at);
    assert_eq!(m.clock.final_through(), Some(101 + STALL_SLACK_STEPS));
    assert_eq!(m.hashes.confirmable_until(), 0);
    assert_eq!(m.hashes.forwarded_count(SlotId(0)), 0);
    assert_eq!(m.hashes.forwarded_count(SlotId(1)), 0);
    assert_eq!(
        m.turns_complete_handle()
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    assert!(
        m.slots
            .values()
            .all(|slot| slot.last_forward_advance_at.is_none())
    );
}

#[test]
fn replay_before_the_clock_records_the_outage_without_counting_echoes() {
    let start = Instant::now();
    let mut m = replacement();
    let at = on_time(start, 105) + Duration::from_secs(3);
    for seq in (100..120).rev() {
        let _ = turn(&mut m, 0, seq, at);
        let _ = turn(&mut m, 1, seq, at);
    }
    assert!(!m.clock.is_anchored());
    let mut frame = inherited(start);
    frame.since_anchor_us = u64::try_from(us(at - start)).unwrap();
    let _ = m.merge_session_clock(&frame, at, 0);
    assert_eq!(m.clock.final_through(), Some(119 + STALL_SLACK_STEPS));
    assert_eq!(m.clock.pause(), Duration::from_secs(3));
    let held = m.clock.to_frame(at).unwrap();
    for _ in 0..10 {
        let _ = m.merge_session_clock(&held, at, 0);
    }
    assert_eq!(
        m.clock.to_frame(at),
        Some(held),
        "echoes cannot create progress from slack"
    );
}

#[test]
fn stale_or_foreign_anchor_copies_cannot_skip_a_recovery_gap() {
    let start = Instant::now();
    let mut m = replacement();
    let frame = inherited(start);
    let at = on_time(start, 99);
    let _ = m.merge_session_clock(&frame, at, 0);
    for slot in 0..2 {
        let _ = turn(&mut m, slot, 101, at);
    }
    let mut foreign = frame.clone();
    foreign.anchor_step += 1;
    foreign.final_through += 100;
    assert!(m.merge_session_clock(&foreign, at, 0).is_empty());
    let _ = m.merge_session_clock(&frame, at, 0);
    assert_eq!(m.clock_confirmed, 100);
    assert_eq!(m.clock.final_through(), Some(frame.final_through));
}

#[test]
fn peer_tracking_survives_promotion_and_another_fresh_replacement() {
    let start = Instant::now();
    let mut first = replacement();
    let _ = first.set_authority(Authority::Peer, &HashSet::new());
    let _ = first.merge_session_clock(&inherited(start), on_time(start, 99), 0);
    for seq in 100..120 {
        for slot in 0..2 {
            let _ = turn(&mut first, slot, seq, on_time(start, seq));
        }
    }
    assert_eq!(first.clock.final_through(), Some(99 + STALL_SLACK_STEPS));
    let _ = first.set_authority(Authority::SelfRelay, &HashSet::new());
    for slot in 0..2 {
        let _ = turn(&mut first, slot, 120, on_time(start, 120));
    }
    assert_eq!(first.clock.final_through(), Some(120 + STALL_SLACK_STEPS));
    assert_eq!(first.clock.pause(), Duration::ZERO);
    let mut second = replacement();
    let at = on_time(start, 120);
    let _ = second.merge_session_clock(&first.session_clock_frame(at).unwrap(), at, 0);
    for seq in 121..140 {
        for slot in 0..2 {
            let _ = turn(&mut second, slot, seq, on_time(start, seq));
        }
    }
    assert_eq!(second.clock.final_through(), Some(139 + STALL_SLACK_STEPS));
    assert_eq!(second.hashes.confirmable_until(), 0);
}

#[test]
fn high_client_sequences_without_a_peer_clock_never_invent_a_baseline() {
    let start = Instant::now();
    let mut m = replacement();
    for seq in 100..200 {
        for slot in 0..2 {
            let _ = turn(&mut m, slot, seq, start + steps(seq));
        }
    }
    assert_eq!(m.clock_confirmed, 0);
    assert!(!m.clock.is_anchored());
}

#[test]
fn a_later_peer_baseline_settles_measurements_from_an_already_received_suffix() {
    let start = Instant::now();
    let mut m = replacement();
    let _ = m.merge_session_clock(&inherited(start), on_time(start, 99), 0);
    let at = on_time(start, 119);
    let _ = m.note_lead_arrival(SlotId(0), 119, at);
    for seq in (101..120).rev() {
        for slot in 0..2 {
            let _ = turn(&mut m, slot, seq, at);
        }
    }
    assert_eq!(m.clock.final_through(), Some(99 + STALL_SLACK_STEPS));
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);
    // The peer has confirmed the missing turn 100. That proof joins the retained
    // suffix; no additional turn needs to arrive for the queued sample to settle.
    let mut original = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut original, &[0, 1], 101, start);
    let reports = m.merge_session_clock(&original.session_clock_frame(at).unwrap(), at, 0);
    assert_eq!(m.clock.final_through(), Some(119 + STALL_SLACK_STEPS));
    assert!(
        reports
            .iter()
            .any(|(slot, report)| *slot == SlotId(0) && report.through_step == 119)
    );
    assert_eq!(m.hashes.confirmable_until(), 0);
}

#[test]
fn observers_and_departed_players_do_not_hold_the_recovered_clock() {
    let start = Instant::now();
    let mut m = replacement();
    m.set_expected_slots([SlotId(0), SlotId(1), SlotId(2)].into());
    m.set_observers([SlotId(2)].into());
    let _ = m.merge_session_clock(&inherited(start), on_time(start, 99), 0);
    let at = on_time(start, 105) + Duration::from_secs(3);
    for seq in 100..120 {
        let _ = turn(&mut m, 0, seq, at);
    }
    assert_eq!(
        m.clock_confirmed, 100,
        "the absent player still holds the clock"
    );
    let _ = m.seed_departed(SlotId(1), DepartureKind::Left, Some(100), true);
    let _ = turn(&mut m, 0, 120, at);
    assert_eq!(m.clock.final_through(), Some(120 + STALL_SLACK_STEPS));
    assert_eq!(
        m.clock.pause(),
        Duration::from_secs(3),
        "the old limit owns the wait"
    );
    assert_eq!(m.hashes.confirmable_until(), 0);
}
