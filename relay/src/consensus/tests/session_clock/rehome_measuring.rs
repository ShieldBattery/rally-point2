//! A new home measures live timing, not retained turns replayed after an outage.

use super::*;

fn original_clock(start: Instant) -> SessionClockFrame {
    let mut original = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut original, &[0, 1], 100, start);
    original.session_clock_frame(on_time(start, 99)).unwrap()
}

fn new_home() -> DecisionMaker {
    let mut m = rollback(peer_maker(), &[0, 1]);
    m.set_homed_slots([SlotId(0)].into());
    m.mark_homes_rehomed();
    m.recover_clock();
    let _ = m.seed_resumed(&[]);
    let _ = m.set_authority(Authority::SelfRelay, &HashSet::new());
    m
}

#[test]
fn replayed_final_deadlines_are_skipped_but_live_reports_carry_the_outage_stop() {
    let start = Instant::now();
    let mut m = new_home();
    let _ = m.merge_session_clock(&original_clock(start), on_time(start, 99), 0);
    let at = on_time(start, 105) + Duration::from_secs(5);
    assert!(m.activate_connection_epoch(SlotId(0), 1, at));
    for seq in 60..=105 {
        assert_eq!(m.note_lead_arrival(SlotId(0), seq, at), None);
    }
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);
    // The first live turn waits for a final deadline, then uses the stop recorded
    // by actual progress. Its timing must not contain the retained history's delay.
    assert_eq!(m.note_lead_arrival(SlotId(0), 106, at), None);
    let mut reports = Vec::new();
    for seq in 100..=106 {
        for slot in 0..2 {
            if let Some(update) = m.note_forwarded_turn(SlotId(slot), seq, None, at) {
                reports.extend(update.reports);
            }
        }
    }
    assert!(
        reports
            .iter()
            .any(|(_, report)| report.pause_us == 5_000_000)
    );
    let report = m.lead_report(SlotId(0)).unwrap();
    assert_eq!((report.samples, report.through_step), (1, 106));
    assert!(report.p90_us.abs() < 100_000);
}

#[test]
fn a_clock_arriving_after_replay_uses_its_inherited_limit_not_the_recovered_tip() {
    let start = Instant::now();
    let mut m = new_home();
    let at = on_time(start, 120);
    assert!(m.activate_connection_epoch(SlotId(0), 1, at));
    for seq in 60..120 {
        for slot in 0..2 {
            let _ = m.note_forwarded_turn(SlotId(slot), seq, None, at);
        }
        assert_eq!(m.note_lead_arrival(SlotId(0), seq, at), None);
    }
    let mut frame = original_clock(start);
    frame.since_anchor_us = u64::try_from(us(at - start)).unwrap();
    let _ = m.merge_session_clock(&frame, at, 0);
    assert_eq!(m.clock.final_through(), Some(125));
    assert_eq!(m.note_lead_arrival(SlotId(0), 105, at), None);
    let report = m.note_lead_arrival(SlotId(0), 120, at).unwrap();
    assert_eq!((report.samples, report.through_step), (1, 120));
}

#[test]
fn repeated_connection_epochs_do_not_move_the_measurement_cutoff() {
    let start = Instant::now();
    let mut m = new_home();
    let _ = m.merge_session_clock(&original_clock(start), on_time(start, 99), 0);
    assert!(m.activate_connection_epoch(SlotId(0), 1, on_time(start, 99)));
    for seq in 100..130 {
        for slot in 0..2 {
            let _ = m.note_forwarded_turn(SlotId(slot), seq, None, on_time(start, seq));
        }
    }
    assert!(m.activate_connection_epoch(SlotId(0), 1, on_time(start, 129)));
    let report = m
        .note_lead_arrival(SlotId(0), 129, on_time(start, 129))
        .unwrap();
    assert_eq!((report.samples, report.through_step), (1, 129));
    assert!(m.activate_connection_epoch(SlotId(0), 2, on_time(start, 129)));
    assert!(!m.activate_connection_epoch(SlotId(0), 1, on_time(start, 130)));
    assert_eq!(
        m.note_lead_arrival(SlotId(0), 130, on_time(start, 130)),
        None
    );
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);
}

#[test]
fn an_ordinary_home_still_measures_late_and_reordered_turns() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    m.set_homed_slots([SlotId(0)].into());
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let at = on_time(start, 105) + Duration::from_secs(5);
    assert!(m.activate_connection_epoch(SlotId(0), 1, at));
    let report = m.note_lead_arrival(SlotId(0), 90, at).unwrap();
    assert!(report.p90_us > 5_000_000);
    let _ = m.note_lead_arrival(SlotId(0), 89, at);
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 2);
}

#[test]
fn returning_to_a_previous_home_clears_samples_but_keeps_dedup_and_totals() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    m.set_homed_slots([SlotId(0)].into());
    play_on_schedule(&mut m, &[0, 1], 100, start);
    assert!(m.activate_connection_epoch(SlotId(0), 1, on_time(start, 99)));
    let _ = m.note_lead_arrival(SlotId(0), 90, on_time(start, 90));
    let _ = m.note_lead_arrival(SlotId(0), 120, on_time(start, 99));
    m.rehome_homed_slots(HashSet::new());
    m.rehome_homed_slots([SlotId(0)].into());
    assert!(m.activate_connection_epoch(SlotId(0), 2, on_time(start, 105)));
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);
    // A queued arrival from the previous link must not later become a sample,
    // and replaying it on this link must not count it again either.
    play_on_schedule(&mut m, &[0, 1], 130, start);
    assert_eq!(
        m.note_lead_arrival(SlotId(0), 120, on_time(start, 129)),
        None
    );
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);
    let report = m
        .note_lead_arrival(SlotId(0), 129, on_time(start, 129))
        .unwrap();
    assert_eq!((report.samples, report.through_step), (1, 129));
    let totals = m.take_lead_samples().unwrap();
    assert_eq!(totals.slots[0].1.lateness_histogram.iter().sum::<u64>(), 2);
}
