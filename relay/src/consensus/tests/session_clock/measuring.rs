//! A home slot's turns measured against the clock once their deadlines are final, and the lead
//! reports and flight recorder figures made from them.

use super::*;

#[test]
fn a_home_slots_turns_are_measured_against_the_clock() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS + 20, start);
    let due = |seq: u64| on_time(start, seq);

    assert_eq!(
        m.note_lead_arrival(SlotId(0), 10, start),
        None,
        "the lockstep start isn't measured",
    );
    // The first measured turn reports at once.
    let first = m
        .note_lead_arrival(SlotId(0), ANCHOR + 1, due(ANCHOR + 1) + 5 * MS)
        .expect("a slot's first measured turn reports");
    assert_eq!(first.through_step, ANCHOR + 1);
    assert_eq!(
        (first.median_us, first.p90_us, first.samples),
        (5_000, 5_000, 1)
    );
    // A copy of a turn already measured (a resume replay on a new link) doesn't count again.
    let _ = m.note_lead_arrival(
        SlotId(0),
        ANCHOR + 1,
        due(ANCHOR + 1) + Duration::from_secs(9),
    );
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 1);

    // The next twelve turns arrive 0 to 11 ms late (one of them early by 2 ms), and the twelfth
    // is due a report.
    let mut report = None;
    for (i, seq) in (ANCHOR + 2..=ANCHOR + 13).enumerate() {
        let arrived = if i == 3 {
            due(seq) - 2 * MS
        } else {
            due(seq) + MS * u32::try_from(i).unwrap()
        };
        report = m.note_lead_arrival(SlotId(0), seq, arrived);
        if seq < ANCHOR + 13 {
            assert_eq!(report, None, "reports come every 12 turns");
        }
    }
    let report = report.expect("the twelfth turn after the first report");
    // Lateness in ms: 5, 0, 1, 2, -2, 4, 5, 6, 7, 8, 9, 10, 11.
    assert_eq!(report.through_step, ANCHOR + 13);
    assert_eq!(report.samples, 13);
    assert_eq!(report.median_us, 5_000);
    assert_eq!(report.p90_us, 10_000);
    assert_eq!(report.pause_us, 0);
}

#[test]
fn a_turn_first_arriving_after_a_newer_one_is_measured_but_a_repeat_is_not() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS + 10, start);
    let due = |seq: u64| on_time(start, seq);

    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 2, due(ANCHOR + 2));
    // Turns arrive out of order: the turn before it shows up 30 ms late, after it. It is a first
    // arrival like any other, and its lateness counts.
    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 1, due(ANCHOR + 1) + 30 * MS);
    let report = m.lead_report(SlotId(0)).unwrap();
    assert_eq!(report.samples, 2);
    assert_eq!(report.p90_us, 30_000, "the late turn is in the window");
    assert_eq!(
        report.through_step,
        ANCHOR + 2,
        "the newest seq stays the newest"
    );

    // A copy of either (a resume replay on a new link) doesn't count again, and neither does a
    // turn too far behind the newest to tell from one.
    let _ = m.note_lead_arrival(
        SlotId(0),
        ANCHOR + 1,
        due(ANCHOR + 1) + Duration::from_secs(9),
    );
    let _ = m.note_lead_arrival(
        SlotId(0),
        ANCHOR + 2,
        due(ANCHOR + 2) + Duration::from_secs(9),
    );
    let far = ANCHOR + 2 + 200;
    let _ = m.note_lead_arrival(SlotId(0), far, due(far));
    let _ = m.note_lead_arrival(
        SlotId(0),
        ANCHOR + 3,
        due(ANCHOR + 3) + Duration::from_secs(9),
    );
    let report = m.lead_report(SlotId(0)).unwrap();
    assert_eq!(
        report.samples, 2,
        "the far turn waits for the clock to reach it, and the one far behind it is skipped",
    );
    assert_eq!(report.p90_us, 30_000);
}

#[test]
fn a_turn_past_the_limit_waits_until_its_deadline_is_final() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 30, start);
    assert_eq!(m.clock.final_through(), Some(29 + STALL_SLACK_STEPS));

    // A turn sent early enough to arrive past the limit: the clock may yet stop before its step.
    let early = 29 + STALL_SLACK_STEPS + 5;
    assert_eq!(
        m.note_lead_arrival(SlotId(0), early, on_time(start, early) - 5 * MS),
        None,
    );
    assert_eq!(m.lead_report(SlotId(0)).unwrap().samples, 0);

    // The session plays on, and once the limit reaches it the turn is measured, its report going
    // out with the advance that made its deadline final.
    let reaching = early - STALL_SLACK_STEPS + 1;
    for count in 31..reaching {
        assert_eq!(
            forward(&mut m, &[0, 1], count, on_time(start, count - 1)),
            None
        );
    }
    let update = forward(&mut m, &[0, 1], reaching, on_time(start, reaching - 1))
        .expect("the limit reached the waiting turn");
    assert_eq!(update.frame, None, "the clock never stopped");
    assert_eq!(update.reports.len(), 1);
    let (slot, report) = update.reports[0];
    assert_eq!(slot, SlotId(0));
    assert_eq!(
        (report.through_step, report.samples, report.median_us),
        (early, 1, -5_000)
    );
}

#[test]
fn a_turn_that_arrives_while_the_clock_stands_still_is_measured_against_the_stop() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    let resumed = stopped_at + Duration::from_secs(2);
    let _ = m.note_lead_arrival(SlotId(0), limit, stopped_at + 3 * MS);

    // Slot 0 sends its next turn on schedule, while the clock stands still waiting on slot 1. Its
    // deadline isn't final yet: it will be however long the stop lasts.
    assert_eq!(
        m.note_lead_arrival(SlotId(0), limit + 1, stopped_at + STEP),
        None
    );
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("stopped");
    assert!(update.frame.is_some());
    // The stop sends slot 0 its report at once, with its window as it was and the waiting turn
    // measured against the deadline the stop moved: two seconds early, not on time.
    assert_eq!(update.reports.len(), 1, "only slot 0 was measured here");
    let (slot, report) = update.reports[0];
    assert_eq!(slot, SlotId(0));
    assert_eq!(report.pause_us, 2_000_000);
    assert_eq!(report.samples, 2);
    assert_eq!(report.through_step, limit + 1);
    assert_eq!(
        (report.median_us, report.p90_us),
        (3_000, 3_000),
        "the late one of the two"
    );
    let samples = m.take_lead_samples().unwrap();
    assert_eq!(
        samples.slots[0].1.lateness_histogram[0], 1,
        "two seconds early"
    );
}

#[test]
fn nothing_is_measured_outside_a_rollback_session() {
    let start = Instant::now();
    let mut m = maker();
    m.set_expected_slots([SlotId(0), SlotId(1)].into());
    assert_eq!(play_on_schedule(&mut m, &[0, 1], 100, start), None);
    assert_eq!(m.note_lead_arrival(SlotId(0), 50, start), None);
    assert_eq!(m.session_clock_frame(start), None);
}

#[test]
fn lead_figures_cover_their_interval_and_the_histogram_the_whole_recording() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS, start);
    let due = |seq: u64| on_time(start, seq);

    // 5 ms late (and the slot's first report), 45 ms early, 200 ms late, and right on time.
    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 1, due(ANCHOR + 1) + 5 * MS);
    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 2, due(ANCHOR + 2) - 45 * MS);
    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 3, due(ANCHOR + 3) + 200 * MS);
    let _ = m.note_lead_arrival(SlotId(0), ANCHOR + 4, due(ANCHOR + 4));

    let samples = m
        .take_lead_samples()
        .expect("a rollback session has figures");
    assert_eq!(samples.clock_pause_us, Some(0));
    assert_eq!(samples.slots.len(), 1, "only slot 0 was measured");
    let (slot, sample) = &samples.slots[0];
    assert_eq!(*slot, 0);
    assert_eq!((sample.turns, sample.reports), (4, 1));
    let last = sample.last_report.expect("the first turn reported");
    assert_eq!(
        (last.through_step, last.p90_us, last.samples),
        (ANCHOR + 1, 5_000, 1)
    );
    assert_eq!(sample.max_p90_us, Some(5_000));
    assert_eq!(sample.max_lateness_us, Some(200_000));
    // Buckets: at most -40 ms, up to -20, -10, 0, 10, 20, 40, 80, 160, and past 160.
    assert_eq!(sample.lateness_histogram, [1, 0, 0, 1, 1, 0, 0, 0, 0, 1]);

    // The next sample starts a fresh interval; the histogram and the last report carry on.
    let samples = m.take_lead_samples().unwrap();
    let (_, sample) = &samples.slots[0];
    assert_eq!((sample.turns, sample.reports), (0, 0));
    assert_eq!((sample.max_p90_us, sample.max_lateness_us), (None, None));
    assert_eq!(sample.last_report, Some(last));
    assert_eq!(sample.lateness_histogram, [1, 0, 0, 1, 1, 0, 0, 0, 0, 1]);

    let mut lockstep = maker();
    assert_eq!(
        lockstep.take_lead_samples(),
        None,
        "nothing outside a rollback session"
    );
}

#[test]
fn a_stops_report_carries_the_window_in_the_figures() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let _ = m.note_lead_arrival(SlotId(0), 90, on_time(start, 90) + 30 * MS);
    let _ = m.take_lead_samples();

    let resumed = on_time(start, 99 + STALL_SLACK_STEPS) + Duration::from_secs(10);
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("stopped");
    assert_eq!(update.reports.len(), 1);
    let samples = m.take_lead_samples().unwrap();
    assert_eq!(samples.clock_pause_us, Some(10_000_000));
    let (_, sample) = &samples.slots[0];
    assert_eq!(sample.reports, 1, "the stop's report was made");
    assert_eq!(sample.max_p90_us, Some(30_000), "and it carries the window");
    assert_eq!(sample.last_report.unwrap().samples, 1);
}
