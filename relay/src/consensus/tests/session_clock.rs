//! A rollback session's clock and the lead reports measured against it: anchored by the authority
//! once the lockstep start is confirmable, stopped at its limit while the whole session waits,
//! adopted whole by every other relay, and each home slot's turns measured against it once their
//! deadlines are final. In a rollback session the buffer law stops after the start and send-phase
//! alignment never runs.

use super::*;

use rally_point_proto::messages::ClockStop;
use rally_point_proto::rollback::{LOCKSTEP_START_STEPS, STEP_DURATION_US};

const STEP: Duration = Duration::from_micros(STEP_DURATION_US);
const MS: Duration = Duration::from_millis(1);

/// `steps` steps of the session clock.
fn steps(steps: u64) -> Duration {
    STEP * u32::try_from(steps).unwrap()
}

/// `duration` in whole microseconds.
fn us(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap()
}

/// `maker` serving a rollback session of `slots`.
fn rollback(mut maker: DecisionMaker, slots: &[u8]) -> DecisionMaker {
    maker.latch_rollback(true);
    maker.set_expected_slots(slots.iter().map(|&x| SlotId(x)).collect());
    maker
}

/// This relay has forwarded `count` turns of every one of `slots`, as of `at`, returning the last
/// clock change that made.
fn forward(
    maker: &mut DecisionMaker,
    slots: &[u8],
    count: u64,
    at: Instant,
) -> Option<ClockUpdate> {
    let mut update = None;
    for &slot in slots {
        if let Some(change) = maker.note_forwarded_turns(SlotId(slot), count, at) {
            update = Some(change);
        }
    }
    update
}

/// The seq of the turn whose arrival completed the lockstep start: the clock's anchor.
const ANCHOR: u64 = LOCKSTEP_START_STEPS - 1;

/// When the turn with seq `seq` is due on a clock anchored at `start` that never stopped.
fn on_time(start: Instant, seq: u64) -> Instant {
    start + steps(seq - ANCHOR)
}

/// Plays the session on schedule: every one of `slots`' turns through count `through` arrives
/// exactly when it is due, after the lockstep start completed at `start`. Returns the last clock
/// change (the anchor, on an authority that wasn't anchored yet).
fn play_on_schedule(
    maker: &mut DecisionMaker,
    slots: &[u8],
    through: u64,
    start: Instant,
) -> Option<ClockUpdate> {
    let mut update = forward(maker, slots, LOCKSTEP_START_STEPS, start);
    for count in LOCKSTEP_START_STEPS + 1..=through {
        if let Some(change) = forward(maker, slots, count, on_time(start, count - 1)) {
            update = Some(change);
        }
    }
    update
}

#[test]
fn the_authority_anchors_the_clock_when_the_lockstep_start_is_confirmable() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    assert_eq!(
        forward(&mut m, &[0, 1], LOCKSTEP_START_STEPS - 1, start),
        None
    );
    let anchored_at = start + 500 * MS;
    // Slot 0 has its whole start in and slot 1 doesn't yet, so nothing past it is confirmable.
    assert_eq!(
        m.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, anchored_at),
        None
    );
    let update = m
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, anchored_at)
        .expect("the start completing anchors the clock");
    let frame = update.frame.expect("the anchor goes to every other relay");
    assert_eq!(frame.anchor_step, ANCHOR);
    assert_eq!(frame.final_through, ANCHOR + STALL_SLACK_STEPS);
    assert!(frame.stops.is_empty());
    assert!(update.reports.is_empty(), "nothing has been measured yet");
    // The turn that completed the start was due when it arrived, and each later one a step on, as
    // far as the clock may run before the next step is confirmable.
    assert_eq!(m.clock.due_at(ANCHOR), Some(anchored_at));
    let limit = ANCHOR + STALL_SLACK_STEPS;
    assert_eq!(
        m.clock.due_at(limit),
        Some(anchored_at + steps(STALL_SLACK_STEPS))
    );
    assert_eq!(
        m.clock.due_at(limit + 1),
        None,
        "past the limit the clock may still stop, so nothing is due yet",
    );
    assert_eq!(
        m.clock.due_at(0),
        None,
        "the lockstep start has no deadline"
    );
}

#[test]
fn only_the_authority_anchors_the_clock() {
    let start = Instant::now();
    let mut m = rollback(peer_maker(), &[0, 1]);
    assert_eq!(play_on_schedule(&mut m, &[0, 1], 100, start), None);
    assert!(!m.clock.is_anchored());
}

#[test]
fn a_session_on_schedule_never_stops_the_clock() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    let update = play_on_schedule(&mut m, &[0, 1], 500, start).expect("anchored");
    assert_eq!(
        update.frame.map(|frame| frame.anchor_step),
        Some(ANCHOR),
        "the anchor was the only change",
    );
    assert_eq!(m.clock.pause(), Duration::ZERO);
    assert_eq!(
        m.clock.final_through(),
        Some(499 + STALL_SLACK_STEPS),
        "the limit follows what is confirmable",
    );
}

#[test]
fn lateness_within_the_slack_does_not_stop_the_clock() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    // A hiccup as long as the slack: the next step becomes confirmable just as the clock reaches
    // its limit.
    let late = on_time(start, 99 + STALL_SLACK_STEPS);
    assert_eq!(forward(&mut m, &[0, 1], 101, late), None);
    assert_eq!(m.clock.pause(), Duration::ZERO);
}

#[test]
fn a_session_wide_wait_stops_the_clock_at_its_limit() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    // The newest confirmable turn is seq 99, so the clock runs to the slack past it, and then
    // nothing comes for ten seconds: a drop wait.
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    let resumed = stopped_at + Duration::from_secs(10);
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("the wait stopped the clock");
    let frame = update
        .frame
        .expect("a stop goes to every other relay at once");
    assert_eq!(
        frame.stops,
        vec![ClockStop {
            step: limit,
            pause_us: 10_000_000,
        }],
    );
    assert_eq!(frame.final_through, limit + 1);
    assert_eq!(m.clock.pause(), Duration::from_secs(10));
    // The stop moves every step after it and none before.
    assert_eq!(m.clock.due_at(limit), Some(stopped_at));
    assert_eq!(m.clock.due_at(limit + 1), Some(resumed + STEP));
    // So a turn sent on the schedule the stop moved is on time.
    assert_eq!(m.clock.lateness_us(limit + 1, resumed + STEP), Some(0));
}

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
fn a_persistently_late_slot_keeps_getting_reports_and_its_lateness_stays_at_the_slack() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS, start);
    // Slot 0, homed here, sends every turn on time against its own schedule, but its schedule runs
    // twenty steps and change behind the session's: far past the slack.
    let behind = steps(20) + 7 * MS;
    let last = LOCKSTEP_START_STEPS + 400;
    let mut events: Vec<(Instant, u8, u64)> = (LOCKSTEP_START_STEPS + 1..=last)
        .flat_map(|count| {
            let at = on_time(start, count - 1);
            [(at, 1, count), (at + behind, 0, count)]
        })
        .collect();
    events.sort_by_key(|&(at, slot, _)| (at, slot));
    let mut reports = Vec::new();
    for (at, slot, count) in events {
        if let Some(update) = m.note_forwarded_turns(SlotId(slot), count, at) {
            reports.extend(update.reports.into_iter().map(|(_, report)| report));
        }
        if slot == 0 {
            reports.extend(m.note_lead_arrival(SlotId(0), count - 1, at));
        }
    }

    // The clock stopped once, when it first ran into its limit waiting on slot 0, and from then on
    // moved on as each of slot 0's turns arrived.
    let pause = m.clock.pause();
    assert_eq!(pause, behind - steps(STALL_SLACK_STEPS - 1));
    // Every report carried figures, about one every 12 turns.
    assert!(reports.iter().all(|report| report.samples > 0));
    assert!(reports.len() >= 33, "{} reports", reports.len());
    // Once the first stop's turns leave the window, slot 0 reads as late as the clock lets it run
    // ahead of its turns: the slack, less the step its own turn took to arrive.
    let settled = i32::try_from(us(steps(STALL_SLACK_STEPS - 1))).unwrap();
    let steady: Vec<_> = reports
        .iter()
        .filter(|report| report.through_step > ANCHOR + STALL_SLACK_STEPS + 30)
        .collect();
    assert!(!steady.is_empty());
    for report in steady {
        assert_eq!((report.median_us, report.p90_us), (settled, settled));
        assert_eq!(report.pause_us, u64::try_from(us(pause)).unwrap());
    }
}

#[test]
fn a_slot_falling_further_behind_stops_the_clock_every_step_and_still_reads_at_the_slack() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS, start);
    // As above, but slot 0's turns come a millisecond further apart than a step: the clock reaches
    // its limit before every one of them, and stands still a millisecond each time.
    let behind = steps(20) + 7 * MS;
    let first = LOCKSTEP_START_STEPS + 1;
    let last = LOCKSTEP_START_STEPS + 400;
    let mut events: Vec<(Instant, u8, u64)> = (first..=last)
        .flat_map(|count| {
            let at = on_time(start, count - 1);
            let drift = MS * u32::try_from(count - first).unwrap();
            [(at, 1, count), (at + behind + drift, 0, count)]
        })
        .collect();
    events.sort_by_key(|&(at, slot, _)| (at, slot));
    let mut reports = Vec::new();
    let mut stops = 0;
    for (at, slot, count) in events {
        if let Some(update) = m.note_forwarded_turns(SlotId(slot), count, at) {
            stops += usize::from(update.frame.is_some());
            reports.extend(update.reports.into_iter().map(|(_, report)| report));
        }
        if slot == 0 {
            reports.extend(m.note_lead_arrival(SlotId(0), count - 1, at));
        }
    }

    assert_eq!(stops, usize::try_from(last - first + 1).unwrap());
    assert_eq!(
        m.clock.pause(),
        behind - steps(STALL_SLACK_STEPS - 1) + MS * u32::try_from(last - first).unwrap(),
    );
    // Each stop sends slot 0 its report, and every one carries a full window: none of them is
    // thrown away, so the slot's pacing has a reading to act on throughout.
    let steady: Vec<_> = reports
        .iter()
        .filter(|report| report.through_step > ANCHOR + STALL_SLACK_STEPS + 30)
        .collect();
    assert!(steady.len() > 300, "{} reports", steady.len());
    // Its turns read as late as the slack lets the clock run ahead of them, plus the drift across
    // those steps.
    let settled = i32::try_from(us(
        steps(STALL_SLACK_STEPS - 1) + MS * u32::try_from(STALL_SLACK_STEPS).unwrap()
    ))
    .unwrap();
    for report in steady {
        assert_eq!(usize::try_from(report.samples).unwrap(), LEAD_WINDOW_TURNS);
        assert_eq!((report.median_us, report.p90_us), (settled, settled));
    }
}

#[test]
fn old_stops_fold_into_the_base_and_another_relay_reads_the_same_deadlines() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], LOCKSTEP_START_STEPS, start);
    // Every step becomes confirmable 5 ms after the clock reached its limit: a stop each step.
    let mut now = start;
    for count in LOCKSTEP_START_STEPS + 1..=LOCKSTEP_START_STEPS + 300 {
        let limit = authority.clock.final_through().unwrap();
        now = authority.clock.due_at(limit).unwrap() + 5 * MS;
        let update = forward(&mut authority, &[0, 1], count, now).expect("stopped");
        assert!(update.frame.is_some());
    }
    assert_eq!(authority.clock.pause(), 300 * 5 * MS);

    let frame = authority.session_clock_frame(now).unwrap();
    let final_through = frame.final_through;
    assert_eq!(frame.base_step, final_through - KEPT_STOP_STEPS);
    assert_eq!(
        frame.stops.len() as u64,
        KEPT_STOP_STEPS,
        "only the stops within reach of a measured turn are kept by step",
    );
    assert_eq!(
        frame.base_pause_us + frame.stops.iter().map(|stop| stop.pause_us).sum::<u64>(),
        1_500_000,
    );

    // Another relay adopting the frame (sent and received at once) has every deadline the
    // authority can still measure, exactly.
    let mut peer = rollback(peer_maker(), &[0, 1]);
    let _ = peer.adopt_session_clock(&frame, now, 0);
    for seq in frame.base_step..=final_through {
        assert_eq!(
            peer.clock.due_at(seq),
            authority.clock.due_at(seq),
            "seq {seq}"
        );
        assert!(peer.clock.due_at(seq).is_some());
    }
    assert_eq!(peer.clock.due_at(frame.base_step - 1), None);
    assert_eq!(authority.clock.due_at(frame.base_step - 1), None);
}

#[test]
fn another_relay_adopts_frames_whole_and_ignores_older_ones() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], 100, start);
    let first = authority.session_clock_frame(on_time(start, 99)).unwrap();
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + Duration::from_secs(3);
    let _ = forward(&mut authority, &[0, 1], 101, resumed).expect("stopped");
    let second = authority.session_clock_frame(resumed).unwrap();
    let _ = forward(&mut authority, &[0, 1], 102, resumed + STEP);
    let heartbeat = authority.session_clock_frame(resumed + STEP).unwrap();

    // One relay hears the frames in order, another out of order (the stop delayed across a
    // reconnect) and some of them twice.
    let mut in_order = rollback(peer_maker(), &[0, 1]);
    let _ = in_order.adopt_session_clock(&first, on_time(start, 99), 0);
    let _ = in_order.adopt_session_clock(&second, resumed, 0);
    let _ = in_order.adopt_session_clock(&heartbeat, resumed + STEP, 0);
    let mut out_of_order = rollback(peer_maker(), &[0, 1]);
    let _ = out_of_order.adopt_session_clock(&first, on_time(start, 99), 0);
    let _ = out_of_order.adopt_session_clock(&heartbeat, resumed + STEP, 0);
    assert!(
        out_of_order
            .adopt_session_clock(&second, resumed + 2 * STEP, 0)
            .is_empty()
    );
    let _ = out_of_order.adopt_session_clock(&first, resumed + 3 * STEP, 0);
    let _ = out_of_order.adopt_session_clock(&heartbeat, resumed + 4 * STEP, 0);

    for seq in ANCHOR..=limit + 2 {
        assert_eq!(in_order.clock.due_at(seq), authority.clock.due_at(seq));
        assert_eq!(out_of_order.clock.due_at(seq), authority.clock.due_at(seq));
    }
    assert_eq!(out_of_order.clock.pause(), Duration::from_secs(3));
    assert_eq!(out_of_order.clock.final_through(), Some(limit + 2));
}

#[test]
fn another_relay_measures_a_turn_that_arrived_before_it_heard_of_the_stop() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], 100, start);
    let mut peer = rollback(peer_maker(), &[0, 1]);
    let heard = on_time(start, 99);
    let _ = peer.adopt_session_clock(&authority.session_clock_frame(heard).unwrap(), heard, 0);

    // The authority's clock reaches its limit and stands still for three seconds, waiting on slot
    // 0. Slot 1, homed on the other relay, sent the turn at the limit on time, and its next one two
    // seconds into the stop, before the other relay could know there was one.
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    let resumed = stopped_at + Duration::from_secs(3);
    let first = peer
        .note_lead_arrival(SlotId(1), limit, stopped_at + MS)
        .expect("a slot's first measured turn reports");
    assert_eq!(first.median_us, 1_000);
    assert_eq!(
        peer.note_lead_arrival(SlotId(1), limit + 1, stopped_at + Duration::from_secs(2)),
        None,
        "its deadline isn't final there yet",
    );

    // The stop arrives a hop after it ended. The waiting turn is measured against the deadline it
    // moved, more than a second early: not two seconds late, as it would read against the clock
    // as the other relay knew it when the turn arrived.
    let update = forward(&mut authority, &[0, 1], 101, resumed).expect("stopped");
    let reports = peer.adopt_session_clock(&update.frame.unwrap(), resumed + 20 * MS, 40_000);
    assert_eq!(reports.len(), 1);
    let (slot, report) = reports[0];
    assert_eq!(slot, SlotId(1));
    assert_eq!(report.pause_us, 3_000_000);
    assert_eq!((report.samples, report.p90_us), (2, 1_000));
    assert_eq!(report.through_step, limit + 1);
    let samples = peer.take_lead_samples().unwrap();
    assert_eq!(samples.slots[0].1.max_lateness_us, Some(1_000));
    assert_eq!(
        samples.slots[0].1.lateness_histogram[0], 1,
        "more than a second early"
    );
}

#[test]
fn a_heartbeat_measures_the_turns_waiting_on_another_relay() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], LOCKSTEP_START_STEPS, start);
    let mut peer = rollback(peer_maker(), &[0, 1]);
    let _ = peer.adopt_session_clock(&authority.session_clock_frame(start).unwrap(), start, 0);

    // Slot 1's turns arrive on time; those past the limit the other relay last heard of wait.
    for seq in ANCHOR + 1..=ANCHOR + 13 {
        let _ = peer.note_lead_arrival(SlotId(1), seq, on_time(start, seq) + 2 * MS);
    }
    assert_eq!(
        u64::from(peer.lead_report(SlotId(1)).unwrap().samples),
        STALL_SLACK_STEPS,
    );

    // The authority confirms more, and its next heartbeat measures them, bringing the report due.
    play_on_schedule(&mut authority, &[0, 1], ANCHOR + 13, start);
    let sent = on_time(start, ANCHOR + 13);
    let reports = peer.adopt_session_clock(&authority.session_clock_frame(sent).unwrap(), sent, 0);
    assert_eq!(reports.len(), 1);
    let (slot, report) = reports[0];
    assert_eq!(slot, SlotId(1));
    assert_eq!(
        (report.through_step, report.samples, report.p90_us),
        (ANCHOR + 13, 13, 2_000)
    );
    assert_eq!(report.pause_us, 0);
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
fn the_authority_sends_its_clock_to_a_joining_relay_and_ignores_others() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    assert_eq!(
        authority.session_clock_frame(start),
        None,
        "nothing before the anchor"
    );
    play_on_schedule(&mut authority, &[0, 1], 50, start);
    let now = start + Duration::from_secs(2);
    let frame = authority
        .session_clock_frame(now)
        .expect("the authority sends its clock");
    assert_eq!(frame.anchor_step, ANCHOR);
    assert_eq!(frame.since_anchor_us, 2_000_000);
    assert_eq!(frame.final_through, 49 + STALL_SLACK_STEPS);

    let mut peer = rollback(peer_maker(), &[0, 1]);
    assert!(
        peer.adopt_session_clock(&frame, now, 0).is_empty(),
        "nothing measured yet",
    );
    assert_eq!(
        peer.session_clock_frame(now),
        None,
        "only the authority sends it"
    );
    // A frame reaching the authority (from a former one) changes nothing.
    let mut stray = frame;
    stray.final_through += 100;
    stray.base_pause_us = 9_000_000;
    let _ = authority.adopt_session_clock(&stray, now, 0);
    assert_eq!(authority.clock.pause(), Duration::ZERO);
    assert_eq!(
        authority.clock.final_through(),
        Some(49 + STALL_SLACK_STEPS)
    );
}

#[test]
fn another_relay_places_the_anchor_by_the_frames_age_and_half_the_round_trip() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], LOCKSTEP_START_STEPS, start);
    let sent = start + Duration::from_secs(1);
    let frame = authority.session_clock_frame(sent).unwrap();

    let mut peer = rollback(peer_maker(), &[0, 1]);
    // Sent a second after the anchor, it took 10 ms to arrive over a 20 ms round trip.
    let received = sent + 10 * MS;
    let _ = peer.adopt_session_clock(&frame, received, 20_000);
    assert_eq!(peer.clock.due_at(ANCHOR), Some(start));

    // A later frame carrying a stop moves every deadline after it by exactly the stop, however
    // long it took to arrive, and re-sends this relay's measured slots their reports.
    let _ = peer.note_lead_arrival(SlotId(1), ANCHOR + 5, start + steps(5));
    let stopped = SessionClockFrame {
        since_anchor_us: frame.since_anchor_us + 30_000_000,
        final_through: frame.final_through + 1,
        stops: vec![ClockStop {
            step: frame.final_through,
            pause_us: 5_000_000,
        }],
        ..frame.clone()
    };
    let reports = peer.adopt_session_clock(&stopped, received + Duration::from_secs(31), 80_000);
    assert_eq!(peer.clock.due_at(ANCHOR), Some(start));
    assert_eq!(
        peer.clock.due_at(frame.final_through + 1),
        Some(on_time(start, frame.final_through + 1) + Duration::from_secs(5)),
    );
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].1.pause_us, 5_000_000);
    assert_eq!(
        reports[0].1.samples, 1,
        "the window carries on through the stop"
    );
    // A stale frame changes nothing.
    assert!(peer.adopt_session_clock(&frame, received, 0).is_empty());
    assert_eq!(peer.clock.pause(), Duration::from_secs(5));
}

#[test]
fn the_buffer_law_stops_after_the_start_in_a_rollback_session() {
    let mut m = maker();
    m.latch_rollback(true);
    // The start still re-affirms the buffer once, for the lockstep start.
    assert!(ingest_at(&mut m, &conditions(0, 0, 0, 100), 5).is_some());
    // A path that would raise it in a lockstep session decides nothing.
    assert_eq!(ingest_at(&mut m, &conditions(0, 300_000, 0, 100), 6), None);
}

#[test]
fn a_rollback_session_runs_no_send_phase_alignment() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    m.latch_started();
    // Two slots sending half a turn out of phase for far longer than the controller waits.
    for seq in 0..400u64 {
        let at = start + steps(seq);
        assert!(m.ingest_arrival_phase(SlotId(0), seq, at).is_empty());
        assert!(
            m.ingest_arrival_phase(SlotId(1), seq, at + steps(1) / 2)
                .is_empty()
        );
    }
    assert_eq!(m.commanded_phase_delay(SlotId(1)), None);
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

#[test]
fn the_authoritys_anchor_and_stops_earn_flight_events() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    let mark = m.clock_mark();
    play_on_schedule(&mut m, &[0, 1], 100, start);
    assert_eq!(
        m.clock_events(mark, false),
        [
            Some(FlightEvent::SessionClockAnchored {
                anchor_step: ANCHOR,
                adopted: false,
            }),
            None,
        ],
    );

    let resumed = on_time(start, 99 + STALL_SLACK_STEPS) + Duration::from_secs(10);
    let mark = m.clock_mark();
    let _ = forward(&mut m, &[0, 1], 101, resumed).expect("stopped");
    assert_eq!(
        m.clock_events(mark, false),
        [
            None,
            Some(FlightEvent::SessionClockStopped {
                pause_us: 10_000_000,
            }),
        ],
    );
}

#[test]
fn an_adopted_clock_records_its_anchor_and_at_most_the_capped_number_of_stops() {
    let registry = new_decision_makers();
    let k = key();
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            rollback: true,
            ..MakerSync::new(bounds(0, 20), Authority::Peer)
        },
    );
    let received = Instant::now();
    let mut frame = SessionClockFrame {
        anchor_step: ANCHOR,
        since_anchor_us: 1_000_000,
        final_through: ANCHOR + STALL_SLACK_STEPS,
        ..Default::default()
    };
    let _ = registry.adopt_session_clock(&k, &frame, received, 20_000);
    // A session that keeps stopping, past the cap, and a stale repeat that grows nothing.
    let stops = u64::from(MAX_CLOCK_STOP_EVENTS) + 5;
    for _ in 0..stops {
        frame.stops.push(ClockStop {
            step: frame.final_through,
            pause_us: 1_000_000,
        });
        frame.final_through += 1;
        let _ = registry.adopt_session_clock(&k, &frame, received, 20_000);
    }
    let _ = registry.adopt_session_clock(&k, &frame, received, 20_000);

    let events: Vec<FlightEvent> = registry
        .flight_recorder()
        .events(&k)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert_eq!(
        events[0],
        FlightEvent::SessionClockAnchored {
            anchor_step: ANCHOR,
            adopted: true,
        },
    );
    let recorded: Vec<u64> = events[1..]
        .iter()
        .map(|event| match event {
            FlightEvent::SessionClockStopped { pause_us } => *pause_us,
            other => panic!("expected only clock stops after the anchor, got {other:?}"),
        })
        .collect();
    assert_eq!(recorded.len(), MAX_CLOCK_STOP_EVENTS as usize);
    assert_eq!(recorded[0], 1_000_000);
    assert_eq!(
        recorded.last(),
        Some(&(u64::from(MAX_CLOCK_STOP_EVENTS) * 1_000_000))
    );
    // The sample rows still see the whole stopped time past the cap.
    assert_eq!(
        registry.take_lead_samples(&k).unwrap().clock_pause_us,
        Some(stops * 1_000_000),
    );
}
