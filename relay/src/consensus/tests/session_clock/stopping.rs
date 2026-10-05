//! The authority's clock: anchored once the lockstep start is confirmable, stopped at its limit
//! while the whole session waits, and how a late player reads against it. In a rollback session
//! the buffer law stops after the start and send-phase alignment never runs.

use super::*;

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
