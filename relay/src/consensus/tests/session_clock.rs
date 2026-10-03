//! A rollback session's clock and the lead reports measured against it: anchored by the authority
//! once the lockstep start is confirmable, stopped while the whole session waits, adopted by every
//! other relay, and each home slot's turns measured against it. In a rollback session the buffer
//! law stops after the start and send-phase alignment never runs.

use super::*;

use rally_point_proto::rollback::{LOCKSTEP_START_STEPS, STEP_DURATION_US};

const STEP: Duration = Duration::from_micros(STEP_DURATION_US);
const MS: Duration = Duration::from_millis(1);

/// `steps` steps of the session clock.
fn steps(steps: u64) -> Duration {
    STEP * u32::try_from(steps).unwrap()
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
        if let Some(change) = forward(
            maker,
            slots,
            count,
            start + steps(count - LOCKSTEP_START_STEPS),
        ) {
            update = Some(change);
        }
    }
    update
}

/// The seq of the turn whose arrival completed the lockstep start: the clock's anchor.
const ANCHOR: u64 = LOCKSTEP_START_STEPS - 1;

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
    assert_eq!(update.frame.anchor_step, ANCHOR);
    assert_eq!(update.frame.pause_us, 0);
    assert!(update.reports.is_empty(), "nothing has been measured yet");
    // The turn that completed the start was due when it arrived, and each later one a step on.
    assert_eq!(m.clock.due_at(ANCHOR), Some(anchored_at));
    assert_eq!(m.clock.due_at(ANCHOR + 10), Some(anchored_at + steps(10)));
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
        update.frame.anchor_step, ANCHOR,
        "the anchor was the only change"
    );
    assert_eq!(m.clock.pause(), Duration::ZERO);
}

#[test]
fn lateness_within_the_slack_does_not_stop_the_clock() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    // A hiccup of 11 steps: the next turn arrives inside the slack.
    let late = start + steps(100 - LOCKSTEP_START_STEPS + 11);
    assert_eq!(forward(&mut m, &[0, 1], 101, late), None);
    assert_eq!(m.clock.pause(), Duration::ZERO);
}

#[test]
fn a_session_wide_wait_stops_the_clock_past_the_slack() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    // Then nothing for ten seconds: a drop wait.
    let resumed = start + steps(100 - LOCKSTEP_START_STEPS) + Duration::from_secs(10);
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("the wait stopped the clock");
    // The newest confirmable turn was seq 99, so the clock ran 12 steps past it and stopped there
    // until turns came again.
    let stopped_at = start + steps(99 + STALL_SLACK_STEPS - ANCHOR);
    assert_eq!(
        update.frame.pause_us,
        u64::try_from((resumed - stopped_at).as_micros()).unwrap(),
    );
    assert_eq!(m.clock.due_at(99 + STALL_SLACK_STEPS), Some(resumed));
    // So the turn that resumed it measures 11 steps late rather than ten seconds.
    assert_eq!(
        m.clock.lateness_us(100, resumed),
        Some(i64::try_from(steps(STALL_SLACK_STEPS - 1).as_micros()).unwrap()),
    );
}

#[test]
fn a_home_slots_turns_are_measured_against_the_clock() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS, start);
    let anchored_at = m.clock.due_at(ANCHOR).unwrap();
    let due = |seq: u64| anchored_at + steps(seq - ANCHOR);

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
fn nothing_is_measured_outside_a_rollback_session() {
    let start = Instant::now();
    let mut m = maker();
    m.set_expected_slots([SlotId(0), SlotId(1)].into());
    assert_eq!(play_on_schedule(&mut m, &[0, 1], 100, start), None);
    assert_eq!(m.note_lead_arrival(SlotId(0), 50, start), None);
    assert_eq!(m.session_clock_frame(start), None);
}

#[test]
fn a_stop_re_sends_every_measured_slot_a_report_and_starts_its_window_over() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let measured = m.clock.due_at(90).unwrap();
    let _ = m.note_lead_arrival(SlotId(0), 90, measured);

    // Slot 0's next turn arrives after a five-second wait, ahead of the turn that moves the
    // clock, so it is measured against the clock from before the stop.
    let resumed = start + steps(100 - LOCKSTEP_START_STEPS) + Duration::from_secs(5);
    let _ = m.note_lead_arrival(SlotId(0), 100, resumed);
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("stopped");
    assert_eq!(update.reports.len(), 1, "only slot 0 was measured here");
    let (slot, report) = &update.reports[0];
    assert_eq!(*slot, SlotId(0));
    assert_eq!(report.pause_us, update.frame.pause_us);
    assert_eq!(
        report.samples, 0,
        "the report carries the stop and no lateness"
    );

    // Measuring resumes against the moved clock, without the turn that read five seconds late.
    let next = m.clock.due_at(101).unwrap();
    let report = m
        .note_lead_arrival(SlotId(0), 101, next + 2 * MS)
        .or_else(|| m.lead_report(SlotId(0)))
        .unwrap();
    assert_eq!((report.samples, report.median_us), (1, 2_000));
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

    let mut peer = rollback(peer_maker(), &[0, 1]);
    assert!(
        peer.adopt_session_clock(&frame, now, 0).is_empty(),
        "no stop to re-send yet"
    );
    assert_eq!(
        peer.session_clock_frame(now),
        None,
        "only the authority sends it"
    );
    // A frame reaching the authority (from a former one) changes nothing.
    let mut stray = frame;
    stray.pause_us = 9_000_000;
    let _ = authority.adopt_session_clock(&stray, now, 0);
    assert_eq!(authority.clock.pause(), Duration::ZERO);
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

    // A later frame carrying a stop moves every deadline by exactly the stop, however long it
    // took to arrive, and re-sends this relay's measured slots their reports.
    let _ = peer.note_lead_arrival(SlotId(1), ANCHOR + 5, start + steps(5));
    let mut stopped = frame;
    stopped.since_anchor_us += 30_000_000;
    stopped.pause_us = 5_000_000;
    let reports = peer.adopt_session_clock(&stopped, received + Duration::from_secs(31), 80_000);
    assert_eq!(
        peer.clock.due_at(ANCHOR),
        Some(start + Duration::from_secs(5))
    );
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].1.pause_us, 5_000_000);
    // A stale frame with less stopped time changes nothing.
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
