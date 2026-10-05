//! Copies of the clock: every relay merges the others' copies into its own (the later deadline
//! for each step it hasn't made final), with old stops folded into a base, and measures its own
//! players' turns as the copies make deadlines final.

use super::*;

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
    let _ = peer.merge_session_clock(&frame, now, 0);
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
fn another_relay_merges_copies_arriving_late_or_twice_to_the_same_clock() {
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
    let _ = in_order.merge_session_clock(&first, on_time(start, 99), 0);
    let _ = in_order.merge_session_clock(&second, resumed, 0);
    let _ = in_order.merge_session_clock(&heartbeat, resumed + STEP, 0);
    let mut out_of_order = rollback(peer_maker(), &[0, 1]);
    let _ = out_of_order.merge_session_clock(&first, on_time(start, 99), 0);
    let _ = out_of_order.merge_session_clock(&heartbeat, resumed + STEP, 0);
    assert!(
        out_of_order
            .merge_session_clock(&second, resumed + 2 * STEP, 0)
            .is_empty()
    );
    let _ = out_of_order.merge_session_clock(&first, resumed + 3 * STEP, 0);
    let _ = out_of_order.merge_session_clock(&heartbeat, resumed + 4 * STEP, 0);

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
    let _ = peer.merge_session_clock(&authority.session_clock_frame(heard).unwrap(), heard, 0);

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
    let reports = peer.merge_session_clock(&update.frame.unwrap(), resumed + 20 * MS, 40_000);
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
    let _ = peer.merge_session_clock(&authority.session_clock_frame(start).unwrap(), start, 0);

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
    let reports = peer.merge_session_clock(&authority.session_clock_frame(sent).unwrap(), sent, 0);
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
fn every_relay_sends_its_copy_and_the_authority_merges_what_it_lacks() {
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
        .expect("the authority sends its copy");
    assert_eq!(frame.anchor_step, ANCHOR);
    assert_eq!(frame.since_anchor_us, 2_000_000);
    assert_eq!(frame.final_through, 49 + STALL_SLACK_STEPS);

    let mut peer = rollback(peer_maker(), &[0, 1]);
    assert!(
        peer.merge_session_clock(&frame, now, 0).is_empty(),
        "nothing measured yet",
    );
    let copy = peer
        .session_clock_frame(now)
        .expect("every relay sends its copy");
    // The authority merging a copy that knows nothing more changes nothing.
    assert!(authority.merge_session_clock(&copy, now, 0).is_empty());
    assert_eq!(authority.clock.pause(), Duration::ZERO);

    // A copy that knows of a stop the authority doesn't (one a former authority made) is taken in,
    // at the authority's own limit, where it moves nothing the authority holds as final.
    let limit = 49 + STALL_SLACK_STEPS;
    let held_final = authority.clock.due_at(limit);
    let mut knows_more = copy;
    knows_more.final_through += 1;
    knows_more.stops.push(ClockStop {
        step: limit - 2,
        pause_us: 300_000,
    });
    let _ = authority.merge_session_clock(&knows_more, now, 0);
    assert_eq!(authority.clock.pause(), 300 * MS);
    assert_eq!(authority.clock.due_at(limit), held_final);
    assert_eq!(
        authority.clock.due_at(limit + 1),
        Some(on_time(start, limit + 1) + 300 * MS)
    );
}

#[test]
fn copies_merged_in_any_order_agree_on_every_deadline_ahead() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], 100, start);
    let base = authority.session_clock_frame(on_time(start, 99)).unwrap();
    // The clock stops twice; a second relay that believed itself the authority meanwhile made a
    // stop of its own, at another step.
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + 200 * MS;
    let _ = forward(&mut authority, &[0, 1], 101, resumed);
    let once = authority.session_clock_frame(resumed).unwrap();
    let again = on_time(start, limit + 1) + 500 * MS;
    let _ = forward(&mut authority, &[0, 1], 102, again);
    let twice = authority.session_clock_frame(again).unwrap();
    let mut other = twice.clone();
    other.stops = vec![ClockStop {
        step: limit + 1,
        pause_us: 700_000,
    }];
    let copies = [base.clone(), once, twice, other];

    let mut ahead = Vec::new();
    for order in [
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [2, 0, 3, 1],
        [1, 3, 0, 2],
        [3, 3, 1, 1],
    ] {
        let mut relay = rollback(peer_maker(), &[0, 1]);
        let _ = relay.merge_session_clock(&base, on_time(start, 99), 0);
        for index in order {
            let _ = relay.merge_session_clock(&copies[index], again, 0);
            let _ = relay.merge_session_clock(&copies[index], again, 0);
        }
        let through = relay.clock.final_through().unwrap();
        ahead.push((
            through,
            relay.clock.pause(),
            relay.clock.pause_before(through + 1),
        ));
    }
    // Every order ends with the same limit and the same deadlines past it: the later of each
    // copy's, step by step. The two relays' stops cover the same wait, so the stopped time is the
    // most either knows of (700 ms), not their sum.
    assert!(ahead.iter().all(|merged| *merged == ahead[0]), "{ahead:?}");
    assert_eq!(ahead[0], (limit + 2, 700 * MS, 700 * MS));
}

#[test]
fn a_merge_never_moves_a_deadline_this_relay_holds_final() {
    let start = Instant::now();
    let mut authority = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], 100, start);
    let frame = authority.session_clock_frame(on_time(start, 99)).unwrap();
    let mut relay = rollback(peer_maker(), &[0, 1]);
    let _ = relay.merge_session_clock(&frame, on_time(start, 99), 0);
    let limit = 99 + STALL_SLACK_STEPS;
    let held_final: Vec<_> = (ANCHOR..=limit)
        .map(|seq| relay.clock.due_at(seq))
        .collect();

    // Another copy knows of a stop well before this relay's limit, and one past it.
    let mut other = frame.clone();
    other.final_through = limit + 10;
    other.stops = vec![
        ClockStop {
            step: limit - 4,
            pause_us: 250_000,
        },
        ClockStop {
            step: limit + 3,
            pause_us: 100_000,
        },
    ];
    let _ = relay.merge_session_clock(&other, on_time(start, 99), 0);
    let now_final: Vec<_> = (ANCHOR..=limit)
        .map(|seq| relay.clock.due_at(seq))
        .collect();
    assert_eq!(now_final, held_final);
    // The stop before the limit lands at the limit; the one past it, where it was.
    assert_eq!(relay.clock.pause_before(limit + 1), 250 * MS);
    assert_eq!(relay.clock.pause_before(limit + 4), 350 * MS);
    assert_eq!(relay.clock.final_through(), Some(limit + 10));
    // And merging it again changes nothing.
    assert!(
        relay
            .merge_session_clock(&other, on_time(start, 99), 0)
            .is_empty()
    );
    assert_eq!(relay.clock.pause(), 350 * MS);
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
    let _ = peer.merge_session_clock(&frame, received, 20_000);
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
    let reports = peer.merge_session_clock(&stopped, received + Duration::from_secs(31), 80_000);
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
    assert!(peer.merge_session_clock(&frame, received, 0).is_empty());
    assert_eq!(peer.clock.pause(), Duration::from_secs(5));
}

#[test]
fn a_merged_clock_records_its_anchor_and_at_most_the_capped_number_of_stops() {
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
    let _ = registry.merge_session_clock(&k, &frame, received, 20_000);
    // A session that keeps stopping, past the cap, and a stale repeat that grows nothing.
    let stops = u64::from(MAX_CLOCK_STOP_EVENTS) + 5;
    for _ in 0..stops {
        frame.stops.push(ClockStop {
            step: frame.final_through,
            pause_us: 1_000_000,
        });
        frame.final_through += 1;
        let _ = registry.merge_session_clock(&k, &frame, received, 20_000);
    }
    let _ = registry.merge_session_clock(&k, &frame, received, 20_000);

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
