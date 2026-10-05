//! The clock across authority changes, and while two relays both believe they are the
//! authority: no relay's final deadlines move, no stop is lost while any relay knows of it, and
//! the copies converge on the same deadlines ahead.

use super::*;

#[test]
fn a_promoted_relay_holding_an_older_limit_stops_nowhere_the_former_authority_did_not() {
    let start = Instant::now();
    let mut former = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut former, &[0, 1], 100, start);
    let older = former.session_clock_frame(on_time(start, 99)).unwrap();
    play_on_schedule(&mut former, &[0, 1], 104, start);
    let newer = former.session_clock_frame(on_time(start, 103)).unwrap();
    assert_eq!(older.final_through, 99 + STALL_SLACK_STEPS);
    assert_eq!(newer.final_through, 103 + STALL_SLACK_STEPS);

    // One relay has confirmed as far as the authority did, but last heard its older limit; another
    // heard the newer one.
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut promoted, &[0, 1], 104, start);
    let _ = promoted.merge_session_clock(&older, on_time(start, 99), 0);
    let mut other = rollback(peer_maker(), &[0, 1]);
    let _ = other.merge_session_clock(&older, on_time(start, 99), 0);
    let _ = other.merge_session_clock(&newer, on_time(start, 103), 0);
    let final_before = other.clock.due_at(103 + STALL_SLACK_STEPS);

    // The authority fails, the first relay takes over, and the next step becomes confirmable a
    // little late, but well inside the limit the former authority had set.
    let _ = promoted.set_authority(Authority::SelfRelay, &HashSet::new());
    let at = on_time(start, 107);
    let update = forward(&mut promoted, &[0, 1], 105, at);
    assert_eq!(
        update.and_then(|update| update.frame),
        None,
        "no stop: the clock hadn't reached its limit"
    );
    assert_eq!(promoted.clock.pause(), Duration::ZERO);
    assert_eq!(
        promoted.clock.final_through(),
        Some(104 + STALL_SLACK_STEPS)
    );
    // The former authority, had it carried on, would have the same clock.
    let _ = forward(&mut former, &[0, 1], 105, at);
    for seq in ANCHOR..=104 + STALL_SLACK_STEPS {
        assert_eq!(
            promoted.clock.due_at(seq),
            former.clock.due_at(seq),
            "seq {seq}"
        );
    }

    // The other relay adopts the new authority's clock without any deadline it held as final
    // moving.
    let frame = promoted.session_clock_frame(at).unwrap();
    let _ = other.merge_session_clock(&frame, at, 0);
    assert_eq!(other.clock.final_through(), Some(104 + STALL_SLACK_STEPS));
    assert_eq!(other.clock.due_at(103 + STALL_SLACK_STEPS), final_before);
    assert_eq!(other.clock.pause(), Duration::ZERO);
}

/// Promotes `relay` to the session's authority.
fn promote(relay: &mut DecisionMaker) {
    let _ = relay.set_authority(Authority::SelfRelay, &HashSet::new());
}

/// The deadlines `maker` holds as final, through `through`.
fn deadlines(maker: &DecisionMaker, through: u64) -> Vec<Option<Instant>> {
    (ANCHOR..=through)
        .map(|seq| maker.clock.due_at(seq))
        .collect()
}

#[test]
fn a_new_authority_learns_a_stop_only_another_relay_heard_of() {
    let start = Instant::now();
    let mut former = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut former, &[0, 1], 100, start);
    let older = former.session_clock_frame(on_time(start, 99)).unwrap();
    // The clock stands still at its limit for a second, and the stop's frame reaches the other
    // relay but not the one about to be promoted; then the authority fails.
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + Duration::from_secs(1);
    let stop = forward(&mut former, &[0, 1], 101, resumed)
        .and_then(|update| update.frame)
        .expect("stopped");
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut promoted, &[0, 1], 101, start);
    let _ = promoted.merge_session_clock(&older, on_time(start, 99), 0);
    let mut other = rollback(peer_maker(), &[0, 1]);
    let _ = other.merge_session_clock(&older, on_time(start, 99), 0);
    let _ = other.merge_session_clock(&stop, resumed, 0);
    let held_final = deadlines(&other, limit + 1);
    promote(&mut promoted);

    // The other relay's copy reaches the new authority on the next heartbeat, and the stop with
    // it, at its own step.
    let heartbeat = resumed + 250 * MS;
    let _ =
        promoted.merge_session_clock(&other.session_clock_frame(heartbeat).unwrap(), heartbeat, 0);
    assert_eq!(promoted.clock.pause(), Duration::from_secs(1));
    assert_eq!(
        promoted.clock.due_at(limit + 1),
        Some(on_time(start, limit + 1) + Duration::from_secs(1))
    );
    // And the new authority's copy changes nothing the other relay holds as final.
    let _ = other.merge_session_clock(
        &promoted.session_clock_frame(heartbeat).unwrap(),
        heartbeat,
        0,
    );
    assert_eq!(deadlines(&other, limit + 1), held_final);
    assert_eq!(other.clock.pause(), Duration::from_secs(1));
}

#[test]
fn a_lagging_new_authoritys_needless_stop_moves_nothing_another_relay_holds_final() {
    let start = Instant::now();
    let mut former = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut former, &[0, 1], 100, start);
    let older = former.session_clock_frame(on_time(start, 99)).unwrap();
    play_on_schedule(&mut former, &[0, 1], 104, start);
    let newer = former.session_clock_frame(on_time(start, 103)).unwrap();
    // The relay promoted last heard the older limit and is missing one of slot 0's turns, so it
    // has confirmed nothing past seq 99 itself; the other relay heard the newer limit.
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut promoted, &[0, 1], 100, start);
    for count in 101..=104 {
        let _ = promoted.note_forwarded_turns(SlotId(1), count, on_time(start, count - 1));
    }
    let _ = promoted.merge_session_clock(&older, on_time(start, 99), 0);
    let mut other = rollback(peer_maker(), &[0, 1]);
    let _ = other.merge_session_clock(&newer, on_time(start, 103), 0);
    let other_limit = 103 + STALL_SLACK_STEPS;
    let held_final = deadlines(&other, other_limit);
    promote(&mut promoted);

    // The missing turn arrives two steps past the older limit's deadline, before any copy from
    // the other relay: the new authority stops its clock where the former never did.
    let at = on_time(start, 99 + STALL_SLACK_STEPS) + steps(2);
    let frame = promoted
        .note_forwarded_turns(SlotId(0), 104, at)
        .and_then(|update| update.frame)
        .expect("a needless stop");
    assert_eq!(promoted.clock.pause(), steps(2));

    // The other relay takes it in at its own limit: nothing it holds as final moves, and from
    // there on both copies agree.
    let _ = other.merge_session_clock(&frame, at, 0);
    assert_eq!(deadlines(&other, other_limit), held_final);
    assert_eq!(other.clock.pause(), steps(2));
    let _ = promoted.merge_session_clock(&other.session_clock_frame(at).unwrap(), at, 0);
    let ahead = other.clock.final_through().unwrap() + 1;
    assert_eq!(promoted.clock.final_through(), other.clock.final_through());
    assert_eq!(
        promoted.clock.pause_before(ahead),
        other.clock.pause_before(ahead)
    );
}

#[test]
fn a_relay_promoted_while_the_clock_stands_still_keeps_the_stop_where_it_is() {
    let start = Instant::now();
    let mut former = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut former, &[0, 1], 100, start);
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    // The session waits on a dropped player. Three seconds in the authority fails.
    let heard = stopped_at + Duration::from_secs(3);
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut promoted, &[0, 1], 100, start);
    let _ = promoted.merge_session_clock(&former.session_clock_frame(heard).unwrap(), heard, 0);
    promote(&mut promoted);

    // Ten seconds after the stop began, turns come again: the stop is all there, at its step.
    let resumed = stopped_at + Duration::from_secs(10);
    let frame = forward(&mut promoted, &[0, 1], 101, resumed)
        .and_then(|update| update.frame)
        .expect("stopped");
    assert_eq!(
        frame.stops,
        vec![ClockStop {
            step: limit,
            pause_us: 10_000_000,
        }],
    );
}

#[test]
fn a_relay_deciding_the_clock_carries_on_whatever_another_relay_also_decides() {
    let start = Instant::now();
    // Descriptors are settling: two relays both believe they are the authority for a while, and
    // both decide the clock from the same turns.
    let mut first = rollback(maker(), &[0, 1]);
    let mut second = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut first, &[0, 1], 100, start);
    play_on_schedule(&mut second, &[0, 1], 100, start);
    let _ = second.merge_session_clock(
        &first.session_clock_frame(on_time(start, 99)).unwrap(),
        on_time(start, 99),
        0,
    );
    promote(&mut second);
    // The session waits ten seconds; the second stops believing it is the authority just before
    // turns come again, and six of them arrive at once.
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + Duration::from_secs(10);
    let _ = second.set_authority(Authority::Peer, &HashSet::new());
    let mut stops = Vec::new();
    for count in 101..=106 {
        stops.extend(forward(&mut first, &[0, 1], count, resumed).and_then(|update| update.frame));
        let _ = forward(&mut second, &[0, 1], count, resumed);
    }
    // The relay that stayed the authority recorded the stop exactly as it would have alone.
    assert_eq!(stops.len(), 1);
    assert_eq!(
        stops[0].stops,
        vec![ClockStop {
            step: limit,
            pause_us: 10_000_000,
        }],
    );
    // And the other relay, merging its copy on the next heartbeat, agrees with it from here on.
    let heartbeat = resumed + 250 * MS;
    let _ =
        second.merge_session_clock(&first.session_clock_frame(heartbeat).unwrap(), heartbeat, 0);
    let ahead = first.clock.final_through().unwrap() + 1;
    assert_eq!(second.clock.final_through(), first.clock.final_through());
    assert_eq!(
        second.clock.pause_before(ahead),
        first.clock.pause_before(ahead)
    );
}

#[test]
fn a_new_authority_with_a_stale_copy_and_a_relay_with_a_newer_one_converge() {
    let start = Instant::now();
    let mut former = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut former, &[0, 1], 100, start);
    let older = former.session_clock_frame(on_time(start, 99)).unwrap();
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + 500 * MS;
    let _ = forward(&mut former, &[0, 1], 101, resumed);
    for count in 102..=104 {
        let _ = forward(&mut former, &[0, 1], count, resumed + steps(count - 101));
    }
    let newer = former.session_clock_frame(resumed + steps(3)).unwrap();
    // The newer copy, with a stop, reached the other relay; the promoted relay holds the older.
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    let _ = promoted.merge_session_clock(&older, on_time(start, 99), 0);
    let mut other = rollback(peer_maker(), &[0, 1]);
    let _ = other.merge_session_clock(&newer, resumed + steps(3), 0);
    promote(&mut promoted);

    // Each sends its copy to the other on the next heartbeat: both end on the same limit and
    // the same deadlines past it.
    let heartbeat = resumed + steps(6);
    let from_promoted = promoted.session_clock_frame(heartbeat).unwrap();
    let from_other = other.session_clock_frame(heartbeat).unwrap();
    let _ = other.merge_session_clock(&from_promoted, heartbeat, 0);
    let _ = promoted.merge_session_clock(&from_other, heartbeat, 0);
    let ahead = other.clock.final_through().unwrap() + 1;
    assert_eq!(promoted.clock.final_through(), other.clock.final_through());
    assert_eq!(
        promoted.clock.pause_before(ahead),
        other.clock.pause_before(ahead)
    );
    assert_eq!(promoted.clock.pause(), 500 * MS);
}

#[test]
fn a_start_completed_several_steps_at_once_anchors_where_the_newest_step_is_due_now() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    let _ = forward(&mut m, &[0, 1], 20, start);
    // A slow player's turns complete the lockstep start and six steps past it at once.
    let at = start + 300 * MS;
    let update = forward(&mut m, &[0, 1], 30, at).expect("anchored");
    assert_eq!(update.frame.map(|frame| frame.anchor_step), Some(ANCHOR));
    assert_eq!(
        m.clock.due_at(29),
        Some(at),
        "the newest step is the one due now"
    );
    assert_eq!(m.clock.due_at(ANCHOR), Some(at - steps(29 - ANCHOR)));
    assert_eq!(m.clock.final_through(), Some(29 + STALL_SLACK_STEPS));
}

#[test]
fn a_relay_that_missed_the_start_takes_the_anchor_from_a_copy_rather_than_anchoring_its_own() {
    let start = Instant::now();
    // The session has stopped for three seconds by the time a relay that never had the clock
    // is promoted.
    let mut authority = rollback(maker(), &[0, 1]);
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    play_on_schedule(&mut authority, &[0, 1], 100, start);
    play_on_schedule(&mut promoted, &[0, 1], 100, start);
    let limit = 99 + STALL_SLACK_STEPS;
    let resumed = on_time(start, limit) + Duration::from_secs(3);
    let _ = forward(&mut authority, &[0, 1], 101, resumed);
    let _ = forward(&mut promoted, &[0, 1], 101, resumed);
    let _ = promoted.set_authority(Authority::SelfRelay, &HashSet::new());

    // Its next advance anchors nothing: any anchor of its own would carry the three seconds
    // already stopped, which no copy's stops could line up with.
    let next = resumed + STEP;
    assert_eq!(forward(&mut promoted, &[0, 1], 102, next), None);
    let _ = forward(&mut authority, &[0, 1], 102, next);
    assert!(!promoted.clock.is_anchored());

    // The next copy it gets anchors it, on the same deadlines as the relay it came from.
    let heartbeat = next + 100 * MS;
    let _ = promoted.merge_session_clock(
        &authority.session_clock_frame(heartbeat).unwrap(),
        heartbeat,
        0,
    );
    let through = authority.clock.final_through().unwrap();
    assert_eq!(promoted.clock.final_through(), Some(through));
    for seq in ANCHOR..=through {
        assert_eq!(
            promoted.clock.due_at(seq),
            authority.clock.due_at(seq),
            "seq {seq}"
        );
    }
    // And from there it decides the clock itself.
    let held = on_time(start, through) + Duration::from_secs(3) + 50 * MS;
    let frame = forward(&mut promoted, &[0, 1], 103, held)
        .and_then(|update| update.frame)
        .expect("stopped");
    assert_eq!(frame.stops.last().map(|stop| stop.step), Some(through));
}
