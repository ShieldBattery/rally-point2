//! The `turns_complete` count a relay stamps on the packets to its own clients in a rollback
//! session: the fewest gap-free turns it has forwarded of any in-game slot, observers' included.

use super::*;

use std::sync::atomic::Ordering;

fn complete(m: &DecisionMaker) -> u64 {
    m.turns_complete_handle().load(Ordering::Acquire)
}

/// A rollback session of slots 0 and 1, with slot 2 observing.
fn with_observer(authority: Authority) -> DecisionMaker {
    let mut m = DecisionMaker::new(key(), bounds(0, 20), law(), authority, [SlotId(2)].into());
    m.latch_rollback(true);
    m.set_expected_slots([SlotId(0), SlotId(1), SlotId(2)].into());
    m
}

#[test]
fn it_counts_the_turns_every_in_game_slot_has_forwarded_observers_included() {
    let now = Instant::now();
    for authority in [Authority::SelfRelay, Authority::Peer] {
        let mut m = with_observer(authority);
        m.note_forwarded_turns(SlotId(0), 30, now);
        m.note_forwarded_turns(SlotId(1), 28, now);
        assert_eq!(complete(&m), 0, "nothing until every slot has had a turn");
        m.note_forwarded_turns(SlotId(2), 25, now);
        assert_eq!(
            complete(&m),
            25,
            "an observer's turns hold it back like a player's: every client waits on them",
        );
        m.note_forwarded_turns(SlotId(2), 31, now);
        assert_eq!(complete(&m), 28);
    }
}

/// Slots 0 and 1 playing with slot 2 observing, having forwarded 50, 40 and 50 turns.
fn forwarded_50_40_50(now: Instant) -> DecisionMaker {
    let mut m = with_observer(Authority::SelfRelay);
    for (slot, count) in [(0, 50), (1, 40), (2, 50)] {
        m.note_forwarded_turns(SlotId(slot), count, now);
    }
    assert_eq!(complete(&m), 40);
    m
}

#[test]
fn a_held_drop_still_holds_it_back() {
    // Every client still needs slot 1's turn 40 until its leave is decided, so a client stalled on
    // it is waiting on the session, not its own downlink.
    let now = Instant::now();
    let mut m = forwarded_50_40_50(now);
    m.record_departure(SlotId(1), DepartureStamps::default(), LEAVE_REASON_DROPPED);
    m.note_forwarded_turns(SlotId(0), 51, now);
    assert_eq!(complete(&m), 40);
}

#[test]
fn a_counted_leave_holds_it_back_until_its_last_turn_is_in() {
    let now = Instant::now();
    let mut m = forwarded_50_40_50(now);
    m.finalized_drops_enabled = true;
    let _ = m.observe_leave(&LeaveDirective {
        finalized: true,
        slot: 1,
        reason: LEAVE_REASON_DROPPED,
        apply_at_frame: 45,
        leave_seq: 1,
        final_turn_count: Some(45),
    });
    m.note_forwarded_turns(SlotId(0), 51, now);
    assert_eq!(
        complete(&m),
        40,
        "slot 1's turns up to its leave aren't all here"
    );
    m.note_forwarded_turns(SlotId(1), 45, now);
    assert_eq!(
        complete(&m),
        50,
        "and once they are, it waits on nobody's turns past it"
    );
}

#[test]
fn a_leave_without_a_count_stops_holding_it_back_once_decided() {
    // A client applies it as soon as the directive reaches it, which only its own downlink can
    // hold up.
    let now = Instant::now();
    let mut m = forwarded_50_40_50(now);
    let _ = m.observe_leave(&LeaveDirective {
        finalized: false,
        slot: 1,
        reason: LEAVE_REASON_LEFT,
        apply_at_frame: 41,
        leave_seq: 1,
        final_turn_count: None,
    });
    m.note_forwarded_turns(SlotId(0), 51, now);
    assert_eq!(complete(&m), 50);
}

#[test]
fn a_lockstep_session_stamps_nothing() {
    let now = Instant::now();
    let mut m = maker();
    m.set_expected_slots([SlotId(0), SlotId(1)].into());
    m.note_forwarded_turns(SlotId(0), 30, now);
    m.note_forwarded_turns(SlotId(1), 30, now);
    assert_eq!(complete(&m), 0);
}
