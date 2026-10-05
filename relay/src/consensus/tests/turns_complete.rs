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

#[test]
fn a_departed_slot_no_longer_holds_it_back() {
    let now = Instant::now();
    let mut m = with_observer(Authority::SelfRelay);
    for (slot, count) in [(0, 40), (1, 12), (2, 40)] {
        m.note_forwarded_turns(SlotId(slot), count, now);
    }
    assert_eq!(complete(&m), 12);
    m.decide_leave(SlotId(1), LEAVE_REASON_LEFT);
    m.note_forwarded_turns(SlotId(0), 41, now);
    assert_eq!(complete(&m), 40);
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
