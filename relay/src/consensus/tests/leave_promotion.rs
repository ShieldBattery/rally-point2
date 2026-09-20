//! What a promoted relay re-broadcasts and what it re-derives.

use super::*;

/// Two slots leaving are two independent decisions with distinct seqs — the
/// relay pushes each down its own control-stream frame.
#[test]
fn decide_leave_handles_multiple_slots_independently() {
    let mut maker = maker();
    maker.observe_frame(SlotId(0), GameFrameCount(55));
    maker.observe_frame(SlotId(1), GameFrameCount(60));
    maker.observe_frame(SlotId(2), GameFrameCount(70));
    let d1 = maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED).unwrap();
    let d2 = maker.decide_leave(SlotId(2), LEAVE_REASON_DROPPED).unwrap();
    assert_eq!(d1.slot, 1);
    assert_eq!(d2.slot, 2);
    assert_ne!(d1.leave_seq, d2.leave_seq, "distinct leave seqs");
}

/// A demotion keeps the cached leave, and a re-promotion re-broadcasts it
/// *verbatim* — the same apply frame, even though the session frame has since
/// advanced past what a fresh re-derivation would compute. Survivors that
/// already applied it did so at that exact frame, so it must not move.
#[test]
fn promotion_re_broadcasts_a_cached_leave_verbatim() {
    let mut maker = maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    let first = maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED).unwrap();
    assert_eq!(first.apply_at_frame, 51);

    // Demote — the cache survives — then the surviving slot's stamps advance
    // well past the apply frame.
    assert_eq!(
        maker.set_authority(Authority::Peer, &HashSet::new()),
        (Vec::new(), Vec::new())
    );
    maker.observe_frame(SlotId(0), GameFrameCount(200));

    // Re-promote: the cached directive is re-emitted verbatim — apply frame
    // AND leave_seq untouched, not a fresh derivation, so it is not in the
    // `fresh` set either (no second notice for an already-cached leave).
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(
        leaves,
        vec![first],
        "the cached leave re-broadcasts verbatim"
    );
    assert!(
        fresh.is_empty(),
        "a verbatim re-broadcast is not a fresh insert"
    );

    // And decide_leave for that slot is now a no-op (still cached).
    assert_eq!(maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED), None);
}

/// The overshoot regression: survivors' stamped frames advanced past the
/// departed slot's last frame before they stalled, so a survivors-only
/// session frame exceeds it — the re-derived apply frame must still be
/// `last_frame + 1` (where the stalled survivors are pinned), never
/// `session + 1` (a frame they would never reach).
#[test]
fn re_derivation_does_not_overshoot_when_survivors_ran_ahead() {
    let mut maker = peer_maker();
    // The survivor's stamps run ahead of the departed slot's last frame.
    maker.observe_frame(SlotId(0), GameFrameCount(55));
    maker.record_departure(SlotId(1), framed(50), LEAVE_REASON_DROPPED);
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(55)),
        "the survivors-only session frame exceeds the departed slot's last frame",
    );

    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(leaves.len(), 1);
    assert_eq!(
        leaves[0].apply_at_frame, 51,
        "one past the departed slot's frame — the survivors' lead must not push it",
    );
    assert_eq!(fresh, leaves, "a re-derived leave is a fresh insert");
}

/// A promotion re-derives a departure the previous authority never decided:
/// the departure was recorded (via `record_departure`) but no directive was
/// cached, so the promoted relay decides it fresh from the stored last
/// frame -- which is where the frame lives once the slot's own state is
/// gone. A peer decides nothing on its own, which is exactly why the
/// promotion has something left to do.
#[test]
fn promotion_re_derives_a_departure_with_no_cached_directive() {
    // This relay was never the authority: it recorded a peer's SlotDeparted
    // but decided nothing (decide_leave is a no-op on a non-authority).
    let mut maker = peer_maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    maker.record_departure(SlotId(1), framed(50), LEAVE_REASON_DROPPED);
    assert_eq!(
        maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED),
        None,
        "no decision as a peer"
    );
    // Recording captured the frame into the record and retired the live
    // state, so the teardown `remove_slot` the trigger site runs next is a
    // no-op -- and the record, not the slot, is what the promotion reads.
    assert_eq!(
        maker.slot_frame(SlotId(1)),
        None,
        "recording retires the live state"
    );
    maker.remove_slot(SlotId(1));

    // Promoted: it derives the leave fresh from the stored last frame 50.
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].slot, 1);
    assert_eq!(
        leaves[0].apply_at_frame, 51,
        "one past the stored last frame"
    );
    assert_eq!(
        fresh, leaves,
        "a departure with no cached directive is a fresh insert on promotion, \
         which is exactly the case the departure notifier must catch",
    );
}

/// A promotion must not decide a departure whose drop is still held on this
/// relay: a held drop is decided only by an honored manual request. The record
/// is left undecided (not cached), so a later honored request can still decide
/// it — exactly once — and no departure is lost.
#[test]
fn a_promotion_skips_a_held_departure_and_a_request_still_decides_it() {
    let mut maker = peer_maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.record_departure(SlotId(1), framed(50), LEAVE_REASON_DROPPED);

    // Promote while slot 1's drop is still held: the promotion decides nothing.
    let held_slots = HashSet::from([SlotId(1)]);
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &held_slots);
    assert!(
        leaves.is_empty() && fresh.is_empty(),
        "a held departure is not decided by the promotion",
    );
    assert!(
        maker.has_departure(SlotId(1)),
        "the departure record is kept for a manual request to decide from",
    );

    // An honored manual request (which calls `decide_leave`) still decides it —
    // the record was never marked decided, so it is not lost — and only once.
    let decided = maker
        .decide_leave(SlotId(1), LEAVE_REASON_DROPPED)
        .expect("an honored request decides the held leave");
    assert_eq!(decided.slot, 1);
    assert_eq!(decided.apply_at_frame, 51, "one past the stored last frame");
    assert_eq!(
        maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED),
        None,
        "the leave decides only once",
    );
}

/// With two undecided departures on a promoting relay, only the one whose drop
/// is *not* held is decided; the held one is left for a manual request. This is
/// the crux that keeps a presence flap from deciding a reconnecting slot's drop
/// while a genuinely-gone slot is still cleaned up.
#[test]
fn a_promotion_derives_only_the_unheld_departure() {
    let mut maker = peer_maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.record_departure(SlotId(1), framed(50), LEAVE_REASON_DROPPED);
    maker.record_departure(SlotId(2), framed(60), LEAVE_REASON_DROPPED);

    // Slot 1's drop is still held; slot 2 is not held (it left cleanly, or its
    // hold was already released) — only slot 2 is decided.
    let held_slots = HashSet::from([SlotId(1)]);
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &held_slots);
    assert_eq!(leaves.len(), 1, "only the unheld departure is decided");
    assert_eq!(leaves[0].slot, 2);
    assert_eq!(fresh, leaves, "the unheld re-derivation is a fresh insert");
    assert!(
        maker.has_departure(SlotId(1)),
        "the held slot stays undecided"
    );
    assert!(
        maker
            .decide_leave(SlotId(1), LEAVE_REASON_DROPPED)
            .is_some(),
        "an honored request can still decide it later",
    );
}

/// A slot that returned while its drop was held has its departure discarded, so
/// even an unheld promotion (its hold already released by the return) does not
/// re-derive a leave for it.
#[test]
fn reinstate_slot_clears_the_departure_so_a_promotion_does_not_re_derive_it() {
    let mut maker = peer_maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.record_departure(SlotId(1), framed(50), LEAVE_REASON_DROPPED);

    assert!(
        maker.reinstate_slot(SlotId(1)),
        "the recorded departure is cleared",
    );
    assert!(!maker.has_departure(SlotId(1)));
    assert!(
        !maker.reinstate_slot(SlotId(1)),
        "reinstating a slot with no departure is a no-op",
    );

    // Promote with an empty held set (the return already released the hold):
    // there is no departure left to re-derive, so no leave is decided.
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(
        leaves.is_empty() && fresh.is_empty(),
        "a reinstated slot yields no promotion leave",
    );
}

/// A promotion re-broadcasts a cached leave even when the survivors' session
/// frame is at/past its apply frame. The observed frames are survivors' SEND
/// stamps, which lead their execution by the latency buffer's depth: a
/// survivor stalled waiting for this very leave has stamps at or past
/// `apply_at` too, so stamps-past-apply does not mean applied — a skip here
/// could withhold the one re-delivery that unstalls a survivor the original
/// push missed. Re-delivery to survivors that did apply it is deduped by slot.
#[test]
fn promotion_re_broadcasts_even_when_survivor_stamps_pass_apply() {
    let mut maker = maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    let leave = maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED).unwrap();
    assert_eq!(leave.apply_at_frame, 51);

    assert_eq!(
        maker.set_authority(Authority::Peer, &HashSet::new()),
        (Vec::new(), Vec::new())
    );
    // The surviving slot's stamps reach the apply frame — exactly what a
    // stalled, un-served survivor's leading stamps look like.
    maker.observe_frame(SlotId(0), GameFrameCount(51));
    assert_eq!(maker.session_frame(), Some(GameFrameCount(51)));
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(
        leaves,
        vec![leave],
        "the cached leave re-broadcasts regardless of the survivors' stamps",
    );
    assert!(fresh.is_empty(), "already cached — not a fresh insert");
}
