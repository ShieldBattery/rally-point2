//! The queued directive the turn path stamps: its lifetime, its seq ordering, and the initial broadcast.

use super::*;

/// A decision queues a directive that `active_directive` stamps onto every
/// forwarded turn until the session frame reaches its apply frame -- then
/// it retires: every slot has been observed past the frame, so the change
/// is applied (or moot) everywhere.
#[test]
fn a_directive_is_stamped_until_the_session_passes_its_apply_frame() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // No decision yet: nothing to stamp.
    assert_eq!(maker.active_directive(), None);

    // 150ms -> raise to 4 at frame 10.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 10).expect("a raise fires");
    let stamp = maker
        .active_directive()
        .expect("a decision queues a directive");
    assert_eq!(stamp.buffer_turns, 4);
    assert_eq!(stamp.apply_at_frame, d.applied_frame.0);
    assert_eq!(stamp.decision_seq, 1);

    // Every forwarded turn carries it while the session hasn't reached the
    // apply frame -- there is no fixed budget for a quiet spell to exhaust.
    for _ in 0..100 {
        assert_eq!(maker.active_directive(), Some(stamp));
    }

    // The slowest slot passes the apply frame: the directive retires.
    maker.observe_frame(SlotId(0), GameFrameCount(d.applied_frame.0));
    assert_eq!(maker.active_directive(), None, "applied everywhere");
    assert_eq!(maker.active_directive(), None, "and stays retired");
}

/// A directive carries no `authority_relay_id` until
/// `set_own_relay_id` is called -- `DecisionMaker::new` has no relay id
/// to seed it with. Once set, every subsequently queued directive stamps
/// it, including a decision the control law queues on its own (not just
/// the caller re-affirming).
#[test]
fn a_directive_carries_no_relay_id_until_one_is_set_then_stamps_every_decision() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let _ = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 10).expect("a raise fires");
    assert_eq!(
        maker.active_directive().unwrap().authority_relay_id,
        None,
        "no relay id set yet",
    );

    maker.set_own_relay_id(RelayId(7));
    let d2 =
        ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 200).expect("a further raise fires");
    assert_eq!(
        maker.active_directive(),
        Some(BufferDirective {
            buffer_turns: d2.buffer.0,
            apply_at_frame: d2.applied_frame.0,
            decision_seq: 2,
            authority_relay_id: Some(7),
        }),
    );
}

/// Two decision-makers with different relay ids, both promoted
/// `SelfRelay` during the acknowledged staggered-handoff window, stamp a
/// directive at the SAME `decision_seq` (each mints its own count from
/// where it took authority) with different `buffer_turns` -- the exact
/// wire collision the client-side tie-break exists to resolve. This
/// proves the relay's own half of the fix: the two stamps are
/// distinguishable by `authority_relay_id`, which is all a client needs
/// (see `client::directive`'s own tests for the convergence proof).
#[test]
fn two_relays_racing_authority_stamp_a_genuine_collision_distinguishable_by_relay_id() {
    let mut relay_a = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    relay_a.set_own_relay_id(RelayId(1));
    let mut relay_b = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    relay_b.set_own_relay_id(RelayId(2));

    // Both independently raise at their own first decision -- each mints
    // decision_seq 1, from its own count, with a different target.
    ingest_at(&mut relay_a, &conditions(0, 150_000, 0, 100), 10).expect("A raises");
    ingest_at(&mut relay_b, &conditions(0, 600_000, 0, 100), 10).expect("B raises");
    let stamp_a = relay_a.active_directive().unwrap();
    let stamp_b = relay_b.active_directive().unwrap();

    assert_eq!(stamp_a.decision_seq, 1);
    assert_eq!(stamp_b.decision_seq, 1);
    assert_ne!(
        stamp_a.buffer_turns, stamp_b.buffer_turns,
        "a genuine collision: same seq, different decisions",
    );
    assert_eq!(stamp_a.authority_relay_id, Some(1));
    assert_eq!(stamp_b.authority_relay_id, Some(2));
}

/// The broadcast outlives a one-sided stretch of traffic: while one slot
/// is stalled, the session frame (the minimum) doesn't advance, so the
/// directive keeps stamping every turn the other slot produces until the
/// stalled slot is back and past the apply frame.
#[test]
fn a_directive_outlives_a_one_sided_stall() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.observe_frame(SlotId(0), GameFrameCount(10));
    maker.observe_frame(SlotId(1), GameFrameCount(10));
    // Slot 1's link degrades (300ms): raise to 8, applied at 10 + 8 + 3.
    let d = ingest_at(&mut maker, &conditions(1, 300_000, 0, 100), 10).expect("a raise fires");

    // Slot 0 keeps producing turns well past the apply frame while slot 1
    // is stalled. The session frame stays pinned at the stalled slot, so
    // every one of slot 0's forwarded turns still carries the stamp.
    for frame in 11..(d.applied_frame.0 + 50) {
        maker.observe_frame(SlotId(0), GameFrameCount(frame));
        assert!(maker.active_directive().is_some(), "still broadcasting");
    }

    // Slot 1 recovers and passes the apply frame: the directive retires.
    maker.observe_frame(SlotId(1), GameFrameCount(d.applied_frame.0));
    assert_eq!(maker.active_directive(), None);
}

/// A newer decision supersedes an older still-broadcasting one, and its
/// higher `decision_seq` is what lets clients rank interleaved copies.
#[test]
fn a_new_decision_supersedes_a_still_broadcasting_one() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    let first = maker.active_directive().expect("the first raise queues");
    assert_eq!(first.buffer_turns, 4);
    assert_eq!(first.decision_seq, 1);

    // Conditions worsen: a raise to 8 fires, replacing the pending directive.
    ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 2);
    let second = maker
        .active_directive()
        .expect("the new directive is pending");
    assert_eq!(second.buffer_turns, 8, "the latest buffer wins");
    assert!(
        second.decision_seq > first.decision_seq,
        "copies of both may interleave on the wire; the seq ranks them",
    );
}

/// A non-authority relay makes no decision, so it never has a directive to
/// stamp -- it only forwards the authority's already-stamped turns.
#[test]
fn a_non_authority_never_stamps_a_directive() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    // It ingests conditions (and would compute a target) but makes no decision.
    ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 1);
    assert!(maker.target().is_some(), "it still tracks conditions");
    assert_eq!(maker.active_directive(), None, "but never stamps");
}

/// A held decision (target unchanged, or a dwell-suppressed lower) queues
/// no directive -- only an actual buffer change is broadcast.
#[test]
fn a_held_decision_queues_no_directive() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Raise to 4, then let the session pass the apply frame so the
    // directive retires and nothing is pending.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
    maker.observe_frame(SlotId(0), GameFrameCount(d.applied_frame.0));
    assert_eq!(maker.active_directive(), None);

    // Same conditions again: target unchanged, no decision, nothing queued.
    let held = ingest_at(
        &mut maker,
        &conditions(0, 150_000, 0, 100),
        d.applied_frame.0 + 1,
    );
    assert_eq!(held, None, "target unchanged holds");
    assert_eq!(maker.active_directive(), None, "a hold queues no directive");
}

// -- Initial directive & input trace --

/// The first framed turn broadcasts the current buffer unconditionally when
/// the control law itself makes no change (here: no RTT yet, so the target
/// holds) -- so a client seeded at a different buffer is corrected even while
/// the target sits at the minimum. It fires exactly once.
#[test]
fn the_first_framed_turn_broadcasts_the_current_buffer_when_the_law_holds() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // A framed turn with no RTT measurement (rtt_us = 0): the law has no
    // target and holds, so the unconditional initial broadcast fires.
    let d = ingest_at(&mut maker, &conditions(0, 0, 0, 100), 5).expect("initial directive");
    assert_eq!(
        d.buffer,
        BufferSize(0),
        "carries the current (minimum) buffer"
    );
    // Horizon = frame + span(current buffer = 0) + APPLY_HORIZON.
    assert_eq!(d.applied_frame, GameFrameCount(5 + APPLY_HORIZON));
    let stamp = maker.active_directive().expect("queued for broadcast");
    assert_eq!(stamp.buffer_turns, 0);
    assert_eq!(stamp.decision_seq, 1);

    // Fires once: a later still-RTT-less framed turn queues nothing new.
    let again = ingest_at(&mut maker, &conditions(0, 0, 0, 200), 6);
    assert_eq!(again, None, "the initial broadcast is a one-shot");
}

/// The initial broadcast re-affirms `self.buffer`, which is seeded straight
/// from wire `bounds.min` with no validation — a deserialized or inverted
/// bounds (public fields bypass `BufferBounds::new`) can put it past the
/// game-sync-safe ceiling, and a directive that deep deterministically
/// mass-drops the game's players. `queue_directive` caps every
/// locally-authored directive regardless of how the value reached it.
#[test]
fn the_initial_broadcast_is_capped_at_the_game_sync_safe_ceiling() {
    let mut maker = DecisionMaker::new(
        key(),
        // A struct literal, as wire deserialization would produce it: no
        // constructor validation, min already past the ceiling.
        BufferBounds {
            min: GAME_SYNC_SAFE_BUFFER_MAX + 6,
            max: GAME_SYNC_SAFE_BUFFER_MAX + 6,
        },
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let d = ingest_at(&mut maker, &conditions(0, 0, 0, 100), 5).expect("initial directive");
    assert_eq!(d.buffer, BufferSize(GAME_SYNC_SAFE_BUFFER_MAX));
    let stamp = maker.active_directive().expect("queued for broadcast");
    assert_eq!(stamp.buffer_turns, GAME_SYNC_SAFE_BUFFER_MAX);
}

/// Nothing is broadcast before the first framed turn: conditions can flow in
/// the lobby (RTT and all), but with no consensus coordinate there is no frame
/// to schedule an apply against.
#[test]
fn no_initial_directive_before_the_first_framed_turn() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Conditions but no `observe_frame`: session_frame stays None.
    let d = maker.ingest_local(&conditions(0, 150_000, 0, 100));
    assert_eq!(d, None, "no broadcast without a framed turn");
    assert_eq!(maker.active_directive(), None);
}

/// A non-authority never broadcasts an initial directive: it makes no
/// decisions at all, even once the session is framed.
#[test]
fn a_non_authority_broadcasts_no_initial_directive() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let d = ingest_at(&mut maker, &conditions(0, 0, 0, 100), 5);
    assert_eq!(d, None, "a peer decides nothing");
    assert_eq!(maker.active_directive(), None);
}

/// A real decision at the first framed turn *is* the session's first
/// broadcast, so no separate initial directive is queued behind it -- the
/// raise numbers as decision 1, not 2.
#[test]
fn a_first_turn_decision_serves_as_the_initial_broadcast() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
    assert_eq!(d.buffer, BufferSize(4));
    let stamp = maker.active_directive().expect("queued");
    assert_eq!(
        stamp.decision_seq, 1,
        "the raise is decision 1; no initial directive precedes it",
    );
}

/// A newly promoted authority re-affirms the buffer once -- and re-affirms the
/// *committed* buffer it tracked as a peer (via `observe_directive`), not a
/// stale minimum, so a survivor already at that depth applies a no-op resize
/// rather than being slammed down to the minimum.
#[test]
fn promotion_re_affirms_the_committed_buffer() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    // As a peer it forwarded the authority's directive, tracking the committed
    // buffer (5) and its decision seq (7).
    maker.observe_directive(&BufferDirective {
        buffer_turns: 5,
        apply_at_frame: 100,
        decision_seq: 7,
        authority_relay_id: None,
    });
    assert_eq!(
        maker.buffer(),
        BufferSize(5),
        "a peer tracks the committed buffer"
    );
    maker.observe_frame(SlotId(0), GameFrameCount(200));

    // Promotion resets the initial-broadcast flag (mirrors re-broadcasting
    // leaves): the next decision re-affirms the buffer.
    let (all, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(
        all.is_empty() && fresh.is_empty(),
        "no leaves to re-broadcast here"
    );

    let d =
        ingest_at(&mut maker, &conditions(0, 0, 0, 100), 200).expect("re-fires after promotion");
    assert_eq!(
        d.buffer,
        BufferSize(5),
        "re-affirms the committed buffer, not the minimum"
    );
    let stamp = maker.active_directive().expect("queued");
    assert_eq!(stamp.buffer_turns, 5);
    assert!(
        stamp.decision_seq > 7,
        "numbers above what clients already hold",
    );
}

/// Equal-seq directives tie-break by `authority_relay_id`, exactly as the
/// client's `DirectiveTracker` does. During a staggered authority handoff
/// two relays each stamp their own `decision_seq` count, so a peer relay
/// can see two directives at the same seq with different buffers — it must
/// latch the same winner the clients pick (the higher relay id), not
/// whichever copy arrived first, or its committed-buffer view (what a
/// later promotion re-affirms from) drifts from what clients hold.
#[test]
fn equal_seq_directives_tie_break_by_relay_id_like_the_client() {
    let directive = |buffer_turns: u32, decision_seq: u32, relay: Option<u64>| BufferDirective {
        buffer_turns,
        apply_at_frame: 100,
        decision_seq,
        authority_relay_id: relay,
    };
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());

    // First copy at seq 7 from relay 2.
    maker.observe_directive(&directive(5, 7, Some(2)));
    assert_eq!(maker.buffer(), BufferSize(5));

    // The same seq from a LOWER relay id loses, whatever order they arrive.
    maker.observe_directive(&directive(3, 7, Some(1)));
    assert_eq!(maker.buffer(), BufferSize(5), "a lower id never displaces");

    // The same seq from a HIGHER relay id wins — the client's rule.
    maker.observe_directive(&directive(4, 7, Some(3)));
    assert_eq!(maker.buffer(), BufferSize(4), "the higher id displaces");

    // A redundant copy of the winner (same seq, same id) changes nothing,
    // and an id-less stamp never displaces one that names its relay.
    maker.observe_directive(&directive(4, 7, Some(3)));
    maker.observe_directive(&directive(6, 7, None));
    assert_eq!(maker.buffer(), BufferSize(4));

    // A strictly higher seq still always wins, id or no id.
    maker.observe_directive(&directive(6, 8, None));
    assert_eq!(maker.buffer(), BufferSize(6));
}

/// The control-law input trace is rate-limited to once per
/// `BUFFER_TRACE_INTERVAL_TURNS` of session-frame progress: the gate advances
/// only when at least that much has elapsed since the last trace.
#[test]
fn the_input_trace_is_rate_limited_by_session_frame_progress() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // First framed turn with a target: the trace fires and records the frame.
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(maker.last_trace_frame, Some(1));

    // One turn short of the interval: the gate holds.
    ingest_at(
        &mut maker,
        &conditions(0, 150_000, 0, 100),
        BUFFER_TRACE_INTERVAL_TURNS,
    );
    assert_eq!(maker.last_trace_frame, Some(1), "held within the interval");

    // Reaching the interval advances the gate.
    ingest_at(
        &mut maker,
        &conditions(0, 150_000, 0, 100),
        1 + BUFFER_TRACE_INTERVAL_TURNS,
    );
    assert_eq!(
        maker.last_trace_frame,
        Some(1 + BUFFER_TRACE_INTERVAL_TURNS)
    );
}

// -- Slot removal --

/// `remove_slot` clears a departing client's history.
#[test]
fn remove_slot_clears_history() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert!(maker.slots.contains_key(&SlotId(0)));
    assert!(maker.target().is_some());
    maker.remove_slot(SlotId(0));
    assert!(!maker.slots.contains_key(&SlotId(0)));
    assert_eq!(maker.target(), None, "no slots means no target");
}

// -- Registry --
