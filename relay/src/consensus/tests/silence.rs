//! The silence watch: which slot is named, which blocks a verdict, and what a reconnect is owed.

use super::*;

/// The slot everyone waited on delivers a late turn just before the watch
/// ticks. The survivor has not had the round-trip it needs to consume that
/// turn and answer with its own, so its clock is momentarily the oldest —
/// naming it then would evict the one slot that did nothing wrong.
#[test]
fn a_survivor_is_not_named_while_it_is_still_answering_a_late_turn() {
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    maker.note_forward_advance(SlotId(1), start + Duration::from_millis(11_300));

    assert_eq!(
        maker.silent_slot(start + Duration::from_millis(11_400), SILENCE_WINDOW),
        None,
        "the session moved 100ms ago; nobody is judged until it has sat still for a window",
    );

    // The survivor answers, and the session runs on: no verdict.
    maker.note_forward_advance(SlotId(0), start + Duration::from_millis(11_500));
    assert_eq!(
        maker.silent_slot(start + Duration::from_secs(20), SILENCE_WINDOW),
        None,
        "both moved within the window; the session is not stalled",
    );
}

/// The other half of the late-turn case: the slot that delivered one turn
/// and went quiet again is named once the session has sat still for a full
/// window after that turn, and the survivor that answered it is not.
#[test]
fn a_slot_that_went_quiet_again_after_a_late_turn_is_named_after_a_full_window() {
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    maker.note_forward_advance(SlotId(1), start + Duration::from_millis(11_300));
    maker.note_forward_advance(SlotId(0), start + Duration::from_millis(11_500));

    assert_eq!(
        maker.silent_slot(start + Duration::from_millis(21_400), SILENCE_WINDOW),
        None,
        "the survivor's answer is still inside the window",
    );
    assert_eq!(
        maker.silent_slot(start + Duration::from_millis(21_600), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_millis(10_300),
            lead: Duration::from_millis(200),
        }),
    );
}

#[test]
fn the_slot_whose_turns_stopped_first_is_the_one_named() {
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);

    assert_eq!(
        maker.silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_secs(11),
            lead: Duration::from_millis(200),
        }),
        "the survivor outlasted the slot it was waiting on, and by how much",
    );
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(10), SILENCE_WINDOW)
            .is_none(),
        "nine seconds of quiet is still inside the window",
    );
}

#[test]
fn a_slot_that_runs_ahead_of_the_turn_it_withheld_is_still_the_earliest_stopper() {
    // The hostile client withholds one turn and keeps streaming higher seqs,
    // so anything counted from what it *sent* makes it the busiest slot in
    // the session while its opponent looks idle. The relay counts what it
    // could forward in order instead: the withheld turn stopped this slot's
    // prefix, and its opponent's ran on until the buffered turns ran out.
    let (mut maker, start) = silence_maker(&[0, 1], &[0, 1]);
    maker.note_forward_advance(SlotId(1), start + Duration::from_secs(1));
    for seq in 20..40 {
        maker.observe_turn_frame(SlotId(1), seq, GameFrameCount(200 + seq as u32));
    }
    maker.note_forward_advance(SlotId(0), start + Duration::from_millis(1300));

    assert_eq!(
        maker
            .silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW)
            .map(|found| found.slot),
        Some(SlotId(1)),
        "turns above the gap are not progress, however many of them arrive",
    );
}

#[test]
fn a_slot_that_has_forwarded_nothing_stopped_when_the_session_started() {
    // A client can withhold its seed payloads and delay saying its game loop
    // is running, so that the moment it *claims* to have begun is later than the
    // moment its opponent seeded and stalled waiting for it. The stop time it
    // gets is the session's own start either way: it has been the slot
    // everyone is waiting on since the beginning.
    let (mut maker, start) = silence_maker(&[0, 1], &[0]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(5));
    let now = start + Duration::from_secs(31);
    assert!(
        maker.silent_slot(now, SILENCE_WINDOW).is_none(),
        "a slot that has not reported its game loop running is still loading",
    );

    maker.note_slot_started(SlotId(1));
    assert_eq!(
        maker.silent_slot(now, SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_secs(31),
            lead: Duration::from_secs(5),
        }),
        "the late report names the slot, and never re-dates its silence",
    );
}

#[test]
fn a_session_that_stopped_together_names_nobody() {
    // Nothing distinguishes a victim when every slot stopped at once, and
    // closing links would turn a shared stall into a shared drop.
    let (mut maker, start) = silence_maker(&[0, 1], &[0, 1]);
    let stop = start + Duration::from_secs(1);
    maker.note_forward_advance(SlotId(0), stop);
    maker.note_forward_advance(SlotId(1), stop);

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(600), SILENCE_WINDOW)
            .is_none(),
    );
}

#[test]
fn a_slot_that_forwarded_nothing_blocks_the_verdict_while_it_is_not_a_candidate() {
    // Slot 1's link died before it ever reported its game loop running, so
    // this relay never learned whether it was simulating at all. Its drop is
    // the ordinary path's business, and slot 0 — which forwarded until it
    // starved waiting for slot 1 — is not the one to close for it.
    let (mut maker, start) = silence_maker(&[0, 1], &[0]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(1));
    assert!(maker.mark_connection_down(SlotId(1), Some(1)));

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW)
            .is_none(),
    );
}

#[test]
fn an_expected_slot_this_relay_holds_no_state_for_blocks_every_verdict() {
    // Two clients replay into a resumed game and stall waiting for a third
    // that has not connected here yet. The participant holding lockstep up is
    // exactly the one this relay can say nothing about, so counting it as a
    // non-blocker would name whichever of the other two stopped first.
    let (mut maker, start) = silence_maker_with(&[0, 1, 2], &[0, 1], &[0, 1, 2], &[0, 1]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(1));
    maker.note_forward_advance(SlotId(1), start + Duration::from_millis(1200));

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW)
            .is_none(),
        "a roster slot with no state here is a hole in the evidence, not a non-blocker",
    );

    // It arrives, catches up, and stops last of the three. Every participant
    // now has a stop time, so the earliest of them can be named.
    let arrival = start + Duration::from_secs(31);
    connect_slot(&mut maker, 2, arrival);
    maker.note_slot_started(SlotId(2));
    maker.note_forward_advance(SlotId(2), arrival + Duration::from_secs(1));

    assert_eq!(
        maker.silent_slot(arrival + Duration::from_secs(20), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(0),
            silent_for: Duration::from_secs(50),
            lead: Duration::from_millis(200),
        }),
        "with the roster complete, the earliest stopper is the one holding it up",
    );
}

#[test]
fn a_descriptor_with_no_roster_compares_the_slots_this_relay_holds() {
    // A standalone relay or dev-injected descriptor names no roster, so there
    // is no fuller participant set to be missing from: the slots this relay
    // has state for are the session as far as it can ever know.
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    maker.set_expected_slots(HashSet::new());

    assert_eq!(
        maker
            .silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW)
            .map(|found| found.slot),
        Some(SlotId(1)),
    );
}

#[test]
fn a_resumed_session_stands_the_watch_down() {
    // After a re-home this relay's forward gate bases every prefix at seq 0,
    // while a returning client's retained history can legitimately begin
    // above it — so an honest client with incomplete coverage looks exactly
    // like one withholding its first turns, and its prefix never advances at
    // all. No window turns that into evidence.
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    maker.resumed = true;

    for after in [12, 60, 600] {
        assert!(
            maker
                .silent_slot(start + Duration::from_secs(after), SILENCE_WINDOW)
                .is_none(),
            "a re-homed session's forward-prefix clocks are not evidence at any age",
        );
    }
}

#[test]
fn a_slot_held_for_a_drop_counts_until_its_leave_is_decided_and_absorbed() {
    // Slot 1 disconnected and its drop has not been decided, so the survivor
    // is stalled behind an ordinary drop hold: slot 1 froze at the instant
    // the stall began, and it is still what everyone is waiting on.
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    drop_slot(&mut maker, 1);
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW)
            .is_none(),
        "a survivor waiting out a drop hold is not the one holding the game up",
    );

    // Deciding the leave does not by itself clear the survivor: the directive
    // still has to reach it and be applied, so the departed slot stays in the
    // comparison and keeps explaining the stall.
    assert!(maker.decide_leave(SlotId(1), DROPPED).is_some());
    maker
        .decided_leave_at
        .insert(SlotId(1), start + Duration::from_secs(20));
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(60), SILENCE_WINDOW)
            .is_none(),
    );

    // Once the survivor steps again after the decision, the departed slot is
    // retired for good — leaving the survivor alone, with nobody left to be
    // earlier than.
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(61));
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(90), SILENCE_WINDOW)
            .is_none(),
        "a lone slot cannot be holding anyone up",
    );
    assert!(maker.recovered_leaves.contains(&SlotId(1)));
}

#[test]
fn a_decided_leave_leaves_the_comparison_only_once_the_survivors_resume_past_it() {
    // Three players: slot 0 stops first, slots 1 and 2 stop a fraction later
    // waiting on it. Slot 0's undecided departure protects them; the moment
    // its leave is decided must not stop protecting them, because delivery
    // and application of the directive are still pending and both of them sit
    // well past the window already.
    let (mut maker, start) = silence_maker_with(&[0, 1, 2], &[0, 1, 2], &[0, 1, 2], &[0, 1, 2]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(1));
    maker.note_forward_advance(SlotId(1), start + Duration::from_millis(1200));
    maker.note_forward_advance(SlotId(2), start + Duration::from_millis(1300));

    drop_slot(&mut maker, 0);
    assert!(maker.decide_leave(SlotId(0), DROPPED).is_some());
    let decided = start + Duration::from_secs(20);
    maker.decided_leave_at.insert(SlotId(0), decided);

    assert!(
        maker
            .silent_slot(decided + Duration::from_secs(1), SILENCE_WINDOW)
            .is_none(),
        "deciding a leave is not the survivors recovering from it",
    );
    assert!(!maker.recovered_leaves.contains(&SlotId(0)));

    // Both survivors step again after the leave was delivered and applied.
    maker.note_forward_advance(SlotId(1), decided + Duration::from_secs(2));
    maker.note_forward_advance(SlotId(2), decided + Duration::from_secs(3));
    assert!(
        maker
            .silent_slot(decided + Duration::from_secs(4), SILENCE_WINDOW)
            .is_none(),
        "both survivors are well inside the window; there is nothing to name",
    );
    assert!(
        maker.recovered_leaves.contains(&SlotId(0)),
        "a leave every live participant has stepped past is retired for good",
    );

    // Slot 1 now hangs while slot 2 runs on. It is named only once it has
    // been quiet for a window and is the unique earliest of what remains.
    assert!(
        maker
            .silent_slot(decided + Duration::from_secs(11), SILENCE_WINDOW)
            .is_none(),
        "slot 1 has not been quiet for a whole window yet",
    );
    maker.note_forward_advance(SlotId(2), decided + Duration::from_secs(30));
    assert_eq!(
        maker.silent_slot(decided + Duration::from_secs(40), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_secs(38),
            lead: Duration::from_secs(28),
        }),
    );
}

#[test]
fn a_peer_authored_leave_is_retained_until_the_survivor_resumes_past_it_too() {
    // Who decided the leave changes nothing: a peer authority's directive
    // arriving here decides the slot just as much, and starts the same
    // recovery bar for the survivors it left behind.
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    assert!(maker.observe_leave(&LeaveDirective {
        finalized: false,
        slot: 1,
        reason: DROPPED,
        apply_at_frame: 113,
        leave_seq: 4,
        final_turn_count: None,
    }));
    assert!(
        maker.decided_leave_at.contains_key(&SlotId(1)),
        "a peer-authored leave is stamped like this relay's own",
    );
    maker
        .decided_leave_at
        .insert(SlotId(1), start + Duration::from_secs(20));

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(21), SILENCE_WINDOW)
            .is_none(),
        "slot 0's stall is still slot 1's doing until slot 0 steps past the leave",
    );

    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(22));
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(40), SILENCE_WINDOW)
            .is_none(),
        "with slot 1 retired the survivor is alone, and holding nobody up",
    );
    assert!(maker.recovered_leaves.contains(&SlotId(1)));
}

#[test]
fn a_slot_still_loading_blocks_the_verdict_and_is_never_a_candidate() {
    // A client that has not reported its game loop running is legitimately
    // producing nothing, and whatever it does forward is pre-loop seed
    // traffic — so
    // it resolves to no stop time at all and blocks every verdict, and the
    // same missing report keeps it from ever being named itself. The app
    // server's load timeout owns a session that never finishes loading.
    let (mut maker, start) = stalled_session(&[0, 1], &[0]);
    assert!(
        maker
            .silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW)
            .is_none(),
    );

    let (mut maker, start) = silence_maker(&[0, 1], &[0]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(1));
    for after in [11, 60, 600] {
        assert!(
            maker
                .silent_slot(start + Duration::from_secs(after), SILENCE_WINDOW)
                .is_none(),
            "the loading slot is the earliest stopper and cannot be named",
        );
    }
}

#[test]
fn a_loader_that_keeps_forwarding_blocks_instead_of_shifting_the_blame() {
    // The regression a candidacy-only start rule would reintroduce: a client
    // flushes its seed payloads before its loop runs, so slot 1's prefix can
    // be fresher than that of slot 0 — which finished loading, seeded, and sits
    // waiting for slot 1's first simulated turn, having stopped four seconds
    // earlier. Slot 1's
    // advances are traffic, not simulation, so they are no clock at all, and
    // naming slot 0 off them would blame the player who was ready first.
    let (mut maker, start) = silence_maker(&[0, 1], &[0]);
    maker.note_forward_advance(SlotId(0), start + Duration::from_secs(1));
    maker.note_forward_advance(SlotId(1), start + Duration::from_secs(5));

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW)
            .is_none(),
        "a participant with no game-started report has no stop time to compare",
    );

    // Once slot 1 is known to be simulating, both clocks mean the same thing
    // and the earlier stopper is the one holding lockstep up.
    maker.note_slot_started(SlotId(1));
    assert_eq!(
        maker.silent_slot(start + Duration::from_secs(31), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(0),
            silent_for: Duration::from_secs(30),
            lead: Duration::from_secs(4),
        }),
    );
}

/// A game-loop report reaches only the slot's own home, so a peer-homed slot
/// is unknown here until that home shares it across the mesh — and an unknown
/// participant blocks every verdict, including one against a slot this relay
/// homes.
#[test]
fn a_peer_homed_slot_blocks_the_watch_until_its_home_shares_the_start_report() {
    let (mut maker, start) = stalled_session(&[1], &[1]);

    assert!(
        maker
            .silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW)
            .is_none(),
        "this relay cannot weigh a peer's slot before its home says it is simulating",
    );

    maker.note_peer_slot_started(SlotId(0));
    assert_eq!(
        maker.silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_secs(11),
            lead: Duration::from_millis(200),
        }),
        "the shared report completes the roster, and the earliest stopper is named",
    );
}

#[test]
fn a_slot_not_ours_or_already_on_its_way_out_is_never_named() {
    let (mut not_homed, start) = stalled_session(&[0], &[0, 1]);
    let now = start + Duration::from_secs(12);
    assert!(
        not_homed.silent_slot(now, SILENCE_WINDOW).is_none(),
        "only the slot's home owns its link and may close it",
    );

    let (mut down, start) = stalled_session(&[0, 1], &[0, 1]);
    assert!(down.mark_connection_down(SlotId(1), Some(1)));
    assert!(
        down.silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW)
            .is_none(),
        "a slot whose link already died is the ordinary drop path's business",
    );

    let (mut evicted, start) = stalled_session(&[0, 1], &[0, 1]);
    evicted.mark_silence_evicted(SlotId(1));
    assert!(
        evicted
            .silent_slot(start + Duration::from_secs(12), SILENCE_WINDOW)
            .is_none(),
        "a slot already closing must not be re-reported every tick",
    );
}

#[test]
fn a_reconnected_slot_is_owed_a_window_but_never_a_newer_stop_time() {
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    let redial = start + Duration::from_secs(12);
    assert_eq!(
        maker
            .silent_slot(redial, SILENCE_WINDOW)
            .map(|found| found.slot),
        Some(SlotId(1)),
    );

    // The client redialed, and the replacement connection registered before
    // the dead one's departure was recorded. It has forwarded nothing on a
    // link seconds old, so the watch leaves it alone for a window.
    assert!(maker.activate_connection_epoch(SlotId(1), 2, redial));
    assert!(
        maker
            .silent_slot(redial + Duration::from_secs(9), SILENCE_WINDOW)
            .is_none(),
        "the fresh link is owed a full window to forward its first turn",
    );

    // Its stop time never moved with the redial, so the survivor it stalled
    // — which stopped later, after consuming what slot 1 had already sent -
    // is still not the earliest stopper, and slot 1 is named again the moment
    // the grace runs out with nothing forwarded.
    let after_grace = redial + Duration::from_secs(11);
    assert_eq!(
        maker.silent_slot(after_grace, SILENCE_WINDOW),
        Some(SilentSlot {
            slot: SlotId(1),
            silent_for: Duration::from_secs(22),
            lead: Duration::from_millis(200),
        }),
        "a redial buys time, never a fresher place in the stop order",
    );

    // Re-announcing the generation it already holds is not a fresh link, and
    // grants no further grace.
    assert!(maker.activate_connection_epoch(SlotId(1), 2, after_grace));
    assert_eq!(
        maker
            .silent_slot(after_grace, SILENCE_WINDOW)
            .map(|found| found.slot),
        Some(SlotId(1)),
    );
}

#[test]
fn a_healthy_replacement_link_refreshes_its_clock_by_forwarding() {
    // The reconnect that is not an attack: turns start flowing inside the
    // grace, which is the only thing that moves a slot's clock — and the
    // survivor that was stalled behind it starts stepping again with it.
    let (mut maker, start) = stalled_session(&[0, 1], &[0, 1]);
    let redial = start + Duration::from_secs(12);
    assert!(maker.activate_connection_epoch(SlotId(1), 2, redial));
    let resumed = redial + Duration::from_secs(1);
    maker.note_forward_advance(SlotId(1), resumed);
    maker.note_forward_advance(SlotId(0), resumed + Duration::from_millis(100));

    // Past the grace the resumed link stands on its forwarding alone, and
    // that is enough.
    assert!(
        maker
            .silent_slot(redial + Duration::from_millis(10_500), SILENCE_WINDOW)
            .is_none(),
    );
}

#[test]
fn a_silence_evicted_slot_is_refused_readmission_without_taking_the_hold() {
    let (mut maker, _start) = stalled_session(&[0, 1], &[0, 1]);
    maker.mark_silence_evicted(SlotId(1));
    drop_slot(&mut maker, 1);

    let transition = maker.resolve_reconnect(SlotId(1), Some(2), true);
    assert_eq!(transition.admission, ReconnectAdmission::Rejected);
    assert!(
        !transition.consume_hold,
        "the hold is what lets the survivors decide the drop; a redial must not clear it",
    );
    assert!(
        maker.has_departure(SlotId(1)),
        "the refused readmission leaves the departure standing",
    );
}
