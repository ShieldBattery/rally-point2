//! Correction mechanics: convergence onto the cluster's latest phase, the
//! circular cluster search across the cycle wrap, the per-round change cap,
//! the evaluation dwell, and the per-slot command fence (unacknowledged
//! commands, dead-band crossings, reconnects, and late echoes).

use super::*;

#[test]
fn aligned_slots_get_no_corrections() {
    // Two slots inside the dead-band: spread 2 ms.
    let corrections = corrections_for(&[(slot(0), 0), (slot(1), 2_000)]);
    assert!(corrections.is_empty(), "got {corrections:?}");
}

#[test]
fn spread_slots_converge_in_capped_steps_onto_the_latest_phase() {
    // Three slots at 0 / 10 / 20 ms. The cluster's latest phase is 20 ms,
    // so slots 0 and 1 walk onto it — never more than the per-round cap at
    // a time — and slot 2 stays put throughout.
    let rounds = run_to_convergence(&[(slot(0), 0), (slot(1), 10_000), (slot(2), 20_000)], 8);
    assert!(!rounds.is_empty());
    let mut final_delay: HashMap<SlotId, u32> = HashMap::new();
    let mut prior: HashMap<SlotId, i64> = HashMap::new();
    for round in &rounds {
        for &(id, delay) in round {
            assert_ne!(id, slot(2), "the latest slot is never corrected");
            let before = prior.get(&id).copied().unwrap_or(0);
            assert!(
                (i64::from(delay) - before).abs() <= SLOT_MAX_CHANGE_US,
                "per-round change capped, got {before} -> {delay}"
            );
            prior.insert(id, i64::from(delay));
            final_delay.insert(id, delay);
        }
    }
    let d0 = *final_delay.get(&slot(0)).expect("slot 0 corrected");
    let d1 = *final_delay.get(&slot(1)).expect("slot 1 corrected");
    assert!(
        (17_000..=23_000).contains(&d0),
        "slot 0 ends ~20 ms, got {d0}"
    );
    assert!(
        (7_000..=13_000).contains(&d1),
        "slot 1 ends ~10 ms, got {d1}"
    );
}

#[test]
fn the_cluster_is_found_across_the_cycle_wrap() {
    // Phases at 38 ms and 1 ms sit 4.667 ms apart *across* the wrap; the
    // naive linear reading (37 ms apart) would delay the late slot by most
    // of a turn. The circular gap search must instead nudge the 38 ms slot
    // forward onto 1 ms.
    let corrections = corrections_for(&[(slot(0), 38_000), (slot(1), 1_000 + 41_667)]);
    // Slot 1's arrivals ride the next cycle (offset past one turn), which
    // is exactly the mod-T ambiguity the controller must be blind to.
    let by_slot: HashMap<SlotId, u32> = corrections.into_iter().collect();
    let d0 = *by_slot.get(&slot(0)).expect("slot 0 corrected");
    assert!(
        (3_600..=5_800).contains(&d0),
        "slot 0 walks forward across the wrap (~4.7 ms), got {d0}"
    );
    assert_eq!(by_slot.get(&slot(1)), None, "the target slot stays put");
}

#[test]
fn corrections_do_not_reissue_inside_the_dwell() {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let last = feed_steady(
        &mut controller,
        start,
        &[(slot(0), 0), (slot(1), 6_000)],
        0,
        300,
    );
    let first = controller.evaluate(last + Duration::from_millis(1));
    assert!(!first.is_empty());
    // Immediately after issuing, and well inside slew+settle, nothing new
    // is issued even though the (not yet moved) estimates still disagree.
    let again = controller.evaluate(last + Duration::from_secs(1));
    assert!(again.is_empty(), "got {again:?}");
}

#[test]
fn an_unacknowledged_command_is_never_advanced_by_peer_drift() {
    // Slot 0 never acknowledges its correction. However its peers drift
    // afterwards — the exact measurement ambiguity that once let a moving
    // reference impersonate a response — the fence is explicit now, so
    // slot 0 draws no second command. A stale echo (the wrong delay)
    // must not release it either.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let offsets = [(slot(0), 0i64), (slot(1), 9_000), (slot(2), 10_000)];
    let mut clock = feed_steady(&mut controller, start, &offsets, 0, 300);
    let first = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(
        first.iter().map(|&(s, _)| s).collect::<Vec<_>>(),
        vec![slot(0)],
        "only the early slot is corrected"
    );

    // A stale echo: acknowledging a delay that was never commanded.
    controller.note_applied(slot(0), 999, clock + Duration::from_millis(2));
    // The target peer then drifts 5 ms later while slot 0 applies
    // nothing; no measurement can reopen an explicit fence.
    let drifted = [(slot(0), 0i64), (slot(1), 9_000), (slot(2), 15_000)];
    let mut seq = 300u64;
    for _ in 0..3u32 {
        for s_ in seq..seq + 1_000 {
            for &(id, offset) in &drifted {
                let at = start + Duration::from_micros((s_ as i64 * turn + offset) as u64);
                controller.note_arrival(id, s_, at);
                clock = clock.max(at);
            }
        }
        seq += 1_000;
        let corrections = controller.evaluate(clock + Duration::from_millis(1));
        assert!(
            !corrections.iter().any(|&(s, _)| s == slot(0)),
            "the unmoved slot draws no second command, got {corrections:?}"
        );
    }
    let parked = controller.commanded(slot(0)).expect("first command stands");
    assert!(
        i64::from(parked) <= SLOT_MAX_CHANGE_US,
        "the command stays parked at one cap step, got {parked}"
    );
}

#[test]
fn dead_band_crossings_do_not_reopen_the_command_fence() {
    // An ignoring slot near the dead-band boundary: jitter walks the span
    // in and out of the band. Each inward crossing resets the round
    // counter, so without a persistent fence every outward crossing would
    // add another command — a slow ratchet no latch would catch. The
    // fence must survive the crossings and keep the command parked.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let mut clock = start;
    let mut seq = 0u64;
    let feed =
        |controller: &mut PhaseController, seq: &mut u64, clock: &mut Instant, peer_offset: i64| {
            for s_ in *seq..*seq + 1_000 {
                for (id, offset) in [(slot(0), 0i64), (slot(1), peer_offset)] {
                    let at = start + Duration::from_micros((s_ as i64 * turn + offset) as u64);
                    controller.note_arrival(id, s_, at);
                    if at > *clock {
                        *clock = at;
                    }
                }
            }
            *seq += 1_000;
        };
    // Out of band: the one and only command.
    feed(&mut controller, &mut seq, &mut clock, 4_000);
    let first = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(first.len(), 1, "got {first:?}");
    let parked = first[0].1;

    for _ in 0..4u32 {
        // The peer jitters inward: span inside the band, rounds reset.
        feed(&mut controller, &mut seq, &mut clock, 2_500);
        assert!(
            controller
                .evaluate(clock + Duration::from_millis(1))
                .is_empty()
        );
        // And back out: the fence must still hold — slot 0 never moved.
        feed(&mut controller, &mut seq, &mut clock, 4_000);
        assert!(
            controller
                .evaluate(clock + Duration::from_millis(1))
                .is_empty(),
            "no re-command on an outward crossing"
        );
    }
    assert_eq!(controller.commanded(slot(0)), Some(parked));
}

#[test]
fn a_reconnect_does_not_reopen_the_command_fence() {
    // The commanded delay survives a slot's teardown for the re-push, so
    // the unacknowledged-command fence must survive with it — otherwise
    // each reconnect of a never-acknowledging client would advance its
    // command by another cap step.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let offsets = [(slot(0), 0i64), (slot(1), 8_000)];
    let mut clock = feed_steady(&mut controller, start, &offsets, 0, 300);
    let first = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(first.len(), 1);
    let commanded = controller.commanded(slot(0)).expect("commanded");

    controller.remove_slot(slot(0));
    // The reconnected client still applies nothing; fresh estimates, same
    // unmoved phase.
    let mut seq = 300u64;
    for _ in 0..2u32 {
        for s_ in seq..seq + 1_000 {
            for &(id, offset) in &offsets {
                let at = start + Duration::from_micros((s_ as i64 * turn + offset) as u64);
                controller.note_arrival(id, s_, at);
                clock = clock.max(at);
            }
        }
        seq += 1_000;
        assert!(
            controller
                .evaluate(clock + Duration::from_millis(1))
                .is_empty(),
            "no re-command across the reconnect"
        );
    }
    assert_eq!(controller.commanded(slot(0)), Some(commanded));
}

#[test]
fn an_acknowledged_command_may_be_advanced() {
    // The matching echo releases the fence: the controller may then step
    // the same slot again. (An acknowledgement without real application
    // only ever hurts the acknowledging client itself — its command keeps
    // stepping, timing it already controls outright.)
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let offsets = [(slot(0), 0i64), (slot(1), 20_000)];
    let mut clock = feed_steady(&mut controller, start, &offsets, 0, 300);
    let first = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(first, vec![(slot(0), 8_000)]);
    controller.note_applied(slot(0), 8_000, clock + Duration::from_millis(2));

    // The client acked but its phase never moved; the released fence
    // permits the next capped step.
    for s_ in 300u64..1_300 {
        for &(id, offset) in &offsets {
            let at = start + Duration::from_micros((s_ as i64 * turn + offset) as u64);
            controller.note_arrival(id, s_, at);
            clock = clock.max(at);
        }
    }
    let second = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(second, vec![(slot(0), 16_000)]);
}

#[test]
fn a_late_echo_re_arms_the_evaluation_dwell() {
    // The echo arrives long after the issue-time dwell expired (slow
    // delivery, or the fresh adoption a reconnect re-push triggers). It
    // must not release the fence straight into an evaluation of a
    // barely-adopted target: release re-arms a full-step slew-plus-settle
    // dwell from receipt, and only after that may the next step issue.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    let offsets = [(slot(0), 0i64), (slot(1), 20_000)];
    let mut clock = feed_steady(&mut controller, start, &offsets, 0, 300);
    let first = controller.evaluate(clock + Duration::from_millis(1));
    assert_eq!(first, vec![(slot(0), 8_000)]);

    // Well past the issue-time dwell, still unacknowledged: fenced.
    clock = feed_steady(&mut controller, start, &offsets, 300, 1_000);
    assert!(
        controller
            .evaluate(clock + Duration::from_millis(1))
            .is_empty()
    );

    // The echo lands now, late. The fence releases — but evaluation right
    // after must still hold, because the dwell restarted from receipt.
    let ack_at = clock + Duration::from_secs(1);
    controller.note_applied(slot(0), 8_000, ack_at);
    for seq in 1_300u64..1_340 {
        for &(id, offset) in &offsets {
            let at = start + Duration::from_micros((seq as i64 * turn + offset) as u64);
            controller.note_arrival(id, seq, at);
            clock = clock.max(at);
        }
    }
    assert!(
        controller
            .evaluate(ack_at + Duration::from_millis(500))
            .is_empty(),
        "the re-armed dwell holds evaluation off a barely-adopted target"
    );

    // Once the re-armed dwell passes (with fresh samples), the next
    // capped step may issue.
    let mut late = ack_at + Duration::from_secs(13);
    let resume_seq = 1_340u64;
    for i in 0..60u64 {
        for &(id, offset) in &offsets {
            let at = late + Duration::from_micros((i as i64 * turn + offset) as u64);
            controller.note_arrival(id, resume_seq + i, at);
        }
    }
    late += Duration::from_micros(59 * u64::from(TURN_US));
    let second = controller.evaluate(late + Duration::from_millis(1));
    assert_eq!(second, vec![(slot(0), 16_000)]);
}

#[test]
fn a_quiet_slot_sits_out_but_keeps_its_commanded_delay() {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let last = feed_steady(
        &mut controller,
        start,
        &[(slot(0), 0), (slot(1), 7_000)],
        0,
        300,
    );
    let first = controller.evaluate(last + Duration::from_millis(1));
    let commanded: HashMap<SlotId, u32> = first.into_iter().collect();
    let corrected = *commanded.keys().next().expect("one slot corrected");

    // Only the other slot keeps sending; the corrected one goes quiet past
    // SAMPLE_MAX_AGE. With one measurable slot there is nothing to align.
    controller.remove_slot(corrected);
    let quiet_until = last + Duration::from_secs(60);
    let other = if corrected == slot(0) {
        slot(1)
    } else {
        slot(0)
    };
    for seq in 300u64..320 {
        let at = quiet_until + Duration::from_micros((seq - 300) * u64::from(TURN_US));
        controller.note_arrival(other, seq, at);
    }
    let corrections = controller.evaluate(quiet_until + Duration::from_secs(2));
    assert!(corrections.is_empty());
    // The departed slot's delay survives for the reconnect re-push.
    assert_eq!(
        controller.commanded(corrected),
        commanded.get(&corrected).copied()
    );
}

#[test]
fn fewer_than_two_measurable_slots_never_correct() {
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let last = feed_steady(&mut controller, start, &[(slot(0), 0)], 0, 300);
    assert!(
        controller
            .evaluate(last + Duration::from_millis(1))
            .is_empty()
    );
    assert_eq!(controller.commanded(slot(0)), None);
}

#[test]
fn seq_history_from_before_measurement_does_not_skew_the_phase() {
    // Two slots at identical phases whose seq counters differ by hundreds
    // (pre-game traffic consumed seqs at a different cadence): the
    // unwrapped residuals differ by whole turns, the phases must not.
    let mut controller = PhaseController::new(TURN_US);
    let start = Instant::now();
    let turn = i64::from(TURN_US);
    for i in 0..300u64 {
        let at = start + Duration::from_micros((i as i64 * turn) as u64);
        controller.note_arrival(slot(0), i, at);
        controller.note_arrival(slot(1), i + 700, at);
    }
    let last = start + Duration::from_micros((299 * turn) as u64);
    let corrections = controller.evaluate(last + Duration::from_millis(1));
    assert!(corrections.is_empty(), "same phase, got {corrections:?}");
}
