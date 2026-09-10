//! Target-formula tests: the pairwise path, the loss and burst terms, and the recent-max jitter estimator.

use super::*;

#[test]
fn single_slot_ingestion_matches_a_one_element_batch() {
    let mut batch = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let mut single = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let samples = [
        SlotConditions {
            slot: 0,
            rtt_us: 0,
            lost_packets: 0,
            sent_packets: 0,
            connection_epoch: None,
        },
        SlotConditions {
            slot: 0,
            rtt_us: 150_000,
            lost_packets: 0,
            sent_packets: 100,
            connection_epoch: None,
        },
        SlotConditions {
            slot: 0,
            rtt_us: 200_000,
            lost_packets: 20,
            sent_packets: 200,
            connection_epoch: None,
        },
        SlotConditions {
            slot: 0,
            rtt_us: 100_000,
            lost_packets: 20,
            sent_packets: 300,
            connection_epoch: None,
        },
    ];

    for (index, sample) in samples.iter().enumerate() {
        let frame = GameFrameCount(index as u32 + 1);
        batch.observe_frame(SlotId(0), frame);
        single.observe_frame(SlotId(0), frame);

        let batch_decision = batch.ingest_local(&LinkConditions {
            slots: vec![*sample],
        });
        let single_decision = single.ingest_local_condition(sample);

        assert_eq!(single_decision, batch_decision, "sample {index}");
        // The two paths capture their acceptance instants microseconds
        // apart; the wall-clock stamp is incidental to the state
        // transitions under comparison, so align it before the equality.
        for (slot, state) in single.slots.iter_mut() {
            state.last_sample_at = batch.slots[slot].last_sample_at;
        }
        assert_eq!(single.slots, batch.slots, "sample {index}");
        assert_eq!(single.buffer, batch.buffer, "sample {index}");
        assert_eq!(single.last_decision_frame, batch.last_decision_frame);
        assert_eq!(single.decision_seq, batch.decision_seq);
        assert_eq!(single.pending_directive, batch.pending_directive);
        assert_eq!(single.initial_directive_sent, batch.initial_directive_sent);
        assert_eq!(single.last_trace_frame, batch.last_trace_frame);
        assert_eq!(single.target(), batch.target(), "sample {index}");
    }
}

#[test]
fn target_fold_matches_sorting_reference_for_ties_missing_rtts_departures_and_loss() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );

    assert_target_inputs_match_reference(&maker);
    maker.ingest_local(&conditions(3, 0, 0, 100));
    assert_target_inputs_match_reference(&maker);
    assert_eq!(maker.target(), None, "a missing RTT contributes no path");

    maker.ingest_local(&multi_conditions(&[
        (0, 100_000, 0, 100),
        (1, 300_000, 0, 100),
        (2, 300_000, 0, 100),
        (3, 0, 0, 100),
    ]));
    assert_target_inputs_match_reference(&maker);
    assert_eq!(maker.target_inputs().unwrap().path_us, 300_000);

    maker.ingest_local(&multi_conditions(&[
        (0, 90_000, 10, 200),
        (1, 250_000, 20, 200),
        (2, 200_000, 5, 200),
        (3, 0, 100, 200),
    ]));
    assert_target_inputs_match_reference(&maker);
    let inputs = maker.target_inputs().unwrap();
    assert_eq!(inputs.path_us, 300_000, "the two top RTTs are tied");
    assert_eq!(inputs.worst_loss_risk, 60_000.0);
    // Slot 3 lost all 100 packets of its interval: a 1-turn blackout, so
    // the burst term contributes even though its RTT (and with it its
    // loss *risk*) is unmeasured -- a fully dark link stalls lockstep
    // regardless of how short its path is.
    assert_eq!(inputs.burst_turns, 1);
    // Path 8, and the worse of the loss terms (risk 60ms -> 2 turns,
    // against the 1-turn burst) rather than their sum.
    assert_eq!(inputs.target, 10);

    maker.record_departure(SlotId(1), DepartureStamps::default(), DROPPED);
    assert_target_inputs_match_reference(&maker);
    let inputs = maker.target_inputs().unwrap();
    assert_eq!(inputs.path_us, 200_000);
    assert_eq!(inputs.worst_loss_risk, 15_000.0);
    // Path 5, plus one turn for loss: the risk and the burst run agree at
    // a turn here, so max and sum would only differ by which is doubled.
    assert_eq!(inputs.target, 6);

    maker.record_departure(SlotId(2), DepartureStamps::default(), DROPPED);
    assert_target_inputs_match_reference(&maker);
    maker.remove_slot(SlotId(0));
    assert_target_inputs_match_reference(&maker);
    assert_eq!(maker.target(), None, "only the missing-RTT slot remains");
}

/// At 150ms RTT, 0% loss: target == ceil(150000/41666.67) + 0 = 4.
#[test]
fn target_at_150ms_zero_loss() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(maker.target(), Some(4));
}

/// At 150ms RTT, 5% loss: loss_risk = 0.05 ** 150000 = 7500us.
/// Separated: ceil(150000/41666.67) + ceil(7500/41666.67) = 4 + 1 = 5.
#[test]
fn target_loss_recovery_is_quantized_to_whole_turns() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    let _ = ingest_at(&mut maker, &conditions(0, 150_000, 5, 200), 2);
    assert_eq!(maker.target(), Some(5));
}

/// At 50ms RTT, 0% loss: target = ceil(50000/41666.67) = 2.
#[test]
fn target_at_low_latency() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
    assert_eq!(maker.target(), Some(2));
}

/// At 10ms RTT: target = ceil(10000/41666.67) = 1. The ceil naturally
/// gives 1 for any positive RTT -- no separate floor.
#[test]
fn target_floor_falls_out_of_ceil() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 10_000, 0, 100), 1);
    assert_eq!(maker.target(), Some(1));
}

/// No RTT measurement (rtt_us == 0): target is None (hold).
#[test]
fn target_none_when_no_rtt() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 0, 0, 100), 1);
    assert_eq!(maker.target(), None);
}

// -- Pairwise path --

/// Two slots at 100ms and 200ms: path = (200000 + 100000) / 2 = 150000.
#[test]
fn worst_pair_path_uses_two_highest_rtts() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(
        &mut maker,
        &multi_conditions(&[(0, 100_000, 0, 100), (1, 200_000, 0, 100)]),
        1,
    );
    assert_eq!(maker.target(), Some(4));
}

/// One outlier at 300ms, rest at 20ms: path = (300000 + 20000) / 2 = 160000.
#[test]
fn single_outlier_does_not_over_provision() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(
        &mut maker,
        &multi_conditions(&[
            (0, 20_000, 0, 100),
            (1, 300_000, 0, 100),
            (2, 20_000, 0, 100),
        ]),
        1,
    );
    assert_eq!(maker.target(), Some(4));
}

// -- Mesh hop --

/// A remote slot's effective RTT includes the mesh hop.
#[test]
fn mesh_hop_increases_target_for_cross_relay_paths() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
    ingest_remote_at(&mut maker, &conditions(1, 50_000, 0, 100), 100_000, 2);
    // eff_local = 50000, eff_remote = 150000.
    // path = (150000 + 50000) / 2 = 100000. target = ceil(100000/41666.67) = 3.
    assert_eq!(maker.target(), Some(3));
}

/// Without the mesh hop, two 50ms slots would give target 2.
#[test]
fn mesh_hop_adds_turns_above_same_relay_baseline() {
    let mut local = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(
        &mut local,
        &multi_conditions(&[(0, 50_000, 0, 100), (1, 50_000, 0, 100)]),
        1,
    );
    let local_target = local.target().unwrap();

    let mut meshed = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut meshed, &conditions(0, 50_000, 0, 100), 1);
    ingest_remote_at(&mut meshed, &conditions(1, 50_000, 0, 100), 100_000, 2);
    let meshed_target = meshed.target().unwrap();

    assert!(meshed_target > local_target);
}

// -- Loss on high-latency links --

/// Same 20% loss on 50ms vs 300ms: the high-latency link needs more turns.
#[test]
fn loss_on_high_latency_link_adds_more_turns() {
    let mut low = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut low, &conditions(0, 50_000, 0, 100), 1);
    ingest_at(&mut low, &conditions(0, 50_000, 20, 200), 2);
    let low_target = low.target().unwrap();

    let mut high = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut high, &conditions(0, 300_000, 0, 100), 1);
    ingest_at(&mut high, &conditions(0, 300_000, 20, 200), 2);
    let high_target = high.target().unwrap();

    assert!(high_target > low_target);
    assert_eq!(low_target, 3); // 2 + 1
    assert_eq!(high_target, 10); // 8 + 2
}

// -- Jitter awareness --

#[test]
fn cached_rtt_max_matches_scanned_window_when_tied_maxima_expire() {
    let mut window = RttWindow::default();
    let mut reference = VecDeque::new();

    let mut samples = vec![100_000, 20_000, 100_000];
    samples.extend((1..=29).map(|sample| sample * 1_000));
    for sample in samples {
        push_rtt_and_check_reference(&mut window, &mut reference, sample);
    }
    assert_eq!(window.max(), 100_000);

    // Zero is a sentinel and must neither enter nor advance the window.
    push_rtt_and_check_reference(&mut window, &mut reference, 0);
    // Expire the first tied maximum; the other copy keeps the same result.
    push_rtt_and_check_reference(&mut window, &mut reference, 40_000);
    assert_eq!(window.max(), 100_000);
    push_rtt_and_check_reference(&mut window, &mut reference, 41_000);
    // Expire the final copy; the cached value must fall to the true new max.
    push_rtt_and_check_reference(&mut window, &mut reference, 42_000);
    assert_eq!(window.max(), 42_000);
}

#[test]
fn cached_rtt_max_matches_scanned_window_across_many_wraps() {
    for seed in 1_u32..=64 {
        let mut window = RttWindow::default();
        let mut reference = VecDeque::new();
        let mut state = seed;

        for _ in 0..512 {
            // A small value range deliberately creates many tied maxima;
            // occasional zeroes exercise the skipped-sentinel path.
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let sample = if state & 0xf == 0 {
                0
            } else {
                ((state >> 16) % 17 + 1) * 1_000
            };
            push_rtt_and_check_reference(&mut window, &mut reference, sample);
        }
    }
}

/// The decision-maker uses the recent max RTT, not the smoothed mean.
#[test]
fn jitter_uses_recent_max_rtt() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    for frame in 1..=4 {
        ingest_at(&mut maker, &conditions(0, 100_000, 0, 100), frame);
    }
    ingest_at(&mut maker, &conditions(0, 200_000, 0, 100), 5);

    assert_eq!(maker.target(), Some(5));
}

/// Without the spike, the target would be lower.
#[test]
fn jitter_spike_raises_target_above_baseline() {
    let mut spiky = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    for frame in 1..=4 {
        ingest_at(&mut spiky, &conditions(0, 100_000, 0, 100), frame);
    }
    ingest_at(&mut spiky, &conditions(0, 200_000, 0, 100), 5);

    let mut stable = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    for frame in 1..=5 {
        ingest_at(&mut stable, &conditions(0, 100_000, 0, 100), frame);
    }

    assert!(spiky.target().unwrap() > stable.target().unwrap());
}

// -- Raise fast, lower slow (asymmetric dwell) --

/// Raise jumps to the target immediately, not incrementally.
#[test]
fn sustained_arrival_stretch_presses_the_buffer_target() {
    // Clean tiny RTT sizes the law's own target at the minimum; a session
    // whose arrival cadence then sits stretched past the sustain window is
    // raised one extra turn — the relay-measured "clients are stalling
    // anyway" backstop — and the raise routes through the ordinary
    // directive machinery.
    let mut maker = DecisionMaker::new(
        key(),
        bounds(1, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.mark_started();
    // First ingest: the initial broadcast at the held minimum, no raise.
    let d = ingest_at(&mut maker, &conditions(0, 5_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(1));

    // Two slots stuck at a 50 ms cadence against the ~41.7 ms turn.
    let start = std::time::Instant::now();
    let cadence = 50_000u64;
    for seq in 0..300u64 {
        let at = start + Duration::from_micros(seq * cadence);
        let _ = maker.ingest_arrival_phase(SlotId(0), seq, at);
        let _ = maker.ingest_arrival_phase(SlotId(1), seq, at + Duration::from_millis(3));
    }

    // Stretched but not yet sustained: the onset latches, nothing raises.
    let d = ingest_at(&mut maker, &conditions(0, 5_000, 0, 200), 2);
    assert!(
        d.is_none(),
        "stretch below the sustain window must not raise"
    );
    assert_eq!(maker.buffer(), BufferSize(1));

    // Once the stretch has (been backdated to have) held past the sustain
    // window, the next decision raises by exactly the one-turn press.
    maker.phase.backdate_stretch(Duration::from_secs(6));
    let d = ingest_at(&mut maker, &conditions(0, 5_000, 0, 300), 3);
    assert_eq!(
        d.unwrap().buffer,
        BufferSize(2),
        "sustained stretch presses one turn"
    );
    assert_eq!(maker.buffer(), BufferSize(2));
}
