//! Target-formula tests: the pairwise path, the loss and burst terms, and the recent-max jitter estimator.

use super::*;

#[test]
fn single_slot_ingestion_matches_a_one_element_batch() {
    let mut batch = maker();
    let mut single = maker();
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
    let mut maker = maker();

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

    maker.record_departure(SlotId(1), DepartureStamps::default(), LEAVE_REASON_DROPPED);
    assert_target_inputs_match_reference(&maker);
    let inputs = maker.target_inputs().unwrap();
    assert_eq!(inputs.path_us, 200_000);
    assert_eq!(inputs.worst_loss_risk, 15_000.0);
    // Path 5, plus one turn for loss: the risk and the burst run agree at
    // a turn here, so max and sum would only differ by which is doubled.
    assert_eq!(inputs.target, 6);

    maker.record_departure(SlotId(2), DepartureStamps::default(), LEAVE_REASON_DROPPED);
    assert_target_inputs_match_reference(&maker);
    maker.remove_slot(SlotId(0));
    assert_target_inputs_match_reference(&maker);
    assert_eq!(maker.target(), None, "only the missing-RTT slot remains");
}

/// The target formula, case by case. Each case ingests its samples in
/// order into a fresh maker and pins both the path the pairwise rule
/// derived and the whole-turn target built on it.
#[test]
fn the_target_formula_over_its_path_loss_and_clamp_cases() {
    /// One slot sample as `(slot, rtt_us, lost_packets, sent_packets)`.
    type Sample = (u8, u32, u64, u64);

    struct Case {
        label: &'static str,
        /// One entry per ingest, in order.
        samples: &'static [&'static [Sample]],
        path_us: Option<u32>,
        target: Option<u32>,
    }

    let turn_us = law().turn_duration_us;
    let cases = [
        Case {
            label: "150ms, no loss: one ceil over the turn period",
            samples: &[&[(0, 150_000, 0, 100)]],
            path_us: Some(150_000),
            target: Some(4),
        },
        Case {
            label: "150ms with 5% loss: path and loss take separate ceils, so \
             4 + 1 -- a combined ceil would read 4",
            samples: &[&[(0, 150_000, 0, 100)], &[(0, 150_000, 5, 200)]],
            path_us: Some(150_000),
            target: Some(5),
        },
        Case {
            label: "50ms: the low-latency case",
            samples: &[&[(0, 50_000, 0, 100)]],
            path_us: Some(50_000),
            target: Some(2),
        },
        Case {
            label: "10ms: the ceil is its own floor, so any positive path costs \
             a turn and no separate minimum is needed",
            samples: &[&[(0, 10_000, 0, 100)]],
            path_us: Some(10_000),
            target: Some(1),
        },
        Case {
            label: "no RTT measurement at all: the law holds rather than guessing",
            samples: &[&[(0, 0, 0, 100)]],
            path_us: None,
            target: None,
        },
        Case {
            label: "two slots at 100ms and 200ms: the path is the mean of the two \
             highest effective RTTs",
            samples: &[&[(0, 100_000, 0, 100), (1, 200_000, 0, 100)]],
            path_us: Some(150_000),
            target: Some(4),
        },
        Case {
            label: "one 300ms outlier against two 20ms links: the outlier is \
             averaged against the next-highest, never taken alone",
            samples: &[&[
                (0, 20_000, 0, 100),
                (1, 300_000, 0, 100),
                (2, 20_000, 0, 100),
            ]],
            path_us: Some(160_000),
            target: Some(4),
        },
        Case {
            label: "a hostile near-u32::MAX RTT claim is clamped to the ingest \
             ceiling on the way in, so it cannot saturate the sums the \
             path is built from",
            samples: &[&[(0, u32::MAX, 0, 100)]],
            path_us: Some(MAX_INGEST_RTT_US),
            target: Some(MAX_INGEST_RTT_US.div_ceil(turn_us)),
        },
    ];

    for case in cases {
        let mut maker = maker();
        for (index, sample) in case.samples.iter().enumerate() {
            ingest_at(&mut maker, &multi_conditions(sample), index as u32 + 1);
        }
        assert_eq!(
            maker.target_inputs().map(|inputs| inputs.path_us),
            case.path_us,
            "{}",
            case.label,
        );
        assert_eq!(maker.target(), case.target, "{}", case.label);
    }
}

// -- Mesh hop --

/// A remote slot's effective RTT includes the mesh hop.
#[test]
fn mesh_hop_increases_target_for_cross_relay_paths() {
    let mut maker = maker();
    ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
    ingest_remote_at(&mut maker, &conditions(1, 50_000, 0, 100), 100_000, 2);
    // eff_local = 50000, eff_remote = 150000.
    // path = (150000 + 50000) / 2 = 100000. target = ceil(100000/41666.67) = 3.
    assert_eq!(maker.target(), Some(3));
}

// -- Loss on high-latency links --

/// Same 20% loss on 50ms vs 300ms: the high-latency link needs more turns.
#[test]
fn loss_on_high_latency_link_adds_more_turns() {
    let mut low = maker();
    ingest_at(&mut low, &conditions(0, 50_000, 0, 100), 1);
    ingest_at(&mut low, &conditions(0, 50_000, 20, 200), 2);
    let low_target = low.target().unwrap();

    let mut high = maker();
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
    let mut maker = maker();
    for frame in 1..=4 {
        ingest_at(&mut maker, &conditions(0, 100_000, 0, 100), frame);
    }
    ingest_at(&mut maker, &conditions(0, 200_000, 0, 100), 5);

    assert_eq!(maker.target(), Some(5));
}

// -- Arrival stretch --

/// The relay-measured stretch term: the automatic replacement for the
/// user-facing latency setting SC:R used to expose.
#[test]
fn sustained_arrival_stretch_presses_the_buffer_target() {
    // Clean tiny RTT sizes the law's own target at the minimum; a session
    // whose arrival cadence then sits stretched past the sustain window is
    // raised one extra turn — the relay-measured "clients are stalling
    // anyway" backstop — and the raise routes through the ordinary
    // directive machinery.
    let mut maker = maker_with(bounds(1, 20));
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
