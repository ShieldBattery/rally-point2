//! Shrink gating: the trailing high-water floor, edge probation, and the continuous-space headroom.

use super::*;

/// Edge probation: a floor-level shrink that gets promptly disproven
/// (the target re-reaches the departed level) burns the edge, and the
/// next floor-level shrink must clear the full 4x-lookback peak-free
/// window -- so on an edge whose peaks recur past the base lookback, the
/// law dips at most once before parking.
#[test]
fn a_disproven_edge_shrink_quadruples_the_next_ones_evidence_window() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 230ms -> target 6, raise.
    let d = ingest_at(&mut maker, &conditions(0, 230_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(6));

    // Quiet at 200ms (target 5) long enough for the 6-peak to age out of
    // the base lookback; the edge shrink to 5 fires.
    let mut sent = 100;
    let mut shrink_frame = 0;
    for frame in 2..=700 {
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 200_000, 0, sent), frame) {
            assert_eq!(d.buffer, BufferSize(5), "the edge shrink");
            assert_eq!(shrink_frame, 0, "exactly one shrink");
            shrink_frame = frame;
        }
    }
    assert!(shrink_frame > 600, "shrink waited out the base lookback");

    // A 230ms peak recurs shortly after: the shrink is disproven, the
    // buffer re-raised, the edge burned.
    sent += 5;
    let d = ingest_at(&mut maker, &conditions(0, 230_000, 0, sent), 710);
    assert_eq!(d.unwrap().buffer, BufferSize(6), "the disproving re-raise");

    // Quiet again for well past the base lookback: the burned edge is
    // still under probation (the 4x window covers the 710 peak), so no
    // shrink fires...
    for frame in 711..=2900 {
        sent += 5;
        let d = ingest_at(&mut maker, &conditions(0, 200_000, 0, sent), frame);
        assert_eq!(d, None, "probation holds the edge (frame {frame})");
    }
    // ...until the 4x window has genuinely aged the peak out.
    let mut second_shrink = None;
    for frame in 2901..=3400 {
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 200_000, 0, sent), frame) {
            second_shrink = Some((frame, d.buffer));
            break;
        }
    }
    let (frame, buffer) = second_shrink.expect("probation is bounded, not forever");
    assert_eq!(buffer, BufferSize(5));
    // Bucket granularity makes the 4x window effectively 31-32 buckets
    // (2325-2400 frames) past the bucket holding the peak.
    assert!(
        frame >= 710 + 2325,
        "the second edge shrink cleared the 4x window (frame {frame})",
    );
}

/// Probation never gates shrinks landing above the floor, so a burned
/// edge costs a genuine regime drop nothing: the descent runs at plain
/// dwell cadence while the burn is still armed.
#[test]
fn a_burned_edge_does_not_slow_a_genuine_regime_drop() {
    // Single-turn steps on purpose: the pattern under test is a *descent's*
    // pacing -- several ungated steps, then one that waits out probation --
    // and only a fine-grained stride puts enough steps above the floor to
    // watch the cadence of. What is being checked (probation gates edge
    // shrinks and nothing else) is independent of how far each step moves.
    let law = ControlLaw {
        lower_step: 1,
        ..ControlLaw::default()
    };
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law,
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Burn the edge: raise to 6, edge-shrink to 5, disprove it.
    let d = ingest_at(&mut maker, &conditions(0, 230_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(6));
    let mut sent = 100;
    let mut frame = 1;
    loop {
        frame += 1;
        sent += 5;
        if ingest_at(&mut maker, &conditions(0, 200_000, 0, sent), frame).is_some() {
            break; // the edge shrink to 5
        }
    }
    sent += 5;
    frame += 10;
    let d = ingest_at(&mut maker, &conditions(0, 230_000, 0, sent), frame);
    assert_eq!(d.unwrap().buffer, BufferSize(6));
    assert!(maker.edge_burned);

    // The RTT then drops to 50ms (target 2): far below the edge. The
    // descent's steps land *above* the new floor, so probation -- still
    // armed -- gates none of them: once eligible they come one dwell
    // (120 turns) apart. Only the final step, which lands ON the new
    // resting target (an edge shrink), waits out the burned 4x window --
    // the bounded biased-high tail after proven-flappy weather.
    let mut descent = Vec::new();
    let descent_start = frame;
    while frame < descent_start + 3000 {
        frame += 1;
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 50_000, 0, sent), frame) {
            descent.push((frame, d.buffer));
        }
    }
    assert!(maker.edge_burned, "the burn persists through the descent");
    let buffers: Vec<_> = descent.iter().map(|&(_, b)| b).collect();
    assert_eq!(
        buffers,
        vec![BufferSize(5), BufferSize(4), BufferSize(3), BufferSize(2)],
        "the full descent ran: {descent:?}",
    );
    // Only the last step lands ON the resting target, so only it is an edge
    // shrink; every step before it lands above the floor and runs at plain
    // dwell cadence, undelayed by the armed burn.
    for pair in descent.windows(2).take(2) {
        assert_eq!(
            pair[1].0 - pair[0].0,
            law.min_dwell_turns,
            "the non-edge steps are dwell-paced, not probation-delayed: {descent:?}",
        );
    }
    let last_gap = descent[3].0 - descent[2].0;
    assert!(
        last_gap > 1000,
        "the final (edge) step waited out probation: {descent:?}",
    );
}

/// Regression for buffer flapping under sustained noisy conditions: a
/// target that keeps *recurring* at the buffer level must never shrink at
/// a dwell expiry just because it happened to dip at that instant --
/// under an instantaneous rule that shrink is immediately re-raised at
/// the next peak, changing the buffer on exactly the dwell cadence. The
/// shrink floor (the target's trailing high-water) parks the buffer
/// instead, then releases it once the peaks age out of the lookback.
#[test]
fn recurring_target_peaks_park_the_buffer_until_they_age_out() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 250ms -> target 7, raise.
    let d = ingest_at(&mut maker, &conditions(0, 250_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(7));

    // The RTT sits at 200ms (target 5) but spikes back to 250ms every two
    // seconds -- the shape sustained jitter takes. The dwell expires many
    // times over; no shrink may fire, because the peaks keep the floor at
    // the buffer.
    let mut sent = 100;
    for frame in 2..=600 {
        sent += 5;
        let rtt = if frame % 48 == 0 { 250_000 } else { 200_000 };
        let d = ingest_at(&mut maker, &conditions(0, rtt, 0, sent), frame);
        assert_eq!(d, None, "no decision while spikes recur (frame {frame})");
    }
    assert_eq!(maker.buffer(), BufferSize(7));

    // Once the spikes genuinely stop, the peak has to age out of the
    // shrink lookback (~25s) before the descent begins; the buffer then
    // walks down to the new target one dwell per step -- monotonically,
    // no oscillation on the way.
    let mut decisions = Vec::new();
    for frame in 601..=1500 {
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 200_000, 0, sent), frame) {
            decisions.push((frame, d.buffer));
        }
    }
    assert!(
        decisions.iter().all(|&(frame, _)| frame >= 1150),
        "the descent must wait out the lookback: {decisions:?}",
    );
    assert_eq!(
        decisions.iter().map(|&(_, b)| b).collect::<Vec<_>>(),
        vec![BufferSize(5)],
        "a monotonic descent, landing on the aged-out floor: {decisions:?}",
    );
    assert_eq!(maker.buffer(), BufferSize(5));
}

/// A path settling just under a whole-turn boundary -- inside the shrink
/// headroom -- must never bait a shrink: the raw target says the smaller
/// size fits, but the ceil's slack there is under a millisecond, so the
/// "improvement" is rounding, not weather. The dwell expires and the old
/// peaks age out of the shrink floor; the headroom alone must hold.
#[test]
fn a_path_inside_the_shrink_headroom_of_a_boundary_never_shrinks() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 150ms -> target 4, raise.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(4));

    // The RTT settles ~1ms under the 3-turn boundary (124,998us): the raw
    // target is 3, but the margined path rounds back up to 4.
    let mut sent = 100;
    for frame in 2..=2000 {
        sent += 5;
        let d = ingest_at(&mut maker, &conditions(0, 124_000, 0, sent), frame);
        assert_eq!(
            d, None,
            "no shrink while the path hugs the boundary (frame {frame})"
        );
    }
    assert_eq!(maker.buffer(), BufferSize(4));
}

/// The headroom must not tax genuine recovery: a path clearing the lowered
/// size's boundary by more than the margin still walks the buffer down
/// once the old peaks age out of the lookback.
#[test]
fn a_path_clear_of_the_shrink_headroom_still_shrinks() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 150ms -> target 4, raise.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(4));

    // 110ms sits ~15ms under the 3-turn boundary: raw and margined targets
    // both say 3, so the descent proceeds after the lookback.
    let mut sent = 100;
    let mut decisions = Vec::new();
    for frame in 2..=2000 {
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 110_000, 0, sent), frame) {
            decisions.push(d.buffer);
        }
    }
    assert_eq!(decisions, vec![BufferSize(3)]);
    assert_eq!(maker.buffer(), BufferSize(3));
}

/// A tuned multi-turn `lower_step` may not step past the margined floor:
/// the descent must clamp its landing at the shrink target, not just gate
/// on it being below the buffer.
#[test]
fn a_multi_turn_lower_step_lands_on_the_shrink_target_not_below_it() {
    let law = ControlLaw {
        lower_step: 2,
        ..ControlLaw::default()
    };
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law,
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 250ms -> target 7, raise.
    let d = ingest_at(&mut maker, &conditions(0, 250_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(7));

    // ~1ms under the 3-turn boundary: raw target 3, margined target 4. The
    // two-turn descent must stop at 4 (7 -> 5 -> 4), never touching 3.
    let mut sent = 100;
    let mut decisions = Vec::new();
    for frame in 2..=2000 {
        sent += 5;
        if let Some(d) = ingest_at(&mut maker, &conditions(0, 124_000, 0, sent), frame) {
            decisions.push(d.buffer);
        }
    }
    assert_eq!(decisions, vec![BufferSize(5), BufferSize(4)]);
    assert_eq!(maker.buffer(), BufferSize(4));
}

// -- Directive broadcast --
