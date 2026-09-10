//! Raise/shrink asymmetry, bounds clamping, the derivation record, and the session frame coordinate.

use super::*;

#[test]
fn raise_jumps_to_target() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(4));
    assert_eq!(maker.buffer(), BufferSize(4));
}

/// A lower steps the buffer down by `lower_step`; it never jumps to the
/// target the way a raise does.
#[test]
fn lower_steps_down_rather_than_jumping_to_the_target() {
    let mut maker = DecisionMaker {
        buffer: BufferSize(5),
        ..DecisionMaker::new(
            key(),
            bounds(0, 20),
            law(),
            Authority::SelfRelay,
            HashSet::new(),
        )
    };
    // 50ms targets 2, but the buffer descends by the step instead.
    let d = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(3));
    assert_eq!(maker.buffer(), BufferSize(3));
}

// -- Asymmetric dwell: raises immediate, lowers gated --

/// A raise fires immediately even within the dwell -- you can't dwell
/// through a stall. A lower is suppressed until the dwell elapses.
#[test]
fn raise_fires_immediately_lower_gated_by_dwell() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 150ms -> target 4. Raise to 4 at frame 1.
    let d1 = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d1.unwrap().buffer, BufferSize(4));

    // Conditions worsen at frame 2 (within 120-turn dwell). Raise fires
    // immediately -- no dwell on raises.
    let d2 = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 2);
    assert_eq!(
        d2.unwrap().buffer,
        BufferSize(8),
        "raise should fire immediately"
    );
    assert_eq!(maker.buffer(), BufferSize(8));

    // Conditions improve at frame 3 (within dwell from the raise at 2).
    // Lower is suppressed -- and the ring buffer still holds the 300ms
    // spike, so the target stays at 8 anyway.
    let d3 = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 3);
    assert_eq!(d3, None, "lower should be suppressed within dwell");
    assert_eq!(maker.buffer(), BufferSize(8));

    // Flush the 300ms spike from the ring buffer (32 samples) so the
    // recent max drops to 50ms. Frames 4--35.
    for frame in 4..=35 {
        let _ = ingest_at(
            &mut maker,
            &conditions(0, 50_000, 0, 100 + u64::from(frame)),
            frame,
        );
    }
    // Now the target is 2 (50ms), but the shrink floor still remembers the
    // spike-era target of 8.
    assert_eq!(maker.target(), Some(2));

    // Once the spike has aged out of the shrink lookback (~25s after the
    // last frame that observed a target of 8), the lower fires.
    let d4 = ingest_at(&mut maker, &conditions(0, 50_000, 0, 1_000), 700);
    assert!(d4.is_some(), "lower fires once the high-water ages out");
    assert_eq!(maker.buffer(), BufferSize(8 - law().lower_step));
}

/// Anti-flap: an oscillating target raises on the first worsening, then
/// holds (lowers suppressed) through the dwell.
#[test]
fn anti_flap_raises_on_worsening_holds_on_improvement() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // 150ms -> target 4. Raise to 4 at frame 1.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(4));

    // Target drops to 2 (50ms) at frame 2 -- lower suppressed.
    let d = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 2);
    assert_eq!(d, None);

    // Target spikes to 8 (300ms) at frame 3 -- raise fires immediately.
    let d = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 3);
    assert_eq!(
        d.unwrap().buffer,
        BufferSize(8),
        "raise should fire despite dwell"
    );

    // The oscillation: one raise (to 4), one raise (to 8). No lowers.
    assert_eq!(maker.buffer(), BufferSize(8));
}

// -- Bounds clamping --

/// Target exceeds max -> clamped to max.
#[test]
fn raise_clamps_to_max() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 3),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let d = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(3));
    assert_eq!(maker.buffer(), BufferSize(3));
}

/// Target below min -> clamped to min.
#[test]
fn lower_clamps_to_min() {
    let mut maker = DecisionMaker {
        buffer: BufferSize(3),
        ..DecisionMaker::new(
            key(),
            bounds(2, 20),
            law(),
            Authority::SelfRelay,
            HashSet::new(),
        )
    };
    let d = ingest_at(&mut maker, &conditions(0, 10_000, 0, 100), 1);
    assert_eq!(d.unwrap().buffer, BufferSize(2));
    assert_eq!(maker.buffer(), BufferSize(2));
}

// -- Recorded decision derivation --

/// A law-authored decision carries the terms it was derived from, and they
/// reconstruct the target the buffer moved to.
#[test]
fn a_law_decision_records_the_terms_it_derived_the_target_from() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let decision = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1).unwrap();
    let recorded = maker
        .pending_decision_inputs
        .as_ref()
        .expect("a law decision records its derivation");

    assert_eq!(recorded.path_us, 150_000);
    assert_eq!(
        recorded.law_target,
        recorded.target - recorded.cushion_turns - recorded.stretch_turns,
        "the additive terms are what separate the law's target from the full one",
    );
    assert_eq!(
        decision.buffer,
        BufferSize(recorded.target),
        "nothing clamped this decision, so the buffer is the target",
    );
    assert_eq!(
        recorded.eff_rtts,
        vec![crate::observability::flight_recorder::SlotEffRtt {
            slot: 0,
            eff_rtt_us: 150_000,
        }],
        "the per-slot detail names which link drove the path",
    );
}

/// A raise the bounds trim still records what the law asked for -- the gap
/// between the recorded target and the applied depth is the only evidence
/// that the session wanted more buffer than it was allowed.
#[test]
fn a_clamped_raise_records_the_target_the_law_asked_for() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 3),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let decision = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 1).unwrap();
    let recorded = maker.pending_decision_inputs.as_ref().unwrap();

    assert_eq!(decision.buffer, BufferSize(3), "trimmed to the bounds");
    assert!(
        recorded.target > 3,
        "the recorded target is the law's ask ({}), not the trimmed depth",
        recorded.target,
    );
}

/// The one-shot re-affirm of the standing buffer is not a law verdict, so
/// it records no derivation rather than an invented one.
#[test]
fn the_standing_buffer_reaffirm_records_no_derivation() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(4, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // A 150ms path targets exactly the minimum the buffer already sits at,
    // so the law holds and the unconditional broadcast is what fires.
    let decision = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1).unwrap();
    assert_eq!(decision.buffer, BufferSize(4));
    assert!(maker.pending_directive.is_some(), "the re-affirm broadcast");
    assert!(maker.pending_decision_inputs.is_none());
}

// -- Authority --

/// A non-authority relay ingests conditions but makes no decision.
#[test]
fn non_authority_ingests_but_does_not_decide() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    assert_eq!(d, None, "non-authority makes no decision");
    assert_eq!(maker.session_frame(), Some(GameFrameCount(1)));
    assert_eq!(maker.target(), Some(4));
}

// -- Frame tracking --

/// The session frame is the minimum of the per-slot observations -- the
/// slowest participant's progress, which is what lockstep advances by.
/// Each slot's own observation is monotonic.
#[test]
fn session_frame_is_the_minimum_across_slots() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    assert_eq!(maker.session_frame(), None, "no framed turn yet");

    maker.observe_frame(SlotId(0), GameFrameCount(10));
    assert_eq!(maker.session_frame(), Some(GameFrameCount(10)));

    maker.observe_frame(SlotId(1), GameFrameCount(4));
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(4)),
        "the slowest slot pins the coordinate",
    );

    // Per-slot observations are monotonic: an older frame arriving out of
    // order doesn't move a slot backward.
    maker.observe_frame(SlotId(1), GameFrameCount(3));
    assert_eq!(maker.session_frame(), Some(GameFrameCount(4)));

    maker.observe_frame(SlotId(1), GameFrameCount(12));
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(10)),
        "slot 0 is now the slowest",
    );
}

/// One slot claiming an absurd frame can't poison the coordinate: the
/// minimum stays with the honest slots, so decision scheduling and the
/// dwell clock are unaffected by a hostile client's `game_frame_count`.
#[test]
fn an_inflated_frame_claim_does_not_move_the_session_frame() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.observe_frame(SlotId(0), GameFrameCount(100));
    maker.observe_frame(SlotId(1), GameFrameCount(u32::MAX));
    assert_eq!(maker.session_frame(), Some(GameFrameCount(100)));

    // A decision still schedules against the honest coordinate, not the
    // inflated claim: raise 0 -> 4 at frame 101 applies at 101 + 4 + 3.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 101).unwrap();
    assert_eq!(d.applied_frame, GameFrameCount(101 + 4 + APPLY_HORIZON));
}

/// The applied frame is a horizon ahead of the session frame: the buffer
/// span (covering observation lag and client spread, both of which scale
/// with the cushion) plus the fixed delivery margin.
#[test]
fn applied_frame_is_a_buffer_spanned_horizon_ahead() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Raise 0 -> 4 at frame 50: span = max(0, 4) = 4.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 50).unwrap();
    assert_eq!(d.applied_frame, GameFrameCount(50 + 4 + APPLY_HORIZON));
    assert!(d.applied_frame.0 > 50);
}

// -- Loss differencing --
