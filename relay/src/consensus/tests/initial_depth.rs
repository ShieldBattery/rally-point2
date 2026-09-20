//! Sizing the session's initial buffer depth at start.

use super::*;

/// A single-relay session expecting `expected`, already sitting at a depth
/// wide enough that a lower has somewhere to go -- the state the RTT
/// coverage gate has to justify before it may shrink.
fn seeded_at_six(expected: &[u8]) -> DecisionMaker {
    DecisionMaker {
        buffer: BufferSize(6),
        ..initial_depth_maker(0, 20, expected, None, true)
    }
}

/// Sizing the seed depth, case by case. Each case builds a session with
/// the given bounds, roster, latency hint and relay span, feeds it
/// whatever conditions it has, and drives every expected slot to the
/// coverage latch -- which is what computes the depth and adopts it.
#[test]
fn the_initial_depth_over_its_observation_hint_and_clamp_cases() {
    struct Case {
        label: &'static str,
        bounds: (u32, u32),
        hint_ms: Option<u32>,
        single_relay: bool,
        samples: &'static [(u8, u32, u64, u64)],
        depth: u32,
    }

    // Every case expects slots 0 and 1. A 150ms link observes a target of
    // 4; a 200ms hint is 5 turns and a 300ms hint is 8.
    let both_at_150ms: &[(u8, u32, u64, u64)] = &[(0, 150_000, 0, 100), (1, 150_000, 0, 100)];
    let cases = [
        Case {
            label: "single-relay with every expected slot sampled is fully \
                    observed: the observed target is the truth and a higher \
                    stale hint is ignored",
            bounds: (0, 20),
            hint_ms: Some(200),
            single_relay: true,
            samples: both_at_150ms,
            depth: 4,
        },
        Case {
            label: "a multi-relay session's per-slot conditions never cross \
                    the mesh before the game starts, so it is never fully \
                    observed: max(observed 4, hint 5) plus a one-turn hop \
                    cushion",
            bounds: (0, 20),
            hint_ms: Some(200),
            single_relay: false,
            samples: both_at_150ms,
            depth: 6,
        },
        Case {
            label: "single-relay with one expected slot never measured is \
                    not fully observed either: the hint covers it, and there \
                    is no hop cushion on one relay",
            bounds: (0, 20),
            hint_ms: Some(300),
            single_relay: true,
            samples: &[(0, 150_000, 0, 100)],
            depth: 8,
        },
        Case {
            label: "nothing observed and no hint: start at the tenant minimum",
            bounds: (3, 20),
            hint_ms: None,
            single_relay: true,
            samples: &[],
            depth: 3,
        },
        Case {
            label: "a huge observed target clamps down to the ceiling",
            bounds: (1, 5),
            hint_ms: None,
            single_relay: true,
            samples: &[(0, 2_000_000, 0, 100), (1, 2_000_000, 0, 100)],
            depth: 5,
        },
        Case {
            label: "a tiny observed target clamps up to the floor",
            bounds: (6, 20),
            hint_ms: None,
            single_relay: true,
            samples: &[(0, 10_000, 0, 100), (1, 10_000, 0, 100)],
            depth: 6,
        },
    ];

    for case in cases {
        let (min, max) = case.bounds;
        let mut maker = initial_depth_maker(min, max, &[0, 1], case.hint_ms, case.single_relay);
        if !case.samples.is_empty() {
            maker.ingest_local(&multi_conditions(case.samples));
        }
        assert!(
            drive_to_coverage(&mut maker, &[0, 1]),
            "coverage fires: {}",
            case.label,
        );
        assert_eq!(
            maker.initial_buffer_turns(),
            Some(case.depth),
            "{}",
            case.label,
        );
        assert_eq!(
            maker.buffer(),
            BufferSize(case.depth),
            "and adopts it as the buffer: {}",
            case.label,
        );
    }
}

#[test]
fn the_adopted_depth_is_what_the_first_frame_re_affirm_broadcasts() {
    // The adoption into `buffer` is load-bearing: the one-shot first-frame
    // re-affirm broadcasts the current buffer, so it must name the stamped
    // depth rather than clobbering it back to the minimum.
    let mut maker = initial_depth_maker(0, 20, &[0, 1], None, true);
    let conds = multi_conditions(&[(0, 150_000, 0, 100), (1, 150_000, 0, 100)]);
    maker.ingest_local(&conds);
    assert!(drive_to_coverage(&mut maker, &[0, 1]));
    assert_eq!(maker.initial_buffer_turns(), Some(4));
    assert_eq!(maker.buffer(), BufferSize(4));

    // The first framed turn: the control law holds (target == buffer), so the
    // one-shot initial re-affirm fires — re-affirming 4 (the adopted depth),
    // not bounds.min.
    let decision = ingest_at(&mut maker, &conds, 10).expect("the re-affirm fires once");
    assert_eq!(
        decision.buffer,
        BufferSize(4),
        "the re-affirm broadcasts the stamped depth, not bounds.min",
    );
    // And it is a one-shot: a later framed turn at the same target re-affirms
    // nothing.
    assert!(ingest_at(&mut maker, &conds, 11).is_none());
}

#[test]
fn a_relay_that_only_marks_started_sizes_no_depth() {
    // A resumed (re-home) relay latches started via `mark_started` without ever
    // running the coverage computation, so it stamps no depth — a stale initial
    // depth must never resize a running game.
    let mut maker = initial_depth_maker(1, 20, &[0, 1], Some(200), true);
    maker.ingest_local(&multi_conditions(&[
        (0, 150_000, 0, 100),
        (1, 150_000, 0, 100),
    ]));
    maker.mark_started();
    assert!(maker.is_started());
    assert_eq!(maker.initial_buffer_turns(), None, "no depth synthesized");
    assert_eq!(
        maker.buffer(),
        BufferSize(1),
        "the buffer stays at the seed"
    );
}

#[test]
fn a_peer_adopts_the_authoritys_stamped_depth() {
    // A peer adopts the authority's carried depth into its buffer and stores it
    // for its own re-pushes; the value is bounds-clamped defensively.
    let mut peer = peer_maker_with(bounds(1, 5));
    peer.adopt_session_start(Some(4));
    assert!(peer.is_started());
    assert_eq!(peer.initial_buffer_turns(), Some(4));
    assert_eq!(peer.buffer(), BufferSize(4));

    let mut clamped = peer_maker_with(bounds(1, 5));
    clamped.adopt_session_start(Some(99));
    assert_eq!(
        clamped.buffer(),
        BufferSize(5),
        "an over-ceiling depth clamps"
    );

    // A depth-less directive (an old authority, or a resumed re-push into a
    // running game) latches started but leaves the seed buffer untouched.
    let mut peerless = peer_maker_with(bounds(1, 5));
    peerless.adopt_session_start(None);
    assert!(peerless.is_started());
    assert_eq!(peerless.initial_buffer_turns(), None);
    assert_eq!(
        peerless.buffer(),
        BufferSize(1),
        "the seed buffer is untouched"
    );
}

/// Wire bounds deserialize with no validation, so a misconfigured or older
/// coordinator can hand a maker a `max` past the game-sync-safe ceiling —
/// but every depth the relay emits is capped at the ceiling regardless: a
/// depth past it deterministically mass-drops the game's players (the
/// game's native sync validation, not the relay, is what breaks).
#[test]
fn emitted_depths_are_capped_at_the_game_sync_safe_ceiling_regardless_of_bounds() {
    let deep = bounds(1, GAME_SYNC_SAFE_BUFFER_MAX + 10);
    let mut m = peer_maker_with(deep);
    m.adopt_session_start(Some(GAME_SYNC_SAFE_BUFFER_MAX + 10));
    assert_eq!(
        m.initial_buffer_turns(),
        Some(GAME_SYNC_SAFE_BUFFER_MAX),
        "an adopted seed past the ceiling caps at it, not at the wire bounds",
    );
    assert_eq!(m.buffer(), BufferSize(GAME_SYNC_SAFE_BUFFER_MAX));
}

#[test]
fn incomplete_rtt_coverage_reaffirms_the_initial_depth_without_lowering() {
    // The first fast link is enough to compute a target, but slot 1 has not
    // reported an RTT. Keep the configured initial depth until that missing
    // link is represented in the control law.
    let mut maker = seeded_at_six(&[0, 1]);
    maker.mark_started();

    let fast = conditions(0, 32_000, 0, 100);
    let initial = ingest_at(&mut maker, &fast, 1).expect("the initial re-affirm");
    assert_eq!(initial.buffer, BufferSize(6));
    assert_eq!(maker.buffer(), BufferSize(6));
    assert!(
        !maker.all_expected_slots_have_rtt(),
        "slot 1 has not supplied an RTT"
    );

    for frame in 2..=500 {
        assert_eq!(
            ingest_at(&mut maker, &fast, frame),
            None,
            "incomplete RTT coverage holds the initial depth (frame {frame})"
        );
    }
    assert_eq!(maker.buffer(), BufferSize(6));
}

#[test]
fn complete_rtt_coverage_eventually_allows_a_lower() {
    let mut maker = seeded_at_six(&[0, 1]);
    maker.mark_started();

    let fast = conditions(0, 32_000, 0, 100);
    assert_eq!(
        ingest_at(&mut maker, &fast, 1).unwrap().buffer,
        BufferSize(6),
        "the incomplete first sample only re-affirms",
    );

    let fully_observed = multi_conditions(&[(0, 32_000, 0, 101), (1, 32_000, 0, 100)]);
    assert!(
        ingest_at(&mut maker, &fully_observed, 2).is_none(),
        "the initial re-affirm's dwell still applies"
    );
    assert!(maker.all_expected_slots_have_rtt());

    let lower_frame = 1 + maker.law.min_dwell_turns;
    for frame in 3..lower_frame {
        assert!(ingest_at(&mut maker, &fully_observed, frame).is_none());
    }
    assert_eq!(
        ingest_at(&mut maker, &fully_observed, lower_frame)
            .expect("complete coverage earns a paced lower")
            .buffer,
        BufferSize(4),
    );
}

#[test]
fn incomplete_rtt_coverage_still_raises_for_a_slow_observed_link() {
    // Slot 2 remains unsampled, but the measured slow slot must still raise
    // immediately; only speculative lowers wait for complete coverage.
    let mut maker = seeded_at_six(&[0, 1, 2]);
    maker.mark_started();

    assert_eq!(
        ingest_at(&mut maker, &conditions(0, 32_000, 0, 100), 1)
            .unwrap()
            .buffer,
        BufferSize(6),
    );
    let raised = ingest_at(
        &mut maker,
        &multi_conditions(&[(0, 32_000, 0, 101), (1, 469_000, 0, 100)]),
        2,
    )
    .expect("a measured slow link raises immediately");
    assert_eq!(raised.buffer, BufferSize(7));
    assert!(
        !maker.all_expected_slots_have_rtt(),
        "slot 2 remains unsampled"
    );
}

#[test]
fn departed_expected_slot_does_not_block_a_lower() {
    // A departed member no longer contributes to the game, so its missing
    // RTT must not prevent the surviving slot's measured safe lower.
    let mut maker = seeded_at_six(&[0, 1]);
    maker.record_departure(SlotId(1), DepartureStamps::default(), LEAVE_REASON_DROPPED);
    maker.mark_started();

    let lowered = ingest_at(&mut maker, &conditions(0, 32_000, 0, 100), 1)
        .expect("the remaining measured slot can lower");
    assert!(
        maker.all_expected_slots_have_rtt(),
        "the departed slot is exempt once the survivor is sampled"
    );
    assert_eq!(lowered.buffer, BufferSize(4),);
}
