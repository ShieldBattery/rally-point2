//! Sizing the session's initial buffer depth at start.

use super::*;

#[test]
fn initial_depth_fully_observed_single_relay_uses_observed_and_ignores_the_hint() {
    // Single-relay with every expected slot sampled is "fully observed": the
    // observed target is the truth, and a (higher) stale hint is ignored.
    let mut maker = initial_depth_maker(0, 20, &[0, 1], Some(200), true);
    // Both slots at 150ms: target = ceil(150000/41666) = 4. Hint 200ms = 5.
    maker.ingest_local(&multi_conditions(&[
        (0, 150_000, 0, 100),
        (1, 150_000, 0, 100),
    ]));
    assert!(drive_to_coverage(&mut maker, &[0, 1]), "coverage fires");
    assert_eq!(maker.target(), Some(4), "the observed target");
    assert_eq!(
        maker.initial_buffer_turns(),
        Some(4),
        "fully observed uses the observed target, not the higher hint",
    );
    assert_eq!(maker.buffer(), BufferSize(4), "and adopts it as the buffer");
}

#[test]
fn initial_depth_multi_relay_uses_max_of_observed_and_hint_plus_a_hop_cushion() {
    // A multi-relay session's per-slot conditions never cross the mesh before
    // the game starts, so it is never fully observed: it takes
    // max(observed, hint) and adds a one-turn hop cushion.
    let mut maker = initial_depth_maker(0, 20, &[0, 1], Some(200), false);
    // Observed target 4 (both at 150ms); hint 200ms = 5; max = 5; +1 = 6.
    maker.ingest_local(&multi_conditions(&[
        (0, 150_000, 0, 100),
        (1, 150_000, 0, 100),
    ]));
    assert!(drive_to_coverage(&mut maker, &[0, 1]));
    assert_eq!(maker.target(), Some(4));
    assert_eq!(
        maker.initial_buffer_turns(),
        Some(6),
        "max(observed 4, hint 5) + a one-turn multi-relay hop cushion",
    );
    assert_eq!(maker.buffer(), BufferSize(6));
}

#[test]
fn initial_depth_single_relay_unobserved_slot_uses_the_hint_without_a_cushion() {
    // Single-relay but one expected slot never produced an RTT sample: not
    // fully observed, so the hint is the fallback — and no hop cushion, since
    // the session spans one relay.
    let mut maker = initial_depth_maker(0, 20, &[0, 1], Some(300), true);
    // Only slot 0 is sampled (150ms → observed 4). Slot 1 is present but never
    // measured. Hint 300ms = ceil(300000/41666) = 8; max(4, 8) = 8, no cushion.
    maker.ingest_local(&conditions(0, 150_000, 0, 100));
    assert!(drive_to_coverage(&mut maker, &[0, 1]));
    assert_eq!(
        maker.initial_buffer_turns(),
        Some(8),
        "the hint covers the unobserved slot, with no multi-relay cushion",
    );
}

#[test]
fn initial_depth_falls_back_to_bounds_min_with_no_conditions_and_no_hint() {
    // Nothing observed and no hint: start at the tenant minimum (today's
    // behavior).
    let mut maker = initial_depth_maker(3, 20, &[0, 1], None, true);
    assert!(drive_to_coverage(&mut maker, &[0, 1]));
    assert_eq!(maker.target(), None, "no RTT observed");
    assert_eq!(
        maker.initial_buffer_turns(),
        Some(3),
        "falls back to the tenant minimum",
    );
    assert_eq!(maker.buffer(), BufferSize(3));
}

#[test]
fn initial_depth_clamps_to_both_bounds() {
    // Above the ceiling: a huge observed target clamps down to max.
    let mut hi = initial_depth_maker(1, 5, &[0, 1], None, true);
    hi.ingest_local(&multi_conditions(&[
        (0, 2_000_000, 0, 100),
        (1, 2_000_000, 0, 100),
    ]));
    assert!(drive_to_coverage(&mut hi, &[0, 1]));
    assert_eq!(hi.initial_buffer_turns(), Some(5), "clamped to the ceiling");
    assert_eq!(hi.buffer(), BufferSize(5));

    // Below the floor: a tiny observed target clamps up to min.
    let mut lo = initial_depth_maker(6, 20, &[0, 1], None, true);
    lo.ingest_local(&multi_conditions(&[
        (0, 10_000, 0, 100),
        (1, 10_000, 0, 100),
    ]));
    assert!(drive_to_coverage(&mut lo, &[0, 1]));
    assert_eq!(
        lo.initial_buffer_turns(),
        Some(6),
        "clamped up to the floor"
    );
    assert_eq!(lo.buffer(), BufferSize(6));
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
    let mut peer = DecisionMaker::new(key(), bounds(1, 5), law(), Authority::Peer, HashSet::new());
    peer.adopt_session_start(Some(4));
    assert!(peer.is_started());
    assert_eq!(peer.initial_buffer_turns(), Some(4));
    assert_eq!(peer.buffer(), BufferSize(4));

    let mut clamped =
        DecisionMaker::new(key(), bounds(1, 5), law(), Authority::Peer, HashSet::new());
    clamped.adopt_session_start(Some(99));
    assert_eq!(
        clamped.buffer(),
        BufferSize(5),
        "an over-ceiling depth clamps"
    );

    // A depth-less directive (an old authority, or a resumed re-push into a
    // running game) latches started but leaves the seed buffer untouched.
    let mut peerless =
        DecisionMaker::new(key(), bounds(1, 5), law(), Authority::Peer, HashSet::new());
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
    let mut m = DecisionMaker::new(key(), deep, law(), Authority::Peer, HashSet::new());
    m.adopt_session_start(Some(GAME_SYNC_SAFE_BUFFER_MAX + 10));
    assert_eq!(
        m.initial_buffer_turns(),
        Some(GAME_SYNC_SAFE_BUFFER_MAX),
        "an adopted seed past the ceiling caps at it, not at the wire bounds",
    );
    assert_eq!(m.buffer(), BufferSize(GAME_SYNC_SAFE_BUFFER_MAX));
}
