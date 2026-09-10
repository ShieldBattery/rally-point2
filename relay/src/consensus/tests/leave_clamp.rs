//! Clamping an inflated departing frame to a reachable ceiling.

use super::*;

/// Steady state, honest departure: the survivor leads by the buffer depth
/// before stalling, so it has *provably executed* the departed slot's last
/// frame — the ceiling equals `last_frame` and the clamp is a no-op (no
/// regression from the pre-clamp behavior).
#[test]
fn decide_leave_does_not_clamp_an_honest_lead_ahead_departure() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Survivor slot 0 has run 6 turns (the buffer depth) past the departing
    // slot's last frame before stalling: seqs 0..=21 (frames 100..=121).
    feed_turns(&mut maker, 0, 0..=21);
    // The departing slot 1's last framed turn is seq 15 / frame 115.
    feed_turns(&mut maker, 1, 0..=15);
    assert_eq!(
        maker.reachable_frame(SlotId(1)),
        Some(115),
        "ceiling equals the departed slot's last executed frame",
    );
    let d = home_decide_leave(&mut maker, 1);
    assert_eq!(d.apply_at_frame, 116, "one past last_frame, unclamped");
}

/// Steady state, malicious departure: the slot stamps `u32::MAX` on its last
/// turn then leaves. The ceiling comes from the honest survivor, not the
/// claim, so the leave is clamped to a survivor-reachable frame instead of
/// `u32::MAX` (which would have stalled every survivor forever).
#[test]
fn decide_leave_clamps_an_inflated_departing_frame_to_a_reachable_ceiling() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    feed_turns(&mut maker, 0, 0..=21); // honest survivor, leads by the buffer
    feed_turns(&mut maker, 1, 0..=14); // the malicious slot's honest prefix
    maker.observe_turn_frame(SlotId(1), 15, GameFrameCount(u32::MAX)); // the lie
    assert_eq!(
        maker.slot_frame(SlotId(1)),
        Some(GameFrameCount(u32::MAX)),
        "the slot claims u32::MAX",
    );
    assert_eq!(
        maker.reachable_frame(SlotId(1)),
        Some(115),
        "the ceiling comes from the survivor, not the departing slot's claim",
    );
    let d = home_decide_leave(&mut maker, 1);
    assert_eq!(
        d.apply_at_frame, 116,
        "clamped to a survivor-reachable frame, not u32::MAX + 1",
    );
}

/// A moderate (2x) inflation is clamped the same way — the ceiling doesn't
/// depend on how large the lie is.
#[test]
fn decide_leave_clamps_a_moderate_inflation_too() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    feed_turns(&mut maker, 0, 0..=21);
    feed_turns(&mut maker, 1, 0..=14);
    maker.observe_turn_frame(SlotId(1), 15, GameFrameCount(230)); // ~2x the real ~115
    let d = home_decide_leave(&mut maker, 1);
    assert_eq!(
        d.apply_at_frame, 116,
        "clamped to the survivor-reachable ceiling"
    );
}

/// The exact case the audit's fallback would have reopened: an in-game but
/// *early* (seq < buffer_max) inflated-frame departure. The threshold
/// saturates to 0, so the ceiling is the survivor's earliest reachable frame
/// — the leave is clamped, never left unclamped at `u32::MAX` (a stall).
#[test]
fn decide_leave_clamps_an_early_game_inflation_no_stall() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    feed_turns(&mut maker, 0, 0..=3); // only a few turns in (< buffer_max = 6)
    feed_turns(&mut maker, 1, 0..=2);
    maker.observe_turn_frame(SlotId(1), 3, GameFrameCount(u32::MAX));
    assert_eq!(
        maker.reachable_frame(SlotId(1)),
        Some(100),
        "early game: the ceiling is the earliest reachable frame",
    );
    let d = home_decide_leave(&mut maker, 1);
    assert_eq!(
        d.apply_at_frame, 101,
        "clamped — the unclamped fallback would have stalled at u32::MAX",
    );
}

/// An honest *early-game* departure takes a bounded, deterministic early-drop
/// (the ceiling sits a few frames below `last_frame` because the buffer
/// hasn't filled), never a stall: the apply frame is at or before the natural
/// stall point, so every survivor can reach it.
#[test]
fn decide_leave_early_game_honest_departure_is_a_bounded_early_drop_no_stall() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    feed_turns(&mut maker, 0, 0..=3);
    feed_turns(&mut maker, 1, 0..=3); // honest last frame 103
    let d = home_decide_leave(&mut maker, 1);
    assert_eq!(
        d.apply_at_frame, 101,
        "a bounded few frames early (101 vs the honest 104)"
    );
    assert!(
        d.apply_at_frame <= 104,
        "at or before the natural stall (last_frame + 1) — reachable, never a stall",
    );
}

/// Determinism: the same home-authored departure record (an inflated
/// `last_frame` plus the reachability ceiling) yields the *identical* clamped
/// apply frame on the deciding authority and on a relay promoted to re-derive
/// it — the agreement clients require (they dedup a leave by slot).
#[test]
fn the_clamped_apply_frame_is_reproduced_by_a_peer_and_a_promoted_authority() {
    let last = Some(GameFrameCount(u32::MAX));
    let ceiling = Some(115u32);

    // The authority deciding directly from the record.
    let mut authority = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    authority.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: last,
            reachable_frame: ceiling,
            ..Default::default()
        },
        DROPPED,
    );
    let a = authority
        .decide_leave(SlotId(1), DROPPED)
        .expect("the authority decides the leave");
    assert_eq!(a.apply_at_frame, 116);

    // A peer that only recorded the carried departure, then is promoted: the
    // handoff re-derivation reproduces the identical apply frame.
    let mut peer = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::Peer, HashSet::new());
    peer.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: last,
            reachable_frame: ceiling,
            ..Default::default()
        },
        DROPPED,
    );
    let (leaves, _fresh) = peer.set_authority(Authority::SelfRelay, &HashSet::new());
    let p = leaves
        .iter()
        .find(|l| l.slot == 1)
        .expect("promotion re-derives slot 1's leave");
    assert_eq!(
        p.apply_at_frame, 116,
        "same clamped apply frame from the same carried record",
    );
}
