//! Placing each sync report at its true ordinal: nibble correction, joins, floods and eviction.

use super::*;

#[test]
fn a_departed_slot_is_no_longer_required() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_A);
    feed(&mut m, 2, 0, SYNC_A);
    // Slot 0 alone clears the margin for ordinal 0; all three agree.
    assert_eq!(
        advance(&mut m, 0, SYNC_A, 8),
        None,
        "all agree at ordinal 0"
    );
    assert_eq!(m.sync.base_ordinal, 1);

    // Ordinal 1: slot 1 reports, slot 2 departs before ever reporting it.
    feed(&mut m, 1, 1, SYNC_A);
    m.record_departure(SlotId(2), DepartureStamps::default(), DROPPED);
    assert!(!m.sync.members.contains_key(&SlotId(2)));

    // Slot 0 continues; ordinal 1 completes on the two survivors once the
    // frontier clears the margin for base = 1 (slot 0's own ordinal-1
    // report already landed during the `advance` above).
    let divergence = feed(&mut m, 0, 8, SYNC_A);
    assert_eq!(divergence, None, "no mismatch — retires silently");
    assert_eq!(m.sync.base_ordinal, 2, "ordinal 1 retired without slot 2");
}

/// Hole 3 (reordering): two adjacent turns from the same slot arrive
/// swapped. Nibble-corrected placement lands each at its true ordinal
/// regardless, so the honest agreement across slots never looks like a
/// mismatch — and the correction is flagged for observability.
#[test]
fn a_reordered_adjacent_pair_is_placed_correctly_and_warns() {
    let mut m = authority_maker();
    // Slot 1 reports ordinals 0..5 normally, matching slot 0's values.
    for ordinal in 0..6 {
        feed(&mut m, 1, ordinal, SYNC_A);
    }
    // Slot 0 reports 0..3 normally, but 4 and 5 arrive swapped — 5 first.
    for ordinal in 0..4 {
        feed(&mut m, 0, ordinal, SYNC_A);
    }
    feed_ring(&mut m, 0, 5, SYNC_A, 1005); // ordinal 5 arrives first
    feed_ring(&mut m, 0, 4, SYNC_A, 1004); // ordinal 4 arrives late
    assert!(
        m.sync.corrections >= 1,
        "the out-of-order arrival was corrected and counted",
    );

    // Slot 0 races on so the margin clears every ordinal through 5.
    let divergence = (6..14)
        .filter_map(|ordinal| feed(&mut m, 0, ordinal, SYNC_A))
        .last();
    assert_eq!(
        divergence, None,
        "the reordered pair still compares equal at its true ordinal — no false divergence",
    );
    assert_eq!(m.sync.base_ordinal, 6, "ordinals 0..5 all retired cleanly");
}

/// Hole 2, the exact production failure: at sync activation, one slot's
/// early turns beat the other's first-ever arrival to the relay (routine
/// under asymmetric latency + buffer depth, invisible on a symmetric
/// loopback test). The old frontier-floor scheme landed the late slot's
/// true ordinal 0 at whatever the frontier happened to be (here, 4) — a
/// permanent misalignment that turns every later honest turn into a false
/// mismatch. Nibble-corrected placement anchors the late slot at its true
/// ordinal instead. Two slots only, so this is also the 1v1 shape of the
/// production failure.
#[test]
fn a_late_joining_slot_lands_at_its_true_ordinal_not_the_frontier() {
    let mut m = authority_maker();
    for ordinal in 0..4 {
        feed(&mut m, 0, ordinal, SYNC_A);
    }
    // Slot 1's first-ever report is genuinely ordinal 0 (ring 0), arriving
    // only now. Nibble-corrected placement anchors it there, not at 4.
    feed_ring(&mut m, 1, 0, SYNC_A, 2000);
    assert_eq!(
        m.sync.members[&SlotId(1)].since,
        0,
        "slot 1's join ordinal is its true ordinal 0, not the frontier it joined at",
    );

    feed(&mut m, 1, 1, SYNC_A);
    feed(&mut m, 1, 2, SYNC_A);
    feed(&mut m, 1, 3, SYNC_A);

    // Both slots continue in lockstep agreement; nothing should ever look
    // like a divergence.
    let mut divergence = None;
    for ordinal in 4u8..12 {
        if let Some(d) = feed(&mut m, 0, ordinal, SYNC_A) {
            divergence = Some(d);
        }
        if let Some(d) = feed(&mut m, 1, ordinal, SYNC_A) {
            divergence = Some(d);
        }
    }
    assert_eq!(
        divergence, None,
        "the late join aligned correctly — no false desync"
    );
}

/// A deep join (>7 ordinals from the frontier — a gap the shipped dev-tenant
/// policy 1..=12 allows, past the ±7 nibble ceiling) still lands on its true
/// ordinal **once a rate is corroborated by ≥3 distinct slots**. This is the
/// honest-case counterpart to the calibration-poisoning defense: with a
/// corroborated rate (which a lone slot cannot swing), the frame projection is
/// trustworthy again and the deep join is placed correctly rather than
/// deferred.
#[test]
fn a_deep_join_lands_on_its_true_ordinal_once_three_slots_corroborate_the_rate() {
    let mut m = DecisionMaker::new(
        key(),
        bounds(1, 12),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let margin = sync_eval_margin(12);
    assert_eq!(margin, 14);

    // Three slots advance together for ten ordinals at ~2 frames/turn, so
    // every ordinal 0..10 is reported by ≥3 distinct slots with agreeing
    // frames — a corroborated (median) rate a single slot cannot move.
    for ordinal in 0u8..10 {
        let frame = 5000 + 2 * u32::from(ordinal);
        for slot in [0u8, 2, 3] {
            feed_ring(&mut m, slot, ordinal, SYNC_A, frame);
        }
    }
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        10,
        "frontier at 10"
    );
    assert_eq!(
        m.sync.frame_rate(),
        Some(2.0),
        "≥3 slots corroborated the rate"
    );

    // Slot 1's first-ever report is genuinely ordinal 0 (ring 0), ten
    // ordinals behind the frontier — past the nibble ceiling — with a frame
    // close to ordinal 0's corroborated frame (5000). The corroborated
    // projection lands it on its true ordinal, not the frontier.
    feed_ring(&mut m, 1, 0, SYNC_A, 5001);
    assert_eq!(
        m.sync.members[&SlotId(1)].since,
        0,
        "the corroborated anchor placed slot 1 at its true ordinal 0, not the frontier (10)",
    );

    // Everyone agrees; racing slot 0 past the depth-12 margin retires ordinal
    // 0 silently — no false divergence from the deep join.
    let mut divergence = None;
    for ordinal in 10u8..(margin as u8) {
        if let Some(d) = feed_ring(&mut m, 0, ordinal, SYNC_A, 5000 + 2 * u32::from(ordinal)) {
            divergence = Some(d);
        }
    }
    assert_eq!(divergence, None, "no false divergence from the deep join");
}

/// Finding B, the whole point: an attacker controlling only its own slot
/// cannot frame a joining victim by seeding calibration. The attacker races
/// the frontier ahead (one `0x37` per turn) and stamps whatever frames it
/// likes; when the honest victim joins at its true ordinal 0, there is no
/// corroborated rate (a lone slot can't make one), so the victim is DEFERRED
/// — never placed a full ring cycle ahead at ~16 and never named diverged.
#[test]
fn an_attacker_cannot_frame_a_joining_victim_by_seeding_calibration_alone() {
    let mut m = DecisionMaker::new(
        key(),
        bounds(1, 12),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // The attacker (slot 0) races ten ordinals ahead, stamping a frame
    // sequence designed to project a low-frame joiner up near ordinal 16.
    for ordinal in 0u8..10 {
        feed_ring(&mut m, 0, ordinal % 16, SYNC_A, 9000 + u32::from(ordinal));
    }
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        10,
        "attacker raced the frontier to 10"
    );
    assert!(
        m.sync.frame_rate().is_none(),
        "a lone slot cannot corroborate a rate to poison",
    );

    // The honest victim joins at its true ordinal 0. No corroboration + the
    // nibble would land it above the frontier (a full cycle off) → deferred.
    assert_eq!(feed_ring(&mut m, 1, 0, SYNC_A, 9002), None);
    assert!(
        !m.sync.members.contains_key(&SlotId(1)),
        "the victim is deferred, never misplaced a full ring cycle ahead at ~16",
    );
    // It keeps reporting; without ≥3 corroborators it stays deferred and is
    // never named as the diverged slot.
    for _ in 0..5 {
        assert_eq!(
            feed_ring(&mut m, 1, 0, SYNC_A, 9002),
            None,
            "still deferred — never a divergence naming the honest victim",
        );
    }
    assert!(!m.sync.members.contains_key(&SlotId(1)));
}

/// A 2-reporter ordinal never corroborates (the threshold is ≥3), so an
/// attacker's outlier frame at a 2-reporter ordinal can't poison a rate — the
/// median that would reject it never even gets computed, because no rate
/// forms from two reporters at all.
#[test]
fn a_two_reporter_ordinal_with_an_attacker_outlier_does_not_corroborate() {
    let mut m = DecisionMaker::new(
        key(),
        bounds(1, 12),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // One honest slot and one attacker stamping wild frames report ordinals
    // 0..6 — two reporters each, below the ≥3 corroboration threshold.
    for ordinal in 0u8..6 {
        feed_ring(&mut m, 0, ordinal, SYNC_A, 5000 + 2 * u32::from(ordinal));
        feed_ring(&mut m, 1, ordinal, SYNC_A, 900_000 + u32::from(ordinal));
    }
    assert!(
        m.sync.corroborated_latest.is_none(),
        "two reporters never corroborate an ordinal",
    );
    assert!(
        m.sync.frame_rate().is_none(),
        "no rate forms — nothing for the attacker's outlier to poison",
    );
}

/// When a joining report carries no `game_frame` at all, the frame anchor
/// is unavailable and join placement falls back to frontier+nibble (the
/// round-2 behavior) — exercised within the ±7 range where that fallback
/// is still sound on its own.
#[test]
fn a_join_with_no_frame_falls_back_to_frontier_and_nibble() {
    let mut m = authority_maker();
    for ordinal in 0u8..4 {
        feed(&mut m, 0, ordinal, SYNC_A);
    }
    let divergence = m.observe_sync(
        SlotId(1),
        None,
        &sync_command(4, expected_kind_for_ordinal(4), SYNC_A),
    );
    assert_eq!(divergence, None);
    assert_eq!(
        m.sync.members[&SlotId(1)].since,
        4,
        "no frame to anchor on — falls back to the frontier, nibble-corrected",
    );
}

/// A joining report carries a frame, but the tracker doesn't have a rate
/// yet (only one calibration point exists) — falls back to
/// frontier+nibble exactly like the no-frame case, ignoring the frame
/// entirely rather than projecting from an unreliable single point.
#[test]
fn a_join_with_a_frame_but_no_rate_yet_falls_back_to_frontier_and_nibble() {
    let mut m = authority_maker();
    // Slot 0 reports exactly once — one calibration point, not enough to
    // compute a rate.
    feed(&mut m, 0, 0, SYNC_A);
    // Slot 1 joins with a frame that would, under any rate assumption,
    // suggest a wildly different ordinal — but with no rate to project
    // from, this still falls back to the frontier (1), nibble-corrected.
    let divergence = feed_ring(&mut m, 1, 1, SYNC_A, 999_999);
    assert_eq!(divergence, None);
    assert_eq!(
        m.sync.members[&SlotId(1)].since,
        1,
        "no rate yet — falls back to the frontier, nibble-corrected, ignoring the frame",
    );
}

/// A turn carrying more than one `0x37` counts as a **single** ordinal
/// advance. An honest client emits exactly one sync command per outgoing
/// turn; packing several into one turn is the lever a malicious client
/// would use to inflate its own frontier (and seed join-placement
/// calibration) in a single turn — and to race its own ordinals past the
/// eviction window to evade detection. Only the first is fed to the
/// comparator; the extras are ignored and flagged.
#[test]
fn multiple_sync_commands_in_one_turn_advance_the_ordinal_by_one() {
    let mut m = authority_maker();
    // Three sync commands packed into a single turn (one observe_sync call).
    let mut commands = sync_command(0, expected_kind_for_ordinal(0), SYNC_A);
    commands.extend(sync_command(1, expected_kind_for_ordinal(1), SYNC_A));
    commands.extend(sync_command(2, expected_kind_for_ordinal(2), SYNC_A));
    let divergence = m.observe_sync(SlotId(0), Some(1000), &commands);
    assert_eq!(divergence, None);
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        1,
        "only the first sync command counts — the ordinal advances by one, not three",
    );
    assert_eq!(
        m.sync.base_ordinal, 0,
        "the frontier did not vault the window"
    );
    assert_eq!(
        m.sync.multi_sync_warns, 1,
        "the extra sync commands were flagged once"
    );
}

/// The eviction-evasion shape of the same lever: a slot cannot flood enough
/// `0x37`s in one turn to push the comparator's `base_ordinal` past
/// ordinals its honest peers haven't been compared at yet. With one sync
/// command per turn honored, a single turn moves the frontier by one, so
/// the eviction window can't be jumped in a burst.
#[test]
fn a_one_turn_sync_flood_cannot_vault_the_eviction_window() {
    let mut m = authority_maker();
    // An honest slot reports ordinal 0 and stops there.
    feed(&mut m, 1, 0, SYNC_A);
    // The attacker packs a full window-plus of sync commands into one turn.
    let mut flood = Vec::new();
    for ring in 0..(SYNC_WINDOW as u8 + 4) {
        flood.extend(sync_command(
            ring % 16,
            expected_kind_for_ordinal(u64::from(ring % 16)),
            SYNC_B,
        ));
    }
    let divergence = m.observe_sync(SlotId(0), Some(2000), &flood);
    assert_eq!(divergence, None, "no eviction, no premature verdict");
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        1,
        "the flood advanced the attacker's ordinal by one, not the whole window",
    );
    assert_eq!(
        m.sync.base_ordinal, 0,
        "ordinal 0 (where the honest slot reported) is still awaiting evaluation, not evicted",
    );
    assert!(
        m.sync
            .pending
            .get(&0)
            .is_some_and(|r| r.contains_key(&SlotId(1))),
        "the honest slot's ordinal-0 report is still pending, not evicted past",
    );
}

#[test]
fn an_ordinal_is_not_evaluated_until_the_frontier_clears_the_margin() {
    let mut m = authority_maker();
    feed(&mut m, 0, 0, SYNC_A);
    feed(&mut m, 1, 0, SYNC_A);
    assert_eq!(m.sync.base_ordinal, 0, "not yet evaluated");
    assert!(m.sync.pending.contains_key(&0));

    let margin = authority_margin() as u8;
    for ordinal in 1..(margin - 1) {
        feed(&mut m, 0, ordinal, SYNC_A);
        assert_eq!(m.sync.base_ordinal, 0, "still short of the margin");
    }
    feed(&mut m, 0, margin - 1, SYNC_A);
    assert_eq!(
        m.sync.base_ordinal, 1,
        "the margin cleared — ordinal 0 retired"
    );
}

/// The margin scales with the session's negotiated buffer bounds (not a
/// fixed constant): with the shipped dev-tenant policy (1..=12), ordinal
/// `k` isn't evaluated until the frontier reaches `k + 14`
/// (`max(8, 12 + 2)`), not the shallow-policy 8.
#[test]
fn the_evaluation_margin_scales_with_the_session_s_buffer_bounds() {
    let mut m = DecisionMaker::new(
        key(),
        bounds(1, 12),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let margin = sync_eval_margin(12);
    assert_eq!(
        margin, 14,
        "max(8, 12 + 2) -- the shipped dev-tenant policy"
    );

    feed(&mut m, 0, 0, SYNC_A);
    feed(&mut m, 1, 0, SYNC_A);
    // One short of the margin: still held.
    for ordinal in 1..(margin as u8 - 1) {
        feed(&mut m, 0, ordinal, SYNC_A);
        assert_eq!(m.sync.base_ordinal, 0, "still short of the deeper margin");
    }
    // The margin clears: ordinal 0 retires.
    feed(&mut m, 0, margin as u8 - 1, SYNC_A);
    assert_eq!(
        m.sync.base_ordinal, 1,
        "the deeper margin cleared — ordinal 0 retired"
    );
}

#[test]
fn a_slot_that_joins_mid_stream_anchors_its_join_ordinal_to_where_it_actually_joined() {
    let mut m = authority_maker();
    // The very first sync command this tracker ever sees anchors the
    // frontier at the ring's face value — the promotion-mid-stream case,
    // where the authority has no earlier context to correct against.
    feed_ring(&mut m, 0, 10, SYNC_A, 3000);
    assert_eq!(m.sync.members[&SlotId(0)].since, 10);

    // Slot 0 advances a few more ordinals, moving the frontier forward.
    for ring in 11..14 {
        feed_ring(&mut m, 0, ring, SYNC_A, 3000 + u32::from(ring));
    }
    assert_eq!(m.sync.members[&SlotId(0)].next_expected, 14);

    // Slot 1 joins for the first time now: nibble-corrected placement
    // lands it at the current frontier (14), not retroactively at ordinal
    // 0 or at slot 0's own anchor (10) — it was never present for those.
    feed_ring(&mut m, 1, 14, SYNC_A, 4000);
    assert_eq!(
        m.sync.members[&SlotId(1)].since,
        14,
        "slot 1's join ordinal is where it actually joined",
    );
    assert!(
        m.sync.members[&SlotId(1)].since > 10,
        "not required for ordinals before its true join",
    );
}

/// The belt-and-suspenders path: even if a duplicate somehow reached the
/// tracker itself (the mesh-level dedup in `deliver_turn_to_locals` is
/// what should normally prevent this), a repeated report at the same
/// placed ordinal must not be double-counted.
#[test]
fn a_duplicate_report_at_the_same_ordinal_is_ignored_not_double_counted() {
    let mut m = authority_maker();
    feed_ring(&mut m, 0, 0, SYNC_A, 1000);
    feed_ring(&mut m, 0, 0, SYNC_A, 1000);
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        1,
        "a repeated report at the same ordinal must not advance the count twice",
    );
    assert_eq!(m.sync.pending.get(&0).map(HashMap::len), Some(1));
}

#[test]
fn a_non_authority_relay_does_not_compare() {
    let mut m = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::Peer, HashSet::new());
    assert_eq!(feed(&mut m, 0, 0, SYNC_A), None);
    assert_eq!(feed(&mut m, 1, 0, SYNC_B), None);
    assert_eq!(feed(&mut m, 0, 1, SYNC_A), None);
    assert!(m.sync.members.is_empty(), "a peer records nothing");
}

#[test]
fn promotion_resets_the_comparator_state() {
    let mut m = authority_maker();
    feed(&mut m, 0, 0, SYNC_A);
    feed(&mut m, 1, 0, SYNC_A);
    assert!(
        !m.sync.members.is_empty(),
        "state accumulated while authority"
    );

    // Demote (state kept, comparator inert), then promote — which starts the
    // comparator fresh, no per-ordinal state carried across the handoff.
    let _ = m.set_authority(Authority::Peer, &HashSet::new());
    let _ = m.set_authority(Authority::SelfRelay, &HashSet::new());
    assert!(m.sync.members.is_empty(), "promotion reset the compare set");
    assert_eq!(m.sync.base_ordinal, 0, "and the frontier");
}

#[test]
fn the_in_flight_window_is_bounded_by_eviction() {
    let mut m = authority_maker();
    // Slot 1 reports only ordinal 0, then stalls; slot 0 races far ahead. The
    // ordinals slot 1 never reports can't complete, so the oldest are evicted
    // rather than accumulating without bound.
    feed(&mut m, 1, 0, SYNC_A);
    for ordinal in 0..(SYNC_WINDOW as u8 + 6) {
        feed(&mut m, 0, ordinal, SYNC_A);
    }
    assert!(m.sync.evict_warns > 0, "a stalled slot triggered eviction");
    assert!(
        m.sync.pending.len() <= SYNC_WINDOW,
        "the in-flight window stays bounded ({} pending)",
        m.sync.pending.len(),
    );
}

#[test]
fn a_turn_without_a_sync_command_is_ignored() {
    let mut m = authority_maker();
    // A non-sync command stream (a Vision 0x0D, 3 bytes) records nothing.
    assert_eq!(m.observe_sync(SlotId(0), Some(1), &[0x0D, 0, 0]), None);
    assert!(m.sync.members.is_empty());
    // A truncated/garbage tail after a valid command stops the walk without
    // panicking.
    let mut stream = sync_command(0, expected_kind_for_ordinal(0), SYNC_A);
    stream.push(0xFF); // an opcode the table rejects
    assert_eq!(m.observe_sync(SlotId(0), Some(1), &stream), None);
    assert_eq!(
        m.sync
            .members
            .get(&SlotId(0))
            .map(|member| member.next_expected),
        Some(1),
        "the sync command counted",
    );
}
