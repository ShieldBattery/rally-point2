//! Divergence verdicts from a corroborating majority, plus the notice and its rate limits.

use super::*;

#[test]
fn all_agree_retires_the_ordinal_silently() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_A);
    // Slot 0 alone races ahead; ordinal 0 isn't evaluated until the
    // frontier clears the margin, at which point it retires silently
    // (matching values).
    let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8);
    assert_eq!(divergence, None, "matching values retire silently");
    assert_eq!(m.sync.base_ordinal, 1, "ordinal 0 retired");
    assert!(!m.sync.pending.contains_key(&0));
}

#[test]
fn three_slot_majority_identifies_the_diverged_minority() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_A);
    feed(&mut m, 2, 0, SYNC_B); // slot 2's sim diverged
    // Slot 0 alone races ahead to clear the evaluation margin for ordinal 0.
    let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
        .expect("clearing the margin evaluates ordinal 0");
    assert_eq!(divergence.sync_ordinal, 0);
    assert!(!divergence.no_majority);
    assert_eq!(divergence.diverged, vec![SlotId(2)]);
    assert_eq!(divergence.game_frame, Some(1000), "ordinal 0's frame");
    // The minority is dropped from the compare set.
    assert!(!m.sync.members.contains_key(&SlotId(2)));
    assert!(m.sync.members.contains_key(&SlotId(0)));
    assert!(!m.sync.dormant, "survivors keep being watched");
}

#[test]
fn one_v_one_disagreement_is_no_majority_and_goes_dormant() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_B);
    let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
        .expect("clearing the margin evaluates ordinal 0");
    assert_eq!(divergence.sync_ordinal, 0);
    assert!(divergence.no_majority, "1v1 has no majority");
    assert!(divergence.diverged.is_empty(), "no minority named");
    assert!(
        m.sync.dormant,
        "truth is unrecoverable — dormant for the session"
    );
    assert_eq!(
        feed(&mut m, 1, 1, SYNC_B),
        None,
        "a dormant comparator no-ops"
    );
}

#[test]
fn even_split_is_no_majority() {
    let mut m = authority_maker();
    feed(&mut m, 1, 0, SYNC_A);
    feed(&mut m, 2, 0, SYNC_B);
    feed(&mut m, 3, 0, SYNC_B);
    let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
        .expect("clearing the margin evaluates ordinal 0");
    assert!(divergence.no_majority, "2-2 has no strict majority");
    assert!(divergence.diverged.is_empty());
    assert!(m.sync.dormant);
}

#[test]
fn a_second_divergence_fires_again_at_its_own_ordinal() {
    let mut m = authority_maker();
    // Ordinal 0: slot 3 diverges from the 0/1/2 majority.
    feed(&mut m, 1, 0, SYNC_A);
    feed(&mut m, 2, 0, SYNC_A);
    feed(&mut m, 3, 0, SYNC_B);
    let first = advance(&mut m, 0, SYNC_A, 8).expect("slot 0 clearing the margin fires the first");
    assert_eq!(first.sync_ordinal, 0);
    assert_eq!(first.diverged, vec![SlotId(3)]);

    // Survivors {0,1,2} continue. Ordinal 1: slot 2 now diverges. Slot 0's
    // ordinal-1 report already landed during the `advance` above.
    feed(&mut m, 1, 1, SYNC_A);
    feed(&mut m, 2, 1, SYNC_C);
    let second = feed(&mut m, 0, 8, SYNC_A).expect("a second divergence at ordinal 1");
    assert_eq!(second.sync_ordinal, 1, "a distinct, later ordinal");
    assert!(!second.no_majority);
    assert_eq!(second.diverged, vec![SlotId(2)]);
    assert!(!m.sync.members.contains_key(&SlotId(2)));
}

#[test]
fn an_observer_slot_is_excluded_from_comparison() {
    let mut m = authority_maker();
    m.set_observers(HashSet::from([SlotId(1)]));
    // Slot 1 is an observer with a wildly different checksum; it must never
    // join the compare set, so no divergence ever fires from it.
    feed(&mut m, 0, 0, SYNC_A);
    assert_eq!(feed(&mut m, 1, 0, SYNC_B), None, "observer feed is a no-op");
    assert!(
        !m.sync.members.contains_key(&SlotId(1)),
        "observer never joins"
    );
    assert!(!m.sync.dormant);
}

/// A maker created by a descriptor starts with that descriptor's observer
/// set. This is the single-relay session's whole story: it receives exactly
/// one descriptor push (at session create, before any client dials), so the
/// push finds no maker and inserts one seeded with the descriptor's observer
/// slots -- there is no later re-push to carry the set in after the fact.
/// The observer must therefore be excluded from the desync comparator from
/// that maker's first turn onward.
#[test]
fn a_maker_created_by_a_descriptor_excludes_its_observer_slots() {
    let registry = new_decision_makers();
    // One descriptor push naming slot 2 an observer, with no maker yet.
    let leaves = sync_maker(
        &registry,
        &key(),
        bounds(0, 6),
        Authority::SelfRelay,
        HashSet::from([SlotId(2)]),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(leaves.is_empty(), "creating a maker broadcasts no leaves");

    let mut guard = registry.lock();
    let m = guard.get_mut(&key()).expect("the push created the maker");
    assert!(
        m.observers.contains(&SlotId(2)),
        "the observer set is seeded at creation, not on a later push",
    );

    // Two players agree; the observer reports a different checksum. Racing a
    // compared slot ahead clears the evaluation margin for ordinal 0.
    feed(m, 0, 0, SYNC_A);
    feed(m, 1, 0, SYNC_A);
    assert_eq!(
        feed(m, 2, 0, SYNC_B),
        None,
        "the observer's disagreeing report is a no-op",
    );
    let divergence = advance(m, 0, SYNC_A, authority_margin() as u8);
    assert!(
        divergence.is_none(),
        "the observer is never a required reporter, so no divergence fires",
    );
    assert!(
        !m.sync.members.contains_key(&SlotId(2)),
        "the observer never joins the compare set",
    );
    assert!(!m.sync.dormant, "the compared survivors keep being watched");
}

// -- Relay-driven session start --

/// A session whose negotiated buffer bounds reach the absurd-bounds
/// backstop disables desync detection outright — a defensive ceiling far
/// above any real policy, not a live constraint (depth itself no longer
/// threatens correctness; see the module docs and
/// [`BufferBounds`](rally_point_proto::control::BufferBounds)).
#[test]
fn absurd_buffer_bounds_disable_the_comparator() {
    let mut m = DecisionMaker::new(
        key(),
        bounds(0, SYNC_ABSURD_BUFFER_MAX),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // A first sync command trips the check and disables the comparator —
    // even from two slots that would otherwise plainly disagree.
    assert_eq!(feed(&mut m, 0, 0, SYNC_A), None);
    assert!(m.sync.dormant, "absurd bounds disable detection outright");
    assert_eq!(feed(&mut m, 1, 0, SYNC_B), None, "still a no-op");
}

/// End-to-end through the registry: a divergence fires a `DesyncNotice` on the
/// notice channel, stamped with the session's correlation ids.
#[test]
fn observe_sync_fires_a_desync_notice_with_stamped_refs() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 6),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    registry.set_session_refs(
        &k,
        Some("game-77".to_owned()),
        HashMap::from([(SlotId(2), "sb-user-diverged".to_owned())]),
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);

    // 0,1 agree, 2 diverges, all at ordinal 0.
    observe_sync(
        &registry,
        &k,
        SlotId(0),
        Some(500),
        &sync_command(0, expected_kind_for_ordinal(0), SYNC_A),
    );
    observe_sync(
        &registry,
        &k,
        SlotId(1),
        Some(500),
        &sync_command(0, expected_kind_for_ordinal(0), SYNC_A),
    );
    observe_sync(
        &registry,
        &k,
        SlotId(2),
        Some(500),
        &sync_command(0, expected_kind_for_ordinal(0), SYNC_B),
    );
    assert!(rx.try_recv().is_err(), "held until the margin clears");

    // Slot 0 alone races ahead to clear the margin.
    for ordinal in 1u8..(sync_eval_margin(6) as u8) {
        observe_sync(
            &registry,
            &k,
            SlotId(0),
            Some(500 + u32::from(ordinal)),
            &sync_command(
                ordinal,
                expected_kind_for_ordinal(u64::from(ordinal)),
                SYNC_A,
            ),
        );
    }

    let RelayNotice::Desync(notice) = rx.try_recv().expect("a desync notice fires") else {
        panic!("a desync notice");
    };
    assert_eq!(notice.tenant, k.tenant);
    assert_eq!(notice.session, k.session);
    assert_eq!(notice.sync_ordinal, 0);
    assert_eq!(notice.game_frame, Some(500));
    assert!(!notice.no_majority);
    assert_eq!(notice.external_id, Some("game-77".to_owned()));
    assert_eq!(notice.diverged.len(), 1);
    assert_eq!(notice.diverged[0].slot, SlotId(2));
    assert_eq!(
        notice.diverged[0].external_ref,
        Some("sb-user-diverged".to_owned()),
    );
    assert!(notice.detected_at_ms > 0);
}

/// SC:R's initial latency-depth flush burst emits several `0x37`s all
/// stamped identically (same ring, same content) before the first
/// per-turn record advances the ring — the same-ordinal duplicate-ignore
/// already absorbs this without any special-casing (live-relay
/// confirmed): each repeat lands back at the same placed ordinal via
/// ordinary nibble correction.
#[test]
fn a_startup_burst_of_identical_ring_1_reports_causes_no_false_divergence() {
    let mut m = authority_maker();
    // Slot 0's burst: four identical ring-1 reports (kind 2 — ring 1 is
    // odd), exactly the shape the enable path + flush burst produces.
    for _ in 0..4 {
        feed_ring(&mut m, 0, 1, SYNC_A, 1000);
    }
    // Slot 1's own burst, three copies.
    for _ in 0..3 {
        feed_ring(&mut m, 1, 1, SYNC_A, 1000);
    }
    assert_eq!(
        m.sync.members[&SlotId(0)].next_expected,
        2,
        "the repeated burst never advanced past its true ordinal",
    );
    assert_eq!(m.sync.members[&SlotId(1)].next_expected, 2);

    // Both slots continue normally in lockstep agreement, racing the
    // margin far enough to retire the burst's ordinal.
    let margin = authority_margin() as u8;
    let mut divergence = None;
    for ring in 2..(margin + 2) {
        if let Some(d) = feed_ring(&mut m, 0, ring, SYNC_A, 1000 + u32::from(ring)) {
            divergence = Some(d);
        }
        if let Some(d) = feed_ring(&mut m, 1, ring, SYNC_A, 1000 + u32::from(ring)) {
            divergence = Some(d);
        }
    }
    assert_eq!(
        divergence, None,
        "the burst absorbed cleanly — no false divergence",
    );
}

/// The exact live false positive this fix repairs: SC:R's fog/vision
/// bytes (`[4..7]`) are per-sender, vision-masked values the native check
/// only ever compares pairwise against the receiver's own local fog
/// buffer — they legitimately differ between honest players in the same
/// game. The relay must never treat that difference as a desync: only
/// `hash16` (`[2:3]`) feeds the comparison.
#[test]
fn fog_byte_divergence_with_matching_hash16_is_not_a_divergence() {
    let mut m = authority_maker();
    // Two slots whose hash16 always agrees, but whose fog/vision filler
    // bytes never do — exactly the shape a healthy game produces.
    for ordinal in 0u8..(authority_margin() as u8) {
        let ring = ordinal % 16;
        let kind = expected_kind_for_ordinal(u64::from(ordinal));
        let frame = 1000 + u32::from(ordinal);
        let a = sync_command_with_fog(ring, kind, SYNC_A, [1, 2, 3]);
        let b = sync_command_with_fog(ring, kind, SYNC_A, [9, 8, 7]);
        assert_eq!(m.observe_sync(SlotId(0), Some(frame), &a), None);
        assert_eq!(m.observe_sync(SlotId(1), Some(frame), &b), None);
    }
    assert_eq!(
        m.sync.base_ordinal, 1,
        "ordinal 0 retired — the differing fog bytes never entered the comparison",
    );
}

/// A report whose kind disagrees with its placed ordinal's expected
/// parity is an alignment-drift anomaly, not a desync: it's excluded from
/// the `hash16` comparison entirely and just warned about.
#[test]
fn a_kind_parity_mismatch_is_an_anomaly_not_a_divergence() {
    let mut m = authority_maker();
    // Slot 1 agrees with slot 0's hash16 at ordinal 0, but reports kind 2
    // for an even ordinal (should be 1) — excluded from the comparison
    // rather than treated as a mismatch (there is no majority/minority
    // split here; a real one is covered by the malformed-kind and
    // ordinary-divergence tests).
    feed_ring_kind(&mut m, 1, 0, SYNC_KIND_HEADER, SYNC_A, 1000);
    let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8);
    assert_eq!(
        divergence, None,
        "the kind-mismatched report is excluded, not compared",
    );
    assert!(
        m.sync.kind_parity_warns >= 1,
        "the parity mismatch was flagged",
    );
}

/// A `0x37` whose low nibble is neither 1 nor 2 is a malformed sync
/// command — defensive rejection, since validated bytes shouldn't produce
/// this. The report is skipped entirely: no member bookkeeping, no
/// calibration, nothing.
#[test]
fn a_malformed_kind_is_skipped_not_recorded() {
    let mut m = authority_maker();
    for bad_kind in [0u8, 3, 7, 15] {
        let divergence = feed_ring_kind(&mut m, 0, 0, bad_kind, SYNC_A, 1000);
        assert_eq!(divergence, None);
    }
    assert!(
        m.sync.members.is_empty(),
        "a malformed kind never creates a member",
    );
    assert!(
        m.sync.malformed_kind_warns >= 1,
        "the malformed kind was flagged",
    );
}

#[test]
fn token_bucket_admits_a_full_burst_then_recovers_after_refill() {
    let burst = 4;
    let interval = std::time::Duration::from_millis(200);
    let mut bucket = TokenBucket::new(burst, interval);

    for _ in 0..burst {
        assert!(bucket.try_take());
    }
    assert!(
        !bucket.try_take(),
        "the burst is exhausted; the next admission is rejected",
    );

    std::thread::sleep(interval + std::time::Duration::from_millis(50));
    assert!(
        bucket.try_take(),
        "one interval refilled at least one token"
    );
}

#[test]
fn token_bucket_never_refills_past_its_burst_cap() {
    let burst = 2;
    let interval = std::time::Duration::from_millis(10);
    let mut bucket = TokenBucket::new(burst, interval);

    // Idle far longer than many refill intervals: the bucket must still
    // cap at `burst`, not accumulate an unbounded backlog of tokens.
    std::thread::sleep(interval * 50);
    let mut admitted = 0;
    while bucket.try_take() {
        admitted += 1;
    }
    assert_eq!(admitted, burst as usize);
}

// -- Silent-slot eviction: a client whose simulation stopped stepping holds
//    every other player still behind a link that keeps answering, so the
//    relay closes it and lets the ordinary drop path finish the job. The
//    verdict rests on complete knowledge of the session: every participant
//    lockstep still requires must resolve to a relay-observed stop time, and
//    anything the relay cannot vouch for blocks rather than counting for
//    nothing. --
