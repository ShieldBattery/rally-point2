//! The session-level forward-once gate: new-versus-duplicate verdicts, the
//! contiguous prefix and its progress reporting, the sparse-set cap and the
//! collapse it forces, and the cursors read back out of it.

use super::*;

#[test]
fn marks_first_delivery_new_and_redelivery_duplicate() {
    let mut seen = MeshSeen::new();
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::Duplicate);
    assert_eq!(seen.mark_forwarded(SlotId(0), 1).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 1).seen, Seen::Duplicate);
}

#[test]
fn contiguous_prefix_stops_cleanly_at_the_sequence_ceiling() {
    let mut seen = MeshSeen::new();
    seen.slots.insert(
        SlotId(0),
        SlotSeen {
            forwarded_through: Some(u64::MAX - 2),
            ahead: BTreeSet::from([u64::MAX]),
            prefix_collapsed: false,
        },
    );

    // Filling the last gap absorbs the waiting ceiling value without
    // attempting to derive an unrepresentable successor.
    assert_eq!(seen.mark_forwarded(SlotId(0), u64::MAX - 1).seen, Seen::New);
    let state = &seen.slots[&SlotId(0)];
    assert_eq!(state.forwarded_through, Some(u64::MAX));
    assert!(state.ahead.is_empty());
    assert_eq!(
        seen.mark_forwarded(SlotId(0), u64::MAX).seen,
        Seen::Duplicate
    );
}

#[test]
fn keeps_slots_independent() {
    let mut seen = MeshSeen::new();
    // Two slots both have seq 0; both are new — identity is (slot, seq).
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(1), 0).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::Duplicate);
    assert_eq!(seen.mark_forwarded(SlotId(1), 0).seen, Seen::Duplicate);
}

#[test]
fn collapses_out_of_order_arrival() {
    // A turn arrives via path A at seq 3 (gap at 1, 2), then via path B at
    // seq 0. Seq 3 is new; seq 0 is new (it fills the gap). A second copy of
    // seq 3 via path B is a duplicate.
    let mut seen = MeshSeen::new();
    assert_eq!(seen.mark_forwarded(SlotId(0), 3).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 1).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 2).seen, Seen::New);
    assert_eq!(seen.mark_forwarded(SlotId(0), 3).seen, Seen::Duplicate);
}

#[test]
fn drops_late_redundant_copy_below_prefix() {
    // After forwarding 0..3, a late redundant copy of seq 0 arriving via a
    // second path is dropped as below the prefix.
    let mut seen = MeshSeen::new();
    for seq in 0..4 {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
    }
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::Duplicate);
}

/// Reaches into one slot's private forward-gate state so the sparse-set tests
/// can assert on the exact bound; the `mark_forwarded` API deliberately
/// exposes only its verdict, not the representation behind it.
fn slot_ahead_len(seen: &MeshSeen, slot: SlotId) -> usize {
    seen.slots.get(&slot).map_or(0, |s| s.ahead.len())
}

#[test]
fn ordinary_in_order_and_small_reorder_traffic_never_grows_the_sparse_set() {
    // The common case must be untouched by the cap: an in-order stream keeps
    // an empty sparse set (each seq folds straight into the prefix), and a
    // small reorder window holds only the handful of seqs still ahead of the
    // gap, collapsing to empty the moment the gap fills.
    let mut seen = MeshSeen::new();
    for seq in 0..1000 {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
        assert_eq!(
            slot_ahead_len(&seen, SlotId(0)),
            0,
            "in-order holds nothing"
        );
    }

    // Deliver a small window out of order: 1005..1010 arrive before 1000..1005.
    for seq in 1005..1010 {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
    }
    assert!(
        slot_ahead_len(&seen, SlotId(0)) <= SPARSE_SEEN_CAP,
        "a small reorder window stays far under the cap",
    );
    for seq in 1000..1005 {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
    }
    assert_eq!(
        slot_ahead_len(&seen, SlotId(0)),
        0,
        "the filled gap collapses the sparse set back to empty",
    );
}

#[test]
fn gap_heavy_traffic_never_exceeds_the_sparse_cap() {
    // Every other seq is dropped, so the gap below the high-water mark never
    // fills and each arrival lands in the sparse set. Left unbounded the set
    // would grow one entry per arrival for the life of the session; the cap
    // holds it flat.
    let mut seen = MeshSeen::new();
    // seq 0 forms the prefix; from there only even seqs arrive, leaving every
    // odd seq a permanent gap.
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    for seq in (2..20_000).step_by(2) {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
        assert!(
            slot_ahead_len(&seen, SlotId(0)) <= SPARSE_SEEN_CAP,
            "sparse set stayed within the cap after seq {seq}",
        );
    }
    // Well past the cap's worth of arrivals, it is pinned at the bound, not
    // growing with the seq stream.
    assert_eq!(slot_ahead_len(&seen, SlotId(0)), SPARSE_SEEN_CAP);
}

#[test]
fn collapsing_preserves_duplicate_verdicts_for_already_seen_seqs() {
    // The seqs the collapse swallows into the prefix must still read as
    // duplicates: a re-forward of one of them arriving after the collapse is
    // dropped, exactly as it would have been before the prefix moved.
    let mut seen = MeshSeen::new();
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    // Push enough even seqs to force at least one collapse.
    let last = 2 * (SPARSE_SEEN_CAP as u64 + 10);
    for seq in (2..=last).step_by(2) {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
    }
    // Every even seq that has ever been forwarded is still a duplicate,
    // whether the collapse swept it into the prefix or it remains in the
    // sparse set.
    for seq in (0..=last).step_by(2) {
        assert_eq!(
            seen.mark_forwarded(SlotId(0), seq).seen,
            Seen::Duplicate,
            "an already-seen seq {seq} must not be delivered again",
        );
    }
}

#[test]
fn a_withheld_turn_stops_the_slots_reported_progress_at_the_gap() {
    // A client that withholds one turn and keeps streaming higher seqs is
    // the case the reported advance exists to catch: everything it sends
    // after the gap forwards fine, and none of it moves the gap-free prefix
    // its peers are actually stalled on.
    let mut seen = MeshSeen::new();
    for seq in 0..=5 {
        assert!(
            seen.mark_forwarded(SlotId(0), seq).prefix_advanced,
            "an in-order turn extends the prefix",
        );
    }
    for seq in 7..=9 {
        let forwarded = seen.mark_forwarded(SlotId(0), seq);
        assert_eq!(forwarded.seen, Seen::New);
        assert!(
            !forwarded.prefix_advanced,
            "seq {seq} forwards, but the prefix is still stalled at the withheld 6",
        );
    }
    assert_eq!(slot_forwarded_through(&seen, SlotId(0)), Some(5));

    // Flooding far enough ahead makes the sparse-set cap collapse the prefix
    // over the withheld turn. A prefix that jumped a gap is not evidence of
    // forwarding, so neither that arrival nor any after it reports progress.
    for seq in 10..=(SPARSE_SEEN_CAP as u64 + 12) {
        assert!(!seen.mark_forwarded(SlotId(0), seq).prefix_advanced);
    }
    let state = seen.slots.get(&SlotId(0)).expect("slot 0 has gate state");
    assert!(
        state.prefix_collapsed,
        "the flood pushed the sparse set past the cap",
    );
    let collapsed_through = state.forwarded_through;
    assert!(collapsed_through > Some(5), "the collapse jumped the gap");

    // In-order arrivals resume, and the slot's clock stays frozen: past a
    // collapse the prefix no longer counts only turns that really arrived.
    for seq in (SPARSE_SEEN_CAP as u64 + 13)..=(SPARSE_SEEN_CAP as u64 + 20) {
        let forwarded = seen.mark_forwarded(SlotId(0), seq);
        assert_eq!(forwarded.seen, Seen::New);
        assert!(
            !forwarded.prefix_advanced,
            "a collapsed slot's prefix never reports progress again",
        );
    }
}

#[test]
fn a_turn_that_closes_a_gap_reports_the_progress_the_whole_run_makes() {
    // The honest reordering case: the missing turn arrives and the run above
    // it becomes contiguous, which is genuine progress for all of it.
    let mut seen = MeshSeen::new();
    assert!(seen.mark_forwarded(SlotId(0), 0).prefix_advanced);
    for seq in 2..=4 {
        assert!(!seen.mark_forwarded(SlotId(0), seq).prefix_advanced);
    }
    assert!(
        seen.mark_forwarded(SlotId(0), 1).prefix_advanced,
        "closing the gap absorbs the run above it",
    );
    assert_eq!(slot_forwarded_through(&seen, SlotId(0)), Some(4));
    assert!(
        !seen.mark_forwarded(SlotId(0), 1).prefix_advanced,
        "a duplicate moves nothing",
    );
}

/// The top of one slot's contiguous forwarded prefix, for the tests that
/// assert where a withheld turn left it.
fn slot_forwarded_through(seen: &MeshSeen, slot: SlotId) -> Option<u64> {
    seen.slots
        .get(&slot)
        .and_then(|state| state.forwarded_through)
}

#[test]
fn a_gap_seq_arriving_after_the_collapse_is_treated_as_a_duplicate() {
    // A seq in a gap the collapse has already swallowed reads as a duplicate
    // even though it was never actually forwarded — the safe direction: the
    // forward gate would rather drop a lost/replayed gap turn than deliver
    // what it can no longer prove is new.
    let mut seen = MeshSeen::new();
    assert_eq!(seen.mark_forwarded(SlotId(0), 0).seen, Seen::New);
    let last = 2 * (SPARSE_SEEN_CAP as u64 + 10);
    for seq in (2..=last).step_by(2) {
        assert_eq!(seen.mark_forwarded(SlotId(0), seq).seen, Seen::New);
    }
    // The prefix has collapsed forward over the low odd gaps. A low odd seq —
    // one that was skipped and never forwarded — now arrives late and is
    // rejected as below the collapsed prefix.
    assert_eq!(
        seen.mark_forwarded(SlotId(0), 1).seen,
        Seen::Duplicate,
        "a swallowed gap seq is seen, not fresh",
    );
}

/// `forwarded_count` is the home relay's source for a departing slot's final
/// turn count: the gap-free forwarded prefix as a count, `None` whenever the
/// registry has no truthful prefix to answer from — including a prefix the
/// sparse-set cap collapsed over a gap, which is correct for the
/// forward-once gate but would inflate a count with turns that never
/// existed (survivors scheduled on it would wait forever).
#[test]
fn forwarded_count_reports_the_gap_free_prefix_and_refuses_a_collapsed_one() {
    let registries = new_seen_registries();
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId("t".to_owned()),
        session: rally_point_proto::ids::SessionId(1),
    };

    // No session, no slot: no knowledge.
    assert_eq!(forwarded_count(&registries, &key, SlotId(0)), None);

    // A contiguous prefix counts exactly, per slot, unaffected by another
    // slot's traffic.
    for seq in 0..5 {
        mark_seen(&registries, &key, SlotId(0), seq);
    }
    mark_seen(&registries, &key, SlotId(1), 0);
    assert_eq!(forwarded_count(&registries, &key, SlotId(0)), Some(5));
    assert_eq!(forwarded_count(&registries, &key, SlotId(1)), Some(1));

    // Sparse seqs ahead of the prefix never advance the count — only the
    // gap-free prefix answers.
    mark_seen(&registries, &key, SlotId(0), 100);
    assert_eq!(forwarded_count(&registries, &key, SlotId(0)), Some(5));

    // A slot whose first seqs are all ahead of 0 (a re-homed slot whose
    // pre-rehome turns this relay never carried) has no prefix at all.
    mark_seen(&registries, &key, SlotId(2), 500);
    assert_eq!(forwarded_count(&registries, &key, SlotId(2)), None);

    // Once the sparse cap collapses the prefix over a gap, the count is
    // permanently refused: the prefix no longer counts only real turns.
    for seq in (2..).step_by(2).take(SPARSE_SEEN_CAP + 10) {
        mark_seen(&registries, &key, SlotId(1), seq);
    }
    assert_eq!(forwarded_count(&registries, &key, SlotId(1)), None);
}

/// `slot_receipts` reports the forward gate's full receipt record —
/// prefix plus sparse ahead seqs — for resume-window seeding, and keeps
/// answering from a collapsed prefix: the gate already drops arrivals in
/// the swallowed gaps as duplicates, so a window seeded to match mirrors
/// that verdict rather than adding a new failure mode (contrast
/// `forwarded_count`, whose leave-count consumer must refuse a collapsed
/// prefix because an inflated count strands survivors).
#[test]
fn slot_receipts_report_the_prefix_and_the_sparse_ahead_even_collapsed() {
    let registries = new_seen_registries();
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId("t".to_owned()),
        session: rally_point_proto::ids::SessionId(2),
    };

    // No session, no slot: an empty record, not a panic.
    let empty = slot_receipts(&registries, &key, SlotId(0));
    assert_eq!(empty.forwarded_through, None);
    assert!(empty.ahead.is_empty());

    // Prefix 0..=2 with sparse receipts above it.
    for seq in 0..3 {
        mark_seen(&registries, &key, SlotId(0), seq);
    }
    mark_seen(&registries, &key, SlotId(0), 5);
    mark_seen(&registries, &key, SlotId(0), 9);
    let receipts = slot_receipts(&registries, &key, SlotId(0));
    assert_eq!(receipts.forwarded_through, Some(2));
    assert_eq!(receipts.ahead, vec![5, 9]);

    // A collapsed prefix still answers — seeding from it mirrors the
    // gate's own duplicate verdict for the swallowed gaps.
    for seq in (0..).step_by(2).take(SPARSE_SEEN_CAP + 10) {
        mark_seen(&registries, &key, SlotId(1), seq);
    }
    assert_eq!(forwarded_count(&registries, &key, SlotId(1)), None);
    let collapsed = slot_receipts(&registries, &key, SlotId(1));
    assert!(
        collapsed.forwarded_through.is_some(),
        "the collapsed prefix still seeds",
    );
    assert!(
        collapsed.ahead.len() <= SPARSE_SEEN_CAP,
        "the sparse remainder stays bounded",
    );
}
