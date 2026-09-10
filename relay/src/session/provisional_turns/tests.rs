//! Tests for the provisional-ingress journal: drain ordering, the one-shot
//! Gathering -> Draining -> Resolved lifecycle, departure supersession, slot
//! sealing, and the per-session cap / aggregate byte budget overflow paths.

use super::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId("sb-test".to_owned()),
        session: SessionId(7),
    }
}

fn turn(slot: u8, seq: u64) -> PennedIngress {
    PennedIngress::Turn(
        SlotId(slot),
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![0x05].into(),
            ..Default::default()
        },
    )
}

fn departure(slot: u8, reason: u32) -> PennedIngress {
    PennedIngress::Departure {
        slot: SlotId(slot),
        reason,
        connection_epoch: Some(9),
        revision: 0,
    }
}

#[test]
fn entries_drain_in_arrival_order_and_only_once() {
    let pen = ProvisionalTurnPen::default();
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
    assert_eq!(pen.hold(&key(), turn(2, 0)), HoldOutcome::Held);

    let drained = pen.begin_drain(&key()).expect("the first drain claims");
    assert_eq!(drained.len(), 3);
    assert!(matches!(drained[0], PennedIngress::Turn(SlotId(1), _)));
    assert!(matches!(
        drained[1],
        PennedIngress::Departure {
            slot: SlotId(1),
            reason: 3,
            connection_epoch: Some(9),
            ..
        }
    ));
    assert!(matches!(drained[2], PennedIngress::Turn(SlotId(2), _)));
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(
        pen.begin_drain(&key()).is_none(),
        "a resolved session refuses a second drain",
    );
}

/// The receipt query reports every journaled turn for the slot — and
/// keeps reporting a batch a drain holds privately in flight, because
/// those turns have left the queue but not yet passed the forward gate:
/// a resume-seeding read during the replay window must still see them.
#[test]
fn held_turn_seqs_cover_the_queue_and_a_drains_in_flight_batch() {
    let pen = ProvisionalTurnPen::default();
    assert_eq!(pen.hold(&key(), turn(1, 4)), HoldOutcome::Held);
    assert_eq!(pen.hold(&key(), turn(2, 9)), HoldOutcome::Held);
    assert_eq!(pen.hold(&key(), turn(1, 5)), HoldOutcome::Held);
    assert_eq!(
        pen.held_turn_seqs(&key(), SlotId(1)),
        vec![4, 5],
        "queued deposits report per slot",
    );

    let batch = pen.begin_drain(&key()).expect("the drain claims");
    assert_eq!(batch.len(), 3);
    assert_eq!(
        pen.held_turn_seqs(&key(), SlotId(1)),
        vec![4, 5],
        "the in-flight batch still reports while the drainer replays it",
    );
    assert_eq!(pen.held_turn_seqs(&key(), SlotId(2)), vec![9]);

    // A deposit landing mid-drain queues and reports alongside the
    // in-flight batch.
    assert_eq!(pen.hold(&key(), turn(1, 6)), HoldOutcome::Held);
    assert_eq!(pen.held_turn_seqs(&key(), SlotId(1)), vec![6, 4, 5]);

    // The next drain step retires the replayed batch's shadow and takes
    // over the mid-drain deposit.
    let DrainStep::More(next) = pen.continue_drain(&key()) else {
        panic!("the mid-drain deposit forces another pass");
    };
    assert_eq!(next.len(), 1);
    assert_eq!(
        pen.held_turn_seqs(&key(), SlotId(1)),
        vec![6],
        "only the new in-flight batch remains visible",
    );

    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(
        pen.held_turn_seqs(&key(), SlotId(1)).is_empty(),
        "a resolved journal retains no receipts — they all passed the gate",
    );
}

/// The one-shot transition: a deposit that lost the race against the
/// drain is refused, so its caller re-runs against the maker the drain
/// proves exists — never inserting past the completed drain.
#[test]
fn a_deposit_after_the_drain_is_refused_as_resolved() {
    let pen = ProvisionalTurnPen::default();
    let batch = pen
        .begin_drain(&key())
        .expect("the drain claims even a never-deposited session");
    assert!(batch.is_empty());
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(matches!(
        pen.hold(&key(), turn(1, 0)),
        HoldOutcome::Resolved(PennedIngress::Turn(SlotId(1), _)),
    ));
    assert_eq!(pen.held(&key()), 0, "a refused deposit journals nothing");
}

/// A deposit landing mid-drain is journaled and handed to the drain's
/// own next pass, ordered after everything already replayed — never
/// announced ahead of the in-flight batch, never stranded after it.
#[test]
fn a_mid_drain_deposit_is_replayed_by_the_drain_loop() {
    let pen = ProvisionalTurnPen::default();
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    let first = pen.begin_drain(&key()).expect("claims");
    assert_eq!(first.len(), 1);

    // The clean-leave intent lands while the drainer replays.
    assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
    match pen.continue_drain(&key()) {
        DrainStep::More(batch) => {
            assert_eq!(batch.len(), 1);
            assert!(matches!(batch[0], PennedIngress::Departure { .. }));
        }
        DrainStep::Done => panic!("the mid-drain deposit must be replayed"),
    }
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
}

/// A journaled clean leave seals its slot against readmission, and the
/// seal survives the whole drain.
#[test]
fn a_clean_leave_seals_its_slot_across_the_drain() {
    let pen = ProvisionalTurnPen::default();
    assert!(!pen.slot_sealed(&key(), SlotId(1)));
    assert_eq!(
        pen.hold(&key(), departure(1, crate::consensus::LEAVE_REASON_LEFT)),
        HoldOutcome::Held,
    );
    assert!(pen.slot_sealed(&key(), SlotId(1)));

    let _ = pen.begin_drain(&key()).expect("claims");
    assert!(pen.slot_sealed(&key(), SlotId(1)), "sealed while draining");
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(pen.slot_sealed(&key(), SlotId(1)), "sealed once resolved");

    pen.discard(&key());
    assert!(!pen.slot_sealed(&key(), SlotId(1)));
}

/// At most one journaled departure per slot, as an enforced invariant: a
/// maker-less slot connect-and-dropping in a loop must not grow the
/// cap-exempt departure population without bound — the newest
/// observation supersedes the older one, in the newer position, and the
/// older one's revision goes stale.
#[test]
fn repeated_departures_for_one_slot_compact_to_the_newest() {
    let pen = ProvisionalTurnPen::default();
    assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
    assert_eq!(pen.hold(&key(), turn(2, 0)), HoldOutcome::Held);
    assert_eq!(
        pen.hold(
            &key(),
            PennedIngress::Departure {
                slot: SlotId(1),
                reason: 3,
                connection_epoch: Some(11),
                revision: 0,
            },
        ),
        HoldOutcome::Held,
    );
    let drained = pen.begin_drain(&key()).expect("claims");
    assert_eq!(drained.len(), 2, "the older departure was superseded");
    assert!(matches!(drained[0], PennedIngress::Turn(SlotId(2), _)));
    assert!(matches!(
        drained[1],
        PennedIngress::Departure {
            slot: SlotId(1),
            connection_epoch: Some(11),
            revision: 2,
            ..
        }
    ));
}

/// A departure superseded while it sat in a drain's private in-flight
/// batch — beyond the queue compaction's reach — fails the revision
/// validation the drain runs before replaying it, while the superseding
/// entry passes.
#[test]
fn a_superseded_departure_in_an_active_batch_fails_revision_validation() {
    let pen = ProvisionalTurnPen::default();
    assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
    let batch = pen.begin_drain(&key()).expect("claims");
    let PennedIngress::Departure { revision: old, .. } = batch[0] else {
        panic!("the batch holds the journaled departure");
    };
    assert!(pen.departure_is_current(&key(), SlotId(1), old));

    // A newer generation's departure lands mid-drain.
    assert_eq!(
        pen.hold(&key(), departure(1, crate::consensus::LEAVE_REASON_LEFT)),
        HoldOutcome::Held,
    );
    assert!(
        !pen.departure_is_current(&key(), SlotId(1), old),
        "the batched departure is superseded and must not replay",
    );
    match pen.continue_drain(&key()) {
        DrainStep::More(next) => {
            let PennedIngress::Departure { revision, .. } = next[0] else {
                panic!("the superseding departure drains next");
            };
            assert!(pen.departure_is_current(&key(), SlotId(1), revision));
        }
        DrainStep::Done => panic!("the superseding departure must drain"),
    }
}

/// Overflow seals the offending slot atomically with the verdict —
/// installed by `hold` itself, under the caller's ingress gate, never as
/// a separate post-gate step a retirement could interleave with.
#[test]
fn overflow_seals_the_slot_atomically_with_the_verdict() {
    let pen = ProvisionalTurnPen::default();
    for seq in 0..PER_SESSION_CAP as u64 {
        assert_eq!(pen.hold(&key(), turn(1, seq)), HoldOutcome::Held);
    }
    assert!(!pen.slot_sealed(&key(), SlotId(1)));
    assert!(matches!(
        pen.hold(&key(), turn(1, PER_SESSION_CAP as u64)),
        HoldOutcome::Overflow(_),
    ));
    assert!(pen.slot_sealed(&key(), SlotId(1)));
    assert!(
        !pen.slot_sealed(&key(), SlotId(2)),
        "only the overflowing slot is sealed",
    );
}

#[test]
fn overflow_refuses_turns_but_never_departures() {
    let pen = ProvisionalTurnPen::default();
    for seq in 0..PER_SESSION_CAP as u64 {
        assert_eq!(pen.hold(&key(), turn(1, seq)), HoldOutcome::Held);
    }
    assert!(matches!(
        pen.hold(&key(), turn(1, PER_SESSION_CAP as u64)),
        HoldOutcome::Overflow(_),
    ));
    assert_eq!(
        pen.hold(&key(), departure(1, 3)),
        HoldOutcome::Held,
        "a departure is never lost to the cap",
    );
    assert_eq!(pen.held(&key()), PER_SESSION_CAP + 1);
}

#[test]
fn discard_forgets_entries_and_the_resolved_mark() {
    let pen = ProvisionalTurnPen::default();
    let _ = pen.begin_drain(&key()).expect("claims");
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    pen.discard(&key());
    assert_eq!(
        pen.hold(&key(), turn(1, 0)),
        HoldOutcome::Held,
        "a discarded session's later dial starts a fresh journal",
    );
}

/// `discard_if_empty` is the emptied close's atomic check-and-remove: it
/// removes only a provably empty Gathering journal, refuses one holding
/// entries, and refuses a Draining journal outright — an active drain
/// owns the pen, and removing it would reset the revisions a drainer's
/// private batch is validated against.
#[test]
fn discard_if_empty_removes_only_an_empty_gathering_journal() {
    let pen = ProvisionalTurnPen::default();
    assert!(pen.discard_if_empty(&key()), "an absent journal is empty");

    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    assert!(!pen.discard_if_empty(&key()), "entries refuse the discard");

    let batch = pen.begin_drain(&key()).expect("claims");
    assert_eq!(batch.len(), 1);
    assert!(
        !pen.discard_if_empty(&key()),
        "a draining journal refuses even with an empty queue — the drain owns it",
    );
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(
        !pen.discard_if_empty(&key()),
        "a resolved journal belongs to the session lifecycle, not the close",
    );
}

/// The relay-wide budget fails NEW turn deposits closed across sessions
/// — seals the depositor like a per-session overflow — while departures
/// stay exempt and nothing already journaled is deleted.
#[test]
fn the_aggregate_budget_fails_new_turns_closed_across_sessions() {
    // Each turn accounts 1 command byte + 64 overhead = 65; budget fits
    // exactly two turns.
    let pen = ProvisionalTurnPen::with_turn_byte_budget(130);
    let other = SessionKey {
        tenant: rally_point_proto::control::TenantId("sb-test".to_owned()),
        session: SessionId(8),
    };
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    assert_eq!(pen.hold(&other, turn(2, 0)), HoldOutcome::Held);
    assert!(matches!(
        pen.hold(&other, turn(2, 1)),
        HoldOutcome::Overflow(_),
    ));
    assert!(
        pen.slot_sealed(&other, SlotId(2)),
        "the budget-refused depositor is sealed like any overflow",
    );
    assert_eq!(pen.held(&key()), 1, "retained data survives the budget");
    assert_eq!(pen.held(&other), 1);
    assert_eq!(
        pen.hold(&other, departure(3, 3)),
        HoldOutcome::Held,
        "departures stay exempt at the budget",
    );

    // Taking a batch does NOT release its charge — the budget tracks
    // resident memory, and the batch's allocations live until the
    // drainer replays and releases them.
    let batch = pen.begin_drain(&key()).expect("claims");
    assert_eq!(batch.len(), 1);
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(matches!(
        pen.hold(&other, turn(4, 0)),
        HoldOutcome::Overflow(_),
    ));
    let batch_bytes: usize = batch.iter().map(ProvisionalTurnPen::entry_bytes).sum();
    drop(batch);
    pen.release_drained(batch_bytes);
    assert_eq!(
        pen.hold(&other, turn(4, 1)),
        HoldOutcome::Held,
        "released bytes admit new turns again",
    );
}

/// A journaled turn's command bytes are detached from their transport
/// backing at deposit, so retaining a tiny turn cannot pin a whole
/// datagram allocation the accounting never charged for.
#[test]
fn a_journaled_turn_detaches_its_command_bytes() {
    let pen = ProvisionalTurnPen::default();
    // A one-byte command slice viewing a kilobyte shared buffer, the way
    // a decoded datagram's `Bytes` fields alias its allocation.
    let datagram = Payload {
        commands: vec![0xAA; 1024].into(),
        ..Default::default()
    };
    let backing = Payload {
        seq: 0,
        slot: 1,
        commands: datagram.commands.slice(0..1),
        ..Default::default()
    };
    let original_ptr = backing.commands.as_ptr();
    assert_eq!(
        pen.hold(&key(), PennedIngress::Turn(SlotId(1), backing)),
        HoldOutcome::Held,
    );
    let batch = pen.begin_drain(&key()).expect("claims");
    let PennedIngress::Turn(_, journaled) = &batch[0] else {
        panic!("the journaled turn drains back");
    };
    assert_ne!(
        journaled.commands.as_ptr(),
        original_ptr,
        "the journaled copy must own its bytes, not alias the datagram",
    );
    assert_eq!(&journaled.commands[..], &[0xAA]);
}

/// The session ceiling refuses admission reservations and deposits that
/// would CREATE a tracking entry, while already-tracked sessions keep
/// depositing and a descriptor's drain still tracks its session past
/// the ceiling.
#[test]
fn the_session_ceiling_refuses_only_new_tracking_entries() {
    let pen = ProvisionalTurnPen::with_session_ceiling(1);
    assert!(pen.reserve(&key()), "admission reserves below the ceiling");
    assert!(
        pen.reserve(&key()),
        "a tracked session's reservation is a no-op",
    );
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    let other = SessionKey {
        tenant: rally_point_proto::control::TenantId("sb-test".to_owned()),
        session: SessionId(8),
    };
    assert!(
        !pen.reserve(&other),
        "admission for an untracked session is refused at the ceiling",
    );
    assert!(matches!(
        pen.hold(&other, turn(1, 0)),
        HoldOutcome::Overflow(_),
    ));
    assert!(matches!(
        pen.hold(&other, departure(1, 3)),
        HoldOutcome::Overflow(_),
    ));
    assert_eq!(pen.held(&other), 0, "nothing was inserted at the ceiling");
    assert!(
        !pen.slot_sealed(&other, SlotId(1)),
        "no seal either — a seal would itself be the map growth",
    );
    assert_eq!(
        pen.hold(&key(), turn(1, 1)),
        HoldOutcome::Held,
        "tracked sessions keep depositing at the ceiling",
    );
    assert!(
        pen.begin_drain(&other).is_some(),
        "a descriptor's drain tracks its session past the ceiling",
    );
}

/// Discarding a session releases its journaled bytes back to the budget.
#[test]
fn discard_releases_turn_bytes_to_the_budget() {
    let pen = ProvisionalTurnPen::with_turn_byte_budget(65);
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    let other = SessionKey {
        tenant: rally_point_proto::control::TenantId("sb-test".to_owned()),
        session: SessionId(8),
    };
    assert!(matches!(
        pen.hold(&other, turn(2, 0)),
        HoldOutcome::Overflow(_),
    ));
    pen.discard(&key());
    assert_eq!(
        pen.hold(&other, turn(2, 1)),
        HoldOutcome::Held,
        "the discarded session's bytes are back in the budget",
    );
}

/// An empty-but-sealed journal refuses the empty discard: a
/// budget-overflow seal is installed without any deposit, and dropping
/// it in the deregister-to-teardown-deposit window would let the sealed
/// slot readmit past its permanent hole.
#[test]
fn an_empty_but_sealed_journal_refuses_the_empty_discard() {
    let pen = ProvisionalTurnPen::with_turn_byte_budget(0);
    assert!(matches!(
        pen.hold(&key(), turn(1, 0)),
        HoldOutcome::Overflow(_),
    ));
    assert!(pen.slot_sealed(&key(), SlotId(1)));
    assert_eq!(pen.held(&key()), 0, "the refused turn was never journaled");
    assert!(
        !pen.discard_if_empty(&key()),
        "the seal keeps the journal state alive",
    );
}

#[test]
fn has_undrained_tracks_pending_entries() {
    let pen = ProvisionalTurnPen::default();
    assert!(!pen.has_undrained(&key()));
    assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
    assert!(pen.has_undrained(&key()));
    let _ = pen.begin_drain(&key()).expect("claims");
    assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    assert!(!pen.has_undrained(&key()));
}

#[test]
fn arming_is_relay_wide_across_clones() {
    let pen = ProvisionalTurnPen::default();
    let clone = pen.clone();
    assert!(!clone.armed());
    pen.arm();
    assert!(clone.armed(), "the armed flag is shared, not per-clone");
}
