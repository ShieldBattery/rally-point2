//! Tests for everything that folds deliveries into a receive window from
//! outside the datagram stream: seeding it with receipts that predate the
//! connection so acked holes don't wedge the contiguous delivered prefix, and
//! folding in a turn that rode the reliable control stream instead.

use super::*;

/// A resuming relay seeds the fresh receive window with the seqs its turn
/// ring already holds, so an acked hole above the client's sparse-window
/// anchor doesn't wedge the contiguous prefix. Without the seed, the
/// prefix here would stick at 5 forever — seq 6 is never re-sent — and
/// with it the beacon cursor, until the live stream exits the receive
/// window entirely.
#[tokio::test]
async fn a_seeded_receive_window_folds_acked_holes_into_the_prefix() {
    let (mut sender, mut receiver, _ea, _eb) = connected_links().await;

    // The resuming client anchors at its oldest unacked seq (5); the relay
    // knows it already received 6 and seeds it.
    receiver.anchor_receive_window(SlotId(0), 5);
    receiver.seed_delivered(SlotId(0), 6);

    // The replayed 5 arrives; the prefix folds through the seeded 6.
    sender.send(Some(turn(0, 5, 0x55))).unwrap();
    let got = receiver.recv().await.unwrap();
    assert_eq!(got.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(SlotId(0)), Some(6));

    // Live turns continue in order past the hole.
    sender.send(Some(turn(0, 7, 0x77))).unwrap();
    let got = receiver.recv().await.unwrap();
    assert_eq!(got.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(SlotId(0)), Some(7));

    // The seeded seq never re-delivers: a redundant copy of 6 arriving
    // later (an old-connection straggler) is dropped as a duplicate.
    sender.send(Some(turn(0, 6, 0x66))).unwrap();
    let got = receiver.recv().await.unwrap();
    assert_eq!(got.fresh.len(), 0, "the seeded seq is already delivered");
}

/// The bulk seed advances the prefix in one step, folds in the sparse
/// seeds its new prefix left contiguous, and never rewinds a prefix
/// already past it.
#[tokio::test]
async fn a_bulk_seed_folds_the_prefix_and_never_rewinds() {
    let (mut sender, mut receiver, _ea, _eb) = connected_links().await;

    receiver.seed_delivered(SlotId(0), 5);
    receiver.seed_delivered(SlotId(0), 7);
    receiver.seed_delivered_through(SlotId(0), 4);
    assert_eq!(
        receiver.delivered_through(SlotId(0)),
        Some(5),
        "the bulk prefix folds the sparse seed sitting right above it",
    );
    receiver.seed_delivered_through(SlotId(0), 6);
    assert_eq!(
        receiver.delivered_through(SlotId(0)),
        Some(7),
        "advancing over the gap folds the rest of the sparse run",
    );
    receiver.seed_delivered_through(SlotId(0), 2);
    assert_eq!(
        receiver.delivered_through(SlotId(0)),
        Some(7),
        "a lower bulk seed never rewinds the prefix",
    );

    // Live traffic continues in order past the seeded prefix.
    sender.send(Some(turn(0, 8, 0x88))).unwrap();
    let got = receiver.recv().await.unwrap();
    assert_eq!(got.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(SlotId(0)), Some(8));
}

/// A turn too wide for a datagram is diverted to the reliable control stream,
/// and `deliver_external` folds it into the same per-slot dedup the datagram
/// path uses. Without the fold the stream-delivered seq is a permanent gap in
/// the delivered prefix, stalling the beacon cursor behind it forever; with
/// it, the prefix advances across the gap and a turn that somehow arrived both
/// ways collapses to one delivery. The mesh twin is
/// `MeshLink::deliver_external`; this is the client edge's.
#[tokio::test]
async fn deliver_external_folds_a_stream_delivered_seq_into_the_links_dedup() {
    let (mut sender, mut receiver, _ea, _eb) = connected_links().await;

    // Datagram seqs 0 and 1 arrive normally.
    sender.send(Some(turn(0, 0, 0xA0))).unwrap();
    sender.send(Some(turn(0, 1, 0xA1))).unwrap();
    let mut delivered = 0;
    while delivered < 2 {
        delivered += receiver.recv().await.unwrap().fresh.len();
    }
    assert_eq!(receiver.delivered_through(SlotId(0)), Some(1));

    // Seq 2 rode the control stream: folding it advances the prefix exactly
    // as a datagram delivery would.
    assert!(receiver.deliver_external(SlotId(0), 2).unwrap());
    assert_eq!(
        receiver.delivered_through(SlotId(0)),
        Some(2),
        "the stream-delivered seq closes the gap instead of stalling the prefix",
    );

    // A redundant copy of the same stream-delivered seq is a duplicate.
    assert!(!receiver.deliver_external(SlotId(0), 2).unwrap());

    // The datagram path continues past the folded seq without a gap.
    sender.send(Some(turn(0, 3, 0xA3))).unwrap();
    let got = receiver.recv().await.unwrap();
    assert_eq!(got.fresh.len(), 1);
    assert_eq!(receiver.delivered_through(SlotId(0)), Some(3));

    // A seq beyond the receive window is an error here just as on the
    // datagram path, not a silently accepted jump.
    match receiver.deliver_external(SlotId(0), u64::MAX) {
        Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
            assert_eq!(slot, SlotId(0));
            assert_eq!(seq, u64::MAX);
        }
        other => panic!("expected PayloadOutOfWindow, got {other:?}"),
    }
}
