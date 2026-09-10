//! Tests for resuming a slot's seq stream mid-flight: anchoring a fresh
//! receive window at the oldest replayable seq so the replay is not rejected
//! as out-of-window, and seeding that window with receipts predating the
//! connection so acked holes don't wedge the contiguous delivered prefix.

use super::*;

#[tokio::test]
async fn same_relay_resume_anchor_from_oldest_unacked_accepts_a_past_window_stream() {
    // The same-relay reconnect fix, end to end at the transport layer: a client
    // deep into a game (unacked turns at a high absolute seq) sources its own-slot
    // resume anchor from `oldest_replayable_seq` — exactly what the driver presents on
    // a same-relay dial — and a fresh relay-side dedup anchored there accepts the
    // resumed stream that a from-zero window would reject as out-of-window (the
    // production blocker for any game past ~4096 turns).
    let (mut sender, _peer, _ea, _eb) = connected_links().await;

    let high = |seq: u64| Payload {
        seq,
        slot: 0,
        commands: vec![0u8; 4].into(),
        ..Default::default()
    };
    // The peer never acks, so these stay in flight — the window the redundancy
    // pass re-carries over a rebound connection, oldest-first.
    for seq in [8000u64, 8001, 8002] {
        sender.send(Some(high(seq))).unwrap();
    }
    let anchor = sender
        .oldest_replayable_seq(SlotId(0))
        .expect("turns are in flight");
    assert_eq!(
        anchor, 8000,
        "the same-relay anchor is the oldest unacked seq"
    );

    // The relay builds a fresh dedup on the re-dial. From zero the resumed seq is
    // far beyond the window (the bug); anchored at the resume point it is accepted
    // and the delivered prefix advances from there.
    let mut unanchored = Dedup::with_window(RECEIVE_WINDOW);
    assert_eq!(
        unanchored.accept(SlotId(0), anchor),
        Delivery::OutOfWindow,
        "without the anchor a fresh relay rejects the resumed stream",
    );

    let mut anchored = Dedup::with_window(RECEIVE_WINDOW);
    anchored.anchor(SlotId(0), anchor);
    for seq in [8000u64, 8001, 8002] {
        assert_eq!(anchored.accept(SlotId(0), seq), Delivery::New);
    }
    assert_eq!(anchored.delivered_through(SlotId(0)), Some(8002));
}

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
