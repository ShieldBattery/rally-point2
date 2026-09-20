//! The per-slot ordered-release buffer: what it holds behind a gap, what it
//! releases and in which order, what it drops as already-delivered, and the
//! resume cursor read back off it.
//!
//! Synchronous throughout — the buffer is pure state and the release never
//! awaits — so these drive the real object rather than a QUIC pair.

use super::*;

/// A slot's buffer and a channel deep enough that nothing stalls.
fn reorder() -> (SlotReorder, mpsc::Sender<Payload>, mpsc::Receiver<Payload>) {
    let (tx, rx) = mpsc::channel::<Payload>(64);
    (SlotReorder::default(), tx, rx)
}

fn slot_turn(slot: SlotId, seq: u64, byte: u8) -> Payload {
    let mut payload = turn(seq, &[byte]);
    payload.slot = u32::from(slot.0);
    payload
}

/// Everything the channel has been handed, as `(seq, first command byte)`.
fn drained(rx: &mut mpsc::Receiver<Payload>) -> Vec<(u64, u8)> {
    let mut out = Vec::new();
    while let Ok(payload) = rx.try_recv() {
        out.push((payload.seq, payload.commands[0]));
    }
    out
}

#[test]
fn a_turn_ahead_of_the_gap_is_held_until_the_gap_fills() {
    let slot = SlotId(0);
    let (mut reorder, tx, mut rx) = reorder();

    reorder.observe(slot, slot_turn(slot, 1, 0xB1));
    assert!(matches!(reorder.release_into(&tx), Release::Delivered));
    assert!(
        drained(&mut rx).is_empty(),
        "seq 1 must wait for the missing seq 0",
    );
    assert_eq!(reorder.buffered(slot), 1);
    assert_eq!(reorder.next_needed(slot), 0);

    reorder.observe(slot, slot_turn(slot, 0, 0xB0));
    assert!(matches!(reorder.release_into(&tx), Release::Delivered));
    assert_eq!(
        drained(&mut rx),
        vec![(0, 0xB0), (1, 0xB1)],
        "the whole contiguous run releases in seq order once the gap fills",
    );
    assert_eq!(reorder.buffered(slot), 0);
}

#[test]
fn resume_cursor_is_the_contiguous_high_water_and_absorbs_replayed_turns() {
    // The reconnect path derives its resume cursor from this buffer — the top
    // of the contiguous run delivered to the game, per slot. A replayed
    // already-delivered turn must neither advance the cursor nor re-reach the
    // game.
    let slot = SlotId(0);
    let (mut reorder, tx, mut rx) = reorder();

    let ingest = |reorder: &mut SlotReorder, seq: u64| {
        reorder.observe(slot, slot_turn(slot, seq, seq as u8));
        assert!(matches!(reorder.release_into(&tx), Release::Delivered));
    };

    ingest(&mut reorder, 0);
    ingest(&mut reorder, 1);
    // A gap at 2: seq 3 is held, so the cursor stays at the next-needed 2.
    ingest(&mut reorder, 3);
    assert_eq!(reorder.cursors(), vec![(slot, 2)]);

    // A replay of an already-delivered turn (seq 1 < cursor 2) is dropped: the
    // cursor is unchanged, nothing is buffered under it, and nothing new
    // reaches the game.
    ingest(&mut reorder, 1);
    assert_eq!(reorder.cursors(), vec![(slot, 2)]);
    assert_eq!(reorder.buffered(slot), 1, "only the held seq 3");

    // Seq 2 fills the gap: 2 and the held 3 both release, the cursor jumps to 4.
    ingest(&mut reorder, 2);
    assert_eq!(reorder.cursors(), vec![(slot, 4)]);

    // The game saw 0,1,2,3 once each, in order — no duplicate from the replay.
    assert_eq!(drained(&mut rx), vec![(0, 0), (1, 1), (2, 2), (3, 3)]);
}

#[test]
fn each_slot_reorders_independently() {
    // One slot stuck behind a gap must not hold another slot's turns back:
    // lockstep advances at the pace of the slowest turn, and a peer whose
    // stream is intact keeps feeding the game.
    let (mut reorder, tx, mut rx) = reorder();
    let stuck = SlotId(1);
    let healthy = SlotId(2);

    reorder.observe(stuck, slot_turn(stuck, 1, 0xA1));
    reorder.observe(healthy, slot_turn(healthy, 0, 0xB0));
    reorder.observe(healthy, slot_turn(healthy, 1, 0xB1));
    assert!(matches!(reorder.release_into(&tx), Release::Delivered));

    assert_eq!(drained(&mut rx), vec![(0, 0xB0), (1, 0xB1)]);
    assert_eq!(reorder.buffered(stuck), 1);
    assert_eq!(reorder.next_needed(stuck), 0);
    assert_eq!(reorder.next_needed(healthy), 2);

    // Both slots are in the resume cursors, including the one that has released
    // nothing: the relay must replay from seq 0 for it.
    let mut cursors = reorder.cursors();
    cursors.sort_unstable();
    assert_eq!(cursors, vec![(stuck, 0), (healthy, 2)]);
}

#[test]
fn a_slot_nothing_arrived_from_has_no_cursor_to_state() {
    let (reorder, _tx, _rx) = reorder();
    assert!(
        reorder.cursors().is_empty(),
        "an empty cursor set is a valid ask, not a request for nothing",
    );
    assert_eq!(reorder.slots().count(), 0);
}

#[test]
fn a_full_game_channel_stalls_without_losing_the_turn_it_could_not_hand_over() {
    // The game stopped draining: the release must surface the stall and leave
    // the undelivered turn (and everything behind it) buffered at the cursor,
    // never advance past a turn the game never saw.
    let slot = SlotId(0);
    let (tx, mut rx) = mpsc::channel::<Payload>(1);
    let mut reorder = SlotReorder::default();

    reorder.observe(slot, slot_turn(slot, 0, 0xC0));
    reorder.observe(slot, slot_turn(slot, 1, 0xC1));
    reorder.observe(slot, slot_turn(slot, 2, 0xC2));
    assert!(matches!(reorder.release_into(&tx), Release::GameStalled));

    assert_eq!(reorder.next_needed(slot), 1, "only seq 0 was handed over");
    assert_eq!(reorder.buffered(slot), 2, "seqs 1 and 2 are still held");

    // Once the game drains, the rest releases in order with nothing missing.
    assert_eq!(drained(&mut rx), vec![(0, 0xC0)]);
    assert!(matches!(reorder.release_into(&tx), Release::GameStalled));
    assert_eq!(drained(&mut rx), vec![(1, 0xC1)]);
    assert!(matches!(reorder.release_into(&tx), Release::Delivered));
    assert_eq!(drained(&mut rx), vec![(2, 0xC2)]);
}

#[test]
fn a_dropped_game_receiver_is_a_clean_stop() {
    let slot = SlotId(0);
    let (tx, rx) = mpsc::channel::<Payload>(4);
    drop(rx);
    let mut reorder = SlotReorder::default();

    reorder.observe(slot, slot_turn(slot, 0, 0xD0));
    assert!(matches!(reorder.release_into(&tx), Release::GameClosed));
}
