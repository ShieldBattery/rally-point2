//! Tests for the turn ring: cursor-based replay (named, unnamed, and
//! empty-cursor slots), oldest-first ordering, the count and byte bounds'
//! drop-oldest eviction and per-session slot-count scaling, and the
//! `replay_local` origin filter mesh resume replies rely on.

use super::*;
use crate::test_support::session_key as key_of;

fn key() -> SessionKey {
    key_of(1)
}

fn turn(slot: u8, seq: u64, len: usize) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0xAB; len].into(),
        ..Default::default()
    }
}

/// [`TurnRing::record`] with the origin and slot count most of these tests
/// don't care about — they exercise the cursor/bound mechanics, which behave
/// identically regardless of origin, at the full-game bounds.
fn record_local(ring: &TurnRing, key: &SessionKey, payload: &Payload) {
    ring.record(key, payload, TurnOrigin::Local, MAX_GAME_SLOTS);
}

/// The slot doing the connecting in the tests that only care about cursor or
/// bound mechanics: one that never produces a turn of its own, so the
/// own-slot skip can never remove anything they assert on.
const RECONNECTING: SlotId = SlotId(9);

#[test]
fn records_and_replays_turns_past_a_cursor() {
    let ring = TurnRing::new();
    let k = key();
    // Slot 0 produces seqs 0..4; slot 1 produces seqs 0..2.
    for seq in 0..4 {
        record_local(&ring, &k, &turn(0, seq, 8));
    }
    for seq in 0..2 {
        record_local(&ring, &k, &turn(1, seq, 8));
    }

    // A client that holds slot 0 through seq 1 and slot 1 through seq 0: each
    // named slot replays from its own cursor and nothing below it.
    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 2), (SlotId(1), 1)].into();
    let replayed = ring.replay(&k, &cursors, RECONNECTING);
    let got: Vec<(u32, u64)> = replayed.iter().map(|p| (p.slot, p.seq)).collect();
    assert_eq!(got, vec![(0, 2), (0, 3), (1, 1)]);
}

#[test]
fn a_slot_the_cursors_never_name_replays_from_the_start() {
    // The wedge this rule exists for: a client froze before a peer's first
    // turn reached it, so its cursor map has no entry for that peer at all,
    // while the relay had already forwarded those turns down the link that
    // then died. Nothing else can carry them, so an unnamed slot replays
    // whole. Its own slot is skipped even though it, too, goes unnamed.
    //
    // A partial map and an empty one are the same rule: an empty map is not
    // proof the client has nothing to catch up on -- a re-homing client that
    // has neither sent nor received a turn presents exactly that -- so each
    // unnamed peer replays whole either way.
    let ring = TurnRing::new();
    let k = key();
    for seq in 0..3 {
        record_local(&ring, &k, &turn(0, seq, 8));
    }
    for seq in 0..2 {
        record_local(&ring, &k, &turn(1, seq, 8));
    }
    record_local(&ring, &k, &turn(2, 0, 8));

    // Slot 2 is reconnecting; with slot 1 named from seq 1, and with nothing
    // named at all. Each expectation is an exact ordered comparison, so it
    // pins the oldest-first replay order too.
    let partial: HashMap<SlotId, u64> = [(SlotId(1), 1)].into();
    for (cursors, expected) in [
        (partial, vec![(0, 0), (0, 1), (0, 2), (1, 1)]),
        (HashMap::new(), vec![(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]),
    ] {
        let got: Vec<(u32, u64)> = ring
            .replay(&k, &cursors, SlotId(2))
            .iter()
            .map(|p| (p.slot, p.seq))
            .collect();
        assert_eq!(
            got, expected,
            "each unnamed peer replays whole, a named one from its cursor, and the \
             reconnecting slot gets none of its own turns back",
        );
    }
}

#[test]
fn the_count_bound_drops_the_oldest_turns() {
    let ring = TurnRing::new();
    let k = key();
    // Overfill by a handful past the count bound with tiny turns (so the byte
    // bound never binds first): the ring holds exactly the cap, and the oldest
    // seqs are the ones dropped.
    let cap = max_turns(MAX_GAME_SLOTS);
    let overflow = 5;
    for seq in 0..(cap + overflow) as u64 {
        record_local(&ring, &k, &turn(0, seq, 1));
    }
    assert_eq!(ring.len(&k), cap, "capped at the count bound");
    assert_eq!(
        ring.totals().local_origin_turns,
        (cap + overflow) as u64,
        "lifetime ingress counts are not reduced by occupancy eviction",
    );

    // The lowest `overflow` seqs were evicted; the newest cap-worth remain.
    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
    let seqs: Vec<u64> = ring
        .replay(&k, &cursors, RECONNECTING)
        .iter()
        .map(|p| p.seq)
        .collect();
    assert_eq!(seqs.first().copied(), Some(overflow as u64));
    assert_eq!(seqs.last().copied(), Some((cap + overflow - 1) as u64));
}

#[test]
fn the_count_bound_scales_with_the_session_slot_count() {
    // A 2-slot session's producers can only fill a sixth of a 12-slot
    // window, and its ring is bounded accordingly.
    let cap = max_turns(2);
    assert_eq!(
        cap,
        RING_WINDOW_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * 2 * 3 / 2
    );
    assert_eq!(max_turns(MAX_GAME_SLOTS), cap * 6);

    let ring = TurnRing::new();
    let k = key();
    let overflow = 5;
    for seq in 0..(cap + overflow) as u64 {
        ring.record(&k, &turn(0, seq, 1), TurnOrigin::Local, 2);
    }
    assert_eq!(ring.len(&k), cap, "capped at the 2-slot count bound");
}

#[test]
fn a_shrinking_slot_count_tightens_the_bounds_on_the_next_record() {
    // A session's slots depart over its life; once the caller reports the
    // smaller shape, the very next record re-derives the bounds and evicts
    // down to them rather than coasting on the larger session's ring.
    let ring = TurnRing::new();
    let k = key();
    let big_cap = max_turns(MAX_GAME_SLOTS);
    let small_cap = max_turns(2);
    for seq in 0..big_cap as u64 {
        record_local(&ring, &k, &turn(0, seq, 1));
    }
    assert_eq!(ring.len(&k), big_cap);

    ring.record(&k, &turn(0, big_cap as u64, 1), TurnOrigin::Local, 2);
    assert_eq!(ring.len(&k), small_cap, "evicted down to the smaller bound");
}

#[test]
fn totals_sum_turns_and_command_bytes_across_sessions() {
    let ring = TurnRing::new();
    let k = key();
    let other = key_of(2);
    record_local(&ring, &k, &turn(0, 0, 10));
    record_local(&ring, &k, &turn(0, 1, 10));
    record_local(&ring, &other, &turn(0, 0, 7));
    assert_eq!(
        ring.totals(),
        RingTotals {
            sessions: 2,
            turns: 3,
            command_bytes: 27,
            local_origin_turns: 3,
            mesh_origin_turns: 0,
        },
    );
}

#[test]
fn origin_totals_are_distinct_record_counts_and_survive_session_teardown() {
    let ring = TurnRing::new();
    let first = key();
    let second = key_of(2);

    ring.record(&first, &turn(0, 0, 8), TurnOrigin::Local, 2);
    ring.record(&first, &turn(1, 0, 8), TurnOrigin::Mesh, 2);
    ring.record(&second, &turn(0, 1, 8), TurnOrigin::Mesh, 2);
    assert_eq!(ring.totals().local_origin_turns, 1);
    assert_eq!(ring.totals().mesh_origin_turns, 2);

    ring.end_session(&first);
    ring.end_session(&second);
    assert_eq!(ring.totals().sessions, 0);
    assert_eq!(ring.totals().turns, 0);
    assert_eq!(ring.totals().command_bytes, 0);
    assert_eq!(ring.totals().local_origin_turns, 1);
    assert_eq!(ring.totals().mesh_origin_turns, 2);
}

#[test]
fn the_byte_bound_drops_the_oldest_turns_before_the_count_bound() {
    let ring = TurnRing::new();
    let k = key();
    // Large turns so the byte budget binds well before the count would: each is
    // 64 KiB, so the ring holds at most the full-game byte bound / 64 KiB of them.
    let big = 64 * 1024;
    let budget = max_bytes(MAX_GAME_SLOTS);
    let per = budget / big;
    for seq in 0..(per + 3) as u64 {
        record_local(&ring, &k, &turn(0, seq, big));
    }
    assert!(ring.len(&k) <= per, "the byte bound capped the count");
    assert!(
        ring.bytes(&k) <= budget,
        "the byte total holds under the budget",
    );
    // What remains is the newest run — the oldest seqs were evicted.
    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
    let seqs: Vec<u64> = ring
        .replay(&k, &cursors, RECONNECTING)
        .iter()
        .map(|p| p.seq)
        .collect();
    assert_eq!(
        seqs.last().copied(),
        Some((per + 2) as u64),
        "the newest turn is retained",
    );
    assert!(
        seqs.first().copied().unwrap() > 0,
        "the oldest were dropped"
    );
}

#[test]
fn ending_a_session_drops_its_ring() {
    let ring = TurnRing::new();
    let k = key();
    record_local(&ring, &k, &turn(0, 0, 8));
    ring.end_session(&k);
    assert_eq!(ring.len(&k), 0);
    assert!(
        ring.replay(&k, &[(SlotId(0), 0)].into(), RECONNECTING)
            .is_empty()
    );
    // The same read a slot's genuine first dial makes — no ring for the
    // session, no cursors of its own — so replaying unnamed slots whole costs
    // a first arrival nothing.
    assert!(ring.replay(&k, &HashMap::new(), SlotId(0)).is_empty());
}

#[test]
fn replay_local_excludes_mesh_delivered_entries() {
    // A slot's turns can be recorded under either origin across a re-home,
    // regardless of which slot they are for. `replay` (the client-facing
    // form) doesn't care; `replay_local`
    // (the mesh resume-reply form) must only ever return the `Local` ones.
    let ring = TurnRing::new();
    let k = key();
    ring.record(&k, &turn(0, 0, 8), TurnOrigin::Local, MAX_GAME_SLOTS);
    ring.record(&k, &turn(0, 1, 8), TurnOrigin::Mesh, MAX_GAME_SLOTS);
    ring.record(&k, &turn(0, 2, 8), TurnOrigin::Local, MAX_GAME_SLOTS);

    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
    assert_eq!(
        ring.replay(&k, &cursors, RECONNECTING)
            .iter()
            .map(|p| p.seq)
            .collect::<Vec<_>>(),
        vec![0, 1, 2],
        "the client-facing replay includes every origin",
    );
    assert_eq!(
        ring.replay_local(&k, &cursors, false)
            .iter()
            .map(|p| p.seq)
            .collect::<Vec<_>>(),
        vec![0, 2],
        "the mesh resume reply skips the mesh-delivered entry",
    );

    // A slot whose every recorded entry arrived by mesh (this relay never
    // hosts that slot's client) has nothing this relay may reply with at all
    // — a mesh peer's ask for it is answered by whichever relay homes it. The
    // origin filter applies before the `resuming` rule, so that holds for a
    // listed cursor and for an absent one asked from zero alike.
    let all_mesh = key_of(2);
    ring.record(&all_mesh, &turn(0, 0, 8), TurnOrigin::Mesh, MAX_GAME_SLOTS);
    ring.record(&all_mesh, &turn(0, 1, 8), TurnOrigin::Mesh, MAX_GAME_SLOTS);
    assert!(ring.replay_local(&all_mesh, &cursors, false).is_empty());
    assert!(ring.replay_local(&all_mesh, &cursors, true).is_empty());
    assert!(
        ring.replay_local(&all_mesh, &HashMap::new(), true)
            .is_empty(),
        "an all-mesh slot has nothing Local to replay even unlisted-from-0",
    );
}

#[test]
fn replay_local_answers_an_unlisted_slot_from_zero_only_when_resuming() {
    // The gap a mesh-side death leaves behind with no other re-carrier:
    // this relay's Local turns for slot 0 were never listed in the
    // asker's cursors at all (its own forward-gate tracking never formed
    // a contiguous prefix for that slot). A non-resuming ask (first Join)
    // gets nothing for it, exactly like any other absent slot; a resuming
    // ask (real prior history, just not for this slot) gets everything
    // from the start, relying on the asker's own dedup to absorb whatever
    // sparse overlap it already has.
    let ring = TurnRing::new();
    let k = key();
    ring.record(&k, &turn(0, 0, 8), TurnOrigin::Local, MAX_GAME_SLOTS);
    ring.record(&k, &turn(0, 1, 8), TurnOrigin::Local, MAX_GAME_SLOTS);
    ring.record(&k, &turn(0, 2, 8), TurnOrigin::Local, MAX_GAME_SLOTS);

    // Slot 0 is entirely absent from the cursor map -- unlisted, not
    // listed-at-zero.
    let cursors: HashMap<SlotId, u64> = HashMap::new();

    assert!(
        ring.replay_local(&k, &cursors, false).is_empty(),
        "a non-resuming ask replays nothing for an unlisted slot",
    );
    assert_eq!(
        ring.replay_local(&k, &cursors, true)
            .iter()
            .map(|p| p.seq)
            .collect::<Vec<_>>(),
        vec![0, 1, 2],
        "a resuming ask replays an unlisted slot's Local turns from the start",
    );
}
