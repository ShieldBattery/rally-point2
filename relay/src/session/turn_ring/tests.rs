//! Tests for the turn ring: cursor-based replay (named, unnamed, and
//! empty-cursor slots), oldest-first ordering, the count and byte bounds'
//! drop-oldest eviction and per-session slot-count scaling, and the
//! `replay_local` origin filter mesh resume replies rely on.

use super::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId("t".to_owned()),
        session: SessionId(1),
    }
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
fn the_count_bound_is_at_least_the_nominal_window_at_every_slot_count() {
    // The whole point of deriving the bound from the nominal window is that the
    // ring can always hold that window's worth of turns for every slot. All
    // inputs are compile-time constants, so this is checked in a `const` block (a
    // plain runtime `assert!` on two constants is itself a clippy lint) — it
    // still catches a future edit to the derivation that breaks the invariant,
    // just at compile time instead of test time.
    const {
        let mut slots = 1;
        while slots <= MAX_GAME_SLOTS {
            assert!(max_turns(slots) >= RING_WINDOW_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * slots);
            slots += 1;
        }
        // Unknown shape sizes for the largest game, never a smaller one.
        assert!(max_turns(0) == max_turns(MAX_GAME_SLOTS));
        assert!(max_bytes(0) == max_bytes(MAX_GAME_SLOTS));
    }
}

#[test]
fn the_byte_floor_clears_a_count_bound_of_ordinary_turns() {
    // The byte bound exists for oversize spray, so even at the smallest
    // session shape it must not bite a count bound's worth of ordinary
    // few-hundred-byte turns.
    const ORDINARY_TURN_BYTES: usize = 300;
    const {
        assert!(max_bytes(1) >= max_turns(1) * ORDINARY_TURN_BYTES);
    }
}

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
    let ring = TurnRing::new();
    let k = key();
    for seq in 0..3 {
        record_local(&ring, &k, &turn(0, seq, 8));
    }
    for seq in 0..2 {
        record_local(&ring, &k, &turn(1, seq, 8));
    }
    record_local(&ring, &k, &turn(2, 0, 8));

    // Slot 2 is reconnecting and names only slot 1, from seq 1.
    let cursors: HashMap<SlotId, u64> = [(SlotId(1), 1)].into();
    let got: Vec<(u32, u64)> = ring
        .replay(&k, &cursors, SlotId(2))
        .iter()
        .map(|p| (p.slot, p.seq))
        .collect();
    assert_eq!(
        got,
        vec![(0, 0), (0, 1), (0, 2), (1, 1)],
        "the unnamed peer replays whole, the named one from its cursor, and the \
         reconnecting slot gets none of its own turns back",
    );
}

#[test]
fn replay_preserves_oldest_first_order() {
    let ring = TurnRing::new();
    let k = key();
    for seq in 0..5 {
        record_local(&ring, &k, &turn(0, seq, 8));
    }
    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
    let seqs: Vec<u64> = ring
        .replay(&k, &cursors, RECONNECTING)
        .iter()
        .map(|p| p.seq)
        .collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4], "oldest-first");
}

#[test]
fn an_empty_cursor_map_replays_every_other_slot_whole() {
    // An empty map is not proof the client has nothing to catch up on — a
    // re-homing client that has neither sent nor received a turn presents
    // exactly this — so it asks for every peer's recorded turns, and only
    // the asking slot's own are held back.
    let ring = TurnRing::new();
    let k = key();
    record_local(&ring, &k, &turn(0, 0, 8));
    record_local(&ring, &k, &turn(1, 0, 8));

    let got: Vec<(u32, u64)> = ring
        .replay(&k, &HashMap::new(), SlotId(1))
        .iter()
        .map(|p| (p.slot, p.seq))
        .collect();
    assert_eq!(got, vec![(0, 0)]);
}

#[test]
fn an_empty_ring_replays_nothing_to_a_first_arrival() {
    // A slot's genuine first dial reads a ring that holds nothing: turns are
    // recorded only once the session has started, and it starts only once
    // every expected slot is present. Replaying an unnamed slot whole
    // therefore costs a first arrival nothing.
    let ring = TurnRing::new();
    let k = key();
    assert!(ring.replay(&k, &HashMap::new(), SlotId(0)).is_empty());
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
fn an_unknown_slot_count_sizes_for_a_full_game() {
    // `0` means the caller genuinely doesn't know the session's shape;
    // under-retaining on unknown would break the reconnect the ring exists
    // for, so it gets the full-game bound.
    let ring = TurnRing::new();
    let k = key();
    let cap = max_turns(MAX_GAME_SLOTS);
    let small_cap = max_turns(2);
    for seq in 0..(small_cap + 5) as u64 {
        ring.record(&k, &turn(0, seq, 1), TurnOrigin::Local, 0);
    }
    assert!(ring.len(&k) > small_cap, "not bounded like a small session");
    assert!(ring.len(&k) <= cap);
}

#[test]
fn totals_sum_turns_and_command_bytes_across_sessions() {
    let ring = TurnRing::new();
    let k = key();
    let other = SessionKey {
        tenant: TenantId("t".to_owned()),
        session: SessionId(2),
    };
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
    let second = SessionKey {
        tenant: TenantId("t".to_owned()),
        session: SessionId(2),
    };

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
}

#[test]
fn replay_local_of_an_all_mesh_slot_is_empty() {
    // A slot every recorded entry arrived by mesh (this relay never hosts
    // that slot's client) has nothing this relay may reply with — a mesh
    // peer's ask for it is answered by whichever relay actually homes it.
    // True regardless of `resuming`: a listed cursor is honored by seq, an
    // absent one by `resuming`, but the origin filter excludes every entry
    // here either way.
    let ring = TurnRing::new();
    let k = key();
    ring.record(&k, &turn(0, 0, 8), TurnOrigin::Mesh, MAX_GAME_SLOTS);
    ring.record(&k, &turn(0, 1, 8), TurnOrigin::Mesh, MAX_GAME_SLOTS);

    let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
    assert!(ring.replay_local(&k, &cursors, false).is_empty());
    assert!(ring.replay_local(&k, &cursors, true).is_empty());

    let no_cursor: HashMap<SlotId, u64> = HashMap::new();
    assert!(
        ring.replay_local(&k, &no_cursor, true).is_empty(),
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
