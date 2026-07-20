//! A bounded per-session record of the turns the relay has forwarded, kept so a
//! client that dropped and re-dialed while its drop was still undecided can be
//! replayed the turns it missed and catch its lockstep sim back up.
//!
//! Every turn the relay fans out to a session's slots is also recorded here, once
//! per distinct `(slot, seq)` (the recording sits at the same single fan-out choke
//! point, right after the session-level dedup, so reconnect/resume or re-home
//! overlap records a repeated turn exactly once). On a re-register the
//! relay reads the reconnecting client's per-slot delivery cursors and replays,
//! on the reliable control stream, every recorded turn the client had not yet
//! received.
//!
//! The ring is bounded two ways — a turn *count* and a total *byte* budget,
//! whichever binds first — and drops oldest-first on overflow. The count bound is
//! sized to a nominal outage window (see `RING_WINDOW_SECS`) at the session's
//! **actual slot count**: over that window a session produces at most
//! `window_secs × turns/s × slots` turns, so a ring sized to that (with headroom)
//! covers the reconnect. Sizing per session rather than for the largest possible
//! game matters because the relay holds one ring per session and most sessions
//! are far smaller than the maximum: a 2-slot session's producers can only ever
//! fill a sixth of a 12-slot window in the same wall-clock time, so a
//! max-slots-sized ring would retain ~6× the window it exists to cover — across
//! hundreds of concurrent sessions, hundreds of megabytes of relay memory
//! covering nothing. An outage can outlast the window — a disconnect is no
//! longer bounded by any timer — but during it the survivors stall in lockstep
//! waiting on the disconnected slot, so few new turns are produced regardless of
//! how long it runs; the ring's growth is bounded by lockstep, not by the outage
//! length. The byte bound is the backstop against a spray of maximum-size
//! oversize turns, which the count bound alone would let occupy far more memory
//! than an ordinary game's tiny turns.
//!
//! The record is **local and ephemeral**, like the drop holds it serves: it is not
//! replicated, and it is dropped when the relay's last local slot for the session
//! leaves.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;

use crate::routing::SessionKey;

/// The nominal per-slot turn cadence of an SC:R game at the standard game speed
/// (~24 turns/second). The count bound is derived from it, not tuned against it.
const NOMINAL_TURNS_PER_SEC_PER_SLOT: usize = 24;

/// The most slots a single SC:R game can hold (8 players + up to 4 observers).
/// The slot count the bounds assume when a session's actual count is unknown
/// (`slots == 0` at [`TurnRing::record`]) — unknown must never under-retain —
/// and the ceiling a hostile or nonsensical count is clamped to.
pub const MAX_GAME_SLOTS: usize = 12;

/// The slot count the bounds are actually derived from: the caller's count
/// clamped into `1..=MAX_GAME_SLOTS`, with `0` (shape unknown) mapped to the
/// full-game assumption rather than a zero-capacity ring.
const fn effective_slots(slots: usize) -> usize {
    if slots == 0 || slots > MAX_GAME_SLOTS {
        MAX_GAME_SLOTS
    } else {
        slots
    }
}

/// The nominal outage window, in whole seconds, the replay ring is sized to
/// cover — keyed to the drop-unlock floor, since a survivor cannot request a
/// disconnected slot's removal until its hold has stood that long, so an outage
/// shorter than this always ends in a reconnect the ring must be able to replay.
///
/// A disconnect is no longer bounded by any timer — a held slot can, in
/// principle, be absent far longer than this before a human either drops it or it
/// reconnects. That does not force the ring larger, because a slot's absence
/// stalls the whole game in lockstep: the survivors block waiting for the
/// disconnected slot's turns, so almost no new turns are produced no matter how
/// long the outage runs. The ring's growth is bounded by lockstep itself, not by
/// the outage length, so sizing it for this nominal window covers the reconnect
/// case with ample headroom in practice.
const RING_WINDOW_SECS: usize = crate::drop_hold::DROP_UNLOCK.as_secs() as usize;

/// The turn-count ceiling for a session of `slots` slots: every slot's turns
/// across a full nominal window, times a ~1.5× headroom. A client that returns
/// after such an outage missed at most the turns produced over that window
/// (`RING_WINDOW_SECS × turns/s × slots`), so a ring this deep always holds
/// them; the headroom absorbs a faster-than-nominal turn rate. Drop-oldest past
/// it.
pub(crate) const fn max_turns(slots: usize) -> usize {
    RING_WINDOW_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * effective_slots(slots) * 3 / 2
}

/// The byte ceiling on a full 12-slot session's recorded turns, counting each
/// turn's command bytes (the variable, dominant cost; the fixed envelope fields
/// are negligible). [`max_bytes`] scales it by the session's slot count exactly
/// like the count bound, floored at [`TURN_RING_MIN_BYTES`].
///
/// An ordinary lockstep turn is a few hundred bytes, so a full
/// [`max_turns`]`(MAX_GAME_SLOTS)` ring of them sits at roughly a megabyte —
/// well under this. The bound bites only a pathological case: a client spraying
/// maximum-size oversize turns (`MAX_OVERSIZE_TURN_COMMANDS_LEN`, 8 KiB each),
/// which count-bounded alone would let occupy `max_turns × 8 KiB` ≈ 34 MiB.
/// Capping at 4 MiB keeps the worst case modest; the oldest turns drop until
/// the budget holds, exactly as for the count bound.
const TURN_RING_FULL_BYTES: usize = 4 * 1024 * 1024;

/// The floor under the slot-scaled byte bound. The byte bound exists to catch
/// oversize-turn spray, not ordinary play, so it must sit comfortably above the
/// count bound's worth of ordinary turns even for the smallest session: a
/// 1-slot count bound (~1,080 turns) of few-hundred-byte turns is ~300 KiB, so
/// a 1 MiB floor keeps ~3× headroom before the byte bound could bite traffic
/// the count bound was sized to keep.
const TURN_RING_MIN_BYTES: usize = 1024 * 1024;

/// The byte ceiling for a session of `slots` slots — [`TURN_RING_FULL_BYTES`]
/// scaled linearly by the slot count, floored at [`TURN_RING_MIN_BYTES`].
const fn max_bytes(slots: usize) -> usize {
    let scaled = TURN_RING_FULL_BYTES * effective_slots(slots) / MAX_GAME_SLOTS;
    if scaled < TURN_RING_MIN_BYTES {
        TURN_RING_MIN_BYTES
    } else {
        scaled
    }
}

/// Where a recorded turn reached this relay from — stamped once, at the
/// moment it wins the session-level dedup and is recorded here, rather than
/// re-derived later from some other state. Re-deriving it later (e.g. from
/// whether the origin slot is *currently* a locally-registered client) would
/// get a genuinely mesh-delivered turn wrong in the window right around a
/// re-home or a race between a client's own send and a stale peer replay of
/// the same turn: the session-level dedup keeps whichever copy of a `(slot,
/// seq)` arrives first, so "is this slot local now" is not the same question
/// as "did THIS entry arrive locally". A resume reply
/// must answer the second question, entry by entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnOrigin {
    /// Delivered by this relay's own client edge — a local client produced it.
    Local,
    /// Delivered by a peer relay over the mesh — forwarded, not originated
    /// here, regardless of which slot it is homed on.
    Mesh,
}

/// One recorded turn plus where it came in from.
struct Entry {
    payload: Payload,
    origin: TurnOrigin,
}

/// One session's recorded turns, oldest at the front. `bytes` tracks the running
/// sum of the turns' command lengths so eviction never rescans the deque.
#[derive(Default)]
struct SessionRing {
    turns: VecDeque<Entry>,
    bytes: usize,
    /// The bounds currently in force, re-derived from the caller's slot count on
    /// every record so the ring follows the session's live shape: slots depart
    /// over a game's life, and the window only ever needs to cover the slots
    /// still producing turns.
    max_turns: usize,
    max_bytes: usize,
}

impl SessionRing {
    /// The command-byte cost the ring charges for one turn — the payload's command
    /// length, the only part that varies materially in size.
    fn cost(payload: &Payload) -> usize {
        payload.commands.len()
    }

    /// Records `payload` (tagged with where it came from), re-derives the bounds
    /// for a session of `slots` slots, and evicts oldest turns until both the
    /// count and byte bounds hold.
    fn record(&mut self, payload: Payload, origin: TurnOrigin, slots: usize) {
        self.max_turns = max_turns(slots);
        self.max_bytes = max_bytes(slots);
        self.bytes += Self::cost(&payload);
        self.turns.push_back(Entry { payload, origin });
        while self.turns.len() > self.max_turns || self.bytes > self.max_bytes {
            let Some(evicted) = self.turns.pop_front() else {
                break;
            };
            self.bytes -= Self::cost(&evicted.payload);
        }
    }
}

/// Per-relay registry of every session's forwarded-turn ring, keyed by session.
/// Cheap to clone (an `Arc` around the shared map), so it rides in
/// [`crate::mesh::MeshState`] alongside the other per-session registries and is
/// handed to every task that forwards a turn.
#[derive(Clone, Default)]
pub struct TurnRing {
    sessions: Arc<Mutex<HashMap<SessionKey, SessionRing>>>,
}

/// One [`TurnRing::totals`] snapshot: ring count plus recorded-turn and
/// command-byte totals across every session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RingTotals {
    pub sessions: usize,
    pub turns: usize,
    pub command_bytes: usize,
}

impl TurnRing {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one forwarded turn for `key`, tagged with where it came from
    /// (see [`TurnOrigin`]). Called once per distinct `(slot, seq)` — at the
    /// single fan-out choke point, after the session-level dedup — so ingress
    /// overlap records a repeated turn exactly once, under whichever origin
    /// the winning copy actually arrived by. The
    /// caller gates this on the session having started; pre-start lobby
    /// traffic has its own replay log and must not be double-buffered here.
    ///
    /// `slots` is the session's slot count as best the caller knows it — it
    /// sizes the ring's bounds to the session's actual shape (see the module
    /// doc). Pass `0` when the shape is genuinely unknown; that sizes the ring
    /// for a maximum-slot game, since unknown must never under-retain.
    pub fn record(&self, key: &SessionKey, payload: &Payload, origin: TurnOrigin, slots: usize) {
        let mut sessions = self.sessions.lock();
        if let Some(ring) = sessions.get_mut(key) {
            ring.record(payload.clone(), origin, slots);
            return;
        }
        sessions
            .entry(key.clone())
            .or_default()
            .record(payload.clone(), origin, slots);
    }

    /// The recorded turns a reconnecting client has not yet received, oldest-first.
    ///
    /// For each recorded turn, `cursors` names — per source slot — the next seq the
    /// client still needs: a turn is replayed when its slot is present in `cursors`
    /// and its seq is at or past that slot's cursor. A slot absent from `cursors` is
    /// not replayed (the client did not ask to resume it), so an empty map — a fresh
    /// dial — replays nothing. Oldest-first preserves each slot's seq order for the
    /// client's per-slot reorder buffer. Every origin qualifies: a reconnecting
    /// client wants everything it missed regardless of whether its home client
    /// edge or a direct peer link first delivered it here.
    ///
    /// A client's own inbound gaps have a second re-carrier besides this replay
    /// — its own unacked-window redundancy, riding its live home-relay link — so
    /// an absent slot here always safely means "nothing to replay", with no
    /// resume-vs-fresh distinction to make. [`replay_local`](Self::replay_local)
    /// (the mesh peer's reply) has no such second re-carrier and needs one; see
    /// its own doc.
    pub fn replay(&self, key: &SessionKey, cursors: &HashMap<SlotId, u64>) -> Vec<Payload> {
        self.matching(key, cursors, None, false)
    }

    /// Like [`replay`](Self::replay), but additionally restricted to turns this
    /// relay recorded as [`TurnOrigin::Local`] — the reply a resume-cursor ask
    /// from a mesh peer gets, so the reply can only ever carry turns this
    /// relay's own client edge produced, never one it itself received from the
    /// mesh. That is what keeps a resume reply from becoming an echo: a mesh
    /// peer's cursors are answered only with what genuinely originated here.
    ///
    /// `resuming` decides what a slot absent from `cursors` means, and it is
    /// not the same "nothing to replay" [`replay`](Self::replay) can always
    /// assume: a mesh peer's own inbound gaps have no second re-carrier once
    /// the link that would have re-carried them has died (unlike a client's,
    /// covered by its still-live home-relay link's own redundancy), so an
    /// asker with genuine prior history for the session (`resuming` true)
    /// needs an absent slot answered from the very start — its own dedup
    /// absorbs whatever sparse overlap it already has — while an asker with
    /// none at all (`resuming` false: a first Join, or one predating this
    /// link) still gets nothing for an absent slot, exactly as `replay` would.
    pub fn replay_local(
        &self,
        key: &SessionKey,
        cursors: &HashMap<SlotId, u64>,
        resuming: bool,
    ) -> Vec<Payload> {
        self.matching(key, cursors, Some(TurnOrigin::Local), resuming)
    }

    /// Shared body for [`replay`](Self::replay) and
    /// [`replay_local`](Self::replay_local): every recorded turn at or past its
    /// slot's cursor, oldest-first, additionally restricted to `origin` when one
    /// is given. `replay_absent_from_zero` governs a slot absent from `cursors`:
    /// excluded when `false` (the cursor asker never named it), included from
    /// seq 0 when `true` (an asker with real history whose own gap-tracking
    /// simply never covered this slot).
    fn matching(
        &self,
        key: &SessionKey,
        cursors: &HashMap<SlotId, u64>,
        origin: Option<TurnOrigin>,
        replay_absent_from_zero: bool,
    ) -> Vec<Payload> {
        let sessions = self.sessions.lock();
        let Some(ring) = sessions.get(key) else {
            return Vec::new();
        };
        ring.turns
            .iter()
            .filter(|entry| origin.is_none_or(|want| entry.origin == want))
            .filter(|entry| {
                let Ok(slot) = u8::try_from(entry.payload.slot) else {
                    return false;
                };
                match cursors.get(&SlotId(slot)) {
                    Some(&cursor) => entry.payload.seq >= cursor,
                    None => replay_absent_from_zero,
                }
            })
            .map(|entry| entry.payload.clone())
            .collect()
    }

    /// Drops a session's ring once the relay's last local slot for it leaves,
    /// mirroring how the roster group and lobby/chat state are dropped then.
    /// Idempotent.
    pub fn end_session(&self, key: &SessionKey) {
        self.sessions.lock().remove(key);
    }

    /// A point-in-time occupancy snapshot across every session's ring, for the
    /// task-stats reporter: how much relay memory the replay record is holding
    /// right now. `command_bytes` counts only the turns' command bytes (what
    /// the byte bound charges), which undercounts real memory — every entry
    /// also carries its fixed envelope — so for sessions of tiny turns the turn
    /// count is the primary footprint signal.
    pub fn totals(&self) -> RingTotals {
        let sessions = self.sessions.lock();
        let mut totals = RingTotals {
            sessions: sessions.len(),
            ..Default::default()
        };
        for ring in sessions.values() {
            totals.turns += ring.turns.len();
            totals.command_bytes += ring.bytes;
        }
        totals
    }

    /// The number of turns currently recorded for `key` — for tests asserting the
    /// count bound and drop-oldest behavior.
    #[cfg(test)]
    pub fn len(&self, key: &SessionKey) -> usize {
        self.sessions
            .lock()
            .get(key)
            .map_or(0, |ring| ring.turns.len())
    }

    /// The running command-byte total currently recorded for `key` — for tests
    /// asserting the byte bound.
    #[cfg(test)]
    pub fn bytes(&self, key: &SessionKey) -> usize {
        self.sessions.lock().get(key).map_or(0, |ring| ring.bytes)
    }
}

#[cfg(test)]
mod tests {
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
                assert!(
                    max_turns(slots) >= RING_WINDOW_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * slots
                );
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

        // A client that has slot 0 through seq 1 and slot 2 not at all: replay slot
        // 0's seqs >= 2 only, and nothing for slot 1 (absent from the cursor map).
        let cursors: HashMap<SlotId, u64> = [(SlotId(0), 2)].into();
        let replayed = ring.replay(&k, &cursors);
        let got: Vec<(u32, u64)> = replayed.iter().map(|p| (p.slot, p.seq)).collect();
        assert_eq!(got, vec![(0, 2), (0, 3)]);
    }

    #[test]
    fn replay_preserves_oldest_first_order() {
        let ring = TurnRing::new();
        let k = key();
        for seq in 0..5 {
            record_local(&ring, &k, &turn(0, seq, 8));
        }
        let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
        let seqs: Vec<u64> = ring.replay(&k, &cursors).iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4], "oldest-first");
    }

    #[test]
    fn an_empty_cursor_map_replays_nothing() {
        let ring = TurnRing::new();
        let k = key();
        record_local(&ring, &k, &turn(0, 0, 8));
        assert!(ring.replay(&k, &HashMap::new()).is_empty());
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

        // The lowest `overflow` seqs were evicted; the newest cap-worth remain.
        let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
        let seqs: Vec<u64> = ring.replay(&k, &cursors).iter().map(|p| p.seq).collect();
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
            },
        );
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
        let seqs: Vec<u64> = ring.replay(&k, &cursors).iter().map(|p| p.seq).collect();
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
        assert!(ring.replay(&k, &[(SlotId(0), 0)].into()).is_empty());
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
            ring.replay(&k, &cursors)
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
}
