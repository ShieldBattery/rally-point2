//! A bounded per-session record of the turns the relay has forwarded, kept so a
//! client that dropped and re-dialed within its disconnect grace can be replayed
//! the turns it missed and catch its lockstep sim back up.
//!
//! Every turn the relay fans out to a session's slots is also recorded here, once
//! per distinct `(slot, seq)` (the recording sits at the same single fan-out choke
//! point, right after the topological dedup, so a turn delivered to the authority
//! by more than one mesh path is recorded exactly once). On a re-register the
//! relay reads the reconnecting client's per-slot delivery cursors and replays,
//! on the reliable control stream, every recorded turn the client had not yet
//! received.
//!
//! The ring is bounded two ways — a turn *count* and a total *byte* budget,
//! whichever binds first — and drops oldest-first on overflow. The count bound is
//! derived from the grace window: a client can be gone at most one full grace, and
//! over that window a session of the most slots SC:R allows produces at most
//! `grace_secs × turns/s × slots` turns, so a ring sized to that (with headroom)
//! always covers a within-grace reconnect. The byte bound is the backstop against
//! a spray of maximum-size oversize turns, which the count bound alone would let
//! occupy far more memory than an ordinary game's tiny turns.
//!
//! The record is **local and ephemeral**, like the disconnect grace it serves: it
//! is not replicated, and it is dropped when the relay's last local slot for the
//! session leaves. A client gone longer than the ring holds simply cannot be
//! caught up from it — but the ring is sized so that never happens within a grace.

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
const MAX_GAME_SLOTS: usize = 12;

/// The grace window, in whole seconds, over which a dropped client can return —
/// the longest a reconnecting client can have been absent, and so the span of
/// turns the ring must be able to replay. Read from the one grace constant so the
/// ring can never be sized smaller than the window it exists to cover.
const GRACE_SECS: usize = crate::leave_grace::DISCONNECT_GRACE.as_secs() as usize;

/// The turn-count ceiling: every slot's turns across a full grace window, times a
/// ~1.5× headroom. A client that returns within the grace missed at most the
/// turns produced over that window (`GRACE_SECS × turns/s × slots`), so a ring
/// this deep always holds them; the headroom absorbs a faster-than-nominal turn
/// rate. Drop-oldest past it.
const TURN_RING_MAX_TURNS: usize =
    GRACE_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * MAX_GAME_SLOTS * 3 / 2;

/// The byte ceiling on one session's recorded turns, counting each turn's command
/// bytes (the variable, dominant cost; the fixed envelope fields are negligible).
///
/// An ordinary lockstep turn is a few hundred bytes, so a full [`TURN_RING_MAX_TURNS`]
/// ring of them sits at roughly a megabyte — well under this. The bound bites only
/// a pathological case: a client spraying maximum-size oversize turns
/// (`MAX_OVERSIZE_TURN_COMMANDS_LEN`, 8 KiB each), which count-bounded alone would
/// let occupy `TURN_RING_MAX_TURNS × 8 KiB` ≈ 34 MiB. Capping at 4 MiB keeps the
/// worst case modest; the oldest turns drop until the budget holds, exactly as for
/// the count bound.
const TURN_RING_MAX_BYTES: usize = 4 * 1024 * 1024;

/// One session's recorded turns, oldest at the front. `bytes` tracks the running
/// sum of the turns' command lengths so eviction never rescans the deque.
#[derive(Default)]
struct SessionRing {
    turns: VecDeque<Payload>,
    bytes: usize,
}

impl SessionRing {
    /// The command-byte cost the ring charges for one turn — the payload's command
    /// length, the only part that varies materially in size.
    fn cost(payload: &Payload) -> usize {
        payload.commands.len()
    }

    /// Records `payload` and evicts oldest turns until both the count and byte
    /// bounds hold.
    fn record(&mut self, payload: Payload) {
        self.bytes += Self::cost(&payload);
        self.turns.push_back(payload);
        while self.turns.len() > TURN_RING_MAX_TURNS || self.bytes > TURN_RING_MAX_BYTES {
            let Some(evicted) = self.turns.pop_front() else {
                break;
            };
            self.bytes -= Self::cost(&evicted);
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

impl TurnRing {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one forwarded turn for `key`. Called once per distinct `(slot, seq)`
    /// — at the single fan-out choke point, after the topological dedup — so a turn
    /// the mesh delivers by more than one path is recorded exactly once. The caller
    /// gates this on the session having started; pre-start lobby traffic has its own
    /// replay log and must not be double-buffered here.
    pub fn record(&self, key: &SessionKey, payload: &Payload) {
        self.sessions
            .lock()
            .entry(key.clone())
            .or_default()
            .record(payload.clone());
    }

    /// The recorded turns a reconnecting client has not yet received, oldest-first.
    ///
    /// For each recorded turn, `cursors` names — per source slot — the next seq the
    /// client still needs: a turn is replayed when its slot is present in `cursors`
    /// and its seq is at or past that slot's cursor. A slot absent from `cursors` is
    /// not replayed (the client did not ask to resume it), so an empty map — a fresh
    /// dial — replays nothing. Oldest-first preserves each slot's seq order for the
    /// client's per-slot reorder buffer.
    pub fn replay(&self, key: &SessionKey, cursors: &HashMap<SlotId, u64>) -> Vec<Payload> {
        let sessions = self.sessions.lock();
        let Some(ring) = sessions.get(key) else {
            return Vec::new();
        };
        ring.turns
            .iter()
            .filter(|payload| {
                u8::try_from(payload.slot)
                    .ok()
                    .and_then(|slot| cursors.get(&SlotId(slot)))
                    .is_some_and(|cursor| payload.seq >= *cursor)
            })
            .cloned()
            .collect()
    }

    /// Drops a session's ring once the relay's last local slot for it leaves,
    /// mirroring how the roster group and lobby/chat state are dropped then.
    /// Idempotent.
    pub fn end_session(&self, key: &SessionKey) {
        self.sessions.lock().remove(key);
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

    #[test]
    fn the_count_bound_is_at_least_the_full_grace_window() {
        // The whole point of deriving the bound from the grace is that the ring can
        // always hold a full grace's worth of turns for every slot. Both sides are
        // compile-time constants, so this is checked in a `const` block (a plain
        // runtime `assert!` on two constants is itself a clippy lint) — it still
        // catches a future edit to the derivation that breaks the invariant, just
        // at compile time instead of test time.
        const {
            assert!(
                TURN_RING_MAX_TURNS >= GRACE_SECS * NOMINAL_TURNS_PER_SEC_PER_SLOT * MAX_GAME_SLOTS
            );
        }
    }

    #[test]
    fn records_and_replays_turns_past_a_cursor() {
        let ring = TurnRing::new();
        let k = key();
        // Slot 0 produces seqs 0..4; slot 1 produces seqs 0..2.
        for seq in 0..4 {
            ring.record(&k, &turn(0, seq, 8));
        }
        for seq in 0..2 {
            ring.record(&k, &turn(1, seq, 8));
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
            ring.record(&k, &turn(0, seq, 8));
        }
        let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
        let seqs: Vec<u64> = ring.replay(&k, &cursors).iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4], "oldest-first");
    }

    #[test]
    fn an_empty_cursor_map_replays_nothing() {
        let ring = TurnRing::new();
        let k = key();
        ring.record(&k, &turn(0, 0, 8));
        assert!(ring.replay(&k, &HashMap::new()).is_empty());
    }

    #[test]
    fn the_count_bound_drops_the_oldest_turns() {
        let ring = TurnRing::new();
        let k = key();
        // Overfill by a handful past the count bound with tiny turns (so the byte
        // bound never binds first): the ring holds exactly the cap, and the oldest
        // seqs are the ones dropped.
        let overflow = 5;
        for seq in 0..(TURN_RING_MAX_TURNS + overflow) as u64 {
            ring.record(&k, &turn(0, seq, 1));
        }
        assert_eq!(
            ring.len(&k),
            TURN_RING_MAX_TURNS,
            "capped at the count bound"
        );

        // The lowest `overflow` seqs were evicted; the newest cap-worth remain.
        let cursors: HashMap<SlotId, u64> = [(SlotId(0), 0)].into();
        let seqs: Vec<u64> = ring.replay(&k, &cursors).iter().map(|p| p.seq).collect();
        assert_eq!(seqs.first().copied(), Some(overflow as u64));
        assert_eq!(
            seqs.last().copied(),
            Some((TURN_RING_MAX_TURNS + overflow - 1) as u64),
        );
    }

    #[test]
    fn the_byte_bound_drops_the_oldest_turns_before_the_count_bound() {
        let ring = TurnRing::new();
        let k = key();
        // Large turns so the byte budget binds well before the count would: each is
        // 64 KiB, so the ring holds at most TURN_RING_MAX_BYTES / 64 KiB of them.
        let big = 64 * 1024;
        let per = TURN_RING_MAX_BYTES / big;
        for seq in 0..(per + 3) as u64 {
            ring.record(&k, &turn(0, seq, big));
        }
        assert!(ring.len(&k) <= per, "the byte bound capped the count");
        assert!(
            ring.bytes(&k) <= TURN_RING_MAX_BYTES,
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
        ring.record(&k, &turn(0, 0, 8));
        ring.end_session(&k);
        assert_eq!(ring.len(&k), 0);
        assert!(ring.replay(&k, &[(SlotId(0), 0)].into()).is_empty());
    }
}
