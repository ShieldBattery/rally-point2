//! The per-slot ordered-release buffer: where a turn waits until the gap below
//! it fills, how the contiguous run below is handed to the game, and the
//! delivery cursor a resume is read back from.

use std::collections::{BTreeMap, HashMap};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use tokio::sync::mpsc;

/// What [`SlotReorder::release_into`] observed while handing released turns to
/// the game.
pub(super) enum Release {
    /// Every releasable turn was handed off (possibly none).
    Delivered,
    /// The game dropped its receiver: a clean stop.
    GameClosed,
    /// The game stopped draining and the inbound buffer filled.
    GameStalled,
}

/// The turns received from the relay that the game has not been handed yet,
/// held per slot until the gap below them fills. The link dedups and orders
/// within a datagram but follows arrival order across them, so the ordering the
/// game sees is restored here, never on the wire — and both delivery paths (a
/// datagram's fresh turns and an oversize turn off the reliable control stream)
/// feed this one buffer, so a turn is released the same way whichever path
/// brought it.
///
/// The cursor per slot — the lowest seq not yet handed to the game — is also
/// the authoritative per-slot delivery high-water mark: it is the top of the
/// contiguous run delivered to the game, and thus the "next needed" seq
/// presented as the resume cursor on a reconnect, so the relay replays exactly
/// the turns missed and this buffer (plus the link's dedup) absorbs any overlap
/// the replay carries. The whole thing is preserved across a reconnect so turns
/// received but not yet released aren't re-asked-for or lost.
#[derive(Default)]
pub(super) struct SlotReorder {
    /// Per peer slot, the lowest seq not yet handed to the game.
    next_seq: HashMap<SlotId, u64>,
    /// Per peer slot, turns that arrived ahead of its cursor.
    pending: HashMap<SlotId, BTreeMap<u64, Payload>>,
}

impl SlotReorder {
    /// Buffers one received turn for `slot`, registering the slot as one this
    /// client has heard from (which is what puts it in the resume cursors and
    /// the delivered-through beacon pushes, even while nothing is releasable
    /// yet).
    ///
    /// A turn below its slot's next-needed seq has already been handed to the
    /// game — a resume replays turns the relay cannot know arrived — so it is
    /// dropped rather than buffered: the release only ever removes the entry
    /// sitting exactly at the cursor, and the cursor never rewinds, so a turn
    /// buffered beneath it could never be delivered again anyway.
    pub(super) fn observe(&mut self, slot: SlotId, payload: Payload) {
        let slot_next = self.next_seq.entry(slot).or_insert(0);
        if payload.seq >= *slot_next {
            self.pending
                .entry(slot)
                .or_default()
                .insert(payload.seq, payload);
        }
    }

    /// Releases each slot's contiguous run of buffered turns to the game,
    /// holding the rest. Hands off without ever awaiting: blocking on a full
    /// channel would park the whole driver — no acks, no outbound turns, no
    /// link-failure detection — behind a stalled consumer.
    pub(super) fn release_into(&mut self, inbound: &mpsc::Sender<Payload>) -> Release {
        for (slot, slot_next) in self.next_seq.iter_mut() {
            let Some(slot_pending) = self.pending.get_mut(slot) else {
                continue;
            };
            while let Some(payload) = slot_pending.remove(slot_next) {
                match inbound.try_send(payload) {
                    Ok(()) => *slot_next += 1,
                    Err(mpsc::error::TrySendError::Full(payload)) => {
                        // Put the held turn back before surfacing the stall.
                        slot_pending.insert(*slot_next, payload);
                        return Release::GameStalled;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return Release::GameClosed,
                }
            }
        }
        Release::Delivered
    }

    /// The per-slot resume cursors to present on a reconnect: for each peer slot
    /// this client has received from, the seq it next needs. The relay replays
    /// every recorded turn at or past the cursor and nothing below it, and the
    /// dedup absorbs any overlap. A peer this driver has never received a turn
    /// from has no cursor to state, so it is simply absent — and the relay
    /// replays such a slot from the start of what it still holds, which is what
    /// un-wedges a client that dropped before a peer's first turn ever reached
    /// it. The dedup absorbs that overlap the same way, so an empty set is a
    /// valid ask, not a request for nothing.
    pub(super) fn cursors(&self) -> Vec<(SlotId, u64)> {
        self.next_seq
            .iter()
            .map(|(&slot, &next)| (slot, next))
            .collect()
    }

    /// The slots this client has received a turn from — the ones a
    /// delivered-through cursor is worth pushing back to the peer for.
    pub(super) fn slots(&self) -> impl Iterator<Item = SlotId> + '_ {
        self.next_seq.keys().copied()
    }

    /// The lowest seq `slot` has not yet been handed to the game. Zero for a
    /// slot nothing has ever arrived from.
    #[cfg(test)]
    pub(super) fn next_needed(&self, slot: SlotId) -> u64 {
        self.next_seq.get(&slot).copied().unwrap_or(0)
    }

    /// How many turns `slot` is holding unreleased, behind a gap.
    #[cfg(test)]
    pub(super) fn buffered(&self, slot: SlotId) -> usize {
        self.pending.get(&slot).map_or(0, BTreeMap::len)
    }
}
