//! The eviction record: slots this relay closed for good, whether the silence
//! watch named them or a rollback verdict did, and the queue that hands a
//! verdict's slots to the layer that closes links.

use super::*;

/// Why a slot was evicted. Both causes refuse the slot's every later dial
/// without consuming the drop hold its survivors stand on; they differ in what
/// ends its drop. A silent slot's drop is decided by the survivors' own drop
/// request, like any lost client's. A desynced slot's home finalizes the drop
/// the moment its link is down, unprompted, since nothing a survivor does can
/// make the slot's game agree with theirs again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionCause {
    /// The slot's turns stopped reaching its peers before anyone else's did
    /// (see [`DecisionMaker::silent_slot`]).
    Silent,
    /// A rollback session's state hash verdict named the slot: its hash
    /// disagreed with the majority's, or it kept sending turns without
    /// reporting one.
    Desync,
    /// A pre-game lobby command did not match the descriptor allow-list. This
    /// refuses redials but deliberately leaves the drop held and undecided.
    LobbyViolation,
}

/// One slot a rollback verdict named, as
/// [`DecisionMaker::claim_desync_evictions`] hands it over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesyncEviction {
    pub slot: SlotId,
    /// The state hash step whose verdict named the slot.
    pub sync_ordinal: u64,
    /// Whether this relay strictly homes the slot, and so has marked it
    /// evicted and owes the close of its link. Every other relay's part is only
    /// to pass the verdict on to the one that does.
    pub homed: bool,
}

impl DecisionMaker {
    /// Records that this relay evicted `slot` for `cause`, so a re-dial is
    /// refused and the silence watch never names it again. The first cause recorded
    /// stands: a slot already on its way out for one reason is not re-filed
    /// under another. Idempotent.
    pub fn mark_evicted(&mut self, slot: SlotId, cause: EvictionCause) {
        self.evictions.entry(slot).or_insert(cause);
    }

    /// Why this relay evicted `slot`, if it did.
    pub fn eviction(&self, slot: SlotId) -> Option<EvictionCause> {
        self.evictions.get(&slot).copied()
    }

    /// Marks `slot` evicted for desync if this relay strictly homes it —
    /// only the home owns the slot's link, and an open fallback on an empty
    /// (legacy) homed set would have every relay claim it. Returns whether
    /// this relay is that home. The mark lands before the caller closes the
    /// link, so a dial racing the close cannot reinstate the slot.
    pub fn mark_desync_evicted(&mut self, slot: SlotId) -> bool {
        if !self.strictly_homes(slot) {
            return false;
        }
        self.mark_evicted(slot, EvictionCause::Desync);
        true
    }

    /// Queues every slot `verdicts` name for eviction. A verdict that found no
    /// majority names nobody at fault, but the players' simulations no longer
    /// agree and nothing can reconcile them, so it queues every slot in
    /// `required` (the players it compared): the game ends for all of them, and
    /// the tenant voids it rather than having the relay pick a side.
    pub(in crate::consensus) fn queue_desync_evictions(
        &mut self,
        verdicts: &[SyncDivergence],
        required: &[SlotId],
    ) {
        for verdict in verdicts {
            let everyone = if verdict.no_majority { required } else { &[] };
            for &slot in everyone
                .iter()
                .chain(&verdict.diverged)
                .chain(&verdict.missing)
            {
                if !self
                    .pending_desync_evictions
                    .iter()
                    .any(|&(queued, _)| queued == slot)
                {
                    self.pending_desync_evictions
                        .push((slot, verdict.sync_ordinal));
                }
            }
        }
    }

    /// Hands over every slot a verdict queued for eviction since the last
    /// claim, marking each one this relay strictly homes (see
    /// [`mark_desync_evicted`](Self::mark_desync_evicted)). Taking the mark
    /// here, under the same lock as the claim, is what keeps a dial landing
    /// between the claim and the close from being admitted. Each queued slot
    /// is handed over once.
    pub fn claim_desync_evictions(&mut self) -> Vec<DesyncEviction> {
        let pending = std::mem::take(&mut self.pending_desync_evictions);
        pending
            .into_iter()
            .map(|(slot, sync_ordinal)| DesyncEviction {
                slot,
                sync_ordinal,
                homed: self.mark_desync_evicted(slot),
            })
            .collect()
    }
}
