//! The lifecycle fence over relay-stamped slot-connectivity changes: which of
//! them may still move the game's display of a member, and what makes one
//! member's state final for good.

use std::collections::{HashMap, HashSet};

use rally_point_proto::ids::SlotId;

/// One member's physical connection lifecycle as this client last accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConnectivityState {
    pub(super) epoch: u64,
    pub(super) connected: bool,
}

/// Relay-stamped physical connection lifecycle per member, plus the fence that
/// decides which changes may still be applied. Kept across this client's own
/// reconnect so a delayed connectivity frame from another member's superseded
/// link cannot regress the game's display.
///
/// Missing entries retain rolling-upgrade compatibility with relays that do not
/// stamp epochs; once an epoch is present for a slot, an epoch-less frame can
/// no longer downgrade it.
#[derive(Debug, Default)]
pub(super) struct ConnectivityFence {
    /// The live epoch and level per slot.
    current: HashMap<SlotId, ConnectivityState>,
    /// Superseded random epochs, retained for the whole session. They cannot be
    /// bounded safely: epochs have equality semantics, and a delayed reliable
    /// frame has no age after which it becomes safe to accept again.
    retired: HashSet<(SlotId, u64)>,
    /// Slots for which a final synced leave has reached this client. A leave is
    /// terminal game state, so no later physical-link generation may make its
    /// subject appear connected again. Kept across this client's reconnects.
    terminal: HashSet<SlotId>,
}

impl ConnectivityFence {
    /// Records that `slot`'s departure is final: every later connectivity
    /// change for it, of any epoch or none, is refused from here on.
    pub(super) fn mark_terminal(&mut self, slot: SlotId) {
        self.terminal.insert(slot);
    }

    /// Whether this connectivity change may be applied — the same lifecycle
    /// fence the relays use. `Down(E)` is terminal within its own epoch, a
    /// previously unseen `level=true` epoch opens a replacement and retires the
    /// one it supersedes for good, and epoch-less compatibility ends
    /// permanently once an epoch is observed.
    pub(super) fn admit(&mut self, slot: SlotId, connected: bool, observed: Option<u64>) -> bool {
        if self.terminal.contains(&slot) {
            return false;
        }
        if observed.is_some_and(|epoch| self.retired.contains(&(slot, epoch))) {
            return false;
        }
        match (self.current.get(&slot).copied(), observed) {
            (Some(current), Some(epoch)) if current.epoch == epoch => {
                if !current.connected && connected {
                    return false;
                }
                self.current
                    .insert(slot, ConnectivityState { epoch, connected });
                true
            }
            (Some(current), Some(epoch)) if connected => {
                self.retired.insert((slot, current.epoch));
                self.current.insert(
                    slot,
                    ConnectivityState {
                        epoch,
                        connected: true,
                    },
                );
                true
            }
            (Some(_), _) => false,
            (None, Some(epoch)) => {
                self.current
                    .insert(slot, ConnectivityState { epoch, connected });
                true
            }
            (None, None) => true,
        }
    }

    /// The live epoch and level this client holds for `slot`, if it has ever
    /// admitted an epoch-stamped change for it.
    #[cfg(test)]
    pub(super) fn state(&self, slot: SlotId) -> Option<ConnectivityState> {
        self.current.get(&slot).copied()
    }
}
