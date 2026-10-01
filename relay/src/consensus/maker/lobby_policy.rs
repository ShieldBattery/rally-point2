//! The immutable descriptor policy for pre-game lobby commands.

use super::*;

impl DecisionMaker {
    /// Checks only the descriptor's immutable allow-list for a command a peer
    /// relay already admitted. A receiving relay cannot evict a peer-homed slot.
    pub fn allows_mesh_lobby_command(&self, slot: SlotId, payload: &[u8]) -> bool {
        self.lobby_policy
            .as_ref()
            .is_none_or(|policy| policy.admits(slot, payload))
    }

    /// Closes this relay's home-authored lobby policy epoch.
    ///
    /// This does not affect turns, game-start reports, or peer-delivered lobby
    /// commands. The session's home relays each make this cut under their own
    /// ingress gate before an attested failed-setup result may rely on the
    /// absence of another policy violation.
    pub fn settle_lobby(&mut self) {
        self.lobby_closed = true;
    }

    /// Every slot this relay itself evicted for a pre-game lobby-policy
    /// violation, in deterministic order for retained load-state snapshots.
    pub fn lobby_violations(&self) -> Vec<SlotId> {
        let mut slots: Vec<_> = self
            .evictions
            .iter()
            .filter_map(|(&slot, &cause)| (cause == EvictionCause::LobbyViolation).then_some(slot))
            .collect();
        slots.sort_unstable();
        slots
    }

    /// Checks a home slot and records an eviction for a pre-start mismatch.
    pub fn admit_lobby_command(&mut self, slot: SlotId, payload: &[u8]) -> LobbyCommandVerdict {
        if self.eviction(slot).is_some() {
            return LobbyCommandVerdict::AlreadyEvicted;
        }
        if self.lobby_closed {
            return LobbyCommandVerdict::DroppedAfterSettlement;
        }
        let Some(policy) = &self.lobby_policy else {
            return LobbyCommandVerdict::Allowed;
        };
        if policy.admits(slot, payload) {
            return LobbyCommandVerdict::Allowed;
        }
        if self.has_started(slot) {
            return LobbyCommandVerdict::DroppedAfterStart;
        }
        self.mark_evicted(slot, EvictionCause::LobbyViolation);
        LobbyCommandVerdict::Violation
    }
}
