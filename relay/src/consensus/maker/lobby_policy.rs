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

    /// Checks a home slot and records an eviction for a pre-start mismatch.
    pub fn admit_lobby_command(&mut self, slot: SlotId, payload: &[u8]) -> LobbyCommandVerdict {
        if self.eviction(slot).is_some() {
            return LobbyCommandVerdict::AlreadyEvicted;
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
