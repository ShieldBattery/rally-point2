//! Registry entry point for the descriptor-bound lobby policy.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LobbyCommandVerdict {
    /// A descriptor has not created this session's decision maker yet.
    AwaitingDescriptor,
    /// The command is permitted by the session's policy, if one exists.
    Allowed,
    /// A started slot sent a command outside its policy; discard it without a penalty.
    DroppedAfterStart,
    /// A pre-start command violated the policy and atomically marked its slot evicted.
    Violation,
    /// Setup finality closed new home-authored lobby commands without a penalty.
    DroppedAfterSettlement,
    /// The slot has already been marked evicted for a policy violation.
    AlreadyEvicted,
}

impl DecisionMakers {
    /// Checks a home client's command against the installed descriptor policy.
    /// A missing maker must be resolved by the caller: managed relays wait for
    /// their descriptor, while standalone relays have no descriptor source.
    pub fn admit_lobby_command(
        &self,
        key: &SessionKey,
        slot: SlotId,
        payload: &[u8],
    ) -> LobbyCommandVerdict {
        self.lock()
            .get_mut(key)
            .map(|maker| maker.admit_lobby_command(slot, payload))
            .unwrap_or(LobbyCommandVerdict::AwaitingDescriptor)
    }

    /// Closes future home-authored lobby ingress if a maker exists, returning whether the
    /// descriptor had established one.
    pub fn settle_lobby(&self, key: &SessionKey) -> bool {
        self.lock()
            .get_mut(key)
            .map(|maker| {
                maker.settle_lobby();
            })
            .is_some()
    }

    /// Checks a peer relay's lobby command without modifying eviction state.
    /// Missing makers allow a command from an authenticated peer whose own
    /// descriptor may have arrived first.
    pub fn allows_mesh_lobby_command(
        &self,
        key: &SessionKey,
        slot: SlotId,
        payload: &[u8],
    ) -> bool {
        self.lock()
            .get(key)
            .is_none_or(|maker| maker.allows_mesh_lobby_command(slot, payload))
    }

    /// Reports a policy violation already marked by `admit_lobby_command`.
    pub fn report_lobby_violation(&self, key: &SessionKey, slot: SlotId) {
        self.emit_notice(RelayNotice::LobbyViolation(
            self.lobby_violation_notice(key, slot),
        ));
    }
}
