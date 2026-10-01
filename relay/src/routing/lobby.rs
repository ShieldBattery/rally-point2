//! Descriptor-bound delivery of home-authored lobby commands and game starts.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::LobbyCommand;

use crate::consensus::LobbyCommandVerdict;
use crate::key::SessionKey;
use crate::mesh::MeshState;

use super::{Sessions, close_slots_for_lobby_violation};

/// Publishes a rate-admitted command after the descriptor policy is available.
/// The caller holds the session ingress gate so retirement cannot interleave
/// policy admission, the local replay log, and mesh fan-out.
pub(crate) fn deliver_lobby_command(
    sessions: &Sessions,
    mesh: &MeshState,
    key: &SessionKey,
    slot: SlotId,
    mut command: LobbyCommand,
) -> LobbyCommandVerdict {
    let verdict = mesh
        .session
        .decision_makers
        .admit_lobby_command(key, slot, &command.payload);
    let verdict = if verdict == LobbyCommandVerdict::AwaitingDescriptor
        && !mesh.session.provisional_turns.armed()
    {
        // Standalone relays have no descriptor source and serve lobby bytes
        // without a coordinator policy.
        LobbyCommandVerdict::Allowed
    } else {
        verdict
    };
    match verdict {
        LobbyCommandVerdict::Allowed => {
            command.slot = u32::from(slot.0);
            if mesh
                .session
                .side_channels
                .lobby
                .deliver(key, command.clone())
            {
                crate::mesh::fan_out_lobby_command(&mesh.links, key, command);
            }
        }
        LobbyCommandVerdict::Violation => {
            mesh.session
                .decision_makers
                .report_lobby_violation(key, slot);
            close_slots_for_lobby_violation(sessions, key, &[slot]);
        }
        LobbyCommandVerdict::AwaitingDescriptor
        | LobbyCommandVerdict::DroppedAfterStart
        | LobbyCommandVerdict::DroppedAfterSettlement
        | LobbyCommandVerdict::AlreadyEvicted => {}
    }
    verdict
}

/// Publishes a home client's first game-loop start report in journal order.
/// A preceding lobby violation evicts the slot before this report can run.
pub(crate) fn report_game_started(mesh: &MeshState, key: &SessionKey, slot: SlotId) {
    if mesh.session.decision_makers.eviction(key, slot).is_some() {
        return;
    }
    mesh.session.decision_makers.note_slot_started(key, slot);
    crate::mesh::fan_out_slot_started(&mesh.links, key, slot);
}
