//! The `MeshControlFrame` builders: one per control-frame kind the relay
//! authors, kept together so the wire shape of an outbound frame is in one
//! place rather than beside each of its callers.

use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{
    GameChat, LeaveDirective, LobbyCommand, MeshControlFrame, PlayerSkin, RequestDrop,
    SessionStart, SlotConnectivity, SlotDeparted, SlotPresent, SlotStarted, mesh_control_frame,
};

/// Builds a `MeshResumeCursors` mesh control frame for `session`, from
/// `cursors` — each entry an origin slot and the next seq this relay's
/// forward-gate still needs from it — and `resuming`, which decides what an
/// absent slot means to the receiver (see the wire frame's own doc).
pub(super) fn resume_cursors_frame(
    session: SessionId,
    cursors: Vec<(SlotId, u64)>,
    resuming: bool,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: cursors
                    .into_iter()
                    .map(
                        |(slot, next_seq)| rally_point_proto::messages::MeshResumeCursor {
                            origin_slot: u32::from(slot.0),
                            next_seq,
                        },
                    )
                    .collect(),
                resuming,
            },
        )),
    }
}

/// Builds a `MeshAckCursors` mesh control frame for `session`, from `cursors`
/// -- each entry a slot and this link's own delivered-through cursor for it.
/// See [`reconcile_ack_cursors`] for the push-on-advance discipline that
/// drives this, and `MeshControlFrame.mesh_ack_cursors` for why this rides the
/// control stream rather than a dedicated beacon uni-stream.
pub(super) fn ack_cursors_frame(
    session: SessionId,
    cursors: Vec<(SlotId, u64)>,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::MeshAckCursors(
            rally_point_proto::messages::MeshAckCursors {
                cursors: cursors
                    .into_iter()
                    .map(
                        |(slot, delivered_through)| rally_point_proto::messages::MeshAckCursor {
                            slot: u32::from(slot.0),
                            delivered_through,
                        },
                    )
                    .collect(),
            },
        )),
    }
}

/// Builds a `RequestDrop` mesh control frame for `session`, carrying the target
/// slot and the relay-stamped requester.
pub(super) fn request_drop_frame(
    session: SessionId,
    target: SlotId,
    requester: SlotId,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
            slot: u32::from(target.0),
            requester: u32::from(requester.0),
        })),
    }
}

/// The wire value of [`FinalizeDropResult::outcome`] for a successful
/// finalization (see the proto message docs).
pub(crate) const FINALIZE_OUTCOME_FINALIZED: u32 = 1;
/// [`FinalizeDropResult::outcome`]: rejected, the slot has a live generation.
pub(crate) const FINALIZE_OUTCOME_REJECTED_LIVE: u32 = 2;
/// [`FinalizeDropResult::outcome`]: rejected, no gap-free cursor to seal.
pub(crate) const FINALIZE_OUTCOME_REJECTED_NO_CURSOR: u32 = 3;

/// Builds a `SlotPresent` mesh control frame for `session`.
pub(super) fn slot_present_frame(session: SessionId, slot: SlotId) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotPresent(SlotPresent {
            slot: u32::from(slot.0),
        })),
    }
}

/// Builds a `SlotStarted` mesh control frame for `session`.
pub(super) fn slot_started_frame(session: SessionId, slot: SlotId) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotStarted(SlotStarted {
            slot: u32::from(slot.0),
        })),
    }
}

/// Builds a `SessionStart` mesh control frame for `session`, stamping the
/// computed initial buffer depth (`None` when the authoring relay sized none).
pub(super) fn session_start_frame(
    session: SessionId,
    initial_buffer_turns: Option<u32>,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns,
        })),
    }
}

/// Builds a `SlotConnectivity` mesh control frame for `session`.
pub(super) fn slot_connectivity_frame(
    session: SessionId,
    slot: SlotId,
    connected: bool,
    connection_epoch: Option<u64>,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: u32::from(slot.0),
                connected,
                connection_epoch,
            },
        )),
    }
}

/// Builds a `SlotDeparted` mesh control frame for `session`.
///
/// `result` is the departing slot's home-authored end-of-game result echo, if it
/// reported one before departing: its fields ride the frame so every peer folds
/// the identical result into its departure record (an empty payload — no result —
/// leaves the echo fields at their defaults, which peers read as "no result").
pub(super) fn slot_departed_frame(
    session: SessionId,
    slot: SlotId,
    stamps: &crate::consensus::DepartureStamps,
    reason: u32,
    connection_epoch: Option<u64>,
) -> MeshControlFrame {
    let (result_payload, result_arrival_ms, result_session_frame, result_slot_frame) =
        match stamps.result.clone() {
            Some(echo) => (
                echo.payload.into(),
                echo.arrival_ms,
                echo.session_frame,
                echo.slot_frame,
            ),
            None => (Vec::new().into(), 0, None, None),
        };
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            // Carried from the record so a reconcile re-send of a
            // home-finalized drop keeps its proof — the receiving sanitizer
            // strips any dropped count that arrives without it, and a
            // control-link failure can leave this frame as the only carrier.
            finalized: stamps.finalized,
            slot: u32::from(slot.0),
            last_frame: stamps.last_frame.map(|f| f.0),
            reachable_frame: stamps.reachable_frame,
            reason,
            result_payload,
            result_arrival_ms,
            result_session_frame,
            result_slot_frame,
            connection_epoch,
            final_turn_count: stamps.final_turn_count,
        })),
    }
}

/// Builds a `LeaveDirective` mesh control frame for `session`.
pub(super) fn leave_directive_frame(session: SessionId, leave: LeaveDirective) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(leave)),
    }
}

/// Builds a `LobbyCommand` mesh control frame for `session`.
pub(super) fn lobby_command_frame(session: SessionId, command: LobbyCommand) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::LobbyCommand(command)),
    }
}

/// Builds a `GameChat` mesh control frame for `session`.
pub(super) fn chat_frame(session: SessionId, chat: GameChat) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::GameChat(chat)),
    }
}

/// Builds a `PlayerSkin` mesh control frame for `session`.
pub(super) fn skin_frame(session: SessionId, skin: PlayerSkin) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::PlayerSkin(skin)),
    }
}
