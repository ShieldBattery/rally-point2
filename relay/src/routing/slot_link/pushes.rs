//! The control-stream push arms: one function per kind of directive the relay
//! writes down a slot's reliable stream. They are near-identical by design - a
//! failed write means the stream is dead, whichever frame kind hit it, so every
//! one but the fence probe ends the link.

use super::*;

/// What a failed control-stream write costs, which is the only way these pushes
/// differ from one another.
enum OnWriteFailure {
    /// The stream is gone, so the connection is gone: log it and end the link.
    CloseLink,
    /// The write was a best-effort question, not a directive the client is owed.
    /// Losing it only leaves this slot unanswered; the dead stream ends the link
    /// through its own reader arm, so this arm carries on.
    Continue,
}

/// Runs one control-stream write and turns its outcome into the serve loop's
/// next step. `kind` names the frame in the log line.
async fn write_or_break(
    ctx: &mut SlotLinkCtx,
    kind: &str,
    on_failure: OnWriteFailure,
    write: impl AsyncFnOnce(
        &mut rally_point_transport::noq::SendStream,
    ) -> Result<(), rally_point_transport::control::ControlSendError>,
) -> ControlFlow<()> {
    let result = write(&mut ctx.control_send).await;
    let Err(error) = result else {
        return ControlFlow::Continue(());
    };
    match on_failure {
        OnWriteFailure::CloseLink => {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                %error,
                "{kind} control-stream push failed; closing slot link",
            );
            ControlFlow::Break(())
        }
        OnWriteFailure::Continue => {
            tracing::debug!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                %error,
                "{kind} control-stream push failed; leaving the slot unanswered",
            );
            ControlFlow::Continue(())
        }
    }
}

/// Writes a synced leave for another slot down this client's control stream.
pub(super) async fn push_leave(ctx: &mut SlotLinkCtx, leave: LeaveDirective) -> ControlFlow<()> {
    let flow = write_or_break(ctx, "leave", OnWriteFailure::CloseLink, async |send| {
        rally_point_transport::control::send_control_leave(send, leave).await
    })
    .await;
    record_leave_control_write(
        &ctx.decision_makers,
        &ctx.key,
        ctx.slot,
        ctx.connection_epoch,
        &leave,
        false,
        flow.is_continue(),
    );
    flow
}

/// Writes the session-start directive down this client's control stream.
pub(super) async fn push_session_start(
    ctx: &mut SlotLinkCtx,
    initial_buffer_turns: Option<u32>,
) -> ControlFlow<()> {
    write_or_break(
        ctx,
        "session-start",
        OnWriteFailure::CloseLink,
        async |send| {
            rally_point_transport::control::send_control_session_start(send, initial_buffer_turns)
                .await
        },
    )
    .await
}

/// Writes a load-state fence probe down this client's control stream. The one
/// push a dead stream does not end the link for: the fence answers without this
/// slot rather than stalling the coordinator's question on it.
pub(super) async fn push_load_state_probe(ctx: &mut SlotLinkCtx, probe_id: u64) -> ControlFlow<()> {
    write_or_break(
        ctx,
        "load-state fence probe",
        OnWriteFailure::Continue,
        async |send| {
            rally_point_transport::control::send_control_load_state_probe(send, probe_id).await
        },
    )
    .await
}

/// Writes a slot-connectivity change down this client's control stream.
pub(super) async fn push_connectivity(
    ctx: &mut SlotLinkCtx,
    (subject, connected, subject_epoch): ConnectivityChange,
) -> ControlFlow<()> {
    write_or_break(
        ctx,
        "connectivity",
        OnWriteFailure::CloseLink,
        async |send| {
            rally_point_transport::control::send_control_connectivity(
                send,
                subject.0,
                connected,
                subject_epoch,
            )
            .await
        },
    )
    .await
}

/// Writes the session's region-label map down this client's control stream.
pub(super) async fn push_region_labels(
    ctx: &mut SlotLinkCtx,
    labels: Vec<RegionLabel>,
) -> ControlFlow<()> {
    write_or_break(
        ctx,
        "region-label",
        OnWriteFailure::CloseLink,
        async |send| rally_point_transport::control::send_control_region_labels(send, labels).await,
    )
    .await
}

/// Writes this client's send-phase directive down this client's control stream.
pub(super) async fn push_phase_directive(
    ctx: &mut SlotLinkCtx,
    directive: PhaseDirective,
) -> ControlFlow<()> {
    write_or_break(ctx, "send-phase", OnWriteFailure::CloseLink, async |send| {
        rally_point_transport::control::send_control_phase_directive(send, directive).await
    })
    .await
}

/// Writes a lobby command another member authored down this client's control stream.
pub(super) async fn push_lobby(
    ctx: &mut SlotLinkCtx,
    command: rally_point_proto::messages::LobbyCommand,
) -> ControlFlow<()> {
    write_or_break(ctx, "lobby", OnWriteFailure::CloseLink, async |send| {
        rally_point_transport::control::send_control_lobby(send, command).await
    })
    .await
}

/// Writes a game-chat message down this client's control stream.
pub(super) async fn push_chat(
    ctx: &mut SlotLinkCtx,
    chat_msg: rally_point_proto::messages::GameChat,
) -> ControlFlow<()> {
    write_or_break(ctx, "chat", OnWriteFailure::CloseLink, async |send| {
        rally_point_transport::control::send_control_chat(send, chat_msg).await
    })
    .await
}

/// Writes a cosmetic-skin blob down this client's control stream.
pub(super) async fn push_skin(
    ctx: &mut SlotLinkCtx,
    skin: rally_point_proto::messages::PlayerSkin,
) -> ControlFlow<()> {
    write_or_break(ctx, "skin", OnWriteFailure::CloseLink, async |send| {
        rally_point_transport::control::send_control_skin(send, skin).await
    })
    .await
}
