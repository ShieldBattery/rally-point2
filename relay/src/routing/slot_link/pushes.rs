//! The control-stream push arms: one function per kind of directive the relay
//! writes down a slot's reliable stream. They are near-identical by design - a
//! failed write means the stream is dead, whichever frame kind hit it, so every
//! one but the fence probe ends the link.

use super::*;

/// Writes a synced leave for another slot down this client's control stream.
pub(super) async fn push_leave(ctx: &mut SlotLinkCtx, leave: LeaveDirective) -> ControlFlow<()> {
    let result =
        rally_point_transport::control::send_control_leave(&mut ctx.control_send, leave).await;
    record_leave_control_write(
        &ctx.decision_makers,
        &ctx.key,
        ctx.slot,
        ctx.connection_epoch,
        &leave,
        false,
        result.is_ok(),
    );
    if let Err(error) = result {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "leave control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes the session-start directive down this client's control stream.
pub(super) async fn push_session_start(
    ctx: &mut SlotLinkCtx,
    initial_buffer_turns: Option<u32>,
) -> ControlFlow<()> {
    if let Err(error) = rally_point_transport::control::send_control_session_start(
        &mut ctx.control_send,
        initial_buffer_turns,
    )
    .await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "session-start control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes a load-state fence probe down this client's control stream.
pub(super) async fn push_load_state_probe(ctx: &mut SlotLinkCtx, probe_id: u64) -> ControlFlow<()> {
    if let Err(error) = rally_point_transport::control::send_control_load_state_probe(
        &mut ctx.control_send,
        probe_id,
    )
    .await
    {
        tracing::debug!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "load-state fence probe write failed; leaving the slot unfenced",
        );
    }
    ControlFlow::Continue(())
}

/// Writes a slot-connectivity change down this client's control stream.
pub(super) async fn push_connectivity(
    ctx: &mut SlotLinkCtx,
    (subject, connected, subject_epoch): ConnectivityChange,
) -> ControlFlow<()> {
    if let Err(error) = rally_point_transport::control::send_control_connectivity(
        &mut ctx.control_send,
        subject.0,
        connected,
        subject_epoch,
    )
    .await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "connectivity control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes the session's region-label map down this client's control stream.
pub(super) async fn push_region_labels(
    ctx: &mut SlotLinkCtx,
    labels: Vec<RegionLabel>,
) -> ControlFlow<()> {
    if let Err(error) =
        rally_point_transport::control::send_control_region_labels(&mut ctx.control_send, labels)
            .await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "region-label control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes this client's send-phase directive down this client's control stream.
pub(super) async fn push_phase_directive(
    ctx: &mut SlotLinkCtx,
    directive: PhaseDirective,
) -> ControlFlow<()> {
    if let Err(error) = rally_point_transport::control::send_control_phase_directive(
        &mut ctx.control_send,
        directive,
    )
    .await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "send-phase control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes a lobby command another member authored down this client's control stream.
pub(super) async fn push_lobby(
    ctx: &mut SlotLinkCtx,
    command: rally_point_proto::messages::LobbyCommand,
) -> ControlFlow<()> {
    if let Err(error) =
        rally_point_transport::control::send_control_lobby(&mut ctx.control_send, command).await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "lobby control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes a game-chat message down this client's control stream.
pub(super) async fn push_chat(
    ctx: &mut SlotLinkCtx,
    chat_msg: rally_point_proto::messages::GameChat,
) -> ControlFlow<()> {
    if let Err(error) =
        rally_point_transport::control::send_control_chat(&mut ctx.control_send, chat_msg).await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "chat control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Writes a cosmetic-skin blob down this client's control stream.
pub(super) async fn push_skin(
    ctx: &mut SlotLinkCtx,
    skin: rally_point_proto::messages::PlayerSkin,
) -> ControlFlow<()> {
    if let Err(error) =
        rally_point_transport::control::send_control_skin(&mut ctx.control_send, skin).await
    {
        tracing::info!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            %error,
            "skin control-stream push failed; closing slot link",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}
