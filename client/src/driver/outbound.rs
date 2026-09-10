//! What the game hands up: its produced turns (sent now, or held out a
//! send-phase delay first) and the frames it authors for the reliable control
//! stream — result report, loop-started announcement, lobby commands, chat,
//! skin blobs, drop requests. Grouped because they all end at the same two
//! exits, the datagram path and the control stream.

use std::collections::VecDeque;
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{GameChat, LobbyCommand, Payload, PlayerSkin};
use rally_point_transport::control::{
    send_control_chat, send_control_game_result, send_control_game_started, send_control_lobby,
    send_control_request_drop, send_control_skin,
};
use rally_point_transport::{Link, noq};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::leave_announcer::LeaveAnnouncer;
use crate::phase::{PhaseSlew, PhaseStatus};

use super::send::{OutboundSend, send_game_turn};
use super::session::ArmFlow;
use super::*;

/// One turn the game produced. With no send-phase delay in effect it goes
/// straight to the wire; under a delay it joins the hold queue, and once
/// anything is held every later turn queues behind it so wire order always
/// matches production order.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_outgoing_turn(
    outgoing: Option<Payload>,
    link: &mut Link,
    control_send: &mut noq::SendStream,
    announcer: &mut LeaveAnnouncer,
    next_outbound_seq: &mut u64,
    retention: &mut VecDeque<Payload>,
    retention_bytes: &mut usize,
    own_slot: SlotId,
    flush_deadline: &mut Instant,
    acks_owed: &mut bool,
    outbound: &mpsc::Receiver<Payload>,
    held: &mut VecDeque<(Instant, Payload)>,
    phase_slew: &mut PhaseSlew,
    phase_status: &watch::Sender<PhaseStatus>,
) -> ArmFlow {
    match outgoing {
        // A turn the game produced. Its local echo already ran
        // on the game side; only the wire handoff happens here.
        // With no send-phase delay in effect it goes out
        // immediately, exactly as if the hold queue did not
        // exist. Under a delay it waits in the hold queue for
        // its deadline instead — and once anything is held,
        // every later turn queues behind it even at delay
        // zero, so wire order always matches production order.
        Some(payload) => {
            let now = Instant::now();
            let delay_us = phase_slew.advance(now);
            let _ = phase_status.send_replace(phase_slew.status());
            if delay_us == 0 && held.is_empty() {
                match send_game_turn(
                    link,
                    control_send,
                    announcer,
                    next_outbound_seq,
                    retention,
                    retention_bytes,
                    own_slot,
                    flush_deadline,
                    acks_owed,
                    payload,
                )
                .await
                {
                    OutboundSend::Sent => {}
                    OutboundSend::EndSession(result) => return ArmFlow::End(result),
                }
                // The turn just sent may have been the last one
                // outstanding, in which case a pending leave intent
                // is now ready to go out.
                if let Err(error) = announcer
                    .maybe_send(control_send, outbound, held.is_empty(), link)
                    .await
                {
                    return ArmFlow::End(Err(DriverError::from(error)));
                }
            } else {
                let due = now + Duration::from_micros(delay_us);
                // Never due ahead of an already-held turn: a
                // delay slewing downward must not reorder the
                // wire against production order.
                let due = held.back().map_or(due, |&(prev, _)| due.max(prev));
                held.push_back((due, payload));
                // The memory backstop: a producer outrunning
                // the turn cadence would otherwise grow the
                // hold without bound (the bounded channel is
                // being drained into it). Send the oldest
                // early — order and delivery hold, only its
                // remaining delay is forfeited.
                while held.len() > HELD_TURN_CAP {
                    let Some((_, early)) = held.pop_front() else {
                        break;
                    };
                    match send_game_turn(
                        link,
                        control_send,
                        announcer,
                        next_outbound_seq,
                        retention,
                        retention_bytes,
                        own_slot,
                        flush_deadline,
                        acks_owed,
                        early,
                    )
                    .await
                    {
                        OutboundSend::Sent => {}
                        OutboundSend::EndSession(result) => return ArmFlow::End(result),
                    }
                }
            }
        }
        // The game dropped its sender: a clean stop (after
        // the held-turn drain below the loop — the final turns
        // of a "send, then close" teardown may still be
        // waiting out their phase delay right here).
        None => return ArmFlow::Teardown,
    }
    ArmFlow::Serve
}

/// A held turn's send-phase delay expired: hand it, and any
/// other turn now due behind it, to the wire. This is the only
/// branch that drains the hold queue mid-session, so the
/// announcer check runs after it — the last held turn going out
/// may release a pending leave intent.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_held_due(
    link: &mut Link,
    control_send: &mut noq::SendStream,
    announcer: &mut LeaveAnnouncer,
    next_outbound_seq: &mut u64,
    retention: &mut VecDeque<Payload>,
    retention_bytes: &mut usize,
    own_slot: SlotId,
    flush_deadline: &mut Instant,
    acks_owed: &mut bool,
    outbound: &mpsc::Receiver<Payload>,
    held: &mut VecDeque<(Instant, Payload)>,
) -> ArmFlow {
    let now = Instant::now();
    while held.front().is_some_and(|&(due, _)| due <= now) {
        let Some((_, payload)) = held.pop_front() else {
            break;
        };
        match send_game_turn(
            link,
            control_send,
            announcer,
            next_outbound_seq,
            retention,
            retention_bytes,
            own_slot,
            flush_deadline,
            acks_owed,
            payload,
        )
        .await
        {
            OutboundSend::Sent => {}
            OutboundSend::EndSession(result) => return ArmFlow::End(result),
        }
    }
    if let Err(error) = announcer
        .maybe_send(control_send, outbound, held.is_empty(), link)
        .await
    {
        return ArmFlow::End(Err(DriverError::from(error)));
    }
    ArmFlow::Serve
}

/// The game handed over its end-of-game result report. Send it up
/// the control stream immediately — mid-game, over a fully live
/// link — rather than waiting for any turn drain: a defeat report
/// must go out while the link is still up. At most one is sent; a
/// second payload, or one arriving after the leave intent already
/// went out, is dropped. Disarmed on the channel's first
/// resolution (the payload, or the sender dropping without one),
/// like the leave-intent branch.
pub(super) async fn on_result(
    payload: Option<Vec<u8>>,
    link: &Link,
    control_send: &mut noq::SendStream,
    announcer: &mut LeaveAnnouncer,
    outbound: &mpsc::Receiver<Payload>,
    held: &VecDeque<(Instant, Payload)>,
    result_alive: &mut bool,
) -> ArmFlow {
    match payload {
        Some(payload) => {
            if announcer.result_sent() {
                tracing::debug!("dropping extra game-result payload; one already sent");
            } else if announcer.sent() {
                tracing::debug!("dropping game-result payload arriving after leave intent");
            } else {
                // A best-effort report: a failed send is not worth
                // tearing the driver down over — the link may still
                // be live for play (a mid-game defeat report leaves
                // the game running), and the relay reasons the
                // outcome from the departure that follows. Latch it
                // as sent regardless, so the leave-intent hold
                // releases and no retry piles up.
                if let Err(error) = send_control_game_result(control_send, payload.into()).await {
                    tracing::debug!(
                        %error,
                        "game-result send failed; dropping the report"
                    );
                }
                announcer.note_result_sent();
                // Sending the result may have been the last thing
                // a pending leave intent was holding for.
                if let Err(error) = announcer
                    .maybe_send(control_send, outbound, held.is_empty(), link)
                    .await
                {
                    return ArmFlow::End(Err(DriverError::from(error)));
                }
            }
        }
        // The game dropped its result sender without ever handing
        // one over: nothing to send, and the leave-intent hold is
        // still bounded by the safety timeout.
        None => *result_alive = false,
    }
    ArmFlow::Serve
}

/// The game announced that its loop has begun running. Retain the
/// fact for the session — every later control stream re-asserts it
/// — and write the fieldless `GameStarted` frame up this one at
/// once: it is only useful while fresh, and there is nothing to
/// drain behind it. Best-effort, like a result report: a failed
/// write is logged and left to the next stream's re-assertion. The
/// already-announced case is a no-op: this stream's own
/// re-assertion, or a fence probe answered ahead of it, has already
/// carried the frame. Disarmed on the channel's first resolution,
/// like the leave-intent and result branches.
pub(super) async fn on_game_started(
    signal: Option<()>,
    control_send: &mut noq::SendStream,
    game_started_announced: &mut bool,
    game_started_on_stream: &mut bool,
    game_started_alive: &mut bool,
) -> ArmFlow {
    *game_started_alive = false;
    if signal.is_some() && !*game_started_announced {
        *game_started_announced = true;
        match send_control_game_started(control_send).await {
            Ok(()) => *game_started_on_stream = true,
            Err(error) => tracing::debug!(
                %error,
                "game-started send failed; retrying on the next stream"
            ),
        }
    }
    ArmFlow::Serve
}

/// A lobby command the game authored during setup. Send it up the
/// reliable control stream at once — setup runs before any turn
/// barrier exists, so there is nothing to drain behind. The relay
/// stamps this client's authenticated slot (the `0` here is
/// ignored) and fans it to the other members. Disarmed when the
/// game drops its sender (setup finished). A send failure means the
/// stream (and almost certainly the connection) is gone; a dropped
/// setup command would leave a member's pre-game state incomplete,
/// so it is the same reconnect trigger as an undeliverable oversize
/// turn — except once our leave intent is out, the relay closing
/// the stream under this write is the expected confirmation.
///
/// Unlike an oversize turn, a lobby command is never retained for
/// redelivery on a resume: `LobbyCommand` carries no seq or other
/// origin identity, and the relay's lobby log neither dedups nor
/// rejects a byte-identical repeat — it is simply appended and
/// fanned out again as a second, indistinguishable command. Ever
/// resending one (even only the "recent tail") risks silently
/// corrupting setup state (a double-applied slot/color/ready
/// toggle), which is worse than the narrow gap this leaves: a
/// drop between this write succeeding locally and the relay
/// actually processing it, on a same-relay resume, can still lose
/// a lobby command with no retry. Known and intentionally out of
/// scope until lobby commands carry real delivery confirmation.
pub(super) async fn on_lobby_out(
    bytes: Option<Vec<u8>>,
    control_send: &mut noq::SendStream,
    announcer: &LeaveAnnouncer,
    lobby_out_alive: &mut bool,
) -> ArmFlow {
    match bytes {
        Some(bytes) => {
            let command = LobbyCommand {
                slot: 0,
                payload: bytes.into(),
            };
            if let Err(error) = send_control_lobby(control_send, command).await {
                return ArmFlow::End(announcer.absorb_link_close(Err(DriverError::from(error))));
            }
        }
        None => *lobby_out_alive = false,
    }
    ArmFlow::Serve
}

/// A chat message the game authored — the mid-game counterpart to
/// the lobby branch above. Sent at once, same as a lobby command:
/// chat has no turn barrier or drain to wait behind either. Unlike
/// a lobby command, though, a send failure here is NOT treated as
/// a link failure: chat has no pre-game state a lost message
/// could leave incomplete, so this is best-effort like a
/// `GameResult` send — log it and keep the driver running rather
/// than tearing the session down over a dropped chat line.
/// Disarmed only when the game drops its sender (chat streams for
/// the whole game, unlike lobby).
pub(super) async fn on_chat_out(
    chat: Option<ChatOut>,
    control_send: &mut noq::SendStream,
    chat_out_alive: &mut bool,
) -> ArmFlow {
    match chat {
        Some(ChatOut {
            target_kind,
            target_slot,
            text,
        }) => {
            let message = GameChat {
                slot: 0,
                target_kind,
                target_slot,
                text,
            };
            if let Err(error) = send_control_chat(control_send, message).await {
                tracing::debug!(
                    %error,
                    "game-chat send failed; dropping the message"
                );
            }
        }
        None => *chat_out_alive = false,
    }
    ArmFlow::Serve
}

/// A cosmetic-skin blob the game authored — broadcast to the other
/// members near game start. Sent at once, same as a chat message:
/// there is no turn barrier or drain to wait behind. The relay
/// stamps this client's authenticated slot (the `0` here is ignored)
/// and fans it to the other members. A send failure is best-effort
/// like a chat send — a skin is cosmetic and non-synced, so a lost
/// blob costs only a wrong cosmetic — so log it and keep the driver
/// running rather than tearing the session down. Disarmed only when
/// the game drops its sender.
pub(super) async fn on_skin_out(
    bytes: Option<Vec<u8>>,
    control_send: &mut noq::SendStream,
    skin_out_alive: &mut bool,
) -> ArmFlow {
    match bytes {
        Some(bytes) => {
            let skin = PlayerSkin {
                slot: 0,
                payload: bytes.into(),
            };
            if let Err(error) = send_control_skin(control_send, skin).await {
                tracing::debug!(
                    %error,
                    "player-skin send failed; dropping the blob"
                );
            }
        }
        None => *skin_out_alive = false,
    }
    ArmFlow::Serve
}

/// A manual drop request the game authored: the survivor asked to
/// drop a disconnected member. Send it up the reliable control stream
/// at once — no drain to wait behind, like chat — naming the target
/// slot; the relay stamps this client's authenticated slot as the
/// requester. Best-effort, exactly like chat: a send failure is
/// logged and swallowed rather than treated as a link failure, since
/// a lost request is not correctness-critical — the survivor can
/// simply click again, and the `LeaveDirective` for the target is the
/// only confirmation. Disarmed only when the game drops its sender.
pub(super) async fn on_request_drop(
    target: Option<SlotId>,
    control_send: &mut noq::SendStream,
    request_drop_alive: &mut bool,
) -> ArmFlow {
    match target {
        Some(target) => {
            if let Err(error) = send_control_request_drop(control_send, u32::from(target.0)).await {
                tracing::debug!(
                    %error,
                    target = target.0,
                    "drop-request send failed; dropping the request"
                );
            }
        }
        None => *request_drop_alive = false,
    }
    ArmFlow::Serve
}
