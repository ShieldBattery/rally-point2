//! The reliable control stream's I/O halves: the reader task and the frame
//! writer, over the sans-I/O framing in
//! [`proto::control_stream`](rally_point_proto::control_stream).
//!
//! Each side of a client ↔ relay connection opens one bidirectional stream
//! after the auth handshake and writes length-prefixed `ControlFrame`s on it;
//! the peer reads the stream it accepted. Both sides use only the send half of
//! the stream they opened — the pairing gives each side a send half that
//! exists from the moment it opens (QUIC's `open_bi` completes locally),
//! instead of one side waiting to accept before it can ever write.
//!
//! Today the stream carries oversize turns — payloads the datagram path can
//! never fit (see [`Link::deliver_external`](crate::Link::deliver_external)
//! for how they rejoin the ordered turn stream) — plus the synced-leave
//! machinery: a relay pushes a `LeaveDirective` down to a surviving client,
//! and a client pushes a `LeaveIntent` up to announce its own clean
//! departure. A client also pushes a `GameResult` up with its end-of-game
//! report. The reader skips a frame kind it doesn't know, so the channel can
//! grow chat/resync frames without a wire break.

use prost::Message;
use prost::bytes::Bytes;
use rally_point_proto::control_stream::{
    CONTROL_LEN_PREFIX, ControlStreamError, decode_frame, encode_frame, frame_len,
};
use rally_point_proto::messages::{
    ControlFrame, GameChat, GameResult, LeaveDirective, LeaveIntent, LobbyCommand, Payload,
    PlayerSkin, RequestDrop, SessionStart, SlotConnectivity, control_frame,
};
use tokio::sync::mpsc;

/// A frame surfaced from the reliable control stream to its consumer.
///
/// The stream carries more than one kind now, so the reader hands back a tagged
/// value rather than a bare payload. On the client edge `OversizeTurn`, `Leave`,
/// `Lobby`, `Chat`, and `Skin` arrive (the relay forwards oversize turns, pushes
/// leaves down, and fans lobby commands, chat messages, and skin blobs from other
/// members down), but never `LeaveIntent` — a client never receives its own intent
/// back, so the client edge ignores one, mirroring how the relay edge ignores a
/// stray `Leave`.
/// On the relay edge, `OversizeTurn`, `LeaveIntent`, `GameResult`, `Lobby`,
/// `Chat`, and `Skin` arrive (a client sends all six up); a relay never receives
/// a `Leave` from another relay on this stream, so the relay edge ignores one.
/// Unlike every other kind, `Lobby`, `Chat`, and `Skin` are legitimate in *both*
/// directions — their `slot` field's authority just flips with direction (see
/// [`LobbyCommand`], [`GameChat`], and [`PlayerSkin`]'s docs).
#[derive(Debug)]
pub enum ControlInbound {
    /// An oversize turn to fold back into the ordered turn stream.
    OversizeTurn(Payload),
    /// A relay-pushed synced player-leave (relay → client). Delivered here, on
    /// the reliable stream, because a drop stops the turn stream that the leave
    /// would otherwise have to ride.
    Leave(LeaveDirective),
    /// A client announcing its own clean departure (client → relay only). A
    /// relay never receives this from another relay, and a client never
    /// receives it at all (it only ever sends one) — either edge that isn't
    /// the relay reading a client's stream ignores it.
    LeaveIntent,
    /// A client's end-of-game result report (client → relay only). The bytes are
    /// opaque here; the relay reading a client's stream stamps and forwards them,
    /// and any other edge ignores a stray one just as it does a `LeaveIntent`.
    GameResult(Bytes),
    /// A lobby command one member authored, in both directions. Client → relay
    /// carries this client's own lobby command (the relay ignores the frame's
    /// `slot` and stamps the authenticated one); relay → client carries another
    /// member's command with the relay's authoritative `slot` naming the author.
    /// The whole message is surfaced so both directions can read the `slot`.
    Lobby(LobbyCommand),
    /// An in-game chat message one member authored, in both directions — the
    /// mid-game counterpart to `Lobby`. Client → relay carries this client's own
    /// message (the relay ignores the frame's `slot` and stamps the
    /// authenticated one); relay → client carries another member's message with
    /// the relay's authoritative `slot` naming the author. The whole message is
    /// surfaced so both directions can read `slot`, `target_kind`, and
    /// `target_slot`.
    Chat(GameChat),
    /// One member's opaque cosmetic-skin blob, in both directions — like `Lobby`
    /// and `Chat`. Client → relay carries this client's own blob (the relay
    /// ignores the frame's `slot` and stamps the authenticated one); relay →
    /// client carries another member's blob with the relay's authoritative `slot`
    /// naming which member it describes, either fanned live or replayed from the
    /// relay's latest-per-slot map when this stream comes up after the blob
    /// flowed. The whole message is surfaced so both directions can read `slot`
    /// and the opaque `payload`.
    Skin(PlayerSkin),
    /// The relay-driven session-start directive (relay → client only): every
    /// expected slot has connected, so the game may begin. A relay never receives
    /// this from a client, so the relay edge ignores a stray one just as it does a
    /// `Leave`. Carries the session's computed initial latency-buffer depth when
    /// the authoring relay sized one (`Some(turns)`) — the game applies it to its
    /// turn buffer before the first frame — or `None` when it sized none (an
    /// authority that predates the field, or a resumed re-home re-push), in which
    /// case the game keeps whatever depth it already seeded.
    SessionStart(Option<u32>),
    /// A relay-pushed slot-connectivity change (relay → client only): a member's
    /// link died (`connected` false) or (re)registered (`connected` true). A relay
    /// never receives this from a client, so the relay edge ignores a stray one
    /// just as it does a `Leave`. The whole message is surfaced so the consumer
    /// reads both `slot` and `connected`.
    Connectivity(SlotConnectivity),
    /// A survivor's manual request to drop a disconnected slot (client → relay
    /// only). Carries only the target slot the requester wants dropped — the
    /// requester itself is bound by the relay to the authenticated connection the
    /// frame arrived on, never read from the wire, so the frame's `requester`
    /// field is deliberately not surfaced here. A client never receives one back
    /// (the relay is the only recipient), so the client edge ignores a stray one
    /// just as it does a `LeaveIntent`.
    RequestDrop(u32),
}

/// Depth of the reader-task → driver channel. Oversize turns are rare (the
/// common turn is tens of bytes against a ~1200-byte datagram budget), so this
/// is a backstop against a brief scheduling hiccup, not a tuned buffer.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Reads one length-prefixed, decoded frame of type `M` off `recv`: the length
/// prefix (validated against the frame cap *before* any allocation), then the
/// body, then [`decode_frame`]. Shared by this module's client ↔ relay reader
/// and [`mesh_control_stream`](crate::mesh_control_stream)'s relay ↔ relay
/// reader — both frame their stream identically and differ only in the
/// message type and in what they do with the result.
///
/// Returns `None` whenever the caller's read loop must stop: the stream ended
/// (the peer closed it or the connection died), a length prefix violated the
/// frame cap, or the body failed to decode. The latter two are protocol
/// violations the framing can't recover from, so they are `warn!`-logged here
/// (tagged with `label`, e.g. `"control"` or `"mesh control"`) before
/// returning `None` — the caller has nothing more useful to add and only needs
/// to know reading is over, not why.
pub(crate) async fn read_one_frame<M: Message + Default>(
    recv: &mut quinn::RecvStream,
    label: &str,
) -> Option<M> {
    let mut prefix = [0u8; CONTROL_LEN_PREFIX];
    if recv.read_exact(&mut prefix).await.is_err() {
        return None;
    }
    let len = match frame_len(prefix) {
        Ok(len) => len,
        Err(error) => {
            // Never an allocation: the cap check precedes the buffer.
            tracing::warn!(%error, "{label} stream framing violation; ignoring stream");
            return None;
        }
    };
    let mut body = vec![0u8; len];
    if recv.read_exact(&mut body).await.is_err() {
        return None;
    }
    match decode_frame(&body) {
        Ok(frame) => Some(frame),
        Err(error) => {
            tracing::warn!(%error, "{label} frame did not decode; ignoring stream");
            None
        }
    }
}

/// Spawns a dedicated task that accepts the peer's control stream, reads its
/// length-prefixed `ControlFrame`s, and forwards each oversize-turn payload
/// over the returned channel.
///
/// A dedicated task for the same reason as the beacon reader: a `read_exact`
/// dropped mid-frame inside a `select!` would desync the length-prefixed
/// framing, so the read loop never crosses a `select!` boundary — the driver
/// receives only complete, decoded payloads, over a channel whose `recv` is
/// cancel-safe. Accepting lazily inside the task means a connection whose peer
/// never sends a control frame just parks the reader harmlessly.
///
/// The length prefix is attacker-facing on the relay side, so it is validated
/// against the frame cap *before* any allocation; an over-cap prefix ends the
/// task (the stream can't be re-framed after a violation). The task also ends
/// when the stream closes or the driver drops its receiver. Either way the
/// dropped sender surfaces as `None` on the driver's `recv()` — a dead control
/// stream is not itself a link failure (that surfaces via the datagram path),
/// but any oversize turn that later needed it will stall the game, so the
/// driver logs it.
pub fn spawn_control_reader(connection: quinn::Connection) -> mpsc::Receiver<ControlInbound> {
    let (tx, rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let Ok((_send_half, mut recv)) = connection.accept_bi().await else {
            // Connection closed before the peer opened its control stream.
            return;
        };
        // The send half of the *peer's* stream is unused by convention — each
        // side writes only on the stream it opened — and dropping it here
        // resets a direction the peer never reads.

        loop {
            let Some(frame) = read_one_frame::<ControlFrame>(&mut recv, "control").await else {
                return;
            };
            let inbound = match frame {
                ControlFrame {
                    kind: Some(control_frame::Kind::OversizeTurn(payload)),
                } => ControlInbound::OversizeTurn(payload),
                ControlFrame {
                    kind: Some(control_frame::Kind::LeaveDirective(leave)),
                } => ControlInbound::Leave(leave),
                ControlFrame {
                    kind: Some(control_frame::Kind::LeaveIntent(LeaveIntent {})),
                } => ControlInbound::LeaveIntent,
                ControlFrame {
                    kind: Some(control_frame::Kind::GameResult(GameResult { payload })),
                } => ControlInbound::GameResult(payload),
                ControlFrame {
                    kind: Some(control_frame::Kind::LobbyCommand(command)),
                } => ControlInbound::Lobby(command),
                ControlFrame {
                    kind: Some(control_frame::Kind::GameChat(chat)),
                } => ControlInbound::Chat(chat),
                ControlFrame {
                    kind: Some(control_frame::Kind::PlayerSkin(skin)),
                } => ControlInbound::Skin(skin),
                ControlFrame {
                    kind:
                        Some(control_frame::Kind::SessionStart(SessionStart {
                            initial_buffer_turns,
                        })),
                } => ControlInbound::SessionStart(initial_buffer_turns),
                ControlFrame {
                    kind: Some(control_frame::Kind::SlotConnectivity(connectivity)),
                } => ControlInbound::Connectivity(connectivity),
                ControlFrame {
                    // Only the target `slot` is surfaced; the wire `requester` is
                    // never trusted (the relay stamps the authenticated slot).
                    kind: Some(control_frame::Kind::RequestDrop(RequestDrop { slot, .. })),
                } => ControlInbound::RequestDrop(slot),
                // A frame kind this build predates: skip it, keep the stream.
                ControlFrame { kind: None } => {
                    tracing::debug!("skipping unknown control frame kind");
                    continue;
                }
            };
            if tx.send(inbound).await.is_err() {
                // Consumer dropped its receiver: winding down.
                return;
            }
        }
    });
    rx
}

/// Writes one oversize turn onto the control stream. An error means the stream
/// (and almost certainly the connection) is gone; the caller must treat it as
/// a link failure — unlike a lost datagram, this payload has no redundancy
/// re-carrying it, so it cannot be silently dropped without desyncing
/// lockstep.
pub async fn send_control_turn(
    control_send: &mut quinn::SendStream,
    payload: Payload,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::OversizeTurn(payload)),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Pushes one synced player-leave down the control stream (relay → client). Like
/// an oversize turn it is reliable and un-redundant: an error means the stream
/// is gone, which the caller treats as that client having left too. Delivering
/// the leave here rather than on the turn envelope is the whole point — a drop
/// stalls the game and stops the datagram turn stream, so the reliable stream is
/// the only path that still reaches a stalled survivor.
pub async fn send_control_leave(
    control_send: &mut quinn::SendStream,
    leave: LeaveDirective,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::LeaveDirective(leave)),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Announces a client's own clean departure up the control stream (client →
/// relay). Sent once, after the client has flushed its final turns, and never
/// acked: the client's confirmation that the relay processed it is the relay
/// closing the link. An error here means the stream (and almost certainly the
/// connection) is already gone, in which case the departure needs no
/// announcing — the relay will observe the link death directly.
pub async fn send_control_leave_intent(
    control_send: &mut quinn::SendStream,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::LeaveIntent(LeaveIntent {})),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Sends a client's end-of-game result report up the control stream (client →
/// relay). Sent once, the moment the game produces the result — mid-game, ahead
/// of any final-turn drain — and never acked: it is a best-effort optimization
/// feed, not a correctness signal, so an error here (the stream or connection
/// gone) needs no recovery — the relay reasons the game's outcome from the
/// departure that follows regardless.
pub async fn send_control_game_result(
    control_send: &mut quinn::SendStream,
    payload: Bytes,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::GameResult(GameResult { payload })),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Sends a lobby command on the control stream, in either direction: a client
/// pushes its own authored command up (leaving `slot` at 0 — the relay stamps
/// the authenticated slot and never trusts a client value), and a relay fans a
/// member's command down with `slot` stamped to the author. Reliable and
/// un-redundant like an oversize turn: an error means the stream (and almost
/// certainly the connection) is gone, so the caller treats it as a link failure
/// — a dropped setup command would leave a member's pre-game state incomplete,
/// so it cannot be silently dropped.
pub async fn send_control_lobby(
    control_send: &mut quinn::SendStream,
    command: LobbyCommand,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::LobbyCommand(command)),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Sends an in-game chat message on the control stream, in either direction: a
/// client pushes its own authored message up (leaving `slot` at 0 — the relay
/// stamps the authenticated slot and never trusts a client value), and a relay
/// fans a member's message down with `slot` stamped to the author. Unlike a
/// lobby command, a failed send here is not correctness-critical for the caller
/// to treat as a link failure — chat has no pre-game state a lost message could
/// leave incomplete — so the client-edge driver logs and continues on an
/// `Err` here rather than propagating it as a fatal error, the same treatment
/// it gives a failed `GameResult` send.
pub async fn send_control_chat(
    control_send: &mut quinn::SendStream,
    chat: GameChat,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::GameChat(chat)),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Sends a cosmetic-skin blob on the control stream, in either direction: a
/// client pushes its own authored blob up (leaving `slot` at 0 — the relay
/// stamps the authenticated slot and never trusts a client value), and a relay
/// fans a member's blob down with `slot` stamped to the author (a live send or a
/// replay from the relay's latest-per-slot map). Like a chat message, a failed
/// send here is not correctness-critical for the caller to treat as a link
/// failure — a skin is cosmetic, non-synced, and best-effort, so a lost blob
/// costs only a wrong cosmetic — so the client-edge driver logs and continues on
/// an `Err` here rather than propagating it as a fatal error, the same treatment
/// it gives a failed `GameChat` send.
pub async fn send_control_skin(
    control_send: &mut quinn::SendStream,
    skin: PlayerSkin,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::PlayerSkin(skin)),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Pushes the session-start directive down the control stream (relay → client),
/// carrying the session's computed initial latency-buffer depth in
/// `initial_buffer_turns` (`Some(turns)`), or `None` when the authoring relay
/// sized none (an authority that predates the field, or a resumed re-home
/// re-push into a running game — where a stale depth must never resize the live
/// buffer). Reliable and un-redundant like a leave: an error means the stream is
/// gone, which the caller treats as that client having left. The relay may send
/// it more than once (a re-push on a late slot, an authority handoff); the client
/// dedups, so a repeat costs only a frame.
pub async fn send_control_session_start(
    control_send: &mut quinn::SendStream,
    initial_buffer_turns: Option<u32>,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns,
        })),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Pushes a slot-connectivity change down the control stream (relay → client):
/// `slot` either lost its link (`connected` false) or (re)registered one
/// (`connected` true). Best-effort and informational — an error means the stream
/// is gone, which the caller treats as that client having left, exactly like a
/// leave or session-start push. The relay may send several over a game (a slot
/// can flip more than once), and a client that missed one simply never sees it.
pub async fn send_control_connectivity(
    control_send: &mut quinn::SendStream,
    slot: u8,
    connected: bool,
    connection_epoch: Option<u64>,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::SlotConnectivity(SlotConnectivity {
            slot: u32::from(slot),
            connected,
            connection_epoch,
        })),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Sends a manual drop request up the control stream (client → relay). `slot` is
/// the disconnected slot the requester wants dropped; the requester is left for
/// the relay to bind to the authenticated connection, so the frame's `requester`
/// field is unset here. Best-effort and un-acked: an error means the stream (and
/// almost certainly the connection) is gone, but a drop request is not
/// correctness-critical the way a turn or lobby command is — a survivor whose
/// request never lands can simply send another once its link is back — so the
/// caller logs and continues rather than treating an error as a link failure,
/// the same treatment a `GameChat` send gets.
pub async fn send_control_request_drop(
    control_send: &mut quinn::SendStream,
    slot: u32,
) -> Result<(), ControlSendError> {
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::RequestDrop(RequestDrop {
            slot,
            requester: 0,
        })),
    };
    let encoded = encode_frame(&frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Why an oversize turn could not be written to the control stream.
#[derive(Debug, thiserror::Error)]
pub enum ControlSendError {
    /// The turn exceeds even the control stream's frame cap — it can be
    /// delivered by no channel at all, so the caller must fail fast rather
    /// than stall lockstep on a turn that will never arrive.
    #[error("turn does not fit a control frame: {0}")]
    Frame(#[from] ControlStreamError),
    /// The stream is gone (the connection dropped or the peer stopped it).
    #[error("control stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
}
