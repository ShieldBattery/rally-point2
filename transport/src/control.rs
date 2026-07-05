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

use prost::bytes::Bytes;
use rally_point_proto::control_stream::{
    CONTROL_LEN_PREFIX, ControlStreamError, decode_frame, encode_frame, frame_len,
};
use rally_point_proto::messages::{
    ControlFrame, GameResult, LeaveDirective, LeaveIntent, Payload, control_frame,
};
use tokio::sync::mpsc;

/// A frame surfaced from the reliable control stream to its consumer.
///
/// The stream carries more than one kind now, so the reader hands back a tagged
/// value rather than a bare payload. On the client edge both `OversizeTurn` and
/// `Leave` arrive (the relay forwards oversize turns and pushes leaves down),
/// but never `LeaveIntent` — a client never receives its own intent back, so
/// the client edge ignores one, mirroring how the relay edge ignores a stray
/// `Leave`. On the relay edge, `OversizeTurn`, `LeaveIntent`, and `GameResult`
/// arrive (a client sends all three up); a relay never receives a `Leave` from
/// another relay on this stream, so the relay edge ignores one.
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
}

/// Depth of the reader-task → driver channel. Oversize turns are rare (the
/// common turn is tens of bytes against a ~1200-byte datagram budget), so this
/// is a backstop against a brief scheduling hiccup, not a tuned buffer.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

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
            let mut prefix = [0u8; CONTROL_LEN_PREFIX];
            if recv.read_exact(&mut prefix).await.is_err() {
                // Stream ended (peer closed it) or the connection died.
                return;
            }
            let len = match frame_len(prefix) {
                Ok(len) => len,
                Err(error) => {
                    // An over-cap length is a protocol violation; the framing
                    // can't be trusted past it, so stop reading. Never an
                    // allocation: the cap check precedes the buffer.
                    tracing::warn!(%error, "control stream framing violation; ignoring stream");
                    return;
                }
            };
            let mut body = vec![0u8; len];
            if recv.read_exact(&mut body).await.is_err() {
                return;
            }
            let inbound = match decode_frame(&body) {
                Ok(ControlFrame {
                    kind: Some(control_frame::Kind::OversizeTurn(payload)),
                }) => ControlInbound::OversizeTurn(payload),
                Ok(ControlFrame {
                    kind: Some(control_frame::Kind::LeaveDirective(leave)),
                }) => ControlInbound::Leave(leave),
                Ok(ControlFrame {
                    kind: Some(control_frame::Kind::LeaveIntent(LeaveIntent {})),
                }) => ControlInbound::LeaveIntent,
                Ok(ControlFrame {
                    kind: Some(control_frame::Kind::GameResult(GameResult { payload })),
                }) => ControlInbound::GameResult(payload),
                // A frame kind this build predates: skip it, keep the stream.
                Ok(ControlFrame { kind: None }) => {
                    tracing::debug!("skipping unknown control frame kind");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "control frame did not decode; ignoring stream");
                    return;
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
