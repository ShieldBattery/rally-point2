//! The relay ↔ relay mesh control stream's I/O halves: the reader task and the
//! frame writer, over the sans-I/O framing in
//! [`proto::control_stream`](rally_point_proto::control_stream).
//!
//! Each mesh link carries one bidirectional QUIC stream on which both relays
//! write length-prefixed [`MeshControlFrame`]s and read the peer's. The dialer
//! opens the stream right after its hello and the acceptor `accept_bi`s it; each
//! side then writes on its send half and reads the peer's on its recv half. The
//! stream carries what the mesh's datagram path cannot: **synced player-leave
//! propagation** — a relay tells its peers when one of its home clients departs
//! (`SlotDeparted`), and the session's decision authority pushes the resulting
//! synced leave to the other relays (`LeaveDirective`); a drop stops the
//! datagram turn stream that would otherwise carry these, so like presence they
//! ride a reliable stream — and the **oversize-turn divert** (`OversizeTurn`): a
//! turn too large for any mesh datagram travels here, QUIC's stream reliability
//! standing in for the redundancy no bundle could give it, exactly as on the
//! client-edge control stream.
//!
//! This mirrors the client-edge [`control`](crate::control) reader/writer: the
//! read loop lives in its own task so a `read_exact` never crosses a `select!`
//! boundary and desyncs the framing, the length prefix is validated against the
//! frame cap before any allocation, and the caller does its own dispatch off the
//! decoded frames the reader forwards.

use rally_point_proto::control_stream::{
    CONTROL_LEN_PREFIX, ControlStreamError, decode_frame, encode_frame, frame_len,
};
use rally_point_proto::messages::MeshControlFrame;
use tokio::sync::mpsc;

/// Depth of the reader-task → driver channel. Mesh control frames are rare (one
/// per player departure, plus a re-announce on a redialed link), and the driver
/// drains them promptly; this is a backstop against a brief scheduling hiccup,
/// not a tuned buffer.
const MESH_CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Spawns a dedicated task that reads length-prefixed [`MeshControlFrame`]s off
/// `recv` — the mesh control stream's recv half, already located by the caller
/// (from `open_bi`/`accept_bi`) — and forwards each decoded frame over the
/// returned channel.
///
/// A dedicated task for the same reason as the presence and beacon readers: a
/// `read_exact` dropped mid-frame inside a `select!` would desync the
/// length-prefixed framing, so the read loop never crosses a `select!`
/// boundary; the driver receives only complete, decoded frames, over a channel
/// whose `recv` is cancel-safe.
///
/// The length prefix is validated against the frame cap *before* any allocation;
/// an over-cap prefix ends the task (the stream can't be re-framed after a
/// violation). The empty establishment/keepalive frame the dialer writes to make
/// `accept_bi` complete (a zero-session, unset-kind frame) is dropped here rather
/// than forwarded — it carries nothing to dispatch. The task also ends when the
/// stream closes or the driver drops its receiver; either surfaces as `None` on
/// the driver's `recv()`, which the driver treats as the peer's control stream
/// going quiet (not itself a link failure — that surfaces via the datagram path).
pub fn spawn_mesh_control_reader(recv: quinn::RecvStream) -> mpsc::Receiver<MeshControlFrame> {
    let (tx, rx) = mpsc::channel(MESH_CONTROL_CHANNEL_CAPACITY);
    tokio::spawn(read_mesh_control_frames(recv, tx));
    rx
}

/// [`spawn_mesh_control_reader`] for a side that must first *accept* the peer's
/// bidirectional stream before reading it — used where the recv half isn't
/// already located from an `open_bi`/`accept_bi` (e.g. a test harness that opens
/// its own send stream and accepts the peer's separately). Accepting lazily
/// inside the task means a peer that never opens its stream just parks the reader
/// harmlessly. The accepted send half is unused (each side writes only on the
/// stream it opened) and dropped.
pub fn spawn_mesh_control_reader_accepting(
    connection: quinn::Connection,
) -> mpsc::Receiver<MeshControlFrame> {
    let (tx, rx) = mpsc::channel(MESH_CONTROL_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let Ok((_send, recv)) = connection.accept_bi().await else {
            return;
        };
        read_mesh_control_frames(recv, tx).await;
    });
    rx
}

/// Reads length-prefixed [`MeshControlFrame`]s from `recv` and forwards each over
/// `tx` until the stream ends, a framing violation is hit, or the consumer drops
/// its receiver. The empty establishment/keepalive frame is dropped rather than
/// forwarded.
async fn read_mesh_control_frames(mut recv: quinn::RecvStream, tx: mpsc::Sender<MeshControlFrame>) {
    loop {
        let mut prefix = [0u8; CONTROL_LEN_PREFIX];
        if recv.read_exact(&mut prefix).await.is_err() {
            // Stream ended (peer closed it) or the connection died.
            return;
        }
        let len = match frame_len(prefix) {
            Ok(len) => len,
            Err(error) => {
                // An over-cap length is a protocol violation; the framing can't
                // be trusted past it, so stop reading. Never an allocation: the
                // cap check precedes the buffer.
                tracing::warn!(%error, "mesh control stream framing violation; ignoring stream");
                return;
            }
        };
        let mut body = vec![0u8; len];
        if recv.read_exact(&mut body).await.is_err() {
            return;
        }
        let frame: MeshControlFrame = match decode_frame(&body) {
            Ok(frame) => frame,
            Err(error) => {
                tracing::warn!(%error, "mesh control frame did not decode; ignoring stream");
                return;
            }
        };
        // The empty establishment/keepalive frame (zero session, no kind) exists
        // only to make the peer's `accept_bi` complete; there is nothing to
        // dispatch, so drop it here rather than forward it.
        if frame.session == 0 && frame.kind.is_none() {
            continue;
        }
        if tx.send(frame).await.is_err() {
            // Consumer dropped its receiver: winding down.
            return;
        }
    }
}

/// Writes one [`MeshControlFrame`] onto the mesh control stream. An error means
/// the stream (and almost certainly the connection) is gone; the caller treats
/// it as a link failure — like an oversize turn, this frame has no redundancy
/// re-carrying it, and a dropped leave leaves a survivor stalled.
pub async fn send_mesh_control_frame(
    control_send: &mut quinn::SendStream,
    frame: &MeshControlFrame,
) -> Result<(), MeshControlSendError> {
    let encoded = encode_frame(frame)?;
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Writes the empty establishment/keepalive frame that makes the peer's
/// `accept_bi` complete. QUIC does not surface an opened bidirectional stream to
/// the peer until its opener writes on it, so the dialer sends this the moment it
/// opens the stream — otherwise the acceptor's bounded `accept_bi` would time out
/// on a link that carries no leaves. The reader drops it on receipt.
pub async fn establish_mesh_control(
    control_send: &mut quinn::SendStream,
) -> Result<(), MeshControlSendError> {
    send_mesh_control_frame(control_send, &MeshControlFrame::default()).await
}

/// Why a mesh control frame could not be written to the control stream.
#[derive(Debug, thiserror::Error)]
pub enum MeshControlSendError {
    /// The frame exceeds the control stream's frame cap. Not expected for a
    /// mesh control frame (a `SlotDeparted`/`LeaveDirective` is a handful of
    /// bytes), but surfaced rather than silently truncated.
    #[error("mesh control frame does not fit: {0}")]
    Frame(#[from] ControlStreamError),
    /// The stream is gone (the connection dropped or the peer stopped it).
    #[error("mesh control stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
}
