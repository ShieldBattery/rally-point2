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
//! synced leave to the other relays (`LeaveDirective`); **delivered-through and
//! resume cursors**, whose reliable cumulative snapshots recover state ordinary
//! packet acks or a prior connection did not; and the **oversize-turn divert**
//! (`OversizeTurn`), where QUIC stream reliability stands in for the redundancy
//! no datagram bundle could give the turn.
//!
//! This mirrors the client-edge [`control`](crate::control) reader/writer: the
//! read loop lives in its own task so a `read_exact` never crosses a `select!`
//! boundary and desyncs the framing, the length prefix is validated against the
//! frame cap before any allocation, and the caller does its own dispatch off the
//! decoded frames the reader forwards.

use prost::Message;
use rally_point_proto::control_stream::{
    CONTROL_LEN_PREFIX, ControlStreamError, MAX_CONTROL_FRAME_LEN, encode_frame,
};
use rally_point_proto::messages::MeshControlFrame;
use tokio::sync::mpsc;

use crate::control::read_one_frame;

/// Depth of the reader-task → driver channel. Most mesh control frames are rare,
/// while delivered-through cursors can arrive as a maintenance burst with one
/// independently framed message per active session. The bounded channel lets
/// that burst backpressure the reliable stream without losing a frame, and the
/// driver drains it promptly without putting the control path on the datagram
/// hot loop.
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
        let Some(frame) = read_one_frame::<MeshControlFrame>(&mut recv, "mesh control").await
        else {
            return;
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

/// Writes several independently framed [`MeshControlFrame`]s with one stream
/// write. Each frame keeps the exact same length-prefix + protobuf encoding as
/// [`send_mesh_control_frame`], so the ordinary reader decodes the batch as the
/// same ordered sequence of frames; only the number of application writes is
/// reduced.
///
/// This is intended for link-wide maintenance that discovers many independent
/// per-session cursor advances at once. An empty slice is a no-op. Every frame
/// is size-checked before the stream is touched, so an invalid frame cannot
/// leave a partially written batch on the stream.
pub async fn send_mesh_control_frames(
    control_send: &mut quinn::SendStream,
    frames: &[MeshControlFrame],
) -> Result<(), MeshControlSendError> {
    let encoded = encode_mesh_control_frames(frames)?;
    if encoded.is_empty() {
        return Ok(());
    }
    control_send.write_all(&encoded).await?;
    Ok(())
}

/// Encodes an ordered control-frame batch without allocating a temporary
/// buffer per frame. The wire remains a concatenation of the ordinary framing,
/// not a new aggregate message, so peers need no protocol change.
fn encode_mesh_control_frames(frames: &[MeshControlFrame]) -> Result<Vec<u8>, ControlStreamError> {
    let mut encoded_len = 0usize;
    for frame in frames {
        let frame_len = frame.encoded_len();
        if frame_len > MAX_CONTROL_FRAME_LEN {
            return Err(ControlStreamError::FrameTooLarge { len: frame_len });
        }
        encoded_len = encoded_len.saturating_add(CONTROL_LEN_PREFIX + frame_len);
    }

    let mut encoded = Vec::with_capacity(encoded_len);
    for frame in frames {
        let frame_len = frame.encoded_len();
        encoded.extend_from_slice(&(frame_len as u32).to_le_bytes());
        frame.encode(&mut encoded).expect("Vec write is infallible");
    }
    Ok(encoded)
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use rally_point_proto::ids::SlotId;
    use rally_point_proto::messages::{MeshAckCursor, MeshAckCursors, Payload, mesh_control_frame};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::quic::{mesh_client_config, server_config};

    fn self_signed() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        (vec![cert_der.clone()], key, cert_der)
    }

    async fn connected_mesh_connections() -> (
        quinn::Connection,
        quinn::Connection,
        quinn::Endpoint,
        quinn::Endpoint,
    ) {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let (dial_chain, dial_key, _) = self_signed();
        let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let accept = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = accept.await.unwrap();
        (client_conn, server_conn, client, server)
    }

    fn ack_cursors_frame(session: u64, slot: SlotId, through: u64) -> MeshControlFrame {
        MeshControlFrame {
            session,
            kind: Some(mesh_control_frame::Kind::MeshAckCursors(MeshAckCursors {
                cursors: vec![MeshAckCursor {
                    slot: u32::from(slot.0),
                    delivered_through: through,
                }],
            })),
        }
    }

    #[test]
    fn batch_encoding_is_the_ordered_concatenation_of_single_frame_encoding() {
        let frames = [
            ack_cursors_frame(7, SlotId(0), 41),
            ack_cursors_frame(9, SlotId(3), 88),
        ];
        let batch = encode_mesh_control_frames(&frames).unwrap();

        let mut separately = Vec::new();
        for frame in &frames {
            separately.extend_from_slice(&encode_frame(frame).unwrap());
        }
        assert_eq!(batch, separately);
        assert!(encode_mesh_control_frames(&[]).unwrap().is_empty());
    }

    #[test]
    fn batch_encoding_rejects_an_oversize_member_before_returning_bytes() {
        let frames = [
            ack_cursors_frame(7, SlotId(0), 41),
            MeshControlFrame {
                session: 9,
                kind: Some(mesh_control_frame::Kind::OversizeTurn(Payload {
                    commands: vec![0; MAX_CONTROL_FRAME_LEN + 1].into(),
                    ..Default::default()
                })),
            },
        ];

        assert!(matches!(
            encode_mesh_control_frames(&frames),
            Err(ControlStreamError::FrameTooLarge { .. }),
        ));
    }

    #[tokio::test]
    async fn one_batch_write_is_read_as_multiple_control_frames() {
        let (client_conn, server_conn, _client_ep, _server_ep) = connected_mesh_connections().await;
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let accept = tokio::spawn(async move {
            let (_send, recv) = server_conn.accept_bi().await.unwrap();
            spawn_mesh_control_reader(recv)
        });
        let expected = [
            ack_cursors_frame(7, SlotId(0), 41),
            ack_cursors_frame(9, SlotId(3), 88),
        ];

        send_mesh_control_frames(&mut send, &expected)
            .await
            .unwrap();
        let mut received = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .expect("peer accepted the batch's stream")
            .unwrap();
        for frame in expected {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), received.recv())
                    .await
                    .expect("reader decoded the next frame"),
                Some(frame),
            );
        }
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn batch_write_surfaces_a_peer_stopped_stream() {
        let (client_conn, server_conn, _client_ep, _server_ep) = connected_mesh_connections().await;
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        let accept = tokio::spawn(async move { server_conn.accept_bi().await.unwrap() });

        send_mesh_control_frame(&mut send, &ack_cursors_frame(7, SlotId(0), 41))
            .await
            .unwrap();
        let (_peer_send, mut peer_recv) = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .expect("peer accepted the established stream")
            .unwrap();
        let stop_code = quinn::VarInt::from_u32(23);
        peer_recv.stop(stop_code).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), send.stopped())
                .await
                .expect("STOP_SENDING reached the writer")
                .unwrap(),
            Some(stop_code),
        );

        assert!(matches!(
            send_mesh_control_frames(
                &mut send,
                &[ack_cursors_frame(9, SlotId(3), 88)],
            )
            .await,
            Err(MeshControlSendError::Write(quinn::WriteError::Stopped(code)))
                if code == stop_code,
        ));
    }
}
