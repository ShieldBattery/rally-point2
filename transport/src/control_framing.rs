//! The reliable control stream's framing I/O, shared by the client ↔ relay edge
//! and the relay ↔ relay mesh.
//!
//! Both streams are framed identically — a little-endian `u32` length prefix
//! validated against the frame cap, then a protobuf body — and differ only in
//! the message type they carry and in what the caller does with a decoded
//! frame. The read half lives here rather than in either stream's own module so
//! neither one has to depend on the other for it.

use prost::Message;
use rally_point_proto::control_stream::{CONTROL_LEN_PREFIX, decode_frame, frame_len};

/// Reads one length-prefixed, decoded frame of type `M` off `recv`: the length
/// prefix (validated against the frame cap *before* any allocation), then the
/// body, then [`decode_frame`].
///
/// Returns `None` whenever the caller's read loop must stop: the stream ended
/// (the peer closed it or the connection died), a length prefix violated the
/// frame cap, or the body failed to decode. The latter two are protocol
/// violations the framing can't recover from, so they are `warn!`-logged here
/// (tagged with `label`, e.g. `"control"` or `"mesh control"`) before
/// returning `None` — the caller has nothing more useful to add and only needs
/// to know reading is over, not why.
pub(crate) async fn read_one_frame<M: Message + Default>(
    recv: &mut noq::RecvStream,
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
