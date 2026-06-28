//! The ack-beacon side-channel driver helpers, shared by the client and relay.
//!
//! [`spawn_beacon_reader`] and [`flush_beacon`] are free functions over a
//! `quinn::Connection` / `quinn::SendStream` — they own no `Link` state, so they
//! live here in the transport crate where both endpoints use one tested copy
//! rather than two divergent duplicates. Cancel-safety is the whole reason this
//! is a module: the reader task assembles complete frames off a dedicated
//! read-loop (never a `read_exact` dropped mid-frame inside a `select!`), and
//! `flush_beacon` pushes only on advance so a healthy link sends nothing.
//!
//! See `proto::beacon` for the wire frame these helpers read and write.

use rally_point_proto::beacon;
use tokio::sync::watch;

/// Spawns a dedicated task that reads the peer's beacon uni-stream and forwards
/// each complete delivered-through cursor over a `watch` channel.
///
/// The stream is accepted lazily *inside* the task: `open_uni` completes locally
/// (no peer round-trip), but the peer's outbound stream isn't visible to
/// `accept_uni` until its first write, and a one-way-traffic link may never send
/// a beacon — accepting in the dial/link-setup flow would block until a timeout
/// on every such link. Accepting here means a link with no inbound beacons just
/// waits harmlessly.
///
/// Reading the stream here — not in the driver's `select!` — is what makes the
/// beacon cancel-safe: a `read_exact` dropped mid-frame inside a `select!` branch
/// would lose the consumed bytes and desync the framing, handing a garbage `u64`
/// to `retire_through`. This task assembles complete 8-byte frames and forwards
/// them; `watch::Receiver::changed` in the driver's `select!` is cancel-safe.
///
/// `watch` (not `mpsc`) because monotonic cursors subsume their predecessors: the
/// latest always suffices, so a non-blocking overwrite that drops intermediates
/// loses nothing and never back-pressures the reader. The channel is initialized
/// to `None` (seq 0 is a valid cursor, so 0 is not the sentinel).
pub fn spawn_beacon_reader(connection: quinn::Connection) -> watch::Receiver<Option<u64>> {
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        // Lazy accept: waits for the peer to open its beacon stream. A link that
        // never sends a beacon (one-way traffic, or the peer has nothing to retire)
        // parks here forever, which is harmless — the driver's `changed()` never
        // fires and `retire_through` is simply never called.
        let mut recv = match connection.accept_uni().await {
            Ok(recv) => recv,
            // The connection closed before the peer opened a beacon stream. Drop the
            // sender so the driver's `changed()` returns an error, surfacing the
            // closed link (the driver disables the branch on Err rather than spin).
            Err(_) => return,
        };

        let mut buf = [0u8; beacon::BEACON_FRAME_LEN];
        loop {
            // read_exact assembles a complete frame before returning; if it is
            // dropped (task cancelled, stream closed), no partial frame escapes.
            match recv.read_exact(&mut buf).await {
                Ok(()) => {
                    let cursor = beacon::decode_frame(&buf);
                    // Non-blocking: overwrites the held value. A stuck consumer
                    // (the driver not draining) can't stall the reader.
                    let _ = tx.send(Some(cursor));
                }
                // Stream ended (peer closed) or errored. Drop the sender so the
                // driver learns the beacon is gone.
                Err(_) => return,
            }
        }
    });
    rx
}

/// Pushes the local delivered-through cursor to the peer over the beacon stream,
/// but only when it advanced past the last value sent. A healthy link with a
/// static receive prefix (the peer hasn't delivered anything new) sends nothing —
/// the beacon is push-on-advance, not on a timer.
///
/// `last_sent` tracks the highest cursor pushed so the caller can coalesce: pass
/// the same `&mut` each call. A write failure (broken stream) is swallowed — a
/// lost beacon push is recoverable: the cursor advances again on the next
/// delivery, and the hard cap still bounds the window if the peer is truly stuck.
pub async fn flush_beacon(
    beacon_send: &mut quinn::SendStream,
    last_sent: &mut Option<u64>,
    delivered_through: Option<u64>,
) {
    let Some(cursor) = delivered_through else {
        // Nothing delivered yet; nothing to push.
        return;
    };
    if matches!(last_sent, Some(prev) if *prev >= cursor) {
        // Already pushed this or a later cursor; no-op.
        return;
    }
    let frame = beacon::encode_frame(cursor);
    if beacon_send.write_all(&frame).await.is_ok() {
        *last_sent = Some(cursor);
    }
}
