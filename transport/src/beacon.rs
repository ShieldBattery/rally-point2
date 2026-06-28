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

use std::collections::HashMap;

use rally_point_proto::beacon;
use rally_point_proto::ids::SlotId;
use tokio::sync::mpsc;

/// Spawns a dedicated task that reads the peer's beacon uni-stream and forwards
/// each complete `(slot, delivered-through)` cursor over an `mpsc` channel.
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
/// would lose the consumed bytes and desync the framing, handing a garbage
/// `(slot, cursor)` to `retire_through`. This task assembles complete frames and
/// forwards them; `mpsc::Receiver::recv` in the driver's `select!` is
/// cancel-safe.
///
/// `mpsc` (not `watch`) because each slot carries its own cursor and cursors do
/// not subsume each other across slots — a slot-0 advance and a slot-1 advance
/// are independent, so latest-wins would drop one. Within a slot the cursor is
/// monotonic, so a burst collapses to a prefix the driver drains in order.
pub fn spawn_beacon_reader(connection: quinn::Connection) -> mpsc::Receiver<(SlotId, u64)> {
    // Generous depth: cursors are tiny and a healthy link sends one per delivered
    // turn. A burst under loss is bounded by the number of slots, which is small.
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        // Lazy accept: waits for the peer to open its beacon stream. A link that
        // never sends a beacon (one-way traffic, or the peer has nothing to retire)
        // parks here forever, which is harmless — the driver's `recv()` never
        // fires and `retire_through` is simply never called.
        let mut recv = match connection.accept_uni().await {
            Ok(recv) => recv,
            // The connection closed before the peer opened a beacon stream. Drop the
            // sender so the driver's `recv()` returns None, surfacing the closed
            // link.
            Err(_) => return,
        };

        let mut buf = [0u8; beacon::BEACON_FRAME_LEN];
        loop {
            // read_exact assembles a complete frame before returning; if it is
            // dropped (task cancelled, stream closed), no partial frame escapes.
            match recv.read_exact(&mut buf).await {
                Ok(()) => {
                    match beacon::decode_frame(&buf) {
                        Ok(frame) => {
                            // Non-blocking offer: a stuck driver (not draining)
                            // can't stall the reader. If the channel fills, the
                            // cursor is monotonic per slot so the latest survives
                            // via the channel's later entries; an dropped
                            // intermediate is harmless.
                            if tx.try_send(frame).is_err() {
                                // Channel closed (driver dropped its receiver) or
                                // full (driver fell behind on beacons). Either way
                                // stop reading — a full channel means the driver
                                // isn't keeping up and beacons aren't the priority.
                                return;
                            }
                        }
                        // A malformed slot (out of SlotId range). Drop the frame
                        // rather than forward garbage to retire_through; the stream
                        // stays framed, so the next read resyncs cleanly.
                        Err(error) => {
                            tracing::debug!(%error, "dropping malformed beacon frame");
                        }
                    }
                }
                // Stream ended (peer closed) or errored. Drop the sender so the
                // driver learns the beacon is gone.
                Err(_) => return,
            }
        }
    });
    rx
}

/// Pushes the per-slot delivered-through cursor to the peer over the beacon
/// stream, but only when it advanced past the last value sent for that slot. A
/// healthy link with a static receive prefix (the peer hasn't delivered anything
/// new) sends nothing — the beacon is push-on-advance, not on a timer.
///
/// `last_sent` tracks the highest cursor pushed per slot so the caller can
/// coalesce: pass the same `&mut` each call. A write failure (broken stream) is
/// swallowed — a lost beacon push is recoverable: the cursor advances again on
/// the next delivery, and the hard cap still bounds the window if the peer is
/// truly stuck.
pub async fn flush_beacon(
    beacon_send: &mut quinn::SendStream,
    last_sent: &mut HashMap<SlotId, u64>,
    delivered_through: HashMap<SlotId, u64>,
) {
    for (slot, cursor) in delivered_through {
        if matches!(last_sent.get(&slot), Some(prev) if *prev >= cursor) {
            // Already pushed this or a later cursor for this slot; no-op.
            continue;
        }
        let frame = beacon::encode_frame(slot, cursor);
        if beacon_send.write_all(&frame).await.is_ok() {
            last_sent.insert(slot, cursor);
        }
    }
}
