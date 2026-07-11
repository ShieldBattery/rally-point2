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
                            // can't stall the reader. A momentarily full channel
                            // must not permanently kill reverse-path retirement,
                            // so a full channel drops just this frame and keeps
                            // reading; only a dropped receiver ends the task.
                            match tx.try_send(frame) {
                                Ok(()) => {}
                                // The driver fell briefly behind and its channel
                                // is full. Drop this one cursor and keep reading:
                                // the cursor is monotonic per slot and
                                // `flush_beacon` pushes on advance, so the next
                                // delivery advance re-sends a strictly higher
                                // cursor for the slot — a dropped intermediate
                                // loses nothing durable, and the reader stays
                                // alive to carry that later value once the driver
                                // drains. Returning here instead would strand the
                                // link on lost acks for its whole lifetime, right
                                // when the beacon should be rescuing it from the
                                // terminal unacked-window cap.
                                Err(mpsc::error::TrySendError::Full(_)) => {}
                                // The driver dropped its receiver: the task is
                                // orphaned with nowhere to forward, so stop.
                                Err(mpsc::error::TrySendError::Closed(_)) => return,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::quic::{client_config, server_config};

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

    /// Brings up a loopback QUIC connection, returning both raw ends plus the
    /// endpoints (kept alive by the caller). The first connection is the beacon
    /// writer (opens the uni-stream), the second is handed to the reader.
    async fn connected_connections() -> (
        quinn::Connection,
        quinn::Connection,
        quinn::Endpoint,
        quinn::Endpoint,
    ) {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_cfg = client_config(roots).unwrap();

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

    /// A driver that briefly stops draining fills the forwarding channel. The
    /// reader must drop the overflow and stay alive, so that a *later* cursor —
    /// the one the beacon exists to deliver — still reaches the driver once it
    /// resumes. The old code returned unconditionally on a full channel, which
    /// permanently killed reverse-path retirement and stranded the link on a lost
    /// ack until the unacked-window cap tripped.
    #[tokio::test]
    async fn full_channel_drops_frames_but_keeps_reading() {
        let (writer_conn, reader_conn, _writer_ep, _reader_ep) = connected_connections().await;

        // The reader lazily accepts the peer's beacon uni-stream and forwards
        // each cursor over the returned channel (depth 256).
        let mut rx = spawn_beacon_reader(reader_conn);

        // Flood one slot with far more cursors than the channel can hold, without
        // draining `rx`. The reader forwards the prefix, fills the channel, then
        // must hit `Full` on the remainder.
        let mut send = writer_conn.open_uni().await.unwrap();
        const FLOOD: u64 = 400;
        for cursor in 0..FLOOD {
            send.write_all(&beacon::encode_frame(SlotId(0), cursor))
                .await
                .unwrap();
        }

        // Give the reader time to drain the stream into the (now full) channel and
        // drop the overflow. If it had exited, dropping its `connection` would
        // close the link and fail the writes below.
        sleep(Duration::from_millis(200)).await;

        // Drain the forwarded prefix so the channel has room again.
        while rx.try_recv().is_ok() {}

        // A later delivery advance pushes a strictly higher cursor. It must reach
        // the driver — proof the reader survived the full channel.
        send.write_all(&beacon::encode_frame(SlotId(0), 9999))
            .await
            .unwrap();

        // Look for 9999 under one overall timeout, tolerating stragglers: the
        // drain above races the reader task, so a pre-drain cursor it was still
        // forwarding can land in the channel after the drain and arrive first.
        // That's not the behavior under test, so skip anything that isn't 9999
        // rather than asserting on the very first frame.
        let delivered = timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Some(frame) if frame.1 == 9999 => return Some(frame),
                    Some(_stale) => continue,
                    None => return None,
                }
            }
        })
        .await
        .expect("the reader must still be forwarding after a full channel");
        assert_eq!(
            delivered,
            Some((SlotId(0), 9999)),
            "a briefly full channel must not permanently kill the beacon reader",
        );
    }
}
