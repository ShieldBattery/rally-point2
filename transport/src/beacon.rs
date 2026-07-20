//! The ack-beacon side-channel driver helpers, shared by the client and relay.
//!
//! [`spawn_beacon_reader`] and [`BeaconWriter`] own no `Link` state, so they live
//! here in the transport crate where both endpoints use one tested copy rather
//! than two divergent duplicates. Cancel-safety is the whole reason this is a
//! module: the reader task assembles complete frames off a dedicated read-loop
//! (never a `read_exact` dropped mid-frame inside a `select!`), and
//! [`BeaconWriter`] pushes only on advance so a healthy link sends nothing.
//!
//! See `proto::beacon` for the wire frame these helpers read and write.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use rally_point_proto::beacon;
use rally_point_proto::ids::SlotId;
use tokio::sync::Notify;

/// The driver's receive handle for the beacon reader task: a per-slot
/// latest-value cell, not a queue.
///
/// Cursors are cumulative — a slot's newer cursor subsumes every older one — so
/// whatever a driver misses while it isn't draining collapses to exactly one
/// pending value per slot: the newest. That coalescing (rather than a bounded
/// queue that drops on full) is load-bearing, not an optimization: the sender
/// pushes a cursor only when it *advances*, and the beacon may be the only
/// retirement path left when the reverse datagram path is lost. The last
/// cursor before traffic stops therefore has no successor to supersede it — a
/// queue that dropped it on overflow would leave the peer re-carrying its
/// already-delivered unacked tail for the rest of the connection, exactly the
/// stall the beacon exists to rescue.
pub struct BeaconCursors {
    inner: Arc<CursorCell>,
}

/// The shared state between the reader task (folds cursors in) and the driver
/// (takes them out).
struct CursorCell {
    /// Per-slot newest delivered-through cursor not yet taken by the driver.
    /// Max-merged on every decoded frame; each slot is independent (a slot-0
    /// advance never subsumes a slot-1 advance), which is why this is a map and
    /// not a single latest value.
    pending: Mutex<HashMap<SlotId, u64>>,
    /// Wakes the driver's [`BeaconCursors::recv`].
    notify: Notify,
    /// Set (then notified) when the reader task ends — the peer's beacon stream
    /// closed or errored, or the connection closed before one was opened.
    closed: AtomicBool,
}

impl BeaconCursors {
    /// The newest pending cursor for some slot, or `None` once the reader task
    /// has ended and every pending cursor has been taken.
    ///
    /// Cancel-safe for a `select!` branch: a returned value is removed and
    /// yielded within a single poll, and the only await point holds nothing —
    /// a cancelled `recv` loses no cursor. Like an `mpsc` receiver, `None` is
    /// terminal, and a caller should disable its branch on it (every later
    /// poll would return `None` again, spinning the loop).
    pub async fn recv(&mut self) -> Option<(SlotId, u64)> {
        loop {
            if let Some(entry) = self.take_pending() {
                return Some(entry);
            }
            if self.inner.closed.load(Ordering::Acquire) {
                // A cursor folded in between the take above and this check is
                // the reader's last word: hand it out before going terminal.
                return self.take_pending();
            }
            // A fold between the empty take above and this await left a stored
            // permit, so `notified` returns at once — no wakeup is missable.
            self.inner.notify.notified().await;
        }
    }

    /// Removes and returns some slot's pending cursor.
    fn take_pending(&self) -> Option<(SlotId, u64)> {
        let mut pending = self.inner.pending.lock().unwrap();
        let slot = *pending.keys().next()?;
        let cursor = pending.remove(&slot).expect("key was just read");
        Some((slot, cursor))
    }
}

/// Push-on-advance beacon state for one link.
///
/// The writer owns both the per-slot last-sent cursors and a reusable wire
/// buffer. One flush can accept any iterator of `(slot, delivered-through)`
/// pairs; every advancing cursor is encoded into that buffer and the whole
/// batch is written with one stream operation. Callers therefore do not need
/// to allocate a temporary `HashMap`, and a multi-slot client update does not
/// perform one write per twelve-byte frame.
#[derive(Default)]
pub struct BeaconWriter {
    last_sent: HashMap<SlotId, u64>,
    write_buf: Vec<u8>,
}

impl BeaconWriter {
    /// Creates empty writer state for a new beacon stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes every cursor that advanced past the last value successfully sent
    /// for its slot. `delivered_through` must contain at most one value per slot.
    ///
    /// A static receive prefix produces an empty batch and no write. A stream
    /// failure leaves `last_sent` unchanged; the link is already failing, and
    /// retaining the old cursor truth is the conservative state if its caller
    /// gets another chance to flush before teardown.
    pub async fn flush<I>(&mut self, beacon_send: &mut quinn::SendStream, delivered_through: I)
    where
        I: IntoIterator<Item = (SlotId, u64)>,
    {
        self.write_buf.clear();
        for (slot, cursor) in delivered_through {
            if matches!(self.last_sent.get(&slot), Some(prev) if *prev >= cursor) {
                continue;
            }
            self.write_buf
                .extend_from_slice(&beacon::encode_frame(slot, cursor));
        }

        if self.write_buf.is_empty() || beacon_send.write_all(&self.write_buf).await.is_err() {
            return;
        }

        // The buffer contains only frames produced by `encode_frame` above, so
        // every chunk has the exact valid width. Decode after the successful
        // write so a failed write cannot advance `last_sent` prematurely.
        for frame in self.write_buf.chunks_exact(beacon::BEACON_FRAME_LEN) {
            let (slot, cursor) = beacon::decode_frame(frame)
                .expect("BeaconWriter only buffers frames produced by encode_frame");
            self.last_sent.insert(slot, cursor);
        }
    }
}

/// Folds a decoded cursor into the cell (max-merge — a stale or reordered frame
/// never regresses a newer pending value) and wakes the driver.
fn fold_cursor(inner: &CursorCell, slot: SlotId, cursor: u64) {
    {
        let mut pending = inner.pending.lock().unwrap();
        let entry = pending.entry(slot).or_insert(cursor);
        if *entry < cursor {
            *entry = cursor;
        }
    }
    inner.notify.notify_one();
}

/// Marks the cell closed and wakes the driver so its `recv` can go terminal.
/// A no-op if the driver already dropped its handle.
fn close_cell(cell: &Weak<CursorCell>) {
    if let Some(inner) = cell.upgrade() {
        inner.closed.store(true, Ordering::Release);
        inner.notify.notify_one();
    }
}

/// Spawns a dedicated task that reads the peer's beacon uni-stream and folds
/// each complete `(slot, delivered-through)` cursor into the returned
/// [`BeaconCursors`] cell (per-slot latest value — see its doc for why the
/// newest cursor must always survive a slow driver).
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
/// folds them; [`BeaconCursors::recv`] in the driver's `select!` is cancel-safe.
pub fn spawn_beacon_reader(connection: quinn::Connection) -> BeaconCursors {
    let inner = Arc::new(CursorCell {
        pending: Mutex::new(HashMap::new()),
        notify: Notify::new(),
        closed: AtomicBool::new(false),
    });
    // The task holds only a weak handle, so a driver that dropped its
    // `BeaconCursors` doesn't keep the cell alive, and the task can notice the
    // orphaning (a failed upgrade) and stop.
    let cell = Arc::downgrade(&inner);
    tokio::spawn(async move {
        // Lazy accept: waits for the peer to open its beacon stream. A link that
        // never sends a beacon (one-way traffic, or the peer has nothing to retire)
        // parks here forever, which is harmless — the driver's `recv()` never
        // fires and `retire_through` is simply never called.
        let mut recv = match connection.accept_uni().await {
            Ok(recv) => recv,
            // The connection closed before the peer opened a beacon stream.
            // Close the cell so the driver's `recv()` goes terminal, surfacing
            // the ended beacon.
            Err(_) => {
                close_cell(&cell);
                return;
            }
        };

        let mut buf = [0u8; beacon::BEACON_FRAME_LEN];
        loop {
            // read_exact assembles a complete frame before returning; if it is
            // dropped (task cancelled, stream closed), no partial frame escapes.
            match recv.read_exact(&mut buf).await {
                Ok(()) => {
                    match beacon::decode_frame(&buf) {
                        Ok((slot, cursor)) => {
                            // The driver dropped its handle: the task is
                            // orphaned with nowhere to fold, so stop.
                            let Some(inner) = cell.upgrade() else {
                                return;
                            };
                            fold_cursor(&inner, slot, cursor);
                        }
                        // A malformed slot (out of SlotId range). Drop the frame
                        // rather than fold garbage into retire_through; the stream
                        // stays framed, so the next read resyncs cleanly.
                        Err(error) => {
                            tracing::debug!(%error, "dropping malformed beacon frame");
                        }
                    }
                }
                // Stream ended (peer closed) or errored. Close the cell so the
                // driver learns the beacon is gone.
                Err(_) => {
                    close_cell(&cell);
                    return;
                }
            }
        }
    });
    BeaconCursors { inner }
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

    #[tokio::test]
    async fn writer_batches_advances_and_suppresses_static_cursors() {
        let (writer_conn, reader_conn, _writer_ep, _reader_ep) = connected_connections().await;
        let mut rx = spawn_beacon_reader(reader_conn);
        let mut send = writer_conn.open_uni().await.unwrap();
        let mut writer = BeaconWriter::new();

        writer
            .flush(&mut send, [(SlotId(0), 3), (SlotId(1), 7)])
            .await;
        assert_eq!(
            writer.write_buf.len(),
            2 * beacon::BEACON_FRAME_LEN,
            "both advancing cursors share one wire buffer",
        );

        let mut received = HashMap::new();
        for _ in 0..2 {
            let (slot, cursor) = timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("both batched cursors must arrive")
                .expect("the reader remains live");
            received.insert(slot, cursor);
        }
        assert_eq!(received.get(&SlotId(0)), Some(&3));
        assert_eq!(received.get(&SlotId(1)), Some(&7));

        writer
            .flush(&mut send, [(SlotId(0), 3), (SlotId(1), 6)])
            .await;
        assert!(
            writer.write_buf.is_empty(),
            "equal and regressing cursors produce no write batch",
        );
        assert!(
            timeout(Duration::from_millis(25), rx.recv()).await.is_err(),
            "a static prefix stays quiet",
        );

        writer
            .flush(&mut send, [(SlotId(0), 4), (SlotId(1), 7)])
            .await;
        assert_eq!(writer.write_buf.len(), beacon::BEACON_FRAME_LEN);
        assert_eq!(
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("the later advance must arrive"),
            Some((SlotId(0), 4)),
        );
    }

    /// The final cursor before traffic stops must survive an arbitrarily slow
    /// driver: it has no successor to supersede it, and the sender pushes only
    /// on advance, so losing it would leave the peer re-carrying its
    /// already-delivered unacked tail for the rest of the connection. A flood
    /// far past any queue's depth, drained only afterwards, must still hand
    /// the driver the newest cursor.
    #[tokio::test]
    async fn the_final_cursor_survives_a_driver_that_drains_late() {
        let (writer_conn, reader_conn, _writer_ep, _reader_ep) = connected_connections().await;
        let mut rx = spawn_beacon_reader(reader_conn);

        // Flood one slot without draining `rx` at all — every intermediate value
        // is superseded, but the last one is the durable fact.
        let mut send = writer_conn.open_uni().await.unwrap();
        const FLOOD: u64 = 400;
        for cursor in 0..FLOOD {
            send.write_all(&beacon::encode_frame(SlotId(0), cursor))
                .await
                .unwrap();
        }
        // Let the reader consume the whole stream before the late drain.
        sleep(Duration::from_millis(200)).await;

        let delivered = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a pending cursor must be receivable")
            .expect("the reader is still alive");
        assert_eq!(
            delivered,
            (SlotId(0), FLOOD - 1),
            "the newest cursor survives however far the driver fell behind",
        );

        // And the reader keeps serving later advances after the flood.
        send.write_all(&beacon::encode_frame(SlotId(0), 9999))
            .await
            .unwrap();
        let later = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a later advance must still arrive")
            .expect("the reader is still alive");
        assert_eq!(later, (SlotId(0), 9999));
    }

    /// Each slot's cursor is independent — a slot-0 advance never subsumes a
    /// slot-1 advance — so a late drain yields the newest value for *every*
    /// slot, not one global latest.
    #[tokio::test]
    async fn coalescing_is_per_slot_not_global() {
        let (writer_conn, reader_conn, _writer_ep, _reader_ep) = connected_connections().await;
        let mut rx = spawn_beacon_reader(reader_conn);

        let mut send = writer_conn.open_uni().await.unwrap();
        for cursor in 0..100u64 {
            send.write_all(&beacon::encode_frame(SlotId(0), cursor))
                .await
                .unwrap();
            send.write_all(&beacon::encode_frame(SlotId(1), cursor * 2))
                .await
                .unwrap();
        }
        sleep(Duration::from_millis(200)).await;

        let mut newest: HashMap<SlotId, u64> = HashMap::new();
        for _ in 0..2 {
            let (slot, cursor) = timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("both slots' cursors must be pending")
                .expect("the reader is still alive");
            newest.insert(slot, cursor);
        }
        assert_eq!(newest.get(&SlotId(0)), Some(&99));
        assert_eq!(newest.get(&SlotId(1)), Some(&198));
    }

    /// A closed beacon stream goes terminal — but never before the last folded
    /// cursor has been handed out.
    #[tokio::test]
    async fn recv_goes_terminal_only_after_the_last_cursor_is_taken() {
        let (writer_conn, reader_conn, _writer_ep, _reader_ep) = connected_connections().await;
        let mut rx = spawn_beacon_reader(reader_conn);

        let mut send = writer_conn.open_uni().await.unwrap();
        send.write_all(&beacon::encode_frame(SlotId(3), 42))
            .await
            .unwrap();
        // Finish the stream: the reader ends after folding the frame.
        send.finish().unwrap();

        let first = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the folded cursor must be receivable");
        assert_eq!(first, Some((SlotId(3), 42)));
        let second = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("recv must go terminal, not park");
        assert_eq!(
            second, None,
            "an ended reader with nothing pending is terminal"
        );
    }
}
