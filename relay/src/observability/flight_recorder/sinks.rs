//! Where flushed [`FlightBlob`](super::FlightBlob)s go: the dev/loopback
//! [`FileSink`] and the production [`CoordinatorSink`], plus the shipment
//! type and queue-depth constants that connect the latter to the relay's
//! coordinator control connection.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use bytes::Bytes;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;
use tokio::sync::{mpsc, oneshot};

use super::events::{FlightBlob, FlightEvent};

/// Where flushed blobs go. Implementations persist one blob per call; the blob
/// header carries the tenant/session/relay identity the store keys on (so the
/// signature stays one argument and can never disagree with the envelope).
///
/// Hand-rolled boxed-future signature (not `async fn`) so the trait stays
/// object-safe — the recorder holds it as `Arc<dyn FlightSink>`.
pub trait FlightSink: Send + Sync {
    /// Persists `blob`. An error is logged by the caller and the blob is lost —
    /// flight data is observability, never correctness, so a failed store must
    /// not wedge a session close or a drain.
    fn store<'a>(
        &'a self,
        blob: &'a FlightBlob,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>>;
}

/// The dev/loopback sink: one JSON file per blob at
/// `<dir>/<tenant>/<session>/<relay_id>.json`. The tenant-first prefix mirrors
/// the coordinator's durable store (DigitalOcean Spaces): the same
/// tenant/session/relay shape, just rooted under a retention-class prefix
/// there instead of a directory here. No retention: files accumulate until
/// deleted by hand (the S3 lifecycle rules are the production retention
/// story).
pub struct FileSink {
    dir: PathBuf,
}

impl FileSink {
    /// A sink rooted at `dir` (created on first store if absent).
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

/// Reduces a path component sourced from wire data to a safe file name:
/// alphanumerics, `.`, `_`, and `-` pass; anything else (separators included)
/// becomes `_`. Tenant ids come from trusted coordinator descriptors, but a
/// file path is the one place a stray `/` would change meaning, so the sink
/// does not rely on that trust.
fn sanitize_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl FlightSink for FileSink {
    fn store<'a>(
        &'a self,
        blob: &'a FlightBlob,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        let dir = self
            .dir
            .join(sanitize_component(&blob.tenant))
            .join(blob.session.to_string());
        let path = dir.join(format!("{}.json", blob.relay_id));
        let json = serde_json::to_vec_pretty(blob).expect("a flight blob always serializes");
        Box::pin(async move {
            // Plain std::fs on a blocking worker: the write is small and rare
            // (session close / drain), and this avoids growing tokio's feature
            // set for one path.
            tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&path, &json)
            })
            .await
            .map_err(std::io::Error::other)?
        })
    }
}

/// The largest **compressed** flight payload [`CoordinatorSink`] will ship. A shipped
/// payload is a zstd-compressed compact-JSON document; this bounds its post-compression
/// size, the exact byte count the relay asks the coordinator to presign an upload for.
/// The rings ([`MAX_EVENTS_PER_SESSION`](super::MAX_EVENTS_PER_SESSION), [`MAX_SAMPLES_PER_SESSION`](super::MAX_SAMPLES_PER_SESSION)) bound a real
/// blob's *uncompressed* size far below this, and compression only shrinks it, so the
/// cap never trips on genuine data; it stays as a wire-hygiene backstop so a
/// pathological (e.g. incompressible) serialization can never ask the coordinator to
/// grant an unbounded upload.
pub const MAX_SHIPPED_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// The depth of the bounded channel a [`CoordinatorSink`] hands shipments to the
/// coordinator control connection through. Flushes are rare (session close, drain),
/// and the connection ships up to
/// [`MAX_INFLIGHT_FLIGHT_UPLOADS`](crate::coordinator::client::MAX_INFLIGHT_FLIGHT_UPLOADS)
/// recordings at once, so the queue drains several times faster than shipping strictly
/// one at a time — deep enough that a mass session teardown's burst is absorbed rather
/// than shed. A full queue means the connection is wedged or gone (or a burst large
/// enough to outrun even the concurrent drain); the sink then drops the blob rather
/// than blocking a session teardown on observability — flight data is never
/// backpressure.
pub const FLIGHT_SHIP_QUEUE: usize = 32;

/// How many session flushes the drain's wholesale flush ([`FlightRecorder::flush_all`](super::FlightRecorder::flush_all))
/// runs at once. Kept below [`FLIGHT_SHIP_QUEUE`] so the drain's own fan-out can
/// never fill the [`CoordinatorSink`] shipment queue by itself — with headroom
/// left for close-time flushes racing the drain.
pub const DRAIN_FLUSH_CONCURRENCY: usize = 16;

/// One flushed recording handed to the coordinator control connection: the metadata
/// the relay's upload request carries, the compressed bytes it PUTs to storage, and a
/// one-shot the connection fires once the recording is **stored**.
///
/// The sink awaits that `sent` ack, so the drain path's
/// [`DRAIN_FLUSH_TIMEOUT`](super::DRAIN_FLUSH_TIMEOUT)-bounded [`FlightRecorder::flush_all`](super::FlightRecorder::flush_all) waits for real
/// storage rather than mere enqueueing. The ack fires only after a successful upload
/// PUT; a dropped sender (the coordinator refused the upload, the PUT failed or timed
/// out, or the connection tore down) resolves the sink's await as an error, so the
/// recording is reported lost rather than stored.
pub struct FlightShipment {
    /// The tenant the recording's session belongs to.
    pub tenant: TenantId,
    /// The coordinator-assigned session id the recording covers.
    pub session: SessionId,
    /// Whether the recording's own events contain a confirmed desync — the coordinator
    /// combines this with its own desync record to pin the retention class.
    pub desynced: bool,
    /// The compressed recording bytes (zstd of compact JSON), the exact payload the
    /// relay PUTs to the presigned URL. Cheaply cloneable so an in-progress upload can
    /// own a copy while the shipment stays parked for a re-request across a reconnect.
    pub payload: Bytes,
    /// Fired by the connection once the recording is stored (a successful upload PUT).
    /// A dropped sender (an upload refusal, PUT failure/timeout, or connection
    /// teardown) resolves the sink's await as an error, so an unstored recording is
    /// reported lost rather than stored.
    pub sent: oneshot::Sender<()>,
}

/// The production flight sink: hands each flushed blob to the relay's coordinator
/// control connection as a [`FlightShipment`], which the connection uploads to durable
/// storage via a coordinator-minted presigned URL. The relay compresses the blob but
/// holds no long-lived store credentials — only the short-lived URL the coordinator
/// grants per upload — and never reads a stored blob back.
///
/// A `store` call serializes the blob to compact JSON, zstd-compresses it, refuses one
/// whose compressed size exceeds [`MAX_SHIPPED_BLOB_BYTES`], `try_send`s the shipment
/// onto the bounded channel (a full queue is a logged loss, never a block — flight data
/// is observability, not backpressure on a session teardown), then awaits the
/// connection's ack so the drain flush genuinely bounds storage. Delivery is
/// at-least-once: an ambiguous failure re-ships, idempotently overwriting the same
/// object key.
pub struct CoordinatorSink {
    tx: mpsc::Sender<FlightShipment>,
}

impl CoordinatorSink {
    /// Builds a sink over `tx`, the send half of the bounded shipment channel the
    /// coordinator control connection drains. Pair it with the receiver threaded
    /// into
    /// [`run_descriptor_subscriber`](crate::coordinator::client::run_descriptor_subscriber),
    /// which ships each shipment and fires its ack.
    pub fn new(tx: mpsc::Sender<FlightShipment>) -> Self {
        Self { tx }
    }
}

impl FlightSink for CoordinatorSink {
    fn store<'a>(
        &'a self,
        blob: &'a FlightBlob,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        // Derive the shipment metadata from the blob's own header fields (the same
        // single-argument reasoning as the `FlightSink` trait doc: the shipment can
        // never disagree with the envelope). `desynced` is derived by scanning the
        // recording's own events, so the shipping relay reports what it actually
        // saw — the coordinator needs it when its own desync record was lost to a
        // restart.
        let tenant = TenantId(blob.tenant.clone());
        let session = SessionId(blob.session);
        let desynced = blob
            .events
            .iter()
            .any(|record| matches!(record.event, FlightEvent::DesyncDetected { .. }));
        // Compact JSON (not pretty) so the pre-compression bytes are already minimal,
        // then zstd — a recording is repetitive, structured JSON that compresses
        // heavily. The cap bounds the compressed size, the exact count the coordinator
        // presigns the upload for.
        let json = serde_json::to_vec(blob).expect("a flight blob always serializes");
        Box::pin(async move {
            let compressed = zstd::encode_all(&json[..], 0).map_err(|error| {
                std::io::Error::other(format!("compressing flight blob: {error}"))
            })?;
            if compressed.len() > MAX_SHIPPED_BLOB_BYTES {
                tracing::warn!(
                    tenant = tenant.as_ref(),
                    session = session.0,
                    bytes = compressed.len(),
                    cap = MAX_SHIPPED_BLOB_BYTES,
                    "flight recording exceeds the shipping cap; discarding it",
                );
                return Err(std::io::Error::other(
                    "flight recording exceeds the shipping cap",
                ));
            }
            let (sent_tx, sent_rx) = oneshot::channel();
            // A full or closed queue is a lost blob, not a block: never let
            // observability delay a session close or a drain.
            self.tx
                .try_send(FlightShipment {
                    tenant,
                    session,
                    desynced,
                    payload: Bytes::from(compressed),
                    sent: sent_tx,
                })
                .map_err(|error| {
                    std::io::Error::other(format!("flight shipment queue unavailable: {error}"))
                })?;
            // Resolve only once the connection reports the recording stored (a
            // successful upload PUT); a dropped ack sender (a refusal, PUT failure, or
            // teardown) means it was not stored.
            sent_rx
                .await
                .map_err(|_| std::io::Error::other("flight shipment dropped before it was stored"))
        })
    }
}
