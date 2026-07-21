//! The flight recorder: per-game observability a reported desync, dispute, or
//! stall can be investigated from after the fact.
//!
//! Each session this relay serves accumulates a bounded in-memory recording —
//! discrete **events** (connects, leaves, buffer directives, desyncs, drop
//! holds, session start/close), periodic **link-health samples**, and per-slot
//! **turn-stream counters** — flushed as one self-describing JSON blob when the
//! session closes and, wholesale, when the relay drains for shutdown. The
//! recorder observes; it never participates: no decision logic reads it, and a
//! full recorder changes nothing but what a flushed blob says it lost.
//!
//! # What is deliberately NOT recorded
//!
//! Raw turn/command bytes and chat are **excluded** — the recording carries
//! counters and envelope facts (seqs, frames, slots), never payload content.
//! Together with the relay's standing PII rule (it never holds user identity;
//! slots resolve to users only in the tenant's own records) this keeps every
//! blob pseudonymous: slot-keyed, content-free. User erasure therefore never
//! touches flight data.
//!
//! # Cost model
//!
//! The per-turn hot path only bumps atomics on a pre-fetched
//! [`SlotCounters`] handle — no lock, no allocation. Events are rare (a handful
//! per session) and take a short per-session mutex. The rings are size-capped
//! ([`MAX_EVENTS_PER_SESSION`], [`MAX_SAMPLES_PER_SESSION`]) with oldest-first
//! eviction and a drop counter, so a pathological session costs bounded memory
//! and its blob says exactly what it lost. A relay-wide sampling tick
//! ([`run_sampler`], every [`SAMPLE_INTERVAL`]) folds the counters and the
//! link conditions the slot links already publish into one sample row per live
//! session — the recorder owns the tick; the hot path never samples.
//!
//! # Flush protocol
//!
//! A flushed recording becomes a [`FlightBlob`] — a versioned envelope with a
//! header (tenant/session/relay identity, start/flush timestamps, overflow
//! counts) plus the events and samples — handed to the configured
//! [`FlightSink`]. Two triggers: **session close** (the relay tore down its
//! last local state for the session — the same moment it reports
//! `SessionClosed` to the coordinator) and **drain** (shutdown flushes every
//! live recording concurrently, bounded by [`DRAIN_FLUSH_TIMEOUT`]). With no
//! sink configured the recorder still records — cheap and bounded — and a
//! flush logs what it discarded rather than storing it.
//!
//! Two sinks exist. The dev/loopback [`FileSink`] (`--flight-dir`) writes one
//! uncompressed pretty-JSON file per blob at
//! `<dir>/<tenant>/<session>/<relay_id>.json` — its value is human inspectability.
//! The [`CoordinatorSink`], installed by default on a coordinator-connected relay,
//! compresses each flushed blob and hands it to the relay's control connection as a
//! [`FlightShipment`]: the relay asks the coordinator for a presigned upload URL, PUTs
//! the compressed bytes straight to durable storage, and reports completion — the blob
//! never rides the control socket, and the relay holds no long-lived store
//! credentials, only the short-lived URL. Both sinks key on the tenant/session/relay
//! identity the blob header carries; the tenant-first prefix is the structural hook
//! for tenant-scoped read authorization.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use parking_lot::Mutex;
use rally_point_proto::control::{DepartureKind, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::mesh::ConditionsRegistry;
use crate::routing::SessionKey;

/// The most events one session's ring holds. Events are rare — connects,
/// leaves, directives, a desync — so a real game records a few dozen; the cap
/// exists for the pathological case (a flapping client reconnecting in a loop)
/// and is what makes the drain-flush arithmetic work: bounded rings × bounded
/// live sessions ⇒ the wholesale flush always fits its deadline.
pub const MAX_EVENTS_PER_SESSION: usize = 1024;

/// The most link-health samples one session's ring holds. At one sample per
/// [`SAMPLE_INTERVAL`] this covers ~85 minutes of game — beyond any realistic
/// session — before eviction begins; the cap bounds a stuck session the same
/// way the event cap does.
pub const MAX_SAMPLES_PER_SESSION: usize = 512;

/// How often the sampling tick folds counters + link conditions into a sample
/// row per live session. Coarse on purpose: samples exist to reconstruct a
/// game's health curve after the fact, not to monitor it live.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// How long the drain path waits for the wholesale flush before abandoning
/// what remains. The arithmetic that makes this safe: rings are size-capped and
/// live sessions are bounded by the relay's capacity, so the total flush volume
/// is a few MB at most — this deadline is generous for any real sink, and it
/// nests inside the 90s drain timeout, itself under Fargate's 120s
/// `stopTimeout`. The size caps on the rings exist precisely so this constant
/// can be small and the drain never wedges on observability.
pub const DRAIN_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// The blob envelope version [`FlightBlob::version`] carries.
pub const BLOB_VERSION: u32 = 1;

/// One discrete thing that happened to a session, as the recorder saw it.
/// Frame/turn coordinates ride inside the variants that have them (apply
/// frames, seqs); the wall-clock stamp lives on the enclosing [`EventRecord`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FlightEvent {
    /// A client's link registered on this relay. `resumed` marks a dial that
    /// presented resume cursors — a reconnect or a re-home re-dial — rather
    /// than a fresh first connect.
    SlotConnected { slot: u8, resumed: bool },
    /// A client's link ended (any exit: clean leave, drop, isolation).
    SlotDisconnected { slot: u8 },
    /// This relay (as session authority) decided the synced leave for a slot.
    LeaveDecided {
        slot: u8,
        kind: DepartureKind,
        apply_frame: u32,
        leave_seq: u32,
    },
    /// This relay (as session authority) queued a latency-buffer change.
    BufferDirective {
        buffer_turns: u32,
        apply_frame: u32,
        decision_seq: u32,
    },
    /// The desync comparator confirmed a divergence.
    DesyncDetected {
        sync_ordinal: u64,
        diverged: Vec<u8>,
        no_majority: bool,
    },
    /// A dropped slot's leave decision was placed on hold (survivors stalled
    /// but the slot not yet removed). The later decision, if one comes, is the
    /// [`LeaveDecided`](Self::LeaveDecided) event — there is no separate
    /// "hold decided" record.
    DropHeld { slot: u8 },
    /// A surviving member's manual drop request was admitted (validated and
    /// rate-cap-passed) against a held slot.
    DropRequested { requester: u8, target: u8 },
    /// The session-start directive fired on this relay (it was the authority
    /// observing full expected-slot coverage). `initial_buffer_turns` is the
    /// latency-buffer depth the authority sized and stamped onto the directive,
    /// or absent when it sized none (nothing observed and no hint).
    SessionStart {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_buffer_turns: Option<u32>,
    },
    /// A resumed (re-home) descriptor was applied — this relay took over an
    /// already-running session, seeded with the given number of
    /// already-decided departures.
    ResumedDescriptorApplied { departed_slots: u32 },
    /// The relay tore down its last local state for the session — the same
    /// moment it reports `SessionClosed` to the coordinator, and the trigger
    /// for this recording's flush.
    SessionClosed,
}

/// One recorded event: what happened and when (unix epoch milliseconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    /// Wall clock at recording, unix epoch milliseconds.
    pub at_ms: u64,
    /// The event itself, flattened so the JSON row reads `{at_ms, event, ...}`.
    #[serde(flatten)]
    pub event: FlightEvent,
}

/// One slot's row in a periodic sample: the turn-stream counters (cumulative
/// since the recording began) plus the latest link conditions the slot's own
/// link task published, when it has any.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotSample {
    pub slot: u8,
    /// Turns from this slot's client accepted by validation (client edge).
    pub turns_validated: u64,
    /// Turns delivered *to* this slot's client (fan-out from peers, local and
    /// mesh alike).
    pub turns_forwarded: u64,
    /// The newest transport seq validated from this slot.
    pub newest_seq: u64,
    /// Duplicate deliveries of this slot's turns the session-level gate dropped.
    pub dedup_drops: u64,
    /// Turns to this slot's client too large for a datagram, diverted onto the
    /// reliable control stream.
    pub oversize_diverts: u64,
    /// Smoothed RTT from the client's QUIC path estimator, microseconds — the
    /// same sample the slot link publishes for the latency-buffer
    /// decision-maker. Absent when the slot has no published conditions (never
    /// sampled, or already disconnected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_us: Option<u32>,
    /// Cumulative packets QUIC declared lost on the client's connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_packets: Option<u64>,
    /// Cumulative packets sent on the client's connection (the loss-rate
    /// denominator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_packets: Option<u64>,
}

/// One periodic sample row: every live slot's counters + link health at one
/// instant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SampleRecord {
    /// Wall clock at sampling, unix epoch milliseconds.
    pub at_ms: u64,
    /// Per-slot rows, sorted by slot.
    pub slots: Vec<SlotSample>,
    /// The worst end-to-end delivery lag across the session's `(origin, dest)`
    /// pairs at sampling time, in turns — newest origin seq the relay has seen
    /// minus the destination's claimed delivered cursor (see
    /// [`crate::delivery`]). Absent until a pair has evidence on both ends (or
    /// on the final flush snapshot, which samples counters only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worst_e2e_lag_turns: Option<u64>,
    /// The session's maximum relay hop count across observed pairs: 1 when
    /// every pair shares a home relay, 2 when any pair crosses the mesh.
    /// Absent like [`worst_e2e_lag_turns`](Self::worst_e2e_lag_turns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_relay_hops: Option<u32>,
}

/// One session's flushed recording: the versioned, self-describing envelope a
/// [`FlightSink`] persists. Everything an investigation needs to key on rides
/// the header, so a blob is meaningful with no context beyond itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlightBlob {
    /// Envelope version ([`BLOB_VERSION`]); bumped on any breaking shape change.
    pub version: u32,
    /// The tenant the session belongs to.
    pub tenant: String,
    /// The coordinator-assigned session id (unique within the tenant).
    pub session: u64,
    /// The recording relay's id (0 for a standalone relay with none assigned).
    pub relay_id: u64,
    /// When the recording began (first touch), unix epoch milliseconds.
    pub started_at_ms: u64,
    /// When the recording was flushed, unix epoch milliseconds.
    pub flushed_at_ms: u64,
    /// Events evicted from the ring before this flush — what the blob lost.
    pub events_dropped: u64,
    /// Samples evicted from the ring before this flush.
    pub samples_dropped: u64,
    pub events: Vec<EventRecord>,
    pub samples: Vec<SampleRecord>,
}

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
/// The rings ([`MAX_EVENTS_PER_SESSION`], [`MAX_SAMPLES_PER_SESSION`]) bound a real
/// blob's *uncompressed* size far below this, and compression only shrinks it, so the
/// cap never trips on genuine data; it stays as a wire-hygiene backstop so a
/// pathological (e.g. incompressible) serialization can never ask the coordinator to
/// grant an unbounded upload.
pub const MAX_SHIPPED_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// The depth of the bounded channel a [`CoordinatorSink`] hands shipments to the
/// coordinator control connection through. Flushes are rare (session close, drain),
/// and the connection ships up to
/// [`MAX_INFLIGHT_FLIGHT_UPLOADS`](crate::coordinator_client::MAX_INFLIGHT_FLIGHT_UPLOADS)
/// recordings at once, so the queue drains several times faster than shipping strictly
/// one at a time — deep enough that a mass session teardown's burst is absorbed rather
/// than shed. A full queue means the connection is wedged or gone (or a burst large
/// enough to outrun even the concurrent drain); the sink then drops the blob rather
/// than blocking a session teardown on observability — flight data is never
/// backpressure.
pub const FLIGHT_SHIP_QUEUE: usize = 32;

/// How many session flushes the drain's wholesale flush ([`FlightRecorder::flush_all`])
/// runs at once. Kept below [`FLIGHT_SHIP_QUEUE`] so the drain's own fan-out can
/// never fill the [`CoordinatorSink`] shipment queue by itself — with headroom
/// left for close-time flushes racing the drain.
pub const DRAIN_FLUSH_CONCURRENCY: usize = 16;

/// One flushed recording handed to the coordinator control connection: the metadata
/// the relay's upload request carries, the compressed bytes it PUTs to storage, and a
/// one-shot the connection fires once the recording is **stored**.
///
/// The sink awaits that `sent` ack, so the drain path's
/// [`DRAIN_FLUSH_TIMEOUT`]-bounded [`FlightRecorder::flush_all`] waits for real
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
    /// [`run_descriptor_subscriber`](crate::coordinator_client::run_descriptor_subscriber),
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

/// One slot's turn-stream counters: plain atomics the hot path bumps through a
/// pre-fetched `Arc` handle — no lock, no allocation per turn. Cumulative for
/// the recording's lifetime; the sampling tick snapshots them into rows, so a
/// reader differences consecutive rows for rates.
#[derive(Default)]
pub struct SlotCounters {
    turns_validated: AtomicU64,
    turns_forwarded: AtomicU64,
    newest_seq: AtomicU64,
    dedup_drops: AtomicU64,
    oversize_diverts: AtomicU64,
}

impl SlotCounters {
    /// One turn from this slot's client passed validation, carrying `seq`.
    pub fn note_validated(&self, seq: u64) {
        self.turns_validated.fetch_add(1, Ordering::Relaxed);
        self.newest_seq.fetch_max(seq, Ordering::Relaxed);
    }

    /// One turn was delivered to this slot's client.
    pub fn note_forwarded(&self) {
        self.turns_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// One turn to this slot's client was diverted onto the reliable control
    /// stream (too large for a datagram).
    pub fn note_oversize_divert(&self) {
        self.oversize_diverts.fetch_add(1, Ordering::Relaxed);
    }

    fn note_dedup_drop(&self) {
        self.dedup_drops.fetch_add(1, Ordering::Relaxed);
    }
}

/// Relay-lifetime work totals used to normalize task CPU during load tests.
///
/// This is derived from the recorder's existing per-slot atomics at task-stats
/// poll time. Closing a quiescent recording first folds its final totals into
/// the retired aggregate, so normal steady-state snapshots remain cumulative
/// when sessions end. The relaxed per-slot loads are suitable for interval
/// telemetry, not a transactional accounting boundary; a forced shutdown drain
/// can race a final counter update from a link that has not quiesced yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayWorkSnapshot {
    /// Client-origin turns that passed validation on their home relay.
    pub client_turns_validated: u64,
    /// Turns dequeued for a locally connected destination, including reliable
    /// oversize diverts. This measures local forwarding work, not confirmed
    /// receipt by the client: the destination's send can still fail afterward.
    pub local_turn_deliveries: u64,
    /// Local deliveries too large for a datagram and diverted to the reliable
    /// control stream.
    pub oversize_diverts: u64,
}

impl RelayWorkSnapshot {
    fn accumulate(&mut self, other: Self) {
        self.client_turns_validated = self
            .client_turns_validated
            .saturating_add(other.client_turns_validated);
        self.local_turn_deliveries = self
            .local_turn_deliveries
            .saturating_add(other.local_turn_deliveries);
        self.oversize_diverts = self.oversize_diverts.saturating_add(other.oversize_diverts);
    }
}

/// One session's live recording: the bounded rings plus the per-slot counters.
struct SessionRecording {
    started_at_ms: u64,
    events: Mutex<VecDeque<EventRecord>>,
    events_dropped: AtomicU64,
    samples: Mutex<VecDeque<SampleRecord>>,
    samples_dropped: AtomicU64,
    counters: Mutex<HashMap<SlotId, Arc<SlotCounters>>>,
}

impl SessionRecording {
    fn new() -> Self {
        Self {
            started_at_ms: now_ms(),
            events: Mutex::new(VecDeque::new()),
            events_dropped: AtomicU64::new(0),
            samples: Mutex::new(VecDeque::new()),
            samples_dropped: AtomicU64::new(0),
            counters: Mutex::new(HashMap::new()),
        }
    }

    fn push_event(&self, record: EventRecord) {
        let mut events = self.events.lock();
        if events.len() >= MAX_EVENTS_PER_SESSION {
            events.pop_front();
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        events.push_back(record);
    }

    fn push_sample(&self, record: SampleRecord) {
        let mut samples = self.samples.lock();
        if samples.len() >= MAX_SAMPLES_PER_SESSION {
            samples.pop_front();
            self.samples_dropped.fetch_add(1, Ordering::Relaxed);
        }
        samples.push_back(record);
    }

    /// The work counters already maintained for flight-recorder rows, folded
    /// without adding another contended atomic update to the per-turn path.
    fn work_snapshot(&self) -> RelayWorkSnapshot {
        let counters = self.counters.lock();
        counters
            .values()
            .fold(RelayWorkSnapshot::default(), |mut total, counter| {
                total.accumulate(RelayWorkSnapshot {
                    client_turns_validated: counter.turns_validated.load(Ordering::Relaxed),
                    local_turn_deliveries: counter.turns_forwarded.load(Ordering::Relaxed),
                    oversize_diverts: counter.oversize_diverts.load(Ordering::Relaxed),
                });
                total
            })
    }

    /// Builds one sample row from the current counters plus the given
    /// conditions snapshot (the slot link's latest published QUIC stats) and
    /// the session's end-to-end delivery view.
    fn sample_row(
        &self,
        conditions: Option<&HashMap<SlotId, SlotConditionsRow>>,
        e2e: (Option<u64>, Option<u32>),
    ) -> SampleRecord {
        let counters = self.counters.lock();
        let mut slots: Vec<SlotSample> = counters
            .iter()
            .map(|(slot, c)| {
                let cond = conditions.and_then(|m| m.get(slot));
                SlotSample {
                    slot: slot.0,
                    turns_validated: c.turns_validated.load(Ordering::Relaxed),
                    turns_forwarded: c.turns_forwarded.load(Ordering::Relaxed),
                    newest_seq: c.newest_seq.load(Ordering::Relaxed),
                    dedup_drops: c.dedup_drops.load(Ordering::Relaxed),
                    oversize_diverts: c.oversize_diverts.load(Ordering::Relaxed),
                    rtt_us: cond.map(|c| c.rtt_us),
                    lost_packets: cond.map(|c| c.lost_packets),
                    sent_packets: cond.map(|c| c.sent_packets),
                }
            })
            .collect();
        slots.sort_by_key(|s| s.slot);
        SampleRecord {
            at_ms: now_ms(),
            slots,
            worst_e2e_lag_turns: e2e.0,
            max_relay_hops: e2e.1,
        }
    }
}

/// The subset of a slot's published conditions the sampler folds in.
struct SlotConditionsRow {
    rtt_us: u32,
    lost_packets: u64,
    sent_packets: u64,
}

/// The outcome of flushing one session's recording — mostly for tests and
/// logging; production callers fire-and-log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// The blob was handed to the sink and it reported success.
    Stored,
    /// No sink is configured: the recording was discarded, logged.
    NoSink,
    /// The sink reported an error: the blob is lost, logged.
    Failed,
    /// No recording existed for the session (already flushed, or never touched).
    Nothing,
}

/// The relay-wide flight recorder: a cheap-clone `Arc` handle over the
/// per-session recordings. Lives on the consensus registry
/// ([`crate::consensus::DecisionMakers`]) because that `Arc` already reaches
/// every wiring site — the slot-link tasks (via `MeshState`), the consensus
/// decision paths (it *is* the registry), `MeshControl`, and the binary.
#[derive(Clone, Default)]
pub struct FlightRecorder {
    inner: Arc<RecorderInner>,
}

#[derive(Default)]
struct RecorderInner {
    recordings: Mutex<RecorderState>,
    /// This relay's id, stamped into every blob header. Set once at startup;
    /// absent (a standalone relay with no `--relay-id`) blobs carry 0.
    relay_id: OnceLock<RelayId>,
    /// Where flushed blobs go. Set once at startup; absent, a flush is a
    /// logged discard (the recorder still records — cheap and bounded).
    sink: OnceLock<Arc<dyn FlightSink>>,
}

/// Live recordings plus work retired by terminal flushes. Keeping them behind
/// one mutex makes moving a quiescent recording from the live set into the
/// cumulative total atomic with respect to
/// [`FlightRecorder::relay_work_snapshot`]. A forced drain may deliberately
/// remove a recording while an outstanding counter handle is still winding
/// down; that shutdown-tail race is described in `take_blob`.
#[derive(Default)]
struct RecorderState {
    sessions: HashMap<SessionKey, Arc<SessionRecording>>,
    retired_work: RelayWorkSnapshot,
}

impl FlightRecorder {
    /// Stamps this relay's id into future blob headers. Set once; a second
    /// call is ignored (first wins), like the notice notifier it lives beside.
    pub fn set_identity(&self, relay_id: RelayId) {
        let _ = self.inner.relay_id.set(relay_id);
    }

    /// Installs the flush sink. Set once at startup; a second call is ignored.
    pub fn set_sink(&self, sink: Arc<dyn FlightSink>) {
        let _ = self.inner.sink.set(sink);
    }

    fn recording(&self, key: &SessionKey) -> Arc<SessionRecording> {
        let mut state = self.inner.recordings.lock();
        Arc::clone(
            state
                .sessions
                .entry(key.clone())
                .or_insert_with(|| Arc::new(SessionRecording::new())),
        )
    }

    /// Records one event for `key`'s session, creating the recording on first
    /// touch. Events are rare, so the short per-session mutex is fine here —
    /// this is never called on the per-turn path.
    pub fn record(&self, key: &SessionKey, event: FlightEvent) {
        self.recording(key).push_event(EventRecord {
            at_ms: now_ms(),
            event,
        });
    }

    /// The counter handle for `key`'s `slot`, fetched **once** at link start so
    /// the per-turn path bumps plain atomics with no lock and no map lookup.
    pub fn slot_counters(&self, key: &SessionKey, slot: SlotId) -> Arc<SlotCounters> {
        let recording = self.recording(key);
        let mut counters = recording.counters.lock();
        Arc::clone(counters.entry(slot).or_default())
    }

    /// Cumulative relay work since process start. This scans only at the
    /// task-stats cadence, reusing the per-slot atomics the recorder already
    /// maintains instead of adding a second global atomic RMW to every turn.
    /// Session removal and retired-total capture share one lock, so successive
    /// snapshots can safely be differenced after the session's link tasks have
    /// quiesced. A forced shutdown drain can race their final counter updates;
    /// steady-state load-test intervals do not use that tail.
    pub fn relay_work_snapshot(&self) -> RelayWorkSnapshot {
        let (mut total, recordings): (RelayWorkSnapshot, Vec<Arc<SessionRecording>>) = {
            let state = self.inner.recordings.lock();
            (
                state.retired_work,
                state.sessions.values().map(Arc::clone).collect(),
            )
        };
        for recording in recordings {
            total.accumulate(recording.work_snapshot());
        }
        total
    }

    /// Counts a duplicate the session-level delivery gate dropped for `key`/`slot`.
    /// Takes the map locks — acceptable because the duplicate branch is off the
    /// common per-turn path (normally only reconnect/resume or re-home overlap
    /// reaches it), which is why this is not routed through a pre-fetched handle
    /// like the hot counters.
    pub fn note_dedup_drop(&self, key: &SessionKey, slot: SlotId) {
        self.slot_counters(key, slot).note_dedup_drop();
    }

    /// Folds the current counters, published link conditions, and per-session
    /// end-to-end delivery view (`e2e_for`, typically
    /// [`crate::consensus::session_e2e`]) into one sample row per live
    /// recording — the sampling tick's body, exposed so tests drive it
    /// directly.
    pub fn sample_now(
        &self,
        conditions: &ConditionsRegistry,
        e2e_for: impl Fn(&SessionKey) -> (Option<u64>, Option<u32>),
    ) {
        let recordings: Vec<(SessionKey, Arc<SessionRecording>)> = {
            let state = self.inner.recordings.lock();
            state
                .sessions
                .iter()
                .map(|(k, r)| (k.clone(), Arc::clone(r)))
                .collect()
        };
        for (key, recording) in recordings {
            let rows: Option<HashMap<SlotId, SlotConditionsRow>> =
                conditions.lock().get(&key).map(|slots| {
                    slots
                        .iter()
                        .map(|(slot, c)| {
                            (
                                *slot,
                                SlotConditionsRow {
                                    rtt_us: c.rtt_us,
                                    lost_packets: c.lost_packets,
                                    sent_packets: c.sent_packets,
                                },
                            )
                        })
                        .collect()
                });
            let row = recording.sample_row(rows.as_ref(), e2e_for(&key));
            recording.push_sample(row);
        }
    }

    /// The sessions currently holding a recording, for the drain flush and logs.
    pub fn recorded_sessions(&self) -> Vec<SessionKey> {
        self.inner
            .recordings
            .lock()
            .sessions
            .keys()
            .cloned()
            .collect()
    }

    /// A snapshot of `key`'s recorded events, for tests and diagnostics.
    pub fn events(&self, key: &SessionKey) -> Vec<EventRecord> {
        self.inner
            .recordings
            .lock()
            .sessions
            .get(key)
            .map(|r| r.events.lock().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes `key`'s recording and builds its flushed blob, or `None` if no
    /// recording exists. The removal is what makes a flush terminal: later
    /// events for the same key start a fresh recording.
    fn take_blob(&self, key: &SessionKey) -> Option<FlightBlob> {
        let recording = {
            let mut state = self.inner.recordings.lock();
            let recording = state.sessions.remove(key)?;
            // Production flushes happen after the slot links quiesce. A drain
            // deadline can force this snapshot while a final link is winding
            // down; that shutdown-tail race is acceptable for telemetry and is
            // outside the steady-state intervals used for CPU comparisons.
            state.retired_work.accumulate(recording.work_snapshot());
            recording
        };
        // Fold a final counter snapshot in, so a short session that never saw a
        // sampling tick still carries its turn-stream totals. Counters only —
        // the consensus state this flush races may already be gone, so the
        // e2e view is deliberately absent here (the periodic rows carry it).
        let final_row = recording.sample_row(None, (None, None));
        recording.push_sample(final_row);
        Some(FlightBlob {
            version: BLOB_VERSION,
            tenant: key.tenant.as_ref().to_owned(),
            session: key.session.0,
            relay_id: self.inner.relay_id.get().map(|r| r.0).unwrap_or(0),
            started_at_ms: recording.started_at_ms,
            flushed_at_ms: now_ms(),
            events_dropped: recording.events_dropped.load(Ordering::Relaxed),
            samples_dropped: recording.samples_dropped.load(Ordering::Relaxed),
            events: recording.events.lock().iter().cloned().collect(),
            samples: recording.samples.lock().iter().cloned().collect(),
        })
    }

    /// Flushes `key`'s recording to the sink (or logs the discard when no sink
    /// is configured). Terminal for the recording either way.
    pub async fn flush_session(&self, key: &SessionKey) -> FlushOutcome {
        let Some(blob) = self.take_blob(key) else {
            return FlushOutcome::Nothing;
        };
        let Some(sink) = self.inner.sink.get() else {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                events = blob.events.len(),
                "no flight sink configured; discarding the session's recording",
            );
            return FlushOutcome::NoSink;
        };
        match sink.store(&blob).await {
            Ok(()) => {
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    events = blob.events.len(),
                    samples = blob.samples.len(),
                    "flight recording flushed",
                );
                FlushOutcome::Stored
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "flight recording store failed; the blob is lost",
                );
                FlushOutcome::Failed
            }
        }
    }

    /// Fire-and-forget [`flush_session`](Self::flush_session), for the
    /// session-close path (a sync teardown site inside the runtime). Outside a
    /// tokio runtime — some unit tests exercise the close path directly — the
    /// recording is discarded with a log, matching the no-sink behavior.
    pub fn flush_session_detached(&self, key: &SessionKey) {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let recorder = self.clone();
                let key = key.clone();
                handle.spawn(async move {
                    recorder.flush_session(&key).await;
                });
            }
            Err(_) => {
                let _ = self.take_blob(key);
            }
        }
    }

    /// Flushes every live recording, bounded by `deadline` — the drain path's
    /// wholesale flush. Whatever the deadline cuts off is logged and abandoned:
    /// flight data is observability, and the drain's own budget (and Fargate's
    /// stopTimeout behind it) outranks it.
    ///
    /// The fan-out is capped at [`DRAIN_FLUSH_CONCURRENCY`] rather than fully
    /// concurrent: [`CoordinatorSink`] refuses (never blocks on) a full shipment
    /// queue, so an unbounded burst here would overrun that queue on a relay
    /// holding more live sessions than the queue is deep and lose the overflow
    /// even over a healthy connection. Capped below the queue depth, a full
    /// queue at drain time means a genuinely wedged connection, not this flush
    /// racing its own fan-out.
    pub async fn flush_all(&self, deadline: Duration) {
        use futures_util::StreamExt;

        let keys = self.recorded_sessions();
        if keys.is_empty() {
            return;
        }
        tracing::info!(
            sessions = keys.len(),
            "flushing flight recordings for drain"
        );
        let completed = AtomicU64::new(0);
        let flushes = futures_util::stream::iter(keys.iter()).for_each_concurrent(
            DRAIN_FLUSH_CONCURRENCY,
            |key| {
                let completed = &completed;
                async move {
                    self.flush_session(key).await;
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            },
        );
        if tokio::time::timeout(deadline, flushes).await.is_err() {
            let abandoned = keys.len() as u64 - completed.load(Ordering::Relaxed);
            tracing::warn!(
                abandoned,
                "drain flight flush hit its deadline; abandoning the rest",
            );
        }
    }
}

/// The relay-wide sampling tick: folds counters, link conditions, and each
/// session's end-to-end delivery view into a sample row per live session every
/// `interval`. One task per relay, spawned by the binary; never returns.
pub async fn run_sampler(
    recorder: FlightRecorder,
    conditions: ConditionsRegistry,
    makers: Arc<crate::consensus::DecisionMakers>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; skip it so the first sample lands one
    // interval in, once there is something to sample.
    tick.tick().await;
    loop {
        tick.tick().await;
        recorder.sample_now(&conditions, |key| {
            crate::consensus::session_e2e(&makers, key)
        });
    }
}

/// Wall clock as unix epoch milliseconds — the blob's timestamp base.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(session),
        }
    }

    /// A sink that captures every stored blob for assertions.
    #[derive(Default)]
    struct CaptureSink {
        blobs: Mutex<Vec<FlightBlob>>,
    }

    impl FlightSink for CaptureSink {
        fn store<'a>(
            &'a self,
            blob: &'a FlightBlob,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.blobs.lock().push(blob.clone());
                Ok(())
            })
        }
    }

    /// A sink slower than any deadline a test hands the drain flush.
    struct SlowSink;

    impl FlightSink for SlowSink {
        fn store<'a>(
            &'a self,
            _blob: &'a FlightBlob,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            })
        }
    }

    #[test]
    fn the_event_ring_evicts_oldest_and_counts_the_loss() {
        let recorder = FlightRecorder::default();
        let k = key(1);
        for i in 0..(MAX_EVENTS_PER_SESSION + 3) {
            recorder.record(
                &k,
                FlightEvent::SlotConnected {
                    slot: (i % 8) as u8,
                    resumed: false,
                },
            );
        }
        let events = recorder.events(&k);
        assert_eq!(events.len(), MAX_EVENTS_PER_SESSION, "the ring is capped");
        // The three oldest (slots 0, 1, 2 of the first wrap) were evicted; the
        // ring now starts at the fourth event.
        assert_eq!(
            events[0].event,
            FlightEvent::SlotConnected {
                slot: 3,
                resumed: false
            },
            "eviction is oldest-first",
        );

        // The loss is counted into the flushed blob.
        let blob = recorder.take_blob(&k).expect("a recording exists");
        assert_eq!(blob.events_dropped, 3);
    }

    #[test]
    fn counter_bumps_fold_into_a_sample_on_the_tick() {
        let recorder = FlightRecorder::default();
        let k = key(1);
        let counters = recorder.slot_counters(&k, SlotId(2));
        counters.note_validated(7);
        counters.note_validated(9);
        counters.note_forwarded();
        counters.note_oversize_divert();
        recorder.note_dedup_drop(&k, SlotId(2));

        // Drive the tick body directly with an empty conditions registry and no
        // e2e view.
        let conditions = crate::mesh::new_conditions_registry();
        recorder.sample_now(&conditions, |_| (None, None));

        let blob = recorder.take_blob(&k).expect("a recording exists");
        // One tick sample plus the final flush snapshot.
        assert_eq!(blob.samples.len(), 2);
        let row = &blob.samples[0].slots[0];
        assert_eq!(row.slot, 2);
        assert_eq!(row.turns_validated, 2);
        assert_eq!(row.newest_seq, 9);
        assert_eq!(row.turns_forwarded, 1);
        assert_eq!(row.oversize_diverts, 1);
        assert_eq!(row.dedup_drops, 1);
        assert_eq!(row.rtt_us, None, "no published conditions for the slot");
    }

    #[test]
    fn relay_work_totals_aggregate_across_slots_and_survive_session_flush() {
        let recorder = FlightRecorder::default();
        let first_key = key(1);
        let second_key = key(2);
        let first = recorder.slot_counters(&first_key, SlotId(0));
        let second = recorder.slot_counters(&second_key, SlotId(3));

        first.note_validated(1);
        first.note_validated(2);
        first.note_forwarded();
        second.note_validated(7);
        second.note_forwarded();
        second.note_forwarded();
        second.note_oversize_divert();

        assert_eq!(
            recorder.relay_work_snapshot(),
            RelayWorkSnapshot {
                client_turns_validated: 3,
                local_turn_deliveries: 3,
                oversize_diverts: 1,
            }
        );

        // Removing the first session's recording (the synchronous core of a
        // flush) does not remove its contribution from relay-lifetime totals.
        let _ = recorder.take_blob(&first_key).expect("a recording exists");
        assert_eq!(
            recorder.relay_work_snapshot(),
            RelayWorkSnapshot {
                client_turns_validated: 3,
                local_turn_deliveries: 3,
                oversize_diverts: 1,
            }
        );

        // Reusing the same session key creates new slot counters wired to the
        // same relay-lifetime aggregate rather than restarting from zero.
        recorder
            .slot_counters(&first_key, SlotId(0))
            .note_forwarded();
        assert_eq!(
            recorder.relay_work_snapshot(),
            RelayWorkSnapshot {
                client_turns_validated: 3,
                local_turn_deliveries: 4,
                oversize_diverts: 1,
            }
        );
    }

    #[test]
    fn the_sampler_folds_published_link_conditions_into_the_row() {
        let recorder = FlightRecorder::default();
        let k = key(1);
        let _counters = recorder.slot_counters(&k, SlotId(0));

        let conditions = crate::mesh::new_conditions_registry();
        crate::mesh::activate_conditions(
            &conditions,
            &k,
            SlotId(0),
            rally_point_proto::messages::SlotConditions {
                slot: 0,
                rtt_us: 42_000,
                lost_packets: 3,
                sent_packets: 500,
                connection_epoch: None,
            },
        );
        recorder.sample_now(&conditions, |_| (Some(17), Some(2)));

        let blob = recorder.take_blob(&k).expect("a recording exists");
        let sample = &blob.samples[0];
        // The session-level end-to-end view rides the sample row.
        assert_eq!(sample.worst_e2e_lag_turns, Some(17));
        assert_eq!(sample.max_relay_hops, Some(2));
        let row = &sample.slots[0];
        assert_eq!(row.rtt_us, Some(42_000));
        assert_eq!(row.lost_packets, Some(3));
        assert_eq!(row.sent_packets, Some(500));
    }

    #[test]
    fn the_blob_envelope_roundtrips_and_is_self_describing() {
        let recorder = FlightRecorder::default();
        recorder.set_identity(RelayId(7));
        let k = key(42);
        recorder.record(
            &k,
            FlightEvent::LeaveDecided {
                slot: 1,
                kind: DepartureKind::Dropped,
                apply_frame: 900,
                leave_seq: 3,
            },
        );
        recorder.record(&k, FlightEvent::SessionClosed);

        let blob = recorder.take_blob(&k).expect("a recording exists");
        assert_eq!(blob.version, BLOB_VERSION);
        assert_eq!(blob.tenant, "sb-test");
        assert_eq!(blob.session, 42);
        assert_eq!(blob.relay_id, 7);
        assert!(blob.started_at_ms > 0 && blob.flushed_at_ms >= blob.started_at_ms);

        let json = serde_json::to_string_pretty(&blob).unwrap();
        // The envelope is self-describing on the wire: version and tagged events.
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"event\": \"leave_decided\""));
        let back: FlightBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[tokio::test]
    async fn the_file_sink_writes_the_tenant_scoped_path() {
        let dir = std::env::temp_dir().join(format!("rp2-flight-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let recorder = FlightRecorder::default();
        recorder.set_identity(RelayId(7));
        recorder.set_sink(Arc::new(FileSink::new(dir.clone())));
        let k = key(42);
        recorder.record(
            &k,
            FlightEvent::SessionStart {
                initial_buffer_turns: None,
            },
        );

        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

        let path = dir.join("sb-test").join("42").join("7.json");
        let json = std::fs::read_to_string(&path).expect("the blob file exists");
        let blob: FlightBlob = serde_json::from_str(&json).expect("the file is parseable JSON");
        assert_eq!(blob.session, 42);
        assert_eq!(blob.events.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_flush_removes_the_recording() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);
        recorder.record(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.recorded_sessions().len(), 1);

        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);
        assert!(recorder.recorded_sessions().is_empty(), "flush is terminal");
        assert_eq!(sink.blobs.lock().len(), 1);

        // A re-flush of the gone recording is a harmless Nothing.
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);
    }

    #[tokio::test]
    async fn without_a_sink_recording_continues_and_a_flush_is_a_logged_discard() {
        let recorder = FlightRecorder::default();
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::SessionStart {
                initial_buffer_turns: None,
            },
        );
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::NoSink);
        assert!(recorder.recorded_sessions().is_empty());

        // Recording keeps working after the discard.
        recorder.record(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.events(&k).len(), 1);
    }

    #[tokio::test]
    async fn the_drain_flush_respects_its_deadline_against_a_slow_sink() {
        let recorder = FlightRecorder::default();
        recorder.set_sink(Arc::new(SlowSink));
        recorder.record(
            &key(1),
            FlightEvent::SessionStart {
                initial_buffer_turns: None,
            },
        );
        recorder.record(
            &key(2),
            FlightEvent::SessionStart {
                initial_buffer_turns: None,
            },
        );

        let started = std::time::Instant::now();
        recorder.flush_all(Duration::from_millis(100)).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the drain flush returns at its deadline, not the sink's pace",
        );
    }

    #[tokio::test]
    async fn the_coordinator_sink_compresses_a_shipment_that_reconstructs_the_blob() {
        let recorder = FlightRecorder::default();
        recorder.set_identity(RelayId(9));
        let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
        let k = key(42);
        recorder.record(
            &k,
            FlightEvent::SessionStart {
                initial_buffer_turns: Some(3),
            },
        );
        recorder.record(&k, FlightEvent::SessionClosed);

        // `store` blocks awaiting the connection's ack, so drive the flush
        // concurrently with the stand-in connection that pulls it and acks.
        let flush = tokio::spawn(async move { recorder.flush_session(&k).await });

        let shipment = rx.recv().await.expect("a shipment is queued");
        assert_eq!(shipment.tenant.as_ref(), "sb-test");
        assert_eq!(shipment.session, SessionId(42));
        assert!(!shipment.desynced, "no desync event was recorded");
        // The shipped payload is the zstd-compressed compact JSON of the blob;
        // decompressing it reconstructs the blob exactly.
        let json = zstd::decode_all(&shipment.payload[..]).expect("the payload decompresses");
        let blob: FlightBlob = serde_json::from_slice(&json).expect("the payload is the blob");
        assert_eq!(blob.tenant, "sb-test");
        assert_eq!(blob.session, 42);
        assert_eq!(blob.relay_id, 9);
        assert_eq!(blob.events.len(), 2);

        // The ack resolves the store to Stored.
        shipment
            .sent
            .send(())
            .expect("the sink is still awaiting the ack");
        assert_eq!(flush.await.unwrap(), FlushOutcome::Stored);
    }

    #[tokio::test]
    async fn the_shipped_desynced_flag_is_set_only_when_a_desync_event_exists() {
        let recorder = FlightRecorder::default();
        let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::DesyncDetected {
                sync_ordinal: 5,
                diverged: vec![1],
                no_majority: false,
            },
        );
        let flush = tokio::spawn(async move { recorder.flush_session(&k).await });
        let shipment = rx.recv().await.expect("a shipment is queued");
        assert!(
            shipment.desynced,
            "a DesyncDetected event sets the shipped flag",
        );
        shipment.sent.send(()).unwrap();
        assert_eq!(flush.await.unwrap(), FlushOutcome::Stored);
    }

    #[tokio::test]
    async fn an_oversized_compressed_blob_is_refused_and_ships_nothing() {
        let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let sink = CoordinatorSink::new(tx);
        // A blob whose *compressed* form exceeds the shipping cap — a pathological
        // payload the rings would never actually produce, built by hand to exercise
        // the wire-hygiene backstop. The tenant string is filled with high-entropy
        // (incompressible) bytes so zstd cannot shrink it below the cap.
        let blob = FlightBlob {
            version: BLOB_VERSION,
            // Twice the cap of high-entropy source: even at zstd's best case on a
            // 6-bit-per-symbol alphabet (~0.75 ratio) the compressed form clears the
            // 4 MiB cap comfortably.
            tenant: incompressible_string(MAX_SHIPPED_BLOB_BYTES * 2),
            session: 1,
            relay_id: 0,
            started_at_ms: 1,
            flushed_at_ms: 2,
            events_dropped: 0,
            samples_dropped: 0,
            events: vec![],
            samples: vec![],
        };
        assert!(
            sink.store(&blob).await.is_err(),
            "an oversized compressed blob is refused",
        );
        assert!(rx.try_recv().is_err(), "nothing was shipped");
    }

    /// Builds a `len`-byte string of high-entropy ASCII over a 64-symbol alphabet, so
    /// zstd finds no structure to exploit and its output stays near the input size —
    /// used to force the compressed-size backstop to trip in a test without a
    /// multi-megabyte genuinely-recorded blob.
    fn incompressible_string(len: usize) -> String {
        // A 64-char JSON-safe alphabet: 6 bits of entropy per symbol.
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            // xorshift64: high-entropy output zstd finds no structure in.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(ALPHABET[(state & 63) as usize] as char);
        }
        out
    }

    #[tokio::test]
    async fn a_full_shipment_queue_fails_the_flush_without_blocking() {
        let recorder = FlightRecorder::default();
        // Capacity one, its single slot pre-filled: the receiver stays bound and
        // alive, so the sink's next try_send sees a full (not closed) queue.
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(FlightShipment {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(0),
            desynced: false,
            payload: Bytes::from_static(b"{}"),
            sent: oneshot::channel().0,
        })
        .expect("the first send fills the slot");
        recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
        let k = key(1);
        recorder.record(&k, FlightEvent::SessionClosed);
        // A full queue is a lost blob reported Failed — and, crucially, the flush
        // returns at once rather than blocking a session teardown.
        let outcome = tokio::time::timeout(Duration::from_secs(1), recorder.flush_session(&k))
            .await
            .expect("the flush returns at once, it does not hang");
        assert_eq!(outcome, FlushOutcome::Failed);
    }

    #[tokio::test]
    async fn a_dropped_ack_sender_fails_the_flush() {
        let recorder = FlightRecorder::default();
        let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
        let k = key(1);
        recorder.record(&k, FlightEvent::SessionClosed);
        let flush = tokio::spawn(async move { recorder.flush_session(&k).await });
        let shipment = rx.recv().await.expect("a shipment is queued");
        // The connection loop tears down before writing the frame: dropping the
        // shipment drops its ack sender, so the sink reports the blob lost.
        drop(shipment);
        assert_eq!(flush.await.unwrap(), FlushOutcome::Failed);
    }
}
