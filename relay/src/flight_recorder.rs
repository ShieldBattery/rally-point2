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
//! A close seals a recording that exists; it never begins one (see
//! [`FlightRecorder::record_existing`]). A recording starts at the first thing
//! this relay observed about a session, so a session it observed nothing of
//! stores nothing at all — which matters because every recording a relay makes
//! of one session shares a single storage key, and a later store displaces an
//! earlier one.
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

use std::collections::{HashMap, HashSet, VecDeque};
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
        /// The exact native leave reason carried to clients. Older blobs omit
        /// this field, so keep its zero default when decoding them.
        #[serde(default)]
        reason: u32,
        apply_frame: u32,
        leave_seq: u32,
        /// Whether the decision carries a home-sealed final turn count.
        #[serde(default)]
        finalized: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        final_turn_count: Option<u64>,
    },
    /// This relay accepted a peer relay's synced leave into its consensus
    /// cache. Only the first accepted copy is recorded; redundant or
    /// conflicting copies are not local delivery decisions.
    LeaveMeshAccepted {
        source_relay: u64,
        slot: u8,
        reason: u32,
        apply_frame: u32,
        leave_seq: u32,
        finalized: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        final_turn_count: Option<u64>,
    },
    /// One attempt to write a synced leave to a local survivor's reliable
    /// control stream. `succeeded` means the QUIC stream write completed; it
    /// does not claim that the client read or applied the directive.
    LeaveControlWrite {
        recipient: u8,
        connection_epoch: u64,
        slot: u8,
        reason: u32,
        apply_frame: u32,
        leave_seq: u32,
        finalized: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        final_turn_count: Option<u64>,
        /// Reconnect reconciliation writes bypass the live fan-out queue.
        replayed: bool,
        succeeded: bool,
    },
    /// This relay (as session authority) queued a latency-buffer change.
    BufferDirective {
        buffer_turns: u32,
        apply_frame: u32,
        decision_seq: u32,
        /// What the control law derived this depth from. Absent when the
        /// directive carries no law verdict — the one-shot re-affirm that
        /// broadcasts the standing buffer fires precisely when the law had no
        /// target to act on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inputs: Option<BufferDecisionInputs>,
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
    /// A drop finalization was rejected, keeping the drop held and
    /// undecided. `no_cursor` marks the home-side fail-closed branch — no
    /// gap-free forwarded prefix to seal (a collapsed window, or a home
    /// gained mid-session whose cursor cannot cover the slot's whole
    /// history); `false` marks the authority-side refusal to complete a
    /// finalized answer that has no framed scheduling basis yet (a pre-frame
    /// session). Either way survivors stay stalled until they retry or quit;
    /// a session stuck repeating this event is the signal for operator
    /// intervention (or the coordinated-abort follow-up).
    DropFinalizeRejected { slot: u8, no_cursor: bool },
    /// The authority refused a home's FINALIZED answer because its own
    /// forwarded prefix for the slot already extends past the sealed count —
    /// local proof that turns beyond the count entered the mesh after the
    /// seal the answer describes (a partition-delayed result from a home the
    /// slot has since moved past). The drop stays held; a later re-request
    /// answers from the slot's current state.
    DropFinalizeStaleCount {
        slot: u8,
        sealed_count: u64,
        forwarded: u64,
    },
    /// A peer authority's buffer directive above the game-sync-safe ceiling
    /// was forwarded verbatim (rewriting it selectively would hand different
    /// clients different depths). Only an authority running code that
    /// predates the ceiling can author one; a depth past the ceiling
    /// deterministically mass-drops the session once applied. Recorded once
    /// per decision.
    OverCeilingDirectiveForwarded {
        buffer_turns: u32,
        decision_seq: u32,
    },
}

/// The control law's derivation of one latency-buffer decision: every term
/// that fed the target, plus the gate state that decided how far the buffer
/// was allowed to move. A depth on its own says only what the session got;
/// these say why, which is the difference between reading a recording and
/// guessing at one.
///
/// Every turn-valued field is in game turns and every microsecond-valued one
/// says `_us`. The terms compose as
/// `law_target = ceil(path) + ceil(loss_risk) + burst_turns` and
/// `target = law_target + cushion_turns + stretch_turns`; `target` above
/// `buffer_turns` means the session bounds (or the sync-safe ceiling) trimmed
/// what the law asked for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BufferDecisionInputs {
    /// The control law's own target — path, loss, and burst — before the
    /// additive terms.
    pub law_target: u32,
    /// The full target the raise branch compared against the buffer: the law's
    /// target plus the additive cushion and stretch terms.
    pub target: u32,
    /// The target as the shrink gate sees it, with the path term's headroom
    /// margin applied. Always at least `target`; a lower fires only while this
    /// sits below the standing buffer.
    pub shrink_target: u32,
    /// Worst pairwise one-way path across the session, microseconds.
    pub path_us: u32,
    /// Worst per-slot `loss_rate * eff_rtt`, microseconds — how much delivery
    /// delay the measured loss is expected to add.
    pub loss_risk_us: u32,
    /// Worst per-slot blackout-run length in turns, capped by the law.
    pub burst_turns: u32,
    /// The end-to-end delivery cushion: one turn per relay hop past the first,
    /// plus the capped lag-responsive term.
    pub cushion_turns: u32,
    /// The sustained arrival-interval stretch term: nonzero while some home
    /// slot has been producing turns slower than the turn rate for longer than
    /// the law's sustain window.
    pub stretch_turns: u32,
    /// The trailing target high-water mark a shrink may not step below.
    pub shrink_floor: u32,
    /// Whether a disproven edge shrink is holding the floor over the long
    /// probation window rather than the base lookback.
    pub edge_burned: bool,
    /// Every slot's effective RTT at decision time, sorted by slot — the
    /// per-slot detail behind `path_us`, and the only place the mesh's
    /// contribution to a slot's path is visible.
    pub eff_rtts: Vec<SlotEffRtt>,
}

/// One slot's effective RTT as the control law weighed it: the slot's own link
/// RTT plus the one-way mesh hop from the deciding relay to the slot's home
/// relay, so a slot this relay homes and one it reaches across the mesh are
/// directly comparable. Microseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotEffRtt {
    pub slot: u8,
    pub eff_rtt_us: u32,
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
    /// Still-unacked turns re-carried to this slot's client as redundancy,
    /// cumulative since the recording began. Read against `lost_packets`: loss
    /// says how much the link dropped, this says how much forward recovery
    /// spent replacing it.
    pub redundant_payloads: u64,
    /// Packets this slot's client sent that never reached the relay, from gaps
    /// in the client's own packet numbering. `lost_packets` covers only the
    /// relay-to-client direction; this is the other one — and for a client
    /// link it is the direction carrying the turns the whole lockstep waits on.
    ///
    /// Client-numbered, so a client that skips seqs overstates its own loss and
    /// nobody else's. Recording only: no decision reads it.
    pub upstream_lost_packets: u64,
    /// The QUIC path's congestion window for this client, bytes. Turn traffic
    /// is a tiny fixed-rate flow, so this normally sits far above what the
    /// session offers; a window near its floor while turns queue is the
    /// signature of the transport, not the network, holding them back.
    pub cwnd: u64,
    /// Congestion events QUIC has recorded on this client's path.
    pub congestion_events: u64,
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
    redundant_payloads: AtomicU64,
    upstream_lost_packets: AtomicU64,
    cwnd: AtomicU64,
    congestion_events: AtomicU64,
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

    /// A packet to this slot's client re-carried `count` still-unacked turns as
    /// redundancy. Summed over the session, this is how hard forward recovery
    /// was working on the link — the counterpart to the loss counters, which
    /// say how much was dropped but not how much was spent replacing it.
    pub fn note_redundancy(&self, count: usize) {
        if count > 0 {
            self.redundant_payloads
                .fetch_add(count as u64, Ordering::Relaxed);
        }
    }

    /// Publishes the current link-level gauges for this slot: peer packets that
    /// never arrived, and the QUIC path's congestion window and event count.
    ///
    /// These are the live connection's own values, not recorder-owned totals,
    /// so a reconnect starts them over the same way it starts `rtt_us` and the
    /// path loss counters over. Stored rather than accumulated for that reason
    /// — a sample says what the link looked like then, and the row it lands in
    /// already carries the epoch-scoped path counters beside it.
    pub fn note_link_gauges(&self, upstream_lost: u64, cwnd: u64, congestion_events: u64) {
        self.upstream_lost_packets
            .store(upstream_lost, Ordering::Relaxed);
        self.cwnd.store(cwnd, Ordering::Relaxed);
        self.congestion_events
            .store(congestion_events, Ordering::Relaxed);
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
                    redundant_payloads: c.redundant_payloads.load(Ordering::Relaxed),
                    upstream_lost_packets: c.upstream_lost_packets.load(Ordering::Relaxed),
                    cwnd: c.cwnd.load(Ordering::Relaxed),
                    congestion_events: c.congestion_events.load(Ordering::Relaxed),
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
    /// The relay-wide session gates, consulted by create-on-first-touch so a
    /// retired session's straggling event cannot begin a recording. Set once
    /// at startup beside the sink; absent, every session reads as unretired.
    gates: OnceLock<crate::session_gate::SessionGates>,
    /// The sessions stored recently, so a second store for one of them can say
    /// so (see [`RecentStores`]).
    recent_stores: Mutex<RecentStores>,
}

/// How many recently stored sessions the recorder remembers. A store is only
/// worth announcing as a repeat while the recording it displaces is the one an
/// investigation would read, and every way a second store arises — a session
/// this relay serves again, a teardown path evaluated twice — happens within a
/// session teardown's own timescale. So a bounded recent window catches the
/// repeats that matter at fixed cost, rather than remembering every session the
/// relay has ever served for the life of the process.
const RECENT_STORES: usize = 256;

/// The recently stored sessions, oldest-first: a bounded window over what this
/// relay has written to the flight store.
///
/// Every recording a relay makes of one session is stored under a single key, so
/// storing a session twice replaces what the first store wrote: expected when the
/// relay genuinely served the session again, a silently lost recording otherwise.
/// The two are indistinguishable at the store, so the second store says so in the
/// log — and this window is how it knows it is the second.
#[derive(Default)]
struct RecentStores {
    /// The remembered keys in store order; the front is evicted when the window
    /// is full.
    order: VecDeque<SessionKey>,
    /// The same keys, for the membership test.
    keys: HashSet<SessionKey>,
}

impl RecentStores {
    /// Notes a store of `key`'s recording, reporting whether the window already
    /// held one for it — that is, whether this store replaced an earlier one.
    /// A repeat leaves the window unchanged: it names the same session that is
    /// already in it, and re-recording it would evict an unrelated session for
    /// nothing.
    fn note(&mut self, key: &SessionKey) -> bool {
        if self.keys.contains(key) {
            return true;
        }
        if self.order.len() >= RECENT_STORES
            && let Some(evicted) = self.order.pop_front()
        {
            self.keys.remove(&evicted);
        }
        self.order.push_back(key.clone());
        self.keys.insert(key.clone());
        false
    }
}

/// How many close-sealed sessions the recorder remembers (see
/// `RecorderState::closed`). A seal exists only for the window between a
/// session's close flush and its membership retirement — a session-teardown
/// timescale, like [`RECENT_STORES`]'s window — so a bounded set covers every
/// seal that matters; the cap is a leak backstop for sessions whose retirement
/// never arrives, not a size this is expected to reach. It must comfortably
/// exceed the closed-but-unretired sessions a relay can accumulate while the
/// coordinator (whose descriptor removals drive retirement) is unreachable:
/// evicting a still-needed seal reopens the session to the straggler
/// overwrite the seal exists to prevent, so an eviction warns.
const CLOSE_SEAL_WARN_THRESHOLD: usize = 8192;

/// The sessions whose recording was flushed by a close, kept as tombstones so a
/// straggling event cannot conjure a fresh recording. Seals are retained until
/// retirement, never evicted: an evicted seal would silently reopen its
/// closed-but-unretired session to exactly the straggler overwrite the seal
/// exists to prevent. The set is bounded by construction rather than by a cap —
/// every seal is cleared when its session's descriptor is retired, and the
/// closed-but-unretired population can only accumulate while the coordinator
/// (whose descriptor removals drive retirement) is unreachable, during which no
/// new sessions are assigned to the relay either. Each entry is one small
/// `SessionKey`, so even a pathological retirement leak costs memory slowly;
/// crossing [`CLOSE_SEAL_WARN_THRESHOLD`] warns once (re-armed when the count
/// halves) as the tripwire for such a leak.
///
/// A close flush removes the session's recording, but the relay can stay
/// mesh-joined for the session until the coordinator retires its descriptor —
/// and a delayed mesh frame in that window (a late `SlotDeparted` marking a
/// drop hold, say) would otherwise re-create a recording through the ordinary
/// create-on-first-touch path. That replacement describes nothing, lingers
/// until the drain flush, and — every recording of one session sharing a single
/// storage key — its store would displace the real recording. Sealed keys drop
/// their events instead, until the session's membership is retired, which
/// clears the seal. Retirement is the *only* clearing trigger: a descriptor
/// push is routinely an idempotent replay (a coordinator reconnect re-pushes
/// every current descriptor), and a genuine re-serve always passes through a
/// retirement first.
#[derive(Default)]
struct CloseSeals {
    keys: HashSet<SessionKey>,
    /// Latched when the count crosses the warn threshold, so the tripwire
    /// fires once per excursion instead of on every seal past it.
    warned: bool,
}

impl CloseSeals {
    /// Seals `key`. A repeat leaves the set unchanged.
    fn seal(&mut self, key: &SessionKey) {
        if !self.keys.insert(key.clone()) {
            return;
        }
        if self.keys.len() >= CLOSE_SEAL_WARN_THRESHOLD && !self.warned {
            self.warned = true;
            // This many closed-but-unretired sessions means retirement has
            // stopped clearing seals — a very long coordinator outage, or a
            // retirement-path leak. The seals are all kept regardless (see
            // the struct doc); this is the diagnostic, not a limit.
            tracing::warn!(
                count = self.keys.len(),
                "close-seal count crossed the leak-warning threshold",
            );
        }
    }

    /// Clears `key`'s seal, if any.
    fn clear(&mut self, key: &SessionKey) {
        self.keys.remove(key);
        if self.warned && self.keys.len() < CLOSE_SEAL_WARN_THRESHOLD / 2 {
            self.warned = false;
        }
    }

    fn contains(&self, key: &SessionKey) -> bool {
        self.keys.contains(key)
    }
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
    /// Close-flushed sessions whose recording must not be recreated — see
    /// [`CloseSeals`].
    closed: CloseSeals,
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

    /// Wires the relay-wide session-gate registry, so create-on-first-touch
    /// refuses a retired session (see `Self::recording`). Set
    /// once at startup beside the sink; a second call is ignored. Without one
    /// (tests, a standalone recorder) every session reads as unretired.
    pub fn set_gates(&self, gates: crate::session_gate::SessionGates) {
        let _ = self.inner.gates.set(gates);
    }

    /// `key`'s live recording, created on first touch — or `None` when the key
    /// is close-sealed: a session whose recording a close already flushed must
    /// not have a straggler conjure a contentless replacement that would later
    /// displace the stored one (see [`CloseSeals`]).
    fn recording(&self, key: &SessionKey) -> Option<Arc<SessionRecording>> {
        // A retired session must not have a straggling event conjure a fresh
        // recording either: the close seal covers close-to-retirement, and
        // the retirement gate covers everything after — together the whole
        // tail of the session's lifecycle. The create runs INSIDE the gate's
        // ingress section, not after a bare flag read: retirement clears the
        // close seal as its last sweep, so a flag read racing the sweep
        // could pass while unretired, then insert after the seal was
        // cleared — a post-retirement replacement recording that would later
        // displace the stored one. Holding the read side across the insert
        // makes the retirement's write acquisition wait it out (or refuse
        // this create wholesale once marked).
        let create = || {
            let mut state = self.inner.recordings.lock();
            if state.closed.contains(key) {
                return None;
            }
            Some(Arc::clone(
                state
                    .sessions
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(SessionRecording::new())),
            ))
        };
        match self.inner.gates.get() {
            Some(gates) => gates.with_ingress(key, create).flatten(),
            // No gate registry wired (tests, a standalone recorder): every
            // session reads as unretired, exactly as before.
            None => create(),
        }
    }

    /// Records one event for `key`'s session, creating the recording on first
    /// touch — unless the key is close-sealed, in which case the event is
    /// dropped (see `CloseSeals`). Events are rare, so the short per-session
    /// mutex is fine here — this is never called on the per-turn path.
    pub fn record(&self, key: &SessionKey, event: FlightEvent) {
        if let Some(recording) = self.recording(key) {
            recording.push_event(EventRecord {
                at_ms: now_ms(),
                event,
            });
        }
    }

    /// Records one event for `key`'s session **only when a recording already
    /// exists**; with none, the event is dropped and no recording is created.
    ///
    /// This is for an event that only marks the end of an observation — the
    /// session close. Beginning a recording from one would be wrong twice
    /// over: the recording describes nothing that happened (its whole content
    /// is that the session ended), and every recording a relay makes of one
    /// session shares a single storage key, so storing it displaces the
    /// recording of a session the relay really did serve. Both matter once a
    /// flush has removed a session's recording — a close evaluated after that
    /// must be a no-op, not a second, contentless recording of the same
    /// session.
    pub fn record_existing(&self, key: &SessionKey, event: FlightEvent) {
        let recording = self
            .inner
            .recordings
            .lock()
            .sessions
            .get(key)
            .map(Arc::clone);
        if let Some(recording) = recording {
            recording.push_event(EventRecord {
                at_ms: now_ms(),
                event,
            });
        }
    }

    /// The counter handle for `key`'s `slot`, fetched **once** at link start so
    /// the per-turn path bumps plain atomics with no lock and no map lookup.
    /// For a close-sealed key the handle counts into the void (a fresh handle
    /// no recording holds) — the session's recording is already flushed, and
    /// re-creating one for a straggling link is exactly what the seal prevents.
    pub fn slot_counters(&self, key: &SessionKey, slot: SlotId) -> Arc<SlotCounters> {
        let Some(recording) = self.recording(key) else {
            return Arc::default();
        };
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

    /// Clears `key`'s close seal, if any (see `CloseSeals`). Called only when
    /// the session's mesh membership is retired: the mesh has forgotten the
    /// session, so the seal has (almost) nothing left to guard, and a genuine
    /// later re-serve of the key — which always passes through a retirement
    /// first — must be able to record again.
    pub fn clear_close_seal(&self, key: &SessionKey) {
        self.inner.recordings.lock().closed.clear(key);
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
    /// recording exists. The removal is what makes a flush terminal — and when
    /// `seal` is set, the close seal left behind is what *keeps* it terminal:
    /// without it, a straggling event while the session is still mesh-joined
    /// would start a fresh recording whose store later displaces this blob's
    /// (see [`CloseSeals`]). Sealed even when there was nothing to remove, so
    /// a close evaluated against a never-recorded session still blocks
    /// stragglers. A caller passes `seal: false` only for a session with no
    /// coordinator lifecycle (no descriptor ever named it), where no
    /// retirement will ever clear the seal and nothing remains for it to
    /// guard.
    fn take_blob(&self, key: &SessionKey, seal: bool) -> Option<FlightBlob> {
        let recording = {
            let mut state = self.inner.recordings.lock();
            if seal {
                state.closed.seal(key);
            }
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
        self.flush_session_with_seal(key, true).await
    }

    /// [`flush_session`](Self::flush_session) with the caller choosing whether
    /// the flush plants a close seal — see [`take_blob`](Self::take_blob).
    async fn flush_session_with_seal(&self, key: &SessionKey, seal: bool) -> FlushOutcome {
        let Some(blob) = self.take_blob(key, seal) else {
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
                // One key per session per relay: this store replaced whatever the
                // earlier one wrote, so the earlier recording is no longer
                // readable and the fact belongs in the log rather than only in
                // the difference between two stored objects nobody compares.
                if self.inner.recent_stores.lock().note(key) {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        relay_id = blob.relay_id,
                        events = blob.events.len(),
                        samples = blob.samples.len(),
                        "flight recording stored again for a session already stored; \
                         it replaced this relay's earlier recording",
                    );
                }
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
    pub fn flush_session_detached(&self, key: &SessionKey, seal: bool) {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let recorder = self.clone();
                let key = key.clone();
                handle.spawn(async move {
                    recorder.flush_session_with_seal(&key, seal).await;
                });
            }
            Err(_) => {
                let _ = self.take_blob(key, seal);
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
        let blob = recorder.take_blob(&k, true).expect("a recording exists");
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

        let blob = recorder.take_blob(&k, true).expect("a recording exists");
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
        let _ = recorder
            .take_blob(&first_key, true)
            .expect("a recording exists");
        assert_eq!(
            recorder.relay_work_snapshot(),
            RelayWorkSnapshot {
                client_turns_validated: 3,
                local_turn_deliveries: 3,
                oversize_diverts: 1,
            }
        );

        // The flush left the key close-sealed, so a straggling link's counters
        // count into the void — the deliberate cost of never re-creating a
        // flushed recording (see `CloseSeals`).
        recorder
            .slot_counters(&first_key, SlotId(0))
            .note_forwarded();
        assert_eq!(
            recorder.relay_work_snapshot(),
            RelayWorkSnapshot {
                client_turns_validated: 3,
                local_turn_deliveries: 3,
                oversize_diverts: 1,
            }
        );

        // A genuine re-serve clears the seal; new counters then wire into the
        // same relay-lifetime aggregate rather than restarting from zero.
        recorder.clear_close_seal(&first_key);
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
        let counters = recorder.slot_counters(&k, SlotId(0));
        counters.note_redundancy(3);
        counters.note_redundancy(2);
        counters.note_redundancy(0);
        counters.note_link_gauges(9, 12_000, 4);

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

        let blob = recorder.take_blob(&k, true).expect("a recording exists");
        let sample = &blob.samples[0];
        // The session-level end-to-end view rides the sample row.
        assert_eq!(sample.worst_e2e_lag_turns, Some(17));
        assert_eq!(sample.max_relay_hops, Some(2));
        let row = &sample.slots[0];
        assert_eq!(row.rtt_us, Some(42_000));
        assert_eq!(row.lost_packets, Some(3));
        assert_eq!(row.sent_packets, Some(500));
        // Redundancy accumulates across packets; the gauges are the link's
        // latest published values, not a running total.
        assert_eq!(row.redundant_payloads, 5);
        assert_eq!(row.upstream_lost_packets, 9);
        assert_eq!(row.cwnd, 12_000);
        assert_eq!(row.congestion_events, 4);
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
                reason: 0x4000_0006,
                apply_frame: 900,
                leave_seq: 3,
                finalized: true,
                final_turn_count: Some(44),
            },
        );
        recorder.record(
            &k,
            FlightEvent::LeaveMeshAccepted {
                source_relay: 9,
                slot: 1,
                reason: 0x4000_0006,
                apply_frame: 900,
                leave_seq: 3,
                finalized: true,
                final_turn_count: Some(44),
            },
        );
        recorder.record(
            &k,
            FlightEvent::LeaveControlWrite {
                recipient: 2,
                connection_epoch: 17,
                slot: 1,
                reason: 0x4000_0006,
                apply_frame: 900,
                leave_seq: 3,
                finalized: true,
                final_turn_count: Some(44),
                replayed: false,
                succeeded: true,
            },
        );
        recorder.record(&k, FlightEvent::SessionClosed);

        let blob = recorder.take_blob(&k, true).expect("a recording exists");
        assert_eq!(blob.version, BLOB_VERSION);
        assert_eq!(blob.tenant, "sb-test");
        assert_eq!(blob.session, 42);
        assert_eq!(blob.relay_id, 7);
        assert!(blob.started_at_ms > 0 && blob.flushed_at_ms >= blob.started_at_ms);

        let json = serde_json::to_string_pretty(&blob).unwrap();
        // The envelope is self-describing on the wire: version and tagged events.
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"event\": \"leave_decided\""));
        assert!(json.contains("leave_mesh_accepted"));
        assert!(json.contains("leave_control_write"));
        let back: FlightBlob = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    /// A recorded decision's derivation survives the blob round-trip with its
    /// per-slot detail intact, and a directive without one stays absent rather
    /// than serializing a hole.
    #[test]
    fn a_buffer_directives_derivation_roundtrips() {
        let recorder = FlightRecorder::default();
        recorder.set_identity(RelayId(7));
        let k = key(42);
        recorder.record(
            &k,
            FlightEvent::BufferDirective {
                buffer_turns: 12,
                apply_frame: 340,
                decision_seq: 2,
                inputs: Some(BufferDecisionInputs {
                    law_target: 8,
                    target: 13,
                    shrink_target: 13,
                    path_us: 125_000,
                    loss_risk_us: 4_700,
                    burst_turns: 4,
                    cushion_turns: 4,
                    stretch_turns: 1,
                    shrink_floor: 13,
                    edge_burned: true,
                    eff_rtts: vec![
                        SlotEffRtt {
                            slot: 0,
                            eff_rtt_us: 45_000,
                        },
                        SlotEffRtt {
                            slot: 3,
                            eff_rtt_us: 205_000,
                        },
                    ],
                }),
            },
        );
        recorder.record(
            &k,
            FlightEvent::BufferDirective {
                buffer_turns: 5,
                apply_frame: 900,
                decision_seq: 3,
                inputs: None,
            },
        );

        let blob = recorder.take_blob(&k, true).expect("a recording exists");
        let json = serde_json::to_string_pretty(&blob).unwrap();
        assert!(
            json.contains("\"eff_rtts\""),
            "the per-slot detail reaches the wire",
        );
        assert_eq!(
            json.matches("\"inputs\"").count(),
            1,
            "the directive with no derivation serializes no key for one",
        );

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
    async fn a_terminal_event_never_begins_a_recording() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);

        recorder.record_existing(&k, FlightEvent::SessionClosed);

        assert!(
            recorder.recorded_sessions().is_empty(),
            "an event that only marks the end of an observation starts nothing",
        );
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);
        assert!(sink.blobs.lock().is_empty(), "nothing was stored");
    }

    #[tokio::test]
    async fn a_terminal_event_lands_on_a_live_recording() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 3,
                resumed: false,
            },
        );

        recorder.record_existing(&k, FlightEvent::SessionClosed);

        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);
        let blobs = sink.blobs.lock();
        let stored = blobs.first().expect("the recording was stored");
        assert_eq!(
            stored.events.last().map(|record| &record.event),
            Some(&FlightEvent::SessionClosed),
            "the close seals the recording it was recorded against",
        );
    }

    #[tokio::test]
    async fn a_second_close_stores_nothing_over_an_already_stored_recording() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::BufferDirective {
                buffer_turns: 4,
                apply_frame: 1200,
                decision_seq: 9,
                inputs: None,
            },
        );
        recorder.record_existing(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

        // A close evaluated again for the same session — the relay serves it no
        // longer, so nothing has been recorded since.
        recorder.record_existing(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);

        let blobs = sink.blobs.lock();
        assert_eq!(blobs.len(), 1, "only the served session's recording stored");
        assert!(
            blobs[0]
                .events
                .iter()
                .any(|record| matches!(record.event, FlightEvent::BufferDirective { .. })),
            "the stored recording is the one holding what the relay observed",
        );
    }

    #[test]
    fn a_retired_sessions_event_never_begins_a_recording() {
        // The seal covers close-to-retirement; the session gate covers
        // everything after retirement (which clears the seal). Together no
        // straggler can conjure a recording anywhere in the session's tail.
        let recorder = FlightRecorder::default();
        let gates = crate::session_gate::SessionGates::default();
        recorder.set_gates(gates.clone());
        let k = key(1);

        gates.retire(&k);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 0,
                resumed: false,
            },
        );
        assert!(
            recorder.recorded_sessions().is_empty(),
            "a retired session's event records nothing",
        );

        // A genuine re-serve reopens the gate and records again.
        gates.reopen(&k);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 0,
                resumed: false,
            },
        );
        assert!(!recorder.recorded_sessions().is_empty());
    }

    #[test]
    fn a_seal_past_the_warn_threshold_is_retained_not_evicted() {
        // Volume must never evict a seal: an evicted seal would silently
        // reopen its closed-but-unretired session to the straggler overwrite
        // the seal exists to prevent. The threshold only trips the leak warn.
        let mut seals = CloseSeals::default();
        let first = key(1);
        seals.seal(&first);
        for session in 2..=(CLOSE_SEAL_WARN_THRESHOLD as u64 + 4) {
            seals.seal(&key(session));
        }
        assert!(
            seals.contains(&first),
            "the oldest seal survives any volume of later seals",
        );
        assert!(seals.warned, "crossing the threshold trips the leak warn");

        // Retirement clearing drains the set; the warn latch re-arms once the
        // count halves, so a later excursion warns again.
        for session in 1..=(CLOSE_SEAL_WARN_THRESHOLD as u64 + 4) {
            seals.clear(&key(session));
        }
        assert!(!seals.warned, "the warn latch re-arms as the set drains");
        assert!(!seals.contains(&first));
    }

    #[test]
    fn the_recent_store_window_reports_a_repeat_and_evicts_the_oldest() {
        let mut recent = RecentStores::default();
        assert!(!recent.note(&key(1)), "a first store is not a repeat");
        assert!(recent.note(&key(1)), "storing the same session again is");
        assert_eq!(
            recent.order.len(),
            1,
            "a repeat does not re-enter the window"
        );

        // One store past the cap evicts the oldest session, which then reads as a
        // first store again.
        for session in 2..=(RECENT_STORES as u64 + 1) {
            assert!(!recent.note(&key(session)), "each session is new");
        }
        assert_eq!(recent.order.len(), RECENT_STORES, "the window is capped");
        assert!(!recent.note(&key(1)), "the evicted session is forgotten");
    }

    #[tokio::test]
    async fn a_store_for_an_already_stored_session_is_noticed() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 0,
                resumed: false,
            },
        );
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

        // The relay genuinely serves the session again — its retirement
        // cleared the close seal before the re-serve — and the second store
        // replaces what the first one wrote.
        recorder.clear_close_seal(&k);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 0,
                resumed: true,
            },
        );
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

        assert_eq!(sink.blobs.lock().len(), 2, "both stores reached the sink");
        let mut recent = recorder.inner.recent_stores.lock();
        assert!(recent.note(&k), "the flushes remembered the stored session");
        assert_eq!(
            recent.order.len(),
            1,
            "one entry for the one session stored"
        );
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

        // The discard is as terminal as a store: the key is close-sealed, so a
        // straggling event does not begin a replacement recording.
        recorder.record(&k, FlightEvent::SessionClosed);
        assert!(recorder.events(&k).is_empty());

        // A genuine re-serve records again.
        recorder.clear_close_seal(&k);
        recorder.record(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.events(&k).len(), 1);
    }

    /// The regression the close seal exists for: a session's close flushes its
    /// recording while the relay is still mesh-joined for it, and a delayed
    /// mesh frame then produces an ordinary event (a late `SlotDeparted`
    /// marking a drop hold). Without the seal that event re-created a
    /// recording through create-on-first-touch, which lingered until the drain
    /// flush and — one storage key per session per relay — displaced the real
    /// stored recording with a contentless one.
    #[tokio::test]
    async fn a_straggling_event_after_the_close_flush_cannot_displace_the_stored_recording() {
        let recorder = FlightRecorder::default();
        let sink = Arc::new(CaptureSink::default());
        recorder.set_sink(sink.clone());
        let k = key(1);
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: 0,
                resumed: false,
            },
        );
        recorder.record_existing(&k, FlightEvent::SessionClosed);
        assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

        // The straggler: still mesh-joined, a late mesh frame records a hold.
        recorder.record(&k, FlightEvent::DropHeld { slot: 1 });
        assert!(
            recorder.recorded_sessions().is_empty(),
            "the sealed key began no replacement recording",
        );

        // The drain flush finds nothing to store over the real recording.
        recorder.flush_all(Duration::from_secs(1)).await;
        assert_eq!(sink.blobs.lock().len(), 1, "only the real recording stored");

        // Membership retirement clears the seal; nothing arrives after it.
        recorder.clear_close_seal(&k);
        assert!(recorder.recorded_sessions().is_empty());
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
