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
//! The dev sink is [`FileSink`] (`--flight-dir`), writing
//! `<dir>/<tenant>/<session>/<relay_id>.json`; the tenant-first prefix is the
//! structural hook for tenant-scoped read authorization when the durable store
//! (S3) lands. The **read path is not built** — investigating a blob today
//! means opening the JSON; tenant-facing reads land with the durable store,
//! scoped by that same path prefix.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rally_point_proto::control::DepartureKind;
use rally_point_proto::ids::{RelayId, SlotId};
use serde::{Deserialize, Serialize};

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
    /// observing full expected-slot coverage).
    SessionStart,
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
    /// Topological duplicates of this slot's turns the mesh dedup dropped.
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
/// `<dir>/<tenant>/<session>/<relay_id>.json`. The tenant-first prefix is the
/// structural hook tenant-scoped read authorization will key on when the
/// durable store lands; the file tree mirrors the object-key scheme so nothing
/// about the layout changes shape then. No retention: files accumulate until
/// deleted by hand (the S3 lifecycle rule is the production retention story).
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
    sessions: Mutex<HashMap<SessionKey, Arc<SessionRecording>>>,
    /// This relay's id, stamped into every blob header. Set once at startup;
    /// absent (a standalone relay with no `--relay-id`) blobs carry 0.
    relay_id: OnceLock<RelayId>,
    /// Where flushed blobs go. Set once at startup; absent, a flush is a
    /// logged discard (the recorder still records — cheap and bounded).
    sink: OnceLock<Arc<dyn FlightSink>>,
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
        let mut sessions = self.inner.sessions.lock();
        Arc::clone(
            sessions
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

    /// Counts a topological duplicate the mesh dedup dropped for `key`/`slot`.
    /// Takes the map locks — acceptable because the duplicate branch is off the
    /// common per-turn path (only a multi-relay echo reaches it), which is why
    /// this is not routed through a pre-fetched handle like the hot counters.
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
            let sessions = self.inner.sessions.lock();
            sessions
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
        self.inner.sessions.lock().keys().cloned().collect()
    }

    /// A snapshot of `key`'s recorded events, for tests and diagnostics.
    pub fn events(&self, key: &SessionKey) -> Vec<EventRecord> {
        self.inner
            .sessions
            .lock()
            .get(key)
            .map(|r| r.events.lock().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes `key`'s recording and builds its flushed blob, or `None` if no
    /// recording exists. The removal is what makes a flush terminal: later
    /// events for the same key start a fresh recording.
    fn take_blob(&self, key: &SessionKey) -> Option<FlightBlob> {
        let recording = self.inner.sessions.lock().remove(key)?;
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

    /// Flushes every live recording concurrently, bounded by `deadline` — the
    /// drain path's wholesale flush. Whatever the deadline cuts off is logged
    /// and abandoned: flight data is observability, and the drain's own budget
    /// (and Fargate's stopTimeout behind it) outranks it.
    pub async fn flush_all(&self, deadline: Duration) {
        let keys = self.recorded_sessions();
        if keys.is_empty() {
            return;
        }
        tracing::info!(
            sessions = keys.len(),
            "flushing flight recordings for drain"
        );
        let completed = AtomicU64::new(0);
        let flushes = keys.iter().map(|key| {
            let completed = &completed;
            async move {
                self.flush_session(key).await;
                completed.fetch_add(1, Ordering::Relaxed);
            }
        });
        if tokio::time::timeout(deadline, futures_util::future::join_all(flushes))
            .await
            .is_err()
        {
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
    fn the_sampler_folds_published_link_conditions_into_the_row() {
        let recorder = FlightRecorder::default();
        let k = key(1);
        let _counters = recorder.slot_counters(&k, SlotId(0));

        let conditions = crate::mesh::new_conditions_registry();
        crate::mesh::publish_conditions(
            &conditions,
            &k,
            SlotId(0),
            rally_point_proto::messages::SlotConditions {
                slot: 0,
                rtt_us: 42_000,
                lost_packets: 3,
                sent_packets: 500,
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
        recorder.record(&k, FlightEvent::SessionStart);

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
        recorder.record(&k, FlightEvent::SessionStart);
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
        recorder.record(&key(1), FlightEvent::SessionStart);
        recorder.record(&key(2), FlightEvent::SessionStart);

        let started = std::time::Instant::now();
        recorder.flush_all(Duration::from_millis(100)).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the drain flush returns at its deadline, not the sink's pace",
        );
    }
}
