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

mod events;
mod flush;
mod recording;
mod sinks;

pub use events::{
    BufferDecisionInputs, EventRecord, FlightBlob, FlightEvent, SampleRecord, SlotEffRtt,
    SlotSample,
};
pub use recording::{FlushOutcome, RelayWorkSnapshot, SlotCounters};
pub use sinks::{
    CoordinatorSink, DRAIN_FLUSH_CONCURRENCY, FLIGHT_SHIP_QUEUE, FileSink, FlightShipment,
    FlightSink, MAX_SHIPPED_BLOB_BYTES,
};

use recording::{SessionRecording, SlotConditionsRow};

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rally_point_proto::ids::{RelayId, SlotId};

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
    gates: OnceLock<crate::session::gate::SessionGates>,
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
    pub fn set_gates(&self, gates: crate::session::gate::SessionGates) {
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
mod tests;
