//! One session's live recording: the per-slot hot-path counters, the bounded
//! event/sample rings they feed, and the relay-lifetime work snapshot derived
//! from them. Kept apart from [`super::FlightRecorder`] itself, which owns
//! the map of these keyed by session and their lifecycle (create, seal, flush).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;

use super::events::{EventRecord, SampleRecord, SlotSample};
use super::{MAX_EVENTS_PER_SESSION, MAX_SAMPLES_PER_SESSION, now_ms};

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

    pub(super) fn note_dedup_drop(&self) {
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
    pub(super) fn accumulate(&mut self, other: Self) {
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
///
/// `pub(super)`: [`super::FlightRecorder`] and its flush path own the map of
/// these keyed by session and reach into the fields and helpers directly
/// (create on first touch, push events/samples, fold counters into a blob).
pub(super) struct SessionRecording {
    pub(super) started_at_ms: u64,
    pub(super) events: Mutex<VecDeque<EventRecord>>,
    pub(super) events_dropped: AtomicU64,
    pub(super) samples: Mutex<VecDeque<SampleRecord>>,
    pub(super) samples_dropped: AtomicU64,
    pub(super) counters: Mutex<HashMap<SlotId, Arc<SlotCounters>>>,
}

impl SessionRecording {
    pub(super) fn new() -> Self {
        Self {
            started_at_ms: now_ms(),
            events: Mutex::new(VecDeque::new()),
            events_dropped: AtomicU64::new(0),
            samples: Mutex::new(VecDeque::new()),
            samples_dropped: AtomicU64::new(0),
            counters: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn push_event(&self, record: EventRecord) {
        let mut events = self.events.lock();
        if events.len() >= MAX_EVENTS_PER_SESSION {
            events.pop_front();
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        events.push_back(record);
    }

    pub(super) fn push_sample(&self, record: SampleRecord) {
        let mut samples = self.samples.lock();
        if samples.len() >= MAX_SAMPLES_PER_SESSION {
            samples.pop_front();
            self.samples_dropped.fetch_add(1, Ordering::Relaxed);
        }
        samples.push_back(record);
    }

    /// The work counters already maintained for flight-recorder rows, folded
    /// without adding another contended atomic update to the per-turn path.
    pub(super) fn work_snapshot(&self) -> RelayWorkSnapshot {
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
    pub(super) fn sample_row(
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
///
/// `pub(super)`: built by [`super::FlightRecorder::sample_now`] from the
/// slot-link conditions registry, outside this module.
pub(super) struct SlotConditionsRow {
    pub(super) rtt_us: u32,
    pub(super) lost_packets: u64,
    pub(super) sent_packets: u64,
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
