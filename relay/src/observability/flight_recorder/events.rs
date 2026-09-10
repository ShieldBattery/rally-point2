//! Flight-recorder record shapes: the events, per-slot samples, and the
//! flushed blob envelope that wraps them. Pure data — no locking, no I/O —
//! kept separate from the recorder that accumulates and flushes them.

use rally_point_proto::control::DepartureKind;
use serde::{Deserialize, Serialize};

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
    /// The relay closed a slot's link because its turns stopped reaching the
    /// session's other players while everyone else's kept arriving — a hung game
    /// thread or a suspended process behind a link that kept answering
    /// keepalives. Lockstep cannot advance past such a slot, and the survivors'
    /// drop machinery only fires for a slot the relay saw disconnect, so the
    /// relay manufactures the disconnect here; the
    /// [`SlotDisconnected`](Self::SlotDisconnected) and
    /// [`DropHeld`](Self::DropHeld) that follow are the ordinary link-death path
    /// doing the rest. `silent_ms` is how long ago this slot's forwarded turns
    /// stopped; `lead_ms` how much earlier that was than the next-earliest slot
    /// the session still needed — the entire margin the eviction rested on.
    SlotEvictedSilent {
        slot: u8,
        silent_ms: u64,
        lead_ms: u64,
    },
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
    /// A local slot reported that its game loop began running — the client
    /// finished loading and is stepping the simulation. Recorded once per slot
    /// per link (a repeat on the same link is dropped before it reaches here).
    SlotGameStarted { slot: u8 },
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
    /// A slot's validated turn carried a `game_frame_count` below the slot's
    /// newest recorded frame at a *higher* transport seq than any framed turn
    /// before it. A client stamps its executable-turn index, which only
    /// advances once its game loop is stepping, so this ordering means the
    /// index restarted underneath the stamps: a turn stamped before the loop
    /// began, while the index still held its lobby-era value, or a hostile
    /// stamp. The observation is not corrected — the slot's frame stays at the
    /// high-water mark — so a frame-scheduled leave for this slot can land
    /// past the frame the survivors stall at; a recording with this event
    /// followed by a stall after the slot's leave is that failure. Reported
    /// once per slot.
    FrameStampRegressed {
        slot: u8,
        seq: u64,
        frame: u32,
        prior_frame: u32,
    },
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
    /// [`crate::consensus::delivery`]). Absent until a pair has evidence on both ends (or
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
/// [`FlightSink`](super::sinks::FlightSink) persists. Everything an investigation needs to key on rides
/// the header, so a blob is meaningful with no context beyond itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlightBlob {
    /// Envelope version ([`super::BLOB_VERSION`]); bumped on any breaking shape change.
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
