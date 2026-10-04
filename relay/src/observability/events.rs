//! Flight-recorder record shapes: the events, per-slot samples, and the
//! flushed blob envelope that wraps them, plus the one trait a module needs to
//! emit them. Pure data — no locking, no I/O, and no dependency on anything
//! else in this relay — kept separate from the recorder that accumulates and
//! flushes them, which needs the mesh conditions registry and the session
//! gates to do its own job.
//!
//! This separation is what lets a decision or routing path name the event it
//! emits without depending on the recorder's wiring.

use serde::{Deserialize, Serialize};

use rally_point_proto::control::DepartureKind;
use rally_point_proto::messages::{LeadReport, RollbackStats};

use crate::key::SessionKey;

/// Somewhere a flight event can be written. The recorder implements it; a test
/// can stand in with a collecting fake.
///
/// Narrow on purpose: a module that emits events wants exactly these two calls
/// and nothing else the recorder can do (sampling, flushing, sink wiring).
/// Emitters take it as an `impl`/generic bound rather than a trait object —
/// every implementation is known at the call site, and an event can be emitted
/// from the turn path's rare branches, where an indirect call would buy
/// nothing.
pub trait FlightEvents {
    /// Records one event for `key`'s session, beginning the session's
    /// recording if this is the first thing observed about it.
    fn record(&self, key: &SessionKey, event: FlightEvent);

    /// Records one event **only when a recording for `key` already exists**;
    /// with none, the event is dropped and no recording begins. For an event
    /// that only marks the end of an observation, such as a session close.
    fn record_existing(&self, key: &SessionKey, event: FlightEvent);
}

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
    /// The relay closed a slot's link, as its home, because the rollback
    /// session's state hash comparison named it: its hash disagreed with the
    /// majority's, or it kept sending turns without reporting one. Rollback
    /// clients run no native sync, so nothing else takes a diverged player out
    /// of the game. The slot is refused every later dial, and once its link is
    /// down the home finalizes its drop unprompted; the
    /// [`SlotDisconnected`](Self::SlotDisconnected) that follows, and the
    /// finalized leave the session authority then decides, are that path.
    /// `sync_ordinal` is the state hash step whose verdict named the slot.
    SlotEvictedDesync { slot: u8, sync_ordinal: u64 },
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
    /// One connectivity-frame write to a local client. Success means the QUIC
    /// stream accepted the frame, not that the client or game consumed it.
    ConnectivityControlWrite {
        recipient: u8,
        /// The recipient's link epoch, matching `LeaveControlWrite`.
        connection_epoch: u64,
        slot: u8,
        connected: bool,
        /// The subject's lifecycle epoch carried in the connectivity frame.
        subject_connection_epoch: Option<u64>,
        succeeded: bool,
    },
    /// A mesh connectivity change failed the subject's lifecycle admission.
    ConnectivityMeshRejected {
        source_relay: u64,
        slot: u8,
        connected: bool,
        connection_epoch: Option<u64>,
    },
    /// A connectivity change could not enter a local recipient's full queue.
    /// No control-stream write was attempted for this change.
    ConnectivityQueueFull {
        recipient: u8,
        connection_epoch: u64,
        slot: u8,
        connected: bool,
        subject_connection_epoch: Option<u64>,
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
    /// This relay can no longer establish one origin's checksum ordinals.
    /// Observation failure is distinct from a confirmed simulation divergence.
    /// Recorded once per origin, retaining context before pending reports clear.
    SyncOrderingUnavailable {
        slot: u8,
        reason: String,
        seq: u64,
        missing_next: u64,
        previous_ordinal: Option<u64>,
        ring: Option<u8>,
    },
    /// The desync comparator confirmed a divergence, or in a rollback session, that a slot kept
    /// playing without a state hash report it owed (`missing`).
    DesyncDetected {
        sync_ordinal: u64,
        diverged: Vec<u8>,
        no_majority: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        missing: Vec<u8>,
    },
    /// A dropped slot's leave decision was placed on hold (survivors stalled
    /// but the slot not yet removed). The later decision, if one comes, is the
    /// [`LeaveDecided`](Self::LeaveDecided) event — there is no separate
    /// "hold decided" record.
    DropHeld { slot: u8 },
    /// A surviving member's manual drop request was admitted (validated and
    /// rate-cap-passed) against a held slot.
    DropRequested { requester: u8, target: u8 },
    /// A client request was rejected before local honoring or mesh broadcast.
    DropRequestRejected {
        requester: u8,
        /// Preserve the wire value even when it cannot fit in a slot id.
        target: u32,
        reason: DropRequestRejectionReason,
    },
    /// The authority could not honor a request. No hold has no elapsed time;
    /// a lost claim carries the elapsed time observed before the claim attempt.
    DropRequestRefused {
        requester: u32,
        target: u8,
        held_ms: Option<u64>,
        reason: DropRequestRefusalReason,
    },
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
    /// The last rollback statistics a slot's client reported on a link that
    /// has just ended, recorded once per such link, just ahead of its
    /// [`SlotDisconnected`](Self::SlotDisconnected). The periodic sample rows
    /// carry the earlier snapshots; this is the one a game-end report lands in,
    /// since a link that ends with a leave intent has no sample after it.
    SlotRollbackStats {
        slot: u8,
        stats: ClientRollbackStats,
    },
    /// The rollback session clock was anchored on this relay: by this relay as
    /// the session authority once the lockstep start became confirmable
    /// (`adopted` false), or from the authority's clock (`adopted` true).
    /// `anchor_step` is the step due at the anchor.
    SessionClockAnchored { anchor_step: u64, adopted: bool },
    /// The rollback session clock's stopped time grew, to `pause_us` in total:
    /// the whole session waited on turns that weren't coming. Recorded on the
    /// authority when it stops the clock and elsewhere when the authority's
    /// stop arrives, at most [`MAX_CLOCK_STOP_EVENTS`] times per session; the
    /// sample rows' `clock_pause_us` keeps tracking it past that.
    SessionClockStopped { pause_us: u64 },
}

/// The most [`FlightEvent::SessionClockStopped`] events one session records.
/// A session that keeps stopping (a long run of drop waits) would otherwise
/// spend the event ring on them; past this the sample rows' `clock_pause_us`
/// still shows every stop's effect.
pub const MAX_CLOCK_STOP_EVENTS: u32 = 32;

/// Why a manual drop request was rejected at the authenticated client edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropRequestRejectionReason {
    SelfTarget,
    NotDisconnected,
    RateCapped,
    OutOfRange,
}

/// Why the authority left a manual drop request unhonored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropRequestRefusalReason {
    BelowFloor,
    NoHold,
    LostClaim,
}

/// The control law's derivation of one latency-buffer decision: every term
/// that fed the target, plus the gate state that decided how far the buffer
/// was allowed to move. A depth on its own says only what the session got;
/// these say why, which is the difference between reading a recording and
/// guessing at one.
///
/// Every turn-valued field is in game turns and every microsecond-valued one
/// says `_us`. The terms compose as
/// `law_target = ceil(path) + max(ceil(loss_risk), burst_turns)` and
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

/// A relay's current ability to compare player sync checksums. The values are
/// counts rather than slot identities so periodic samples remain compact and
/// suitable for fleet-level aggregation.
///
/// A slot is `ordered` once this relay has a complete transport prefix and a
/// native sync ordinal. `waiting` has a bounded gap, has not emitted a sync
/// command yet, or has never been seen; each may still become ordered.
/// `unavailable` lost the trustworthy prefix or native-ring epoch and is
/// excluded from checksum comparison for the rest of this session on this
/// relay. `expected_players` excludes observers and departed slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncCoverage {
    pub expected_players: u32,
    pub ordered_slots: u32,
    pub waiting_slots: u32,
    pub unavailable_slots: u32,
    /// Players whose ordered checksum reports can currently participate in a
    /// comparison. This can be smaller than `ordered_slots` after an authority
    /// handoff resets comparator membership or while a minority is excluded.
    pub comparable_slots: u32,
    /// Whether this relay currently decides checksum divergences for the
    /// session.
    pub authority: bool,
    /// Whether safety bounds or a disagreement without a majority suspended
    /// the comparator.
    pub dormant: bool,
}

/// A rollback client's own statistics for its game, cumulative from the end of
/// the game's lockstep start through `through_turn`, as it last reported them
/// on a `RollbackStats` control frame. Durations are microseconds. Recorded as
/// the client sent them: the relay checks only their size, never their
/// plausibility, so they are the client's account and nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientRollbackStats {
    pub version: u32,
    pub through_turn: u32,
    pub rollback_target: u32,
    pub prediction_limit: u32,
    pub ticks: u32,
    /// Ticks by how far the shown frame was past the newest fully known turn:
    /// entry `i` counts ticks `i` frames ahead, the last entry that many or
    /// more.
    pub rollback_histogram: Vec<u32>,
    /// Ticks by the client's own input delay in turns: entry `i` counts ticks
    /// at `i` turns, the last entry that many or more.
    pub pipe_histogram: Vec<u32>,
    pub capped_ticks: u32,
    pub rollbacks: u32,
    pub resimulated_frames: u32,
    pub deepest_rollback: u32,
    pub predicted_steps: u32,
    pub mispredicted_turns: u32,
    pub confirmed_predictions: u32,
    pub caught_up_frames: u32,
    pub held_back_ticks: u32,
    pub lead_changes: u32,
    pub schedule_corrections: u32,
    pub schedule_corrected_us: i64,
    pub holds_undone: u32,
    pub clock_stopped_us: u64,
    pub lead_reports: u32,
    pub lead_p90_max_us: i32,
    pub lead_p90_sum_us: i64,
    pub worst_tick_us: u64,
    pub slow_ticks: u32,
    pub restore_us: u64,
    pub snapshot_us: u64,
    pub step_us: u64,
}

impl From<RollbackStats> for ClientRollbackStats {
    fn from(stats: RollbackStats) -> Self {
        Self {
            version: stats.version,
            through_turn: stats.through_turn,
            rollback_target: stats.rollback_target,
            prediction_limit: stats.prediction_limit,
            ticks: stats.ticks,
            rollback_histogram: stats.rollback_histogram,
            pipe_histogram: stats.pipe_histogram,
            capped_ticks: stats.capped_ticks,
            rollbacks: stats.rollbacks,
            resimulated_frames: stats.resimulated_frames,
            deepest_rollback: stats.deepest_rollback,
            predicted_steps: stats.predicted_steps,
            mispredicted_turns: stats.mispredicted_turns,
            confirmed_predictions: stats.confirmed_predictions,
            caught_up_frames: stats.caught_up_frames,
            held_back_ticks: stats.held_back_ticks,
            lead_changes: stats.lead_changes,
            schedule_corrections: stats.schedule_corrections,
            schedule_corrected_us: stats.schedule_corrected_us,
            holds_undone: stats.holds_undone,
            clock_stopped_us: stats.clock_stopped_us,
            lead_reports: stats.lead_reports,
            lead_p90_max_us: stats.lead_p90_max_us,
            lead_p90_sum_us: stats.lead_p90_sum_us,
            worst_tick_us: stats.worst_tick_us,
            slow_ticks: stats.slow_ticks,
            restore_us: stats.restore_us,
            snapshot_us: stats.snapshot_us,
            step_us: stats.step_us,
        }
    }
}

/// The upper bounds, in milliseconds of lateness, of the buckets of
/// [`SlotLeadSample::lateness_histogram`]: a turn falls in the first bucket
/// whose bound it does not exceed, or past the last bound in one more. So the
/// ten buckets hold lateness of at most -40, then over -40 to -20, -20 to -10,
/// -10 to 0, 0 to 10, 10 to 20, 20 to 40, 40 to 80 and 80 to 160 (each
/// including its upper end), and over 160. Negative lateness is a turn that
/// arrived early.
pub const LEAD_LATENESS_BUCKET_BOUNDS_MS: [i32; 9] = [-40, -20, -10, 0, 10, 20, 40, 80, 160];

/// How many buckets [`SlotLeadSample::lateness_histogram`] has.
pub const LEAD_LATENESS_BUCKETS: usize = LEAD_LATENESS_BUCKET_BOUNDS_MS.len() + 1;

/// One lead report as the relay sent it to a slot's client: the lateness of
/// the slot's newest turns against the rollback session clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeadReportRecord {
    /// The newest step whose arrival the report covers.
    pub through_step: u64,
    /// The median lateness of the report's window, in microseconds (negative
    /// when early). Meaningless when `samples` is zero.
    pub median_us: i32,
    /// The 90th percentile lateness, like `median_us`.
    pub p90_us: i32,
    /// How many turns the window held; zero for a report sent because the
    /// clock stopped, which only carries `pause_us`.
    pub samples: u32,
    /// The session clock's total stopped time when the report was made.
    pub pause_us: u64,
}

impl From<&LeadReport> for LeadReportRecord {
    fn from(report: &LeadReport) -> Self {
        Self {
            through_step: report.through_step,
            median_us: report.median_us,
            p90_us: report.p90_us,
            samples: report.samples,
            pause_us: report.pause_us,
        }
    }
}

/// How late one home slot's turns reached this relay against a rollback
/// session's clock: figures for the sample interval since the previous row,
/// plus a histogram cumulative over the whole recording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotLeadSample {
    /// Turns measured during the interval.
    pub turns: u32,
    /// Lead reports made for the slot during the interval: each one due, and
    /// each one a clock stop forced. A reconnect's re-send of the current
    /// report is not a new one.
    pub reports: u32,
    /// The newest report made for the slot, during the interval or before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<LeadReportRecord>,
    /// The highest p90 lateness among the interval's reports that carried any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_p90_us: Option<i32>,
    /// The latest any single turn measured during the interval arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lateness_us: Option<i32>,
    /// Every turn measured since the recording began, by lateness, in the
    /// buckets [`LEAD_LATENESS_BUCKET_BOUNDS_MS`] describes.
    pub lateness_histogram: Vec<u64>,
}

/// One rollback session's lead figures at a sampling instant, as the sampler
/// reads them from the session's decision-maker: each measured home slot's
/// [`SlotLeadSample`] and the clock's stopped time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeadSamples {
    /// The session clock's total stopped time, once the clock is anchored.
    pub clock_pause_us: Option<u64>,
    /// Each measured home slot's figures, by slot id.
    pub slots: Vec<(u8, SlotLeadSample)>,
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
    /// In a rollback session, how late this slot's turns reached this relay,
    /// its home, against the session clock. Absent for a slot homed elsewhere,
    /// before its first measured turn, outside a rollback session, and on the
    /// final flush snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead: Option<SlotLeadSample>,
    /// The latest rollback statistics this slot's client reported to this
    /// relay. Absent until the first report, and outside a rollback session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_stats: Option<ClientRollbackStats>,
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
    /// The checksum comparator's coverage at this sampling instant. Absent
    /// from final-flush snapshots, because their consensus state may already
    /// have been retired, and from sessions with no decision-maker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_coverage: Option<SyncCoverage>,
    /// In a rollback session, the session clock's total stopped time once the
    /// clock is anchored, in microseconds. Absent otherwise, and from
    /// final-flush snapshots like [`sync_coverage`](Self::sync_coverage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_pause_us: Option<u64>,
}

/// One session's flushed recording: the versioned, self-describing envelope a
/// [`FlightSink`](crate::observability::flight_recorder::FlightSink) persists. Everything an investigation needs to key on rides
/// the header, so a blob is meaningful with no context beyond itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlightBlob {
    /// Envelope version ([`crate::observability::flight_recorder::BLOB_VERSION`]); bumped on any breaking shape change.
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
