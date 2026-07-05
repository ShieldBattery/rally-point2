//! The latency-buffer decision-maker: the relay-side core of the runtime
//! consensus authority.
//!
//! This is the *decision* half of the buffer consensus -- which relay decides,
//! from what data, and the control law that turns network conditions into a
//! buffer-size change. The [`DecisionMaker`] itself is pure and synchronous: no
//! I/O, no async, no locks of its own. It is fed conditions and game-frame
//! observations by its caller and returns a [`Decision`] describing what (if
//! anything) to broadcast; the registry-level helpers at the bottom of this
//! module add the locking and logging the turn path needs.
//!
//! The broadcast rides the turn stream as envelope metadata: a decision queues
//! a directive that [`active_directive`](DecisionMaker::active_directive) hands
//! to the caller for every turn it forwards, which sets it on each payload's
//! `buffer_directive` field, until the whole session has passed the directive's
//! apply frame. It is deliberately *not* a command in the SC:R byte stream -- a
//! native latency command would cap the buffer at the game's built-in range and
//! would have to be forged into a slot's turn, and a client applies one turn
//! per remote player per step, so an extra command can't just be handed over.
//! Riding the envelope, the buffer has no ceiling and the game applies it out
//! of band, off the turn it arrives on. The value, the frame to apply it at,
//! and the decision seq that orders it are all this module produces; the caller
//! sets the wire field.
//!
//! # Authority and authority handoff
//!
//! The relays sit in a fixed priority order; the highest still serving live
//! players is the decision-maker. (Multiple relays serving one game is the
//! *normal* case -- players in different regions each connect to a nearby
//! relay, and the mesh carries turns between them. "Handoff" is specifically
//! when the authority relay drops out -- its players have all left -- and
//! authority falls to the next relay in the order, with no coordinator
//! round-trip.) Authority is an **injected input** to this core: the caller
//! (`MeshControl`) computes the verdict from each coordinator descriptor --
//! today by relay-id order, an interim rule until the coordinator assigns an
//! explicit priority order and a presence signal drives handoff -- and
//! re-injects it via [`DecisionMaker::sync`] on every push, so the verdict
//! follows the relay set as players come and go. A promoted relay's decisions
//! must outrank everything the previous authority broadcast; that is what
//! [`observe_directive`](DecisionMaker::observe_directive) is for.
//!
//! # The target formula
//!
//! The buffer is sized to the worst-case one-way delivery time -- the time for
//! a turn to travel from its sender, through the relay (and the mesh, for
//! cross-relay paths), to the slowest receiver, including loss recovery. The
//! formula:
//!
//! ```text
//! target = ceil(pairwise_path / turn_duration) + ceil(loss_risk / turn_duration)
//! ```
//!
//! Path and loss are `ceil`'d separately because loss recovery is quantized to
//! whole turns: a re-carry rides the next packet, exactly one turn_duration
//! later (packets are one turn apart). So a lost turn's delivery is
//! `path + N ** turn_duration` -- a whole number of turns *added* to the path
//! turns, not a continuous addition absorbed into the path's `ceil` slack.
//! Combining them into one `ceil` would absorb the loss term into the path's
//! fractional remainder and under-provision -- e.g. at 150ms path with one
//! re-carry, delivery is `41666 + 150000 = 191666us` needing `ceil(191666/41666)
//! = 5` turns; the separated form gives `4 + 1 = 5` (correct), a combined form
//! gives `ceil(157500/41666) = 4 = 166664us < 191666` (stalls on a single loss).
//!
//! At low latency with no loss, the target is just `ceil(path / turn_duration)`
//! -- the loss term is 0 and adds nothing. The minimum is 1 (any positive RTT
//! rounds up), not 2; the separation only adds turns when there is actual loss
//! to recover from.
//!
//! - **`pairwise_path = (eff_RTT_A + eff_RTT_B) / 2`** -- the worst one-way
//!   path for the two slowest players. Each slot's *effective RTT* is its
//!   QUIC RTT plus the one-way mesh hop from the authority relay to its home
//!   relay (0 for local slots, the relay-pair RTT for remote slots). A turn
//!   from player A to player B travels `eff_RTT_A/2 + eff_RTT_B/2`, so the
//!   worst pair is the two highest-eff-RTT players. Using the actual pairwise
//!   path (not `max_eff_RTT`) avoids overshooting when only one player has
//!   high latency -- lower buffer means less input delay, which feels better.
//! - **`loss_risk = max over slots of (loss_rate * eff_RTT)`** -- burst loss
//!   on a high-latency link is worse than on a low-latency one: more packets
//!   are in flight during the burst window, so more consecutive re-carries
//!   can be lost. The term scales with both loss rate and effective RTT,
//!   capturing that 5% loss on a 300ms link is more dangerous than 5% on 50ms.
//! - **`turn_duration`** -- one game step at 24 turns/sec == ~41.7ms. Each
//!   buffer turn adds one step of dispatch delay, so the buffer is measured
//!   in turns.
//!
//! The `ceil` on the path naturally gives a minimum of 1 for any positive RTT
//! (a turn always has to travel some distance), so no separate floor is needed.
//!
//! # Local vs. remote slots
//!
//! The decision-maker distinguishes slots whose conditions it observes directly
//! (home clients on this relay) from slots whose conditions arrive via the mesh
//! sidecar (home clients on a peer relay). A remote slot's effective RTT
//! includes the mesh hop -- the one-way relay-pair RTT from the authority to
//! the slot's home relay -- so cross-relay paths are sized correctly. The caller
//! supplies the mesh RTT when ingesting remote conditions (sampled from the
//! `MeshLink`'s QUIC connection stats); the transport doesn't carry it in the
//! sidecar because the mesh RTT is a property of the relay-pair, not of any
//! individual client's link.
//!
//! **N-relay gap.** The single `mesh_rtt_us` parameter models a 2-relay path
//! (authority -> peer -> client). For N>2 relays, a turn between two *remote*
//! slots on different peer relays traverses `peer1 -> authority -> peer2`, and
//! the authority doesn't directly observe the peer1<->peer2 mesh RTT. The robust
//! fix is accumulating one-way mesh RTT per hop as conditions flood across the
//! mesh (a proto field + mesh-forward change). Until the mesh edge is wired,
//! this 2-relay simplification is correct for the topology it serves and is
//! not end-to-end testable with peer conditions.
//!
//! # Jitter awareness
//!
//! `rtt_us` from QUIC is a smoothed *mean*. In lockstep a single turn
//! arriving above the mean stalls every player, so the buffer must cover a
//! high percentile of latency, not the average. Each slot keeps a ring
//! buffer of recent RTT samples (~1.3s at 24/sec) and the decision-maker uses
//! the **recent max** as a crude high-percentile estimator. A future
//! improvement would expose QUIC's RTTVAR in the conditions sidecar for a
//! more principled variance term; the recent-max is a practical stand-in that
//! catches the spikes that cause stalls.
//!
//! # Raise fast, lower slow (asymmetric dwell)
//!
//! When the target exceeds the current buffer, the decision-maker **jumps to
//! the target immediately, with no dwell** -- a player hurting now needs the
//! right buffer, and you can't dwell through a stall. When the target drops
//! below the current buffer, it **decrements by one turn per decision, gated
//! by a long min-dwell** (120 turns ~ 5s at 24/sec) -- a conservative shrink so
//! a momentary improvement doesn't flap the buffer down and right back up.
//! A long lower-dwell ensures shrinks are infrequent and well-validated -- at
//! least 120 RTT samples confirm the improvement is stable before the buffer
//! shrinks. Raises, by contrast, fire on the first worsening sample.
//!
//! # Application at an agreed future turn
//!
//! A buffer change every client must apply identically is scheduled at a
//! future `game_frame_count` (the consensus coordinate), not applied at the
//! decision instant: the turn in flight when the decision is made is already
//! past the point where a mid-turn latency change is safe.
//!
//! The coordinate is the **minimum** of the per-slot frames observed from
//! validated turns -- the slowest participant's progress, which is what
//! lockstep actually advances by. Using the minimum (never a single payload's
//! claim) is also the defense against a hostile client: `game_frame_count` is
//! client-asserted and unvalidated, so a slot reporting an absurdly large
//! frame only inflates *its own* per-slot observation -- the session
//! coordinate stays pinned to the honest slots, and the worst a lone attacker
//! can do is under-report and stall decisions, which lockstep already lets it
//! do by stalling outright. (A single-slot session's coordinate is that slot's
//! own claim, but with no second client there is nobody to diverge from.)
//!
//! The change is scheduled a horizon ahead of that coordinate: the current
//! buffer span plus a fixed margin. The relay's view of the slowest client
//! lags by roughly the cushion (frames are observed off turns that took the
//! client->relay path), and the fastest client runs ahead of the slowest by at
//! most the cushion, so the horizon scales with the buffer rather than being a
//! constant that a large cushion could outrun.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use rally_point_proto::commands::command_length;
use rally_point_proto::control::{
    BufferBounds, DepartureKind, DepartureNotice, DesyncNotice, DivergedSlot, ResultEcho,
    ResultNotice, TenantId,
};
use rally_point_proto::ids::{GameFrameCount, SessionId, SlotId};
use rally_point_proto::messages::{BufferDirective, LeaveDirective, LinkConditions};
use tokio::sync::mpsc::UnboundedSender;

use crate::routing::SessionKey;

/// The native `pending_leave_reason` value for an unclean drop
/// (`strPLAYER_WAS_DROPPED`). Any other nonzero reason renders as "player left".
/// A departure is classified for the coordinator by comparing against this
/// value, so the one source of truth lives here alongside the leave decision.
pub const LEAVE_REASON_DROPPED: u32 = 0x4000_0006;

/// The buffer size in turns. StarCraft's `net_user_latency` is the added
/// user latency (0/1/2 in the native game); the decision-maker may widen past
/// 2 via the same synced mechanism, so this is a plain `u32` rather than the
/// native 0--2 enum. One unit == one turn of dispatch delay applied identically
/// on every client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BufferSize(pub u32);

/// Who is the decision-making authority for this session.
///
/// The relays sit in a fixed priority order; the highest still serving live
/// players is the decision-maker. Handoff -- when the authority relay drops
/// out and authority falls to the next relay -- needs the coordinator-assigned
/// priority order and a presence signal, both of which land with the mesh
/// wiring + coordinator (Phase 3). Until then, authority is an injected input
/// so the decision core runs unchanged once peer conditions flow in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// This relay is the decision-maker. The relay decides from its own
    /// home-client conditions plus peer-relay conditions forwarded across the
    /// mesh.
    SelfRelay,
    /// Another relay is the decision-maker. This relay forwards conditions to
    /// the authority across the mesh but makes no decision itself.
    Peer,
}

/// A pending buffer-size change the decision-maker has decided to apply.
///
/// The change targets a future `game_frame_count` -- every client applies it at
/// the same simulated step, so the buffer moves identically for everyone. The
/// `applied_frame` is scheduled a horizon ahead of the session's slowest
/// observed frame so the broadcast reaches every client before that frame
/// arrives.
///
/// This is the decision the control law reached. The change queues a directive
/// the caller broadcasts by stamping it onto every turn it forwards (see
/// [`active_directive`](DecisionMaker::active_directive)); this value is what a
/// debug UI logs and what the decision was, distinct from the per-turn
/// broadcast that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The buffer size to apply, clamped to the coordinator's bounds.
    pub buffer: BufferSize,
    /// The frame at which every client must apply the new buffer. Guaranteed
    /// ahead of the session frame at decision time (the horizon is added to
    /// the slowest per-slot frame the authority has observed).
    pub applied_frame: GameFrameCount,
}

/// The fixed margin of the apply horizon, in turns, added on top of the buffer
/// span (see [`DecisionMaker::decide`]). The buffer span covers observation lag
/// and client spread, which both scale with the cushion; this margin covers the
/// delivery of the stamped turn itself. At the 24/sec turn rate a few turns is
/// well under a quarter-second of scheduling slack -- comfortable for any
/// reasonable path, tight enough that a player feeling lag sees relief
/// promptly.
const APPLY_HORIZON: u32 = 3;

/// How many recent RTT samples to keep per slot for jitter-aware sizing.
/// At 24 turns/sec this is ~1.3s of history -- enough to catch the latency
/// spikes that cause lockstep stalls without excessive memory (128 bytes
/// per slot, 8 slots max = 1KB).
const RTT_WINDOW_SIZE: usize = 32;

/// Tuning for the control law. The defaults encode the target formula with
/// asymmetric "raise fast, lower slow" movement; they are `pub` so a test or
/// a future tuning pass can override them without touching the law itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControlLaw {
    /// The duration of one game turn in microseconds. At the SC:R turn rate
    /// of 24/sec this is `1_000_000 / 24` (~41,667us). The buffer is sized in
    /// turns, so this converts RTT (us) to turns.
    pub turn_duration_us: u32,
    /// How many turns to decrement per lower decision. One at a time: the
    /// cushion shrinks conservatively so a momentary improvement doesn't flap
    /// the buffer down and back up. Raising jumps to the target immediately;
    /// lowering steps down.
    pub lower_step: u32,
    /// Minimum number of turns between *lower* decisions. Raises fire
    /// immediately (no dwell) -- you can't dwell through a stall. The dwell
    /// gates only shrinks: every buffer-size change alters the game feel for
    /// every player, so shrinks should be infrequent and well-validated.
    /// 120 turns ~ 5s-- enough samples (120) to be confident the
    /// improvement is stable before the buffer shrinks.
    pub min_dwell_turns: u32,
}

impl Default for ControlLaw {
    fn default() -> Self {
        Self {
            turn_duration_us: 1_000_000 / 24, // ~41,667us at 24 turns/sec
            lower_step: 1,
            min_dwell_turns: 120, // ~5s at 24/sec
        }
    }
}

/// A fixed-size ring buffer of recent RTT samples for one slot. The
/// decision-maker uses the **max** of the recent samples as a crude
/// high-percentile estimator: in lockstep a single late turn stalls every
/// player, so the buffer must cover latency spikes, not the smoothed mean.
///
/// A `0` RTT (QUIC's "no measurement yet" sentinel) is never pushed -- it
/// means "no data," not "zero latency."
#[derive(Debug, Clone)]
struct RttWindow {
    samples: [u32; RTT_WINDOW_SIZE],
    head: usize,
    len: usize,
}

impl Default for RttWindow {
    fn default() -> Self {
        Self {
            samples: [0; RTT_WINDOW_SIZE],
            head: 0,
            len: 0,
        }
    }
}

impl RttWindow {
    /// Pushes `rtt` into the ring buffer. A `0` (no measurement) is skipped.
    fn push(&mut self, rtt: u32) {
        if rtt == 0 {
            return;
        }
        self.samples[self.head] = rtt;
        self.head = (self.head + 1) % RTT_WINDOW_SIZE;
        if self.len < RTT_WINDOW_SIZE {
            self.len += 1;
        }
    }

    /// The recent max RTT -- the jitter-aware estimate. Returns `0` when no
    /// sample has been pushed yet (no measurement available).
    fn max(&self) -> u32 {
        self.samples[..self.len].iter().copied().max().unwrap_or(0)
    }
}

/// One slot's condition history. RTT samples go into a ring buffer for
/// jitter-aware sizing (the recent max, not the smoothed mean). The cumulative
/// `lost_packets`/`sent_packets` counters are differenced between consecutive
/// samples to get an interval loss rate.
///
/// `mesh_rtt_us` is the one-way mesh hop from the authority relay to this
/// slot's home relay -- `0` for local slots (home clients on this relay), or the
/// relay-pair RTT for remote slots (home clients on a peer relay). The
/// effective RTT (`rtt + mesh_rtt`) is what the path and loss formulas use,
/// so cross-relay paths include the mesh hop automatically.
///
/// The first sample establishes a baseline: `has_delta` stays false until the
/// second sample arrives, so the decision-maker doesn't act on a loss rate
/// computed from a single cumulative snapshot. A high RTT on the first sample
/// can still raise the target -- RTT is instantaneous and doesn't need a
/// baseline.
#[derive(Debug, Clone, Default)]
struct SlotState {
    /// Ring buffer of recent RTT samples for jitter-aware sizing.
    rtt_window: RttWindow,
    /// The one-way mesh hop RTT (us) from the authority to this slot's home
    /// relay. `0` for local slots; the relay-pair RTT for remote slots.
    mesh_rtt_us: u32,
    /// The newest `game_frame_count` observed on this slot's validated turns.
    /// Monotonic per slot; `None` until the slot's first framed turn (lobby
    /// turns carry no frame). The session's consensus coordinate is the
    /// *minimum* across slots, so one slot's inflated claim can't poison it.
    frame: Option<GameFrameCount>,
    /// A bounded, recent history of `(seq, game_frame_count)` for this slot's
    /// framed turns — the turn's transport seq paired with the frame it stamped.
    /// Used to prove which frames a *survivor* has executed when a leave is
    /// decided: a turn stamped at seq `s` is provably executed once the session
    /// advanced `buffer_max` turns past `s`, so the leave's apply frame can be
    /// clamped to a frame every survivor can reach (see
    /// [`DecisionMaker::reachable_frame`]). Capped relative to the buffer depth,
    /// since only the window back to `frontier − buffer_max` is ever consulted.
    /// Only populated by [`observe_turn_frame`](DecisionMaker::observe_turn_frame)
    /// (the seq-aware production path); the seq-less
    /// [`observe_frame`](DecisionMaker::observe_frame) leaves it empty (tests).
    frame_history: VecDeque<(u64, u32)>,
    /// The prior sample's cumulative `lost_packets`. Meaningful only when
    /// `has_delta` is true.
    prev_lost: u64,
    /// The prior sample's cumulative `sent_packets`. Meaningful only when
    /// `has_delta` is true.
    prev_sent: u64,
    /// The current (latest) sample's cumulative `lost_packets`.
    curr_lost: u64,
    /// The current (latest) sample's cumulative `sent_packets`.
    curr_sent: u64,
    /// Whether we have at least two samples (so a loss-rate delta is computable).
    has_delta: bool,
    /// Whether we've ingested at least one sample for this slot.
    seen: bool,
}

impl SlotState {
    /// The jitter-aware RTT: the recent max from the ring buffer. Returns `0`
    /// when no sample has been pushed (no measurement yet).
    fn rtt(&self) -> u32 {
        self.rtt_window.max()
    }

    /// The effective RTT: `rtt + mesh_rtt`. This is the full one-way path from
    /// the client to the authority relay (client ->  -> home-relay + mesh-hop for
    /// remote slots). The path and loss formulas use this so cross-relay paths
    /// are sized correctly.
    fn eff_rtt(&self) -> u32 {
        self.rtt().saturating_add(self.mesh_rtt_us)
    }

    /// The interval loss rate (`delta_lost / delta_sent`), or `None` when no
    /// prior sample exists (first sample) or the counters went backward (a
    /// re-delivered stale sidecar). `saturating_sub` clamps to zero so a stale
    /// sample can't produce a negative rate.
    fn loss_rate(&self) -> Option<f64> {
        if !self.has_delta {
            return None;
        }
        let delta_sent = self.curr_sent.saturating_sub(self.prev_sent);
        if delta_sent == 0 {
            return None;
        }
        let delta_lost = self.curr_lost.saturating_sub(self.prev_lost);
        Some(delta_lost as f64 / delta_sent as f64)
    }

    /// The loss risk: `loss_rate * eff_RTT` (in us). This is the expected burst
    /// duration on this link -- how many us of packets could be lost during one
    /// round-trip. Higher on high-latency links because more packets are in
    /// flight during the burst window. Returns `None` when no loss delta is
    /// available (first sample, or stale sidecar).
    fn loss_risk(&self) -> Option<f64> {
        self.loss_rate().map(|rate| rate * self.eff_rtt() as f64)
    }
}

/// The latency-buffer decision-maker for one session.
///
/// Owns the per-slot condition history (RTT ring buffer for jitter, cumulative
/// counter differencing for loss, mesh-hop RTT for cross-relay paths, the
/// newest validated frame), the current buffer size, the session frame the
/// last decision was made at (for min-dwell on lowers), and the directive
/// currently being broadcast.
///
/// One instance per session. Fed frame observations off validated turns via
/// [`observe_frame`](Self::observe_frame) and conditions by `run_slot_link`
/// (home-client conditions, via [`ingest_local`](Self::ingest_local)) and
/// `run_mesh_link` (peer-relay conditions, via
/// [`ingest_remote`](Self::ingest_remote)) -- but it decides only when
/// `Authority::SelfRelay`.
pub struct DecisionMaker {
    key: SessionKey,
    bounds: BufferBounds,
    law: ControlLaw,
    authority: Authority,

    /// The current buffer size, clamped to bounds. Starts at `bounds.min`.
    buffer: BufferSize,
    /// Per-slot condition history and frame observations.
    slots: HashMap<SlotId, SlotState>,
    /// The session frame at which the last decision was *made* (not applied).
    /// Used to gate lowers: a lower is suppressed until the session frame has
    /// advanced `min_dwell_turns` past it. Raises are never suppressed (you
    /// can't dwell through a stall).
    last_decision_frame: Option<GameFrameCount>,
    /// Orders this session's decisions on the wire. Incremented for every
    /// broadcast directive, so clients receiving copies out of order (or a
    /// superseded directive after its replacement) keep only the newest. Also
    /// advanced by [`observe_directive`](Self::observe_directive) to the
    /// highest seq seen on *forwarded* stamps: every directive floods through
    /// every relay serving the session, so a relay promoted to authority
    /// continues the numbering instead of restarting below what clients
    /// already hold (which they would ignore).
    decision_seq: u32,
    /// The buffer change currently being broadcast, if any. Set when a
    /// decision fires; handed out by
    /// [`active_directive`](Self::active_directive) for every forwarded turn,
    /// and retired once the session frame reaches its apply frame -- by then
    /// every slot has passed the frame, so the change is applied (or moot)
    /// everywhere. A non-authority relay never sets this (it makes no
    /// decisions), so it never stamps -- it only forwards the authority's
    /// already-stamped turns verbatim.
    pending_directive: Option<BufferDirective>,
    /// The synced player-leaves this relay has authored (as authority) or
    /// observed (a peer relay's authority pushed it across the mesh), keyed by
    /// slot. A leave is a one-shot: it is pushed down each surviving client's
    /// reliable control stream (never stamped onto turns -- a drop stops the turn
    /// stream). This map dedups a slot so a duplicate signal doesn't re-decide or
    /// re-cache it, and -- crucially -- **survives a demotion**: it is exactly the
    /// set a later promotion re-broadcasts, so a leave the previous authority
    /// decided is not lost when authority moves. Bounded by the slot count (<=12),
    /// so keeping it costs nothing.
    decided_leaves: HashMap<SlotId, LeaveDirective>,
    /// Every slot departure this relay has observed for the session -- its own
    /// home client's link ending, or a peer relay's `SlotDeparted` frame -- kept
    /// so a later promotion can re-derive a leave the previous authority never got
    /// to author. Also survives a demotion.
    ///
    /// Recording a departure *retires* the slot from `slots` (on every relay,
    /// not just the slot's home — see [`note_departure`](Self::note_departure)),
    /// so this record is the sole owner of the departed slot's last frame, and
    /// membership here doubles as the guard that keeps late in-flight traffic
    /// from resurrecting the slot's live state.
    departures: HashMap<SlotId, Departure>,
    /// Next `leave_seq` to assign -- its own space, distinct from `decision_seq`
    /// (buffer and leave directives never supersede one another). Clients dedup
    /// leaves by slot, so this only has to be non-colliding per distinct leave.
    /// Kept above every observed `leave_seq` so a promoted relay's own numbering
    /// never collides with what clients already hold.
    next_leave_seq: u32,
    /// Slots the coordinator flagged as observers (from the session descriptor).
    /// Excluded from the desync comparator — observers do not reliably emit sync
    /// commands, so requiring their checksums would stall the cross-check.
    /// Descriptor-driven, so it survives authority changes (unlike the comparator
    /// state, which resets on promotion).
    observers: HashSet<SlotId>,
    /// The end-of-game result each slot reported, keyed by slot. First report per
    /// slot wins; a repeat is dropped without firing a second notice — the same
    /// anti-flooding posture as the one-sync-command-per-turn rule. The full
    /// result is retained (not just a marker) so this relay — the reporting slot's
    /// home — can embed it into the slot's departure record and `SlotDeparted`
    /// frame when the slot leaves. Bounded by the slot count (≤12) times the
    /// per-result cap. Not tied to the desync comparator, so it survives an
    /// authority change (a result is a per-slot one-shot the relay reports
    /// regardless of authority).
    results: HashMap<SlotId, ResultEcho>,
    /// The per-session desync comparator. Only meaningful while this relay is the
    /// authority; reset wholesale on promotion (a real desync re-diverges every
    /// interval, so no state need transfer across a handoff).
    sync: SyncTracker,
}

/// One observed slot departure, kept for authority-handoff re-derivation. Holds
/// exactly what deriving the leave's apply frame needs: the departing slot's
/// last observed frame (`None` if it never produced a framed turn -- a lobby
/// departure with no frame basis) and the native leave reason to author. The
/// frame is the max-merge of every observation of this departure (the home
/// relay's carried value, this relay's own view, any re-announce), so the
/// fullest view wins; the reason keeps the first observation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Departure {
    last_frame: Option<GameFrameCount>,
    /// The home-authored reachability ceiling for the leave's apply frame — the
    /// highest frame every survivor had provably executed when the home relay saw
    /// the departure (see [`DecisionMaker::reachable_frame`]). Single-sourced
    /// (only the home computes it, from `reachable_frame`) and carried in the
    /// `SlotDeparted` frame, so [`decide_leave`](DecisionMaker::decide_leave) and
    /// the handoff re-derivation clamp to the identical value on every relay.
    /// `None` when the home had no survivor framed history yet (no clamp).
    reachable_frame: Option<u32>,
    reason: u32,
    /// The end-of-game result this slot reported before departing, if any.
    /// Home-authored: only the departing slot's home relay retains the report
    /// and seeds this; other relays receive it in the `SlotDeparted` frame. Folded
    /// first-non-`None`-wins, exactly like `reachable_frame` — a result can never
    /// be recorded after a slot's departure (reports ride only the live link,
    /// which the departure closes), so once seeded it is final. Carried into the
    /// [`DepartureNotice`] so a departure webhook is atomic terminal truth.
    result: Option<ResultEcho>,
}

// ---------------------------------------------------------------------------
// Relay-side desync detection
// ---------------------------------------------------------------------------
//
// SC:R's lockstep sim exchanges a per-turn checksum through the command stream:
// each client emits exactly one `0x37` sync command per outgoing turn once its
// sync check is active. Because every client's Nth sync command covers the same
// simulated interval, two clients whose sims have diverged produce a *different*
// checksum at the same ordinal. Only the client's own sim reacts to a mismatch
// (by dropping the peer over a transport that is inert under this seam), so under
// netcode v2 a desync is invisible to everyone unless something that sees every
// slot's turns compares the checksums itself. That is what [`SyncTracker`] does,
// on the session's authority relay, off the same turn stream the buffer/leave
// consensus already reads.

/// The SC:R sync-command opcode. A 7-byte command emitted once per network
/// turn while the game's sync check is active: `[0]` = this opcode; `[1]` =
/// `(ring_index << 4) | hash_kind` — the high nibble is a 16-entry ring index
/// (advancing `+1 mod 16` per turn) the comparator uses to place each report,
/// the low nibble is the *hash kind* (1 or 2, never a sender/slot id — there
/// is no sender id anywhere in this payload; identity comes from framing),
/// locked to the ring index's parity (even → 1, odd → 2). So `[1]` cycles a
/// fixed 16-value sequence: `0x01, 0x12, 0x21, 0x32, …, 0xF2`. `[2:3]` is
/// `hash16` (the only byte range the comparator compares — see [`SyncValue`]);
/// `[4..7]` is per-sender, vision-masked fog/vision data the comparator never
/// reads (see [`SyncValue`] for why). This is definitive from a BinaryNinja RE
/// of the native `verify_peer_sync_slot`, not inferred from the wire.
///
/// **Startup burst:** the enable path emits the first sync command at ring
/// index 1 (`[1] = 0x12`), and the initial latency-depth flush emits several
/// more `0x37`s stamped *identically* (same ring, same bytes) before the first
/// per-turn record advances the ring — so a client's first few sync commands
/// legitimately repeat ring 1 with identical content. [`SyncTracker::record`]'s
/// same-ordinal duplicate-ignore absorbs this without any special-casing
/// (live-relay confirmed): a repeat lands back at the same placed ordinal via
/// ordinary nibble correction and is recognized as a duplicate. Ring index 0
/// (and therefore our internal ordinal 0, which anchors to whatever ring value
/// a tracker's very first observation happens to report — see
/// [`SyncTracker::join_expected`]) first appears only once the ring wraps,
/// around turn 15.
const SYNC_COMMAND: u8 = 0x37;

/// The total length of a `0x37` sync command, mirroring the command-length table.
/// A `0x37` that does not measure this is not the sync command the comparator
/// understands (it never is on validated bytes, but the walk stays defensive).
const SYNC_COMMAND_LEN: usize = 7;

/// The length, in bytes, of `hash16` — see [`SyncValue`] for why it's the only
/// comparable range in the 7-byte `0x37`.
const SYNC_HASH16_LEN: usize = 2;

/// The `0x37` low nibble's valid hash-kind values (see [`SYNC_COMMAND`]'s
/// layout note): 1 for the even-ring per-unit hash, 2 for the odd-ring
/// game-header/rng hash. Any other low-nibble value is a malformed sync
/// command (defensive — validated bytes shouldn't produce this; see
/// [`SyncTracker::record`]).
const SYNC_KIND_UNITS: u8 = 1;
const SYNC_KIND_HEADER: u8 = 2;

/// The sync command's ring index is a 16-entry ring, so a slot's true ordinal
/// is congruent to its ring nibble modulo this. The comparator uses it to
/// *place* each report (the ordinal congruent to the ring nearest the slot's
/// expected position), not merely to validate one — see the module docs.
const SYNC_RING_MODULUS: u64 = 16;

/// The floor for [`sync_eval_margin`]'s per-session margin, and the value it
/// returns for any buffer policy shallow enough not to need more: how far past
/// an ordinal the frontier (the furthest any compared slot has reached) must
/// move before that ordinal is evaluated. Replaces a same-instant "does
/// everyone agree right now" check, which is unsound once slots can
/// legitimately arrive out of order or lead each other by the latency
/// buffer's depth (see the module docs): the margin instead waits long enough
/// that every live slot's report for the ordinal has had time to show up,
/// whatever order it arrived in. 8 is also where the ring nibble's own
/// correction becomes ambiguous (see the module docs' bound note on steady-state
/// placement), so there is no benefit to a smaller floor.
const SYNC_EVAL_MARGIN_MIN: u64 = 8;

/// A defensive backstop, not a live constraint under normal policy: buffer
/// bounds at or above this are absurd enough (half the in-flight window,
/// [`SYNC_WINDOW`]) that the evaluation margin they would imply
/// ([`sync_eval_margin`]) swallows most of the window's slack, so the
/// comparator disables itself for the session rather than risk starving on a
/// buffer depth it was never tuned for. Ordinary policy (today's dev tenant:
/// 1..=10) sits far under it — see [`BufferBounds`] for why depth itself no
/// longer threatens the comparator's correctness the way it used to.
const SYNC_ABSURD_BUFFER_MAX: u32 = (SYNC_WINDOW / 2) as u32;

/// The most sync ordinals the comparator keeps in flight per session before
/// evicting the oldest incomplete one. Sized comfortably above what
/// [`sync_eval_margin`] can return under any buffer policy this session would
/// actually run with (see [`SYNC_ABSURD_BUFFER_MAX`]); it is a memory-safety
/// backstop for a slot whose sync stream stalls or stops (its ordinals then
/// never complete and would otherwise accumulate without bound).
const SYNC_WINDOW: usize = 64;

/// The evaluation margin for a session whose buffer policy allows up to
/// `bounds_max` turns of latency-buffer depth: a slot's arrivals can lag the
/// frontier by roughly that depth, so a fixed margin under-waits once the
/// policy allows a deep buffer — this scales the margin with the policy
/// instead, floored at [`SYNC_EVAL_MARGIN_MIN`] (which also covers the
/// transport-reordering slack a buffer depth of 0 wouldn't). `+ 2` is a small
/// cushion above the depth itself for that same reordering slack at higher
/// depths.
///
/// The debug assertion is the tripwire for [`SYNC_WINDOW`] going stale: if a
/// future buffer policy ever needs a margin approaching half the window, the
/// window (and the memory budget it implies) needs revisiting right alongside
/// it, not silently.
fn sync_eval_margin(bounds_max: u32) -> u64 {
    let margin = (u64::from(bounds_max) + 2).max(SYNC_EVAL_MARGIN_MIN);
    debug_assert!(
        margin.saturating_mul(2) <= SYNC_WINDOW as u64,
        "the evaluation margin ({margin}) should stay comfortably under half the eviction \
         window ({SYNC_WINDOW}); a much larger buffer policy needs the window revisited too",
    );
    margin
}

/// One slot's compared checksum: `0x37`'s `hash16` (`[2:3]`, little-endian) —
/// the *only* comparable byte range in the sync command.
///
/// The native `verify_peer_sync_slot` compares `hash16` and the hash kind
/// straight across peers, but checks `[4]` (a folded fog checksum), `[5]`
/// (fog window length), and `[6]` (a per-player vision bit) *pairwise*
/// against the receiver's own local fog buffer with the sender's player bit —
/// they are per-sender, vision-masked values that legitimately differ between
/// honest players in the same game (each player's fog of war differs). A
/// relay comparing them verbatim across all slots (as an earlier version of
/// this comparator did) manufactures a false desync at ordinary game start —
/// live-observed within the first few ordinals, long before any real
/// divergence. So the comparator never reads `[4..7]` at all; do not
/// "strengthen" this by adding them back.
///
/// **Cross-peer `hash16` equality is guaranteed by the native check's own
/// structure**, not merely observed: `verify_peer_sync_slot` only passes a
/// remote report when its `hash16` equals the value the *receiver* computed
/// from its own simulation for that ring index — so in any healthy game every
/// peer's `hash16` for a given ordinal is provably byte-identical (otherwise
/// SC:R's own detection would already be firing constantly). Whatever term
/// the decompiler's guessed local-player-id shift folds into the hash, it
/// must therefore be shared state, not something that diverges honestly
/// across peers.
type SyncValue = [u8; SYNC_HASH16_LEN];

/// A relay-authoritative desync the comparator confirmed: two live slots'
/// checksums disagreed at the same sync ordinal. Pure data the registry layer
/// turns into a [`DesyncNotice`] (stamping correlation ids + a detection
/// timestamp) — the maker itself holds no clock and no tenant refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDivergence {
    /// The per-slot sync ordinal the disagreement was observed at.
    pub sync_ordinal: u64,
    /// The `game_frame_count` of the turn whose sync command completed the
    /// comparison — a human-meaningful interval. `None` only if that turn carried
    /// no frame (it shouldn't; sync commands flow in-game).
    pub game_frame: Option<u32>,
    /// No strict majority shared one checksum (a 1v1 disagreement, or an even
    /// split), so which sim is authoritative is undecidable from the relay's
    /// view. `diverged` is empty when this is set.
    pub no_majority: bool,
    /// The minority slots that diverged from the agreeing majority, ascending.
    /// Empty when `no_majority`.
    pub diverged: Vec<SlotId>,
}

/// One slot's checksum report at an ordinal: its `hash16`, the hash kind
/// (`SYNC_KIND_UNITS`/`SYNC_KIND_HEADER`) it was reported under, and the frame
/// of the turn it rode.
#[derive(Debug, Clone, Copy)]
struct SyncReport {
    value: SyncValue,
    kind: u8,
    game_frame: Option<u32>,
}

/// One compared slot's bookkeeping: where it's expected to report next, and
/// where it first joined the compare set.
#[derive(Debug, Clone, Copy)]
struct Member {
    /// This slot's next expected ordinal — the ordinal one past the last one
    /// it placed a report at. Used both as the anchor a new report is
    /// nibble-corrected against, and (via the max across all members) as the
    /// tracker's *frontier*: the furthest any compared slot has reached.
    next_expected: u64,
    /// The ordinal this slot first joined the compare set at (its own true
    /// ordinal at first observation, after nibble correction — never
    /// retroactively 0). A member is only ever required to have reported an
    /// ordinal at or after this, so a slot that joins mid-stream (a promotion,
    /// or one whose sync simply started later) is never held responsible for
    /// intervals before it existed.
    since: u64,
}

/// The per-session sync-checksum comparator. Lives on the authority relay's
/// [`DecisionMaker`] and is fed one call per turn (via
/// [`DecisionMaker::observe_sync`], called exactly once per distinct
/// `(slot, seq)` turn — see that method's docs), which walks the turn's
/// commands for `0x37`s and hands each here.
///
/// # How ordinals align
///
/// A slot's *sync ordinal* is the count of sync commands seen from it, and the
/// wire only carries the low 4 bits of that count: `ring`, the `0x37`'s
/// `[1] >> 4` (a 16-entry ring, `+1 mod 16` per turn). The low nibble (`[1] &
/// 0xF`) is the hash *kind* (1 or 2 — see [`SYNC_COMMAND`]'s layout note), not
/// a sender/slot id; there is no sender id anywhere in this payload at all.
/// Two properties of the transport make naive "arrival order is the ordinal"
/// counting wrong:
///
/// - **Reordering and lead.** QUIC datagrams are unordered at both the client
///   edge and across mesh flooding, and a client legitimately runs up to the
///   latency buffer's depth *ahead* of its slowest peer's arrivals at the
///   relay (producing turn `k+1` only requires having *executed* step
///   `k+1 - depth`, not having every peer's turn `k` already in hand). So a
///   slot's own turns can arrive at the relay out of order, and a slot's very
///   first observed sync command can already be several ordinals into its
///   stream.
/// - **Duplication.** The mesh legitimately delivers the same turn to the
///   authority via more than one path — that's what `mark_seen`/`MeshSeen`
///   exist to catch. The comparator relies on its caller
///   ([`DecisionMaker::observe_sync`]) handing it each distinct `(slot, seq)`
///   turn exactly once; counting is not idempotent the way `observe_frame`'s
///   monotone max is, so a duplicate that reached this far would silently
///   drift a slot's ordinal.
///
/// The fix is **nibble-corrected placement**, in two flavors depending on
/// whether the reporting slot is already known:
///
/// - **Steady state** (the slot has a [`Member`] entry already): placed at the
///   ordinal congruent to `ring` (mod 16) *nearest the slot's own
///   [`Member::next_expected`]*. This self-heals a reordered pair (a slot's
///   own turns arriving out of sequence) — nearest-match resolves an offset
///   of up to ±7 exactly. Critically, this bound is **transport-level
///   reordering only** (how far out of order the mesh/QUIC can deliver two of
///   *the same slot's* turns), which is far under ±7 regardless of the
///   session's configured buffer depth — a slot's own emission order isn't
///   affected by how much the buffer lets other slots lag behind it. See the
///   bound note below.
/// - **Join** (the slot's first-ever report): the transport-reordering
///   argument above doesn't apply, because there's no prior report from this
///   slot to be "out of order" relative to — its expected ordinal has to come
///   from somewhere else, and that somewhere else (the current *frontier*,
///   the furthest any member has reached) can be arbitrarily far from the
///   join's true ordinal, growing with the session's buffer depth (a deeper
///   buffer lets a fast slot's turns run further ahead of a slow slot's first
///   arrival). Nibble-correcting around the frontier is therefore unsound at
///   depth; instead the join anchors on the reporting turn's
///   `game_frame_count` ([`SyncTracker::join_expected`]): lockstep keeps every
///   client's frame for the same simulated interval within a couple of turns
///   of each other *regardless of buffer depth* (the depth is a session-wide
///   constant that cancels out across clients), so projecting from a recent
///   (ordinal, frame) calibration point and nibble-correcting around *that*
///   estimate lands on the true ordinal at any realistic depth. Falls back to
///   frontier+nibble when no frame is available to anchor on (either the
///   joining report carries none, or the tracker has no calibration yet), and
///   further to the ring's own face value when there is no frontier either
///   (the tracker's very first observation for the session at all — the
///   promotion-mid-stream case, where there is no earlier context of any
///   kind — see [`DecisionMaker::set_authority`]'s promotion reset).
///
/// Either way, a slot's join ordinal is tracked as [`Member::since`], so
/// nothing is retroactively required of it for ordinals before that. A
/// placement that lands below `base_ordinal` (already-retired territory —
/// possible right after a correction, or after an eviction) is dropped
/// silently; that one comparison is lost, which is acceptable.
///
/// **Bound note:** nibble correction is sound only while the gap between the
/// value it corrects around and the report's true ordinal stays under 8 (half
/// the 16-entry ring) — beyond that the nearest-match is ambiguous or wrong.
/// For steady state that gap is transport reordering, bounded independent of
/// buffer depth (see above). For a join, frame-anchoring keeps the gap to
/// lockstep's cross-client frame skew (a couple of turns) rather than the
/// buffer depth itself, so depth no longer threatens correctness either — see
/// [`BufferBounds`] for this from the policy side. [`SYNC_ABSURD_BUFFER_MAX`]
/// is the remaining backstop, for a policy so deep it stops being a
/// buffer-tuning question at all.
///
/// # What retires an ordinal
///
/// An ordinal is evaluated once the frontier has moved at least
/// [`sync_eval_margin`] past it (long enough that every live slot's report for
/// it, however reordered or however deep the buffer let it lag, should have
/// arrived) **and** every member whose `since` is at or before it has
/// reported it. A member that hasn't reported yet despite the margin is rare
/// but possible (a genuinely stalled link); [`SYNC_WINDOW`] eviction is the
/// backstop that bounds the wait.
///
/// A retired ordinal whose reports all agree retires silently. One with a
/// disagreement fires exactly one [`SyncDivergence`]: the strict-majority value
/// is authoritative and every other slot is the diverged minority (dropped from
/// the compare set, so the survivors keep being watched and a later second
/// divergence fires again at its own ordinal); with no strict majority the
/// comparator reports `no_majority` and goes dormant (the truth is unrecoverable
/// for the session). A slot that departs or is dropped stops being required.
///
/// # Bounded state
///
/// In-flight ordinals are capped at [`SYNC_WINDOW`]; a slot that stalls leaves
/// its ordinals forever-incomplete, so the oldest are evicted (with a
/// rate-limited warn naming who failed to report) rather than growing without
/// bound. Comparator state is reset wholesale on authority promotion — a real
/// desync diverges every interval, so the next interval after promotion catches
/// it, and transferring per-ordinal hash state across a handoff would be pure
/// complexity for a one-interval blind spot.
#[derive(Debug, Default)]
struct SyncTracker {
    /// Once set, the comparator has reached a verdict it cannot refine (a
    /// no-majority split, a majority event that left fewer than two comparable
    /// slots, or absurd buffer bounds) and no-ops for the rest of the session.
    dormant: bool,
    /// The lowest ordinal still awaiting evaluation; everything below has retired
    /// (agreed, fired, or been evicted).
    base_ordinal: u64,
    /// Each compared slot's bookkeeping. The key set *is* the compare set: a
    /// slot enters on its first sync command and leaves on departure or as a
    /// dropped minority.
    members: HashMap<SlotId, Member>,
    /// Reports awaiting a complete ordinal, keyed by ordinal then slot.
    pending: BTreeMap<u64, HashMap<SlotId, SyncReport>>,
    /// The lowest-ordinal **corroborated** `(ordinal, median_frame)` calibration
    /// point, paired with `corroborated_latest` to derive the frames-per-ordinal
    /// rate for frame-anchored join placement (see [`Self::join_expected`]). A
    /// point is corroborated only once at least [`SYNC_CORROBORATION_MIN`]
    /// **distinct** slots have reported the same ordinal with a frame — the
    /// median of their frames, which a single attacker (controlling one slot)
    /// cannot move. This replaces the earlier single-slot-sourced calibration a
    /// lone slot could swing to shift an honest joiner a full ring cycle. Kept
    /// independent of `pending`/`members` so it survives ordinal retirement.
    corroborated_first: Option<(u64, u32)>,
    /// The highest-ordinal corroborated `(ordinal, median_frame)` point, paired
    /// with `corroborated_first` for the rate and used as the projection anchor.
    corroborated_latest: Option<(u64, u32)>,
    /// Rate-limit counter for the placement-correction debug log (a nonzero
    /// nibble correction — a reorder, a lead, or a join). Routine (every game
    /// start corrects the first ordinal after a join), so it logs at debug.
    corrections: u64,
    /// Rate-limit counter for the same-ordinal conflicting-value warn (a slot
    /// reporting two different checksums for the same placed ordinal — an
    /// honest client never does this).
    duplicate_warns: u64,
    /// Rate-limit counter for the malformed-hash-kind warn (the `0x37`'s low
    /// nibble is neither 1 nor 2 — validated bytes shouldn't produce this;
    /// see [`SyncTracker::record`]).
    malformed_kind_warns: u64,
    /// Rate-limit counter for the kind/parity-mismatch warn (a report's hash
    /// kind disagrees with its placed ordinal's expected parity — an
    /// alignment-drift indicator, not a desync; see [`SyncTracker::evaluate`]).
    kind_parity_warns: u64,
    /// Rate-limit counter for the window-eviction (stalled-slot) warn.
    evict_warns: u64,
    /// Rate-limit counter for the multiple-sync-commands-in-one-turn warn (an
    /// honest client emits exactly one `0x37` per outgoing turn; more than one
    /// is the flooding lever a malicious client would use to inflate its own
    /// frontier and seed join-placement calibration — see
    /// [`DecisionMaker::observe_sync`]).
    multi_sync_warns: u64,
    /// Rate-limit counter for the deferred-join-placement warn (a joining slot
    /// that can't be safely placed yet — no corroborated rate and the frontier is
    /// more than a ring cycle ahead; its report is dropped and retried).
    defer_warns: u64,
}

/// The number of **distinct** slots that must report the same ordinal (each with
/// a frame) before that ordinal's `(ordinal, median_frame)` becomes a
/// corroborated calibration point for frame-anchored join placement. Three is the
/// smallest count whose **median** a single attacker — who controls exactly one
/// slot — provably cannot move: with ≤1 outlier among ≥3 values the median is
/// still an honest slot's frame. This is what lets the join projection be
/// tolerance-free (no "how close counts as agreeing?" parameter to tune).
const SYNC_CORROBORATION_MIN: usize = 3;

/// The hash kind SC:R's native sync check ties to a ring index's parity: even
/// → [`SYNC_KIND_UNITS`] (the per-unit hash), odd → [`SYNC_KIND_HEADER`] (the
/// game-header/rng hash). A placed ordinal is always congruent to its true
/// ring index modulo 16 ([`SYNC_RING_MODULUS`]), and mod-16 preserves parity
/// (16 is even), so an honestly-placed report's ordinal parity exactly
/// predicts its kind — this is what [`SyncTracker::evaluate`]'s kind/parity
/// cross-check tests.
fn expected_kind_for_ordinal(ordinal: u64) -> u8 {
    if ordinal.is_multiple_of(2) {
        SYNC_KIND_UNITS
    } else {
        SYNC_KIND_HEADER
    }
}

impl SyncTracker {
    /// Records one slot's `0x37`, nibble-correcting its placement, and
    /// evaluates any now-ready ordinals, returning a [`SyncDivergence`] if one
    /// fired. `ring` is the command's ring nibble (the high nibble of `[1]`,
    /// already shifted to 0..15); `kind` is the low nibble (the hash kind).
    ///
    /// `kind` must be [`SYNC_KIND_UNITS`] or [`SYNC_KIND_HEADER`] — anything
    /// else is a malformed sync command (defensive; validated bytes shouldn't
    /// produce this) and the report is skipped entirely: no member
    /// bookkeeping, no calibration, nothing recorded, just a rate-limited warn.
    ///
    /// Placement: the ordinal congruent to `ring` (mod 16) nearest this slot's
    /// expected ordinal — its own [`Member::next_expected`] if already a
    /// member (steady state), else [`Self::join_expected`]'s frame-anchored
    /// (or frontier, or ring-face-value) estimate for a first-ever report. See
    /// the module docs for why the two cases differ and the bound on how far
    /// each correction can reach. `margin` is this session's current
    /// evaluation margin ([`sync_eval_margin`]) — threaded through to
    /// [`Self::evaluate_ready`] rather than stored, so a mid-session bounds
    /// change is picked up immediately without the tracker needing to be told.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
        ring: u8,
        kind: u8,
        value: SyncValue,
        game_frame: Option<u32>,
        margin: u64,
    ) -> Option<SyncDivergence> {
        if kind != SYNC_KIND_UNITS && kind != SYNC_KIND_HEADER {
            self.malformed_kind_warns += 1;
            if should_warn(self.malformed_kind_warns) {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    kind,
                    count = self.malformed_kind_warns,
                    "sync command's hash-kind nibble is neither 1 nor 2; \
                     skipping this report as malformed",
                );
            }
            return None;
        }

        let ring = u64::from(ring);
        let existing_next_expected = self.members.get(&slot).map(|m| m.next_expected);
        let is_new_member = existing_next_expected.is_none();
        let expected = match existing_next_expected {
            Some(expected) => expected,
            None => match self.join_expected(ring, game_frame) {
                Some(expected) => expected,
                // Deep join with no corroborated rate and the frontier more than a
                // ring cycle ahead: defer (see `defer_join`).
                None => return self.defer_join(key, slot),
            },
        };

        // Nearest ordinal ≡ ring (mod 16) to `expected`. `diff` lands in
        // [-8, 8]; the ends (exactly ±8) are the ambiguous case the module
        // docs' bound note calls out — deterministic here, but not
        // necessarily correct, which is why each case's own bound (transport
        // reordering for steady state, frame skew for a join) is what keeps
        // real gaps well inside this range rather than at its edge.
        let expected_mod = (expected % SYNC_RING_MODULUS) as i64;
        let mut diff = ring as i64 - expected_mod;
        if diff > 8 {
            diff -= 16;
        } else if diff < -8 {
            diff += 16;
        }
        let placed = i128::from(expected) + i128::from(diff);

        // A *joining* slot placed above the frontier means the nibble jumped a
        // ring cycle upward off the frontier anchor — the tell-tale of a deep
        // join we can't resolve without a corroborated rate. Defer it (drop and
        // retry) rather than misplace it a full cycle and risk framing an honest
        // slot. Steady-state members are exempt: they legitimately *are* the
        // frontier. (No frontier yet — the very first observation — is never
        // above itself.)
        if is_new_member
            && let Some(frontier) = self.members.values().map(|m| m.next_expected).max()
            && placed > i128::from(frontier)
        {
            return self.defer_join(key, slot);
        }

        if diff != 0 {
            self.corrections += 1;
            if should_warn(self.corrections) {
                tracing::debug!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    expected,
                    ring,
                    placed,
                    count = self.corrections,
                    "sync ordinal placement corrected from the ring nibble; \
                     the turn arrived out of order, the slot is running ahead, \
                     or it just joined the compare set",
                );
            }
        }

        // Advance this member's bookkeeping regardless of whether the
        // placement itself lands in already-retired territory below — a
        // dropped comparison must not also leave the member's own progress
        // stale (it has still, after all, reported this many sync commands).
        let next_expected_candidate = u64::try_from(placed + 1).unwrap_or(0);
        let since_candidate = u64::try_from(placed).unwrap_or(0);
        let member = self.members.entry(slot).or_insert_with(|| Member {
            next_expected: 0,
            since: since_candidate,
        });
        member.next_expected = member.next_expected.max(next_expected_candidate);
        if is_new_member {
            member.since = since_candidate;
        }

        if placed < i128::from(self.base_ordinal) {
            // Already-retired territory (possible right after a correction or
            // an eviction): the comparison is lost, which is acceptable —
            // don't let it perturb anything beyond the bookkeeping above.
            return None;
        }
        let ordinal = placed as u64; // non-negative: checked above

        match self.pending.entry(ordinal).or_default().entry(slot) {
            std::collections::hash_map::Entry::Occupied(existing) => {
                if existing.get().value != value {
                    // An honest client never emits two different checksums for
                    // the same turn; keep the first and just flag it.
                    self.duplicate_warns += 1;
                    if should_warn(self.duplicate_warns) {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            ordinal,
                            count = self.duplicate_warns,
                            "conflicting sync value for a slot already reported \
                             at this ordinal; keeping the first",
                        );
                    }
                }
                // Same value: a harmless duplicate (the belt-and-suspenders
                // case — the caller is expected to already dedup turns, but
                // nibble correction can independently re-place a redundant
                // report at an ordinal it already holds). Either way, nothing
                // to insert.
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(SyncReport {
                    value,
                    kind,
                    game_frame,
                });
            }
        }

        // Fold this ordinal into the corroborated calibration: once ≥3 distinct
        // slots have reported it with frames, its median frame anchors the
        // frame-rate estimate used to place late joins (see `join_expected`).
        self.update_corroboration(ordinal);

        if let Some(divergence) = self.evaluate_ready(key, margin) {
            return Some(divergence);
        }
        self.evict_over_window(key);
        None
    }

    /// The join-placement anchor for a slot's first-ever report: the ordinal
    /// [`Self::record`]'s nibble correction will refine — or `None` to **defer**
    /// the placement entirely when no anchor can be trusted.
    ///
    /// Three cases, in order:
    /// - **No members yet** (the tracker's very first observation): the ring's
    ///   own face value.
    /// - **A corroborated rate is available**: project frame-anchored from the
    ///   corroborated latest `(ordinal, frame)` point — a point ≥3 distinct slots
    ///   agreed on (see [`Self::frame_rate`]), so a lone slot cannot swing it —
    ///   clamped to `[0, frontier]`. This keeps deep honest joins (>7 ordinals
    ///   from the frontier) landing on the true ordinal, exactly as before, but
    ///   now from a reference an attacker can't poison.
    /// - **No corroborated rate yet**: anchor on the frontier and let
    ///   [`Self::record`]'s nibble correction resolve the placement — but only
    ///   within a single ring cycle (`frontier < SYNC_RING_MODULUS`). Beyond one
    ///   cycle the nibble could land a deep joiner a full cycle off a slot's true
    ///   ordinal with no way to tell, so return `None` to **defer**. Within a
    ///   cycle, `record` additionally defers any placement that lands *above* the
    ///   frontier (the tell-tale of a deep joiner whose nibble jumped a cycle
    ///   upward) — so a slot is only ever placed at or below the frontier, within
    ///   the nibble's reliable ±7 range of its true ordinal.
    ///
    /// A joining slot's own single-slot frame is deliberately **never** trusted
    /// as a rate/anchor source; that was the calibration-poisoning lever.
    fn join_expected(&self, ring: u64, game_frame: Option<u32>) -> Option<u64> {
        let Some(frontier) = self.members.values().map(|m| m.next_expected).max() else {
            return Some(ring); // no members at all: the very first observation
        };
        if let Some(frame) = game_frame
            && let Some(rate) = self.frame_rate()
            && let Some((ref_ordinal, ref_frame)) = self.corroborated_latest
        {
            let predicted = ref_ordinal as f64 + (f64::from(frame) - f64::from(ref_frame)) / rate;
            return Some(predicted.clamp(0.0, frontier as f64).round() as u64);
        }
        // No trustworthy rate: safe to anchor on the frontier only within a
        // single ring cycle; deeper than that, defer (the caller drops the report
        // and retries on the slot's next one).
        (frontier < SYNC_RING_MODULUS).then_some(frontier)
    }

    /// The frames-per-ordinal rate this session is advancing at, from the spread
    /// between [`Self::corroborated_first`] and [`Self::corroborated_latest`] —
    /// both **corroborated** points (≥3 distinct slots agreeing), so the slope an
    /// attacker sees is one it cannot move with its single slot. `None` until two
    /// distinct-ordinal corroborated points exist, or if the computed rate isn't a
    /// sane forward rate (frames must advance, not stall or run backward, between
    /// distinct ordinals).
    fn frame_rate(&self) -> Option<f64> {
        let (o1, f1) = self.corroborated_first?;
        let (o2, f2) = self.corroborated_latest?;
        if o2 <= o1 {
            return None;
        }
        let rate = (f64::from(f2) - f64::from(f1)) / (o2 - o1) as f64;
        (rate.is_finite() && rate > 0.0).then_some(rate)
    }

    /// Drops a joining slot's report because it can't be safely placed yet (no
    /// corroborated rate and the frontier is more than a ring cycle ahead, or the
    /// placement would land above the frontier). No member is created and no
    /// calibration is fed, so the slot stays in the join path and retries on its
    /// next report — the natural re-placement, no separate comparison-lost flag.
    /// Missing a possible desync for this slot is an acceptable false negative;
    /// framing an honest slot by misplacing it a full ring cycle is not.
    fn defer_join(&mut self, key: &SessionKey, slot: SlotId) -> Option<SyncDivergence> {
        self.defer_warns += 1;
        if should_warn(self.defer_warns) {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                count = self.defer_warns,
                "deferring a joining slot's sync placement: no corroborated rate \
                 yet and the join is more than a ring cycle from the frontier — \
                 dropping this report, will retry on the slot's next one",
            );
        }
        None
    }

    /// Folds the pending reports at `ordinal` into the corroborated calibration:
    /// once at least [`SYNC_CORROBORATION_MIN`] **distinct** slots have reported
    /// it with a frame, records `(ordinal, median_frame)` as a corroborated point
    /// — extending the corroborated ordinal range at either end. The **median**
    /// is what a single attacker cannot move (≤1 outlier among ≥3 values), so the
    /// resulting rate/anchor is tolerance-free and poisoning-resistant.
    fn update_corroboration(&mut self, ordinal: u64) {
        let Some(reports) = self.pending.get(&ordinal) else {
            return;
        };
        let mut frames: Vec<u32> = reports.values().filter_map(|r| r.game_frame).collect();
        if frames.len() < SYNC_CORROBORATION_MIN {
            return;
        }
        frames.sort_unstable();
        let median = frames[frames.len() / 2];
        if self.corroborated_first.is_none_or(|(o, _)| ordinal < o) {
            self.corroborated_first = Some((ordinal, median));
        }
        if self.corroborated_latest.is_none_or(|(o, _)| ordinal > o) {
            self.corroborated_latest = Some((ordinal, median));
        }
    }

    /// Evaluates every ordinal now ready: the frontier (the furthest any
    /// member has reached) has moved at least `margin` past it (see
    /// [`sync_eval_margin`]), and every member required for it (its `since` at
    /// or before it) has reported it. Returns the first [`SyncDivergence`]
    /// fired, if any — the caller's next `record` call resumes draining from
    /// where this left off.
    fn evaluate_ready(&mut self, key: &SessionKey, margin: u64) -> Option<SyncDivergence> {
        loop {
            let Some(frontier) = self.members.values().map(|m| m.next_expected).max() else {
                return None; // no members yet
            };
            let base = self.base_ordinal;
            if frontier < base + margin {
                return None; // not enough lead yet to trust completeness
            }

            let required: Vec<SlotId> = self
                .members
                .iter()
                .filter(|(_, m)| m.since <= base)
                .map(|(slot, _)| *slot)
                .collect();
            if required.is_empty() {
                // No member was active this far back -- vacuously nothing to
                // compare (only reachable right after a promotion anchors the
                // frontier ahead of ordinal 0, or once every once-required
                // member has since departed). Just retire and move on.
                self.pending.remove(&base);
                self.base_ordinal += 1;
                continue;
            }

            let complete = self
                .pending
                .get(&base)
                .is_some_and(|reports| required.iter().all(|slot| reports.contains_key(slot)));
            if !complete {
                // Should be rare given the margin; a genuinely stalled member
                // is bounded by window eviction instead of blocking here.
                return None;
            }

            let reports = self.pending.remove(&base).expect("just matched complete");
            self.base_ordinal += 1;
            if let Some(divergence) = self.evaluate(base, &reports, key) {
                return Some(divergence);
            }
        }
    }

    /// Marks the comparator permanently dormant because the session's
    /// negotiated buffer bounds reach the absurd-bounds backstop
    /// ([`SYNC_ABSURD_BUFFER_MAX`]) — not a live constraint under any real
    /// policy, just a defensive ceiling: logs once, then behaves exactly like
    /// any other dormant comparator (a cheap no-op).
    fn disable_for_absurd_bounds(&mut self, key: &SessionKey, max_buffer: u32) {
        if !self.dormant {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                max_buffer,
                absurd_at = SYNC_ABSURD_BUFFER_MAX,
                "session's buffer bounds reach the desync comparator's absurd-bounds \
                 backstop; disabling desync detection for this session",
            );
        }
        self.dormant = true;
    }

    /// Compares the reports at a complete `ordinal`. `None` when every
    /// *comparable* report agrees (the ordinal retires silently, whether or
    /// not there were zero or more kind-mismatched reports excluded);
    /// otherwise the [`SyncDivergence`] to fire, after pruning the diverged
    /// minority from the compare set.
    ///
    /// A report whose `kind` disagrees with `ordinal`'s expected parity (see
    /// [`expected_kind_for_ordinal`]) is excluded from the comparison
    /// entirely — a rate-limited warn, not a vote either way: kind is a
    /// deterministic function of the true ring index, so a mismatch here
    /// means this report's placement (not necessarily its sim) drifted, and
    /// grouping a wrong-kind hash alongside the right-kind ones would compare
    /// two different quantities (the native check alternates between a
    /// per-unit hash and a game-header/rng hash — see [`SyncValue`]) as if
    /// they were the same checksum.
    fn evaluate(
        &mut self,
        ordinal: u64,
        reports: &HashMap<SlotId, SyncReport>,
        key: &SessionKey,
    ) -> Option<SyncDivergence> {
        let expected_kind = expected_kind_for_ordinal(ordinal);

        let mut groups: HashMap<SyncValue, Vec<SlotId>> = HashMap::new();
        let mut comparable = 0usize;
        for (slot, report) in reports {
            if report.kind != expected_kind {
                self.kind_parity_warns += 1;
                if should_warn(self.kind_parity_warns) {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        slot = slot.0,
                        ordinal,
                        kind = report.kind,
                        expected_kind,
                        count = self.kind_parity_warns,
                        "sync kind disagrees with this ordinal's expected parity; \
                         excluding this report from the desync comparison as a \
                         likely alignment drift, not a desync",
                    );
                }
                continue;
            }
            comparable += 1;
            groups.entry(report.value).or_default().push(*slot);
        }
        if groups.len() <= 1 {
            return None; // every comparable report agreed (or fewer than 2 were comparable)
        }

        // The frame the mismatch was confirmed at. In lockstep every report at
        // one ordinal shares a frame, so picking the newest present is only a
        // defensive tie-break, not a meaningful choice among disagreeing values.
        let game_frame = reports.values().filter_map(|r| r.game_frame).max();

        let majority = groups
            .iter()
            .find(|(_, slots)| slots.len() * 2 > comparable)
            .map(|(_, slots)| slots.clone());

        match majority {
            Some(majority_slots) => {
                let majority: HashSet<SlotId> = majority_slots.into_iter().collect();
                // Drawn from `groups` (comparable reports only) — a
                // kind-excluded slot never appears here; it was never really
                // "in" the comparison to have diverged from it.
                let mut diverged: Vec<SlotId> = groups
                    .values()
                    .flatten()
                    .copied()
                    .filter(|slot| !majority.contains(slot))
                    .collect();
                diverged.sort_unstable();
                // Drop the minority from the compare set *and* from every future
                // pending ordinal, so the survivors are compared only against each
                // other from here on.
                for slot in &diverged {
                    self.remove_member(*slot);
                }
                // With fewer than two comparable slots left there is nothing to
                // compare, so stop for the session.
                if self.members.len() < 2 {
                    self.dormant = true;
                }
                Some(SyncDivergence {
                    sync_ordinal: ordinal,
                    game_frame,
                    no_majority: false,
                    diverged,
                })
            }
            None => {
                // A 1v1 or even split: undecidable, and no survivor set to keep
                // watching. Report it and go dormant for the session.
                self.dormant = true;
                Some(SyncDivergence {
                    sync_ordinal: ordinal,
                    game_frame,
                    no_majority: true,
                    diverged: Vec::new(),
                })
            }
        }
    }

    /// Evicts the oldest in-flight ordinal(s) while over [`SYNC_WINDOW`]. A slot
    /// that stalled leaves its ordinals forever-incomplete; the eviction bounds
    /// memory and is the missing-sync signal too — the evicted ordinal's report
    /// set names who *did* report, so the rest are the stalled slots.
    fn evict_over_window(&mut self, key: &SessionKey) {
        while self.pending.len() > SYNC_WINDOW {
            let ordinal = *self
                .pending
                .keys()
                .next()
                .expect("over-window is non-empty");
            let reports = self.pending.remove(&ordinal).expect("just matched");
            let mut missing: Vec<u8> = self
                .members
                .keys()
                .filter(|member| !reports.contains_key(member))
                .map(|slot| slot.0)
                .collect();
            missing.sort_unstable();
            self.evict_warns += 1;
            if should_warn(self.evict_warns) {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    ordinal,
                    ?missing,
                    count = self.evict_warns,
                    "evicting an incomplete sync ordinal over the window cap; \
                     a slot's sync stream is lagging or stopped",
                );
            }
            if ordinal >= self.base_ordinal {
                self.base_ordinal = ordinal + 1;
            }
        }
    }

    /// Removes `slot` from the compare set and drops its reports from every
    /// pending ordinal, so it is neither required nor compared from here on.
    /// Idempotent — a slot not in the set is a no-op.
    fn remove_member(&mut self, slot: SlotId) {
        self.members.remove(&slot);
        for reports in self.pending.values_mut() {
            reports.remove(&slot);
        }
    }
}

/// Whether a rate-limited warn should fire at occurrence `count`: on the first,
/// then at every power of two. Bounds log volume to O(log n) for a persistent
/// anomaly while never fully going silent.
fn should_warn(count: u64) -> bool {
    count == 1 || count.is_power_of_two()
}

impl DecisionMaker {
    /// Creates a new decision-maker for `key`, starting at the coordinator's
    /// minimum buffer. `authority` is the injected input: `SelfRelay` to run
    /// the decision core, `Peer` to forward conditions without deciding.
    pub fn new(
        key: SessionKey,
        bounds: BufferBounds,
        law: ControlLaw,
        authority: Authority,
    ) -> Self {
        Self {
            key,
            buffer: BufferSize(bounds.min),
            bounds,
            law,
            authority,
            slots: HashMap::new(),
            last_decision_frame: None,
            decision_seq: 0,
            pending_directive: None,
            decided_leaves: HashMap::new(),
            departures: HashMap::new(),
            next_leave_seq: 0,
            observers: HashSet::new(),
            results: HashMap::new(),
            sync: SyncTracker::default(),
        }
    }

    /// The session this decision-maker serves.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// The current buffer size.
    pub fn buffer(&self) -> BufferSize {
        self.buffer
    }

    /// The session's consensus coordinate: the *minimum* of the per-slot
    /// frames observed so far, i.e. the slowest participant's progress --
    /// which is what lockstep actually advances by. `None` until at least one
    /// slot has produced a framed turn (lobby). Taking the minimum is the
    /// poisoning defense: `game_frame_count` is client-asserted, so one slot's
    /// inflated claim moves only its own observation, never the coordinate.
    ///
    /// A departed slot is excluded: its departure retires it from `slots`, so
    /// the coordinate follows the *survivors* rather than staying pinned at the
    /// departed slot's frozen last frame for the rest of the game -- which would
    /// freeze the dwell clock and keep a pending buffer directive from ever
    /// retiring.
    pub fn session_frame(&self) -> Option<GameFrameCount> {
        self.slots.values().filter_map(|s| s.frame).min()
    }

    /// Records a `game_frame_count` observed on one of `slot`'s validated
    /// turns. Monotonic per slot -- an older frame arriving out of order
    /// doesn't move the observation backward.
    ///
    /// A departed slot is ignored: its final turns can still be in flight across
    /// the mesh when the departure lands, and re-creating its entry here would
    /// resurrect the frozen frame that pins the session coordinate. The
    /// departure record already captured the home relay's complete view of the
    /// slot's last frame (every turn was observed at its home before the link
    /// ended), so a late copy carries nothing new.
    pub fn observe_frame(&mut self, slot: SlotId, frame: GameFrameCount) {
        if self.departures.contains_key(&slot) {
            return;
        }
        let state = self.slots.entry(slot).or_default();
        if state.frame.is_none_or(|current| frame > current) {
            state.frame = Some(frame);
        }
    }

    /// The seq-aware sibling of [`observe_frame`](Self::observe_frame): records the
    /// same monotone per-slot frame **and** appends `(seq, frame)` to the slot's
    /// bounded [`frame_history`](SlotState::frame_history), so a leave decided
    /// later can clamp its apply frame to a survivor-reachable ceiling (see
    /// [`reachable_frame`](Self::reachable_frame)). **Every production
    /// frame-observation on the leave path must go through this**, not the
    /// seq-less `observe_frame`, or the clamp has no history to work from and a
    /// slot's inflated `game_frame_count` could schedule a leave past a
    /// survivor-reachable frame. `observe_frame` is retained only for tests that
    /// don't exercise the leave-frame clamp.
    ///
    /// A departed slot is ignored, exactly as in `observe_frame`.
    pub fn observe_turn_frame(&mut self, slot: SlotId, seq: u64, frame: GameFrameCount) {
        if self.departures.contains_key(&slot) {
            return;
        }
        // Only the window back to `frontier − buffer_max` is ever consulted; keep
        // a little more than the buffer depth so the fastest survivor's history
        // still reaches the threshold turn even under a bit of reordering.
        let cap = (self.bounds.max as usize).saturating_add(4).max(8);
        let state = self.slots.entry(slot).or_default();
        if state.frame.is_none_or(|current| frame > current) {
            state.frame = Some(frame);
        }
        state.frame_history.push_back((seq, frame.0));
        while state.frame_history.len() > cap {
            state.frame_history.pop_front();
        }
    }

    /// The reachability ceiling for a leave's apply frame: the highest game frame
    /// **every surviving slot has provably executed**, or `None` when no survivor
    /// has framed history yet (lobby / the game's very first turns). Computed by
    /// the departing slot's home relay and carried in the `SlotDeparted` record so
    /// every relay clamps to the identical value (see [`decide_leave`] and the
    /// `reachable_frame` field on [`Departure`]).
    ///
    /// A turn stamped at transport seq `s` is provably executed once the session
    /// advanced `buffer_max` turns past `s`. So with `frontier_turn` the leading
    /// seq across survivors and `threshold = frontier_turn − buffer_max`
    /// (saturating, so the game's first turns yield the earliest framed floor
    /// rather than nothing), each survivor's proven-executed frame is the highest
    /// it stamped at seq ≤ `threshold`; the ceiling is the **minimum** across
    /// survivors, so all of them can reach it. Counting is in **turns**, never
    /// frames, so no frames-per-turn assumption enters. Excludes the departing
    /// slot (its own claim must not raise its leave's ceiling) and any slot with
    /// no framed history (it constrains nothing and will catch up).
    fn reachable_frame(&self, departing: SlotId) -> Option<u32> {
        let buffer_max = u64::from(self.bounds.max);
        let frontier_turn = self
            .slots
            .iter()
            .filter(|(slot, _)| **slot != departing)
            .filter_map(|(_, s)| s.frame_history.back().map(|(seq, _)| *seq))
            .max()?;
        let threshold = frontier_turn.saturating_sub(buffer_max);
        let mut ceiling: Option<u32> = None;
        for (slot, s) in &self.slots {
            if *slot == departing || s.frame_history.is_empty() {
                continue;
            }
            // Highest frame proven executed (stamped at/before the threshold
            // turn). A survivor that only started framing after the threshold has
            // no proven frame yet; fall back to its earliest recorded frame — a
            // low, still-reachable bound — rather than abandoning the clamp
            // (which would reopen the inflation stall in the game's first turns).
            let executed = s
                .frame_history
                .iter()
                .filter(|(seq, _)| *seq <= threshold)
                .map(|(_, frame)| *frame)
                .max()
                .or_else(|| s.frame_history.front().map(|(_, frame)| *frame))?;
            ceiling = Some(ceiling.map_or(executed, |c| c.min(executed)));
        }
        ceiling
    }

    /// Records the `decision_seq` of a directive this relay forwarded on
    /// behalf of the session's authority. Keeps `decision_seq` at least that
    /// high, so if this relay is later promoted to authority its first
    /// decision numbers *above* everything clients have already seen --
    /// clients keep only the highest seq, and a restarted numbering would be
    /// silently ignored.
    pub fn observe_directive(&mut self, seq: u32) {
        if seq > self.decision_seq {
            self.decision_seq = seq;
        }
    }

    /// Whether this relay is the decision-making authority for this session.
    pub fn is_authority(&self) -> bool {
        self.authority == Authority::SelfRelay
    }

    /// Reconciles this maker with a re-pushed session descriptor: adopts the
    /// coordinator's current bounds and the freshly computed authority verdict.
    /// The relay set serving a session changes as players join and leave, and
    /// with it who the lowest-id (deciding) relay is -- a maker frozen at its
    /// creation-time verdict could leave a session with two authorities or
    /// none. Condition history and frame observations are kept (they describe
    /// the links, not the descriptor); the committed buffer is kept too, since
    /// it reflects what was last broadcast, and future decisions clamp to the
    /// new bounds. A relay losing authority drops any directive it was still
    /// broadcasting -- only the authority stamps.
    ///
    /// Returns the synced leaves a promotion (Peer -> SelfRelay) must (re)broadcast
    /// -- see [`set_authority`](Self::set_authority); empty otherwise. The second
    /// element names which of those are **freshly derived** by this call (a first
    /// insert into the directive cache, not a verbatim re-broadcast of one already
    /// cached) -- see [`set_authority`](Self::set_authority) for why the caller
    /// needs the distinction.
    #[must_use]
    pub fn sync(
        &mut self,
        bounds: BufferBounds,
        authority: Authority,
    ) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        self.bounds = bounds;
        self.set_authority(authority)
    }

    /// Applies a fresh authority verdict without touching the bounds, returning
    /// the synced leaves a *promotion* must (re)broadcast (empty on any other
    /// transition). This is the presence-driven half of authority tracking:
    /// between descriptor pushes, the verdict moves as relays' players come and
    /// go, while the bounds stay whatever the coordinator last set.
    ///
    /// A relay **losing** authority drops any buffer directive it was still
    /// broadcasting (only the authority stamps), but keeps `decision_seq`, its
    /// cached leaves, and its recorded departures -- those are exactly what a
    /// later re-promotion needs.
    ///
    /// A relay **gaining** authority (Peer -> SelfRelay) yields the leaves to
    /// re-broadcast: every cached directive is re-emitted *verbatim* (its apply
    /// frame must not be recomputed -- survivors that already applied it did so
    /// at that exact frame), and a departure with no cached directive is decided
    /// fresh (safe: a directive that never escaped the dead authority was never
    /// applied by anyone). The caller pushes each down local survivors and across
    /// the mesh; all are idempotent (clients and peer relays dedup by slot), so
    /// re-delivering a leave every survivor already applied costs a few redundant
    /// frames, bounded by the slot count -- while skipping one a stalled survivor
    /// never received would strand it forever.
    ///
    /// Returns `(all, fresh)`: `all` is every leave to (re)broadcast, `fresh` is
    /// the subset that is a **first insert** into the directive cache this call --
    /// a departure re-derived because no directive escaped the dead authority. A
    /// verbatim re-broadcast of an already-cached directive is not in `fresh`:
    /// whichever relay cached it first already reported it, so re-announcing it
    /// again on every promotion would double-count the departure. The registry-
    /// level free function uses `fresh` to fire exactly one departure notice per
    /// slot, by whichever path (`decide_leave`, `observe_leave`, or this one)
    /// first grows the cache.
    #[must_use]
    pub fn set_authority(
        &mut self,
        authority: Authority,
    ) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        if self.authority == authority {
            return (Vec::new(), Vec::new());
        }
        let promoting = self.authority == Authority::Peer && authority == Authority::SelfRelay;
        self.authority = authority;
        if authority == Authority::Peer {
            // Only the authority stamps buffer changes; a demoted relay stops.
            // Its cached leaves and recorded departures are deliberately kept --
            // they are what a later promotion re-broadcasts.
            self.pending_directive = None;
        }
        if promoting {
            // Start the desync comparator fresh. No per-ordinal checksum state
            // transfers across a handoff — a real desync diverges every interval,
            // so the first interval after promotion re-detects it, and carrying
            // the window across would be complexity for a one-interval blind spot.
            // Observer membership is descriptor-driven, so it is deliberately kept.
            self.sync = SyncTracker::default();
            self.drain_handoff_leaves()
        } else {
            (Vec::new(), Vec::new())
        }
    }

    /// The synced leaves a freshly promoted authority must (re)broadcast so no
    /// leave is lost when authority moves off a relay that had decided (or should
    /// have decided) one. Every cached directive is re-emitted verbatim, and
    /// every recorded departure without a cached directive is decided fresh and
    /// cached. See [`set_authority`](Self::set_authority) for the `(all, fresh)`
    /// shape.
    ///
    /// Deliberately **unconditional** -- there is no "already applied everywhere,
    /// skip it" test, because the relay cannot make one. The frames it observes
    /// are survivors' *send stamps*, which lead their execution by the latency
    /// buffer's depth: the survivors-only session frame reaches the apply frame
    /// (`last_frame + 1`) essentially the moment the leave is decided, whether
    /// every survivor applied it or every survivor is still stalled waiting for
    /// it. A predicate that is true in both states cannot gate the one
    /// re-delivery that would unstall a survivor the original push missed, so
    /// the leave is always re-sent and every consumer dedups by slot instead.
    ///
    /// The fresh derivation runs through [`decide_leave`](Self::decide_leave)
    /// itself (not a hand-rolled duplicate of its logic) -- at this point
    /// `self.authority` is already `SelfRelay` (the caller set it just above) and
    /// the slot is confirmed not yet cached, so `decide_leave` always succeeds
    /// unless there is no frame basis yet (the same "hold" it already documents).
    /// Routing through it means a promotion-derived leave is indistinguishable
    /// from any other `decide_leave` call, including the first-insert bookkeeping
    /// the departure notifier keys on -- a promotion that derives a leave for a
    /// slot no relay ever cached before (the case a 2-relay topology hits when the
    /// only other relay is the one that just died) is exactly as much a "first
    /// insert" as the authoring relay's own `decide_leave` would have been, and
    /// must fire the same one notice.
    fn drain_handoff_leaves(&mut self) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        let mut leaves = Vec::new();
        let mut fresh = Vec::new();

        // Cached directives (authored or observed): re-broadcast verbatim. Never
        // "fresh" -- the cache already held these, so whichever relay first
        // cached them already reported the departure.
        leaves.extend(self.decided_leaves.values().copied());

        // Departures with no cached directive: the previous authority never got
        // to author one (or died before it escaped), so decide fresh through
        // `decide_leave`. Collect first to avoid holding an immutable borrow
        // across the mutation.
        let to_derive: Vec<(SlotId, u32)> = self
            .departures
            .iter()
            .filter(|(slot, _)| !self.decided_leaves.contains_key(slot))
            .map(|(slot, departure)| (*slot, departure.reason))
            .collect();
        for (slot, reason) in to_derive {
            if let Some(directive) = self.decide_leave(slot, reason) {
                leaves.push(directive);
                fresh.push(directive);
            }
            // `None` means no frame basis yet (a lobby-era departure) -- hold,
            // exactly as a direct `decide_leave` call would.
        }

        (leaves, fresh)
    }

    /// Ingests this relay's own home-client `LinkConditions` (conditions the
    /// relay observed directly on its local clients).
    ///
    /// Local slots have `mesh_rtt = 0` (no mesh hop -- this relay). RTT
    /// samples are pushed into the per-slot ring buffer for jitter-aware
    /// sizing. Cumulative loss counters are rotated so the next decision can
    /// difference them.
    ///
    /// Returns a [`Decision`] if the control law fires a change, `None` if it
    /// holds (target unchanged, or min-dwell suppressing a lower, or no framed
    /// turn observed yet, or this relay is not the authority). The caller
    /// translates a returned decision into a broadcast.
    pub fn ingest_local(&mut self, conditions: &LinkConditions) -> Option<Decision> {
        self.ingest(conditions, 0)
    }

    /// Ingests a peer relay's `LinkConditions` sidecar (conditions the peer
    /// relay observed on its own home clients, forwarded across the mesh).
    ///
    /// `mesh_rtt_us` is the relay-pair RTT from the authority to the peer
    /// relay -- sampled from the `MeshLink`'s QUIC connection stats. It's added
    /// to each remote slot's effective RTT so cross-relay paths include the
    /// mesh hop. The transport doesn't carry mesh RTT in the sidecar because
    /// it's a property of the relay-pair, not of any individual client's link.
    ///
    /// Returns a [`Decision`] if the control law fires a change, `None` if it
    /// holds.
    pub fn ingest_remote(
        &mut self,
        conditions: &LinkConditions,
        mesh_rtt_us: u32,
    ) -> Option<Decision> {
        self.ingest(conditions, mesh_rtt_us)
    }

    /// Shared ingestion: pushes RTT samples, rotates loss counters, sets the
    /// mesh hop, then runs `decide` if this relay is the authority.
    fn ingest(&mut self, conditions: &LinkConditions, mesh_rtt_us: u32) -> Option<Decision> {
        for slot in &conditions.slots {
            let id = SlotId(slot.slot as u8);
            // A departed slot's stale sample can still be in flight (a mesh
            // datagram raced the departure); re-creating its entry would
            // resurrect state its departure deliberately retired — the same
            // guard `observe_frame` applies.
            if self.departures.contains_key(&id) {
                continue;
            }
            let state = self.slots.entry(id).or_default();
            // RTT goes into the ring buffer for jitter-aware sizing. A `0`
            // (no measurement) is skipped by `push`.
            state.rtt_window.push(slot.rtt_us);
            // The mesh hop is a property of the relay-pair, not the client's
            // link, so it's set per-ingest (local = 0, remote = relay-pair RTT).
            state.mesh_rtt_us = mesh_rtt_us;
            // Rotate cumulative counters: old current becomes previous, so the
            // next decision can difference them. On the first sample (seen=false)
            // there's no prior to rotate.
            if state.seen {
                state.prev_lost = state.curr_lost;
                state.prev_sent = state.curr_sent;
                state.has_delta = true;
            }
            state.curr_lost = slot.lost_packets;
            state.curr_sent = slot.sent_packets;
            state.seen = true;
        }

        if !self.is_authority() {
            return None;
        }

        self.decide()
    }

    /// Computes the target buffer size from current conditions, without
    /// applying it. This is the formula:
    ///
    /// ```text
    /// target = ceil(pairwise_path / turn_duration) + ceil(loss_risk / turn_duration)
    /// ```
    ///
    /// Path and loss are `ceil`'d separately because loss recovery is quantized
    /// to whole turns: a re-carry rides the next packet exactly one
    /// `turn_duration` later, so it adds a whole number of turns to the delivery
    /// time, not a continuous fraction absorbed into the path's `ceil` slack.
    /// Combining them into one `ceil` would under-provision -- e.g. at 150ms
    /// path with one re-carry, delivery is `41666 + 150000 = 191666us` needing
    /// 5 turns; the separated form gives `4 + 1 = 5` (correct), a combined form
    /// gives `ceil(157500/41666) = 4` (stalls on a single loss).
    ///
    /// Returns `None` when no slot has an RTT measurement yet (hold until we
    /// have data). Also public so a caller or debug UI can inspect what the
    /// target would be without firing a decision.
    pub fn target(&self) -> Option<u32> {
        // Collect effective RTTs (rtt + mesh hop) from all slots with a
        // measurement. The effective RTT is the full one-way path from the
        // client to the authority relay, so the pairwise formula naturally
        // includes the mesh hop for cross-relay pairs.
        let mut eff_rtts: Vec<u32> = self
            .slots
            .values()
            .map(|s| s.eff_rtt())
            .filter(|&r| r > 0)
            .collect();

        if eff_rtts.is_empty() {
            return None; // no RTT data yet, hold
        }

        // Worst pairwise path: (eff_A + eff_B) / 2 for the two highest.
        // A turn from A to B travels eff_A/2 + eff_B/2 = (eff_A + eff_B) / 2.
        // Using the actual pairwise path (not max_eff) avoids overshooting
        // when only one player has high latency -- lower buffer = less delay.
        eff_rtts.sort_unstable_by(|a, b| b.cmp(a)); // descending
        let path_us = if eff_rtts.len() >= 2 {
            (eff_rtts[0] + eff_rtts[1]) / 2
        } else {
            // One slot: assume symmetric (both legs same eff_RTT).
            eff_rtts[0]
        };

        // Loss recovery turns: burst loss on high-latency links is worse
        // because more packets are in flight during the burst window. The
        // term scales with loss_rate * eff_RTT.
        let worst_loss_risk = self
            .slots
            .values()
            .filter_map(|s| s.loss_risk())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0);

        let turn_us = self.law.turn_duration_us as f64;
        let path_turns = (path_us as f64 / turn_us).ceil() as u32;
        let loss_turns = (worst_loss_risk / turn_us).ceil() as u32;

        Some(path_turns + loss_turns)
    }

    /// Runs the control law: compute the target, then move toward it
    /// asymmetrically -- raises jump to the target immediately (no dwell, you
    /// can't dwell through a stall); lowers decrement by `lower_step` gated by
    /// `min_dwell_turns` (shrinks are infrequent and well-validated).
    fn decide(&mut self) -> Option<Decision> {
        // No framed turn observed yet (lobby): there is no consensus
        // coordinate to schedule against, so hold.
        let frame = self.session_frame()?;
        let target = self.target()?;

        let new_buffer = if target > self.buffer.0 {
            // Raise fast: jump to the target immediately. No dwell -- a
            // too-small buffer stalls, and you can't wait through a stall.
            target
        } else if target < self.buffer.0 {
            // Lower slow: check the dwell first. Every buffer-size change
            // alters the game feel, so shrinks are gated -- at least
            // `min_dwell_turns` must have elapsed since the last decision
            // before the buffer shrinks. A raise resets the dwell clock
            // (it set `last_decision_frame`), so a raise followed by a
            // would-be lower still waits the full dwell.
            if let Some(last) = self.last_decision_frame
                && frame.0.saturating_sub(last.0) < self.law.min_dwell_turns
            {
                return None;
            }
            self.buffer.0.saturating_sub(self.law.lower_step)
        } else {
            return None;
        };

        let new_buffer = self.bounds.clamp(new_buffer);
        if new_buffer == self.buffer.0 {
            return None;
        }

        // The apply horizon: the session frame is the *slowest* client's
        // progress as observed over its own uplink, so the relay's view lags
        // by roughly the cushion, and the fastest client runs ahead of the
        // slowest by at most the cushion again -- both scale with the buffer,
        // so the horizon does too (the wider of the old and new cushion,
        // plus a fixed delivery margin).
        let span = self.buffer.0.max(new_buffer);
        self.buffer = BufferSize(new_buffer);
        let applied_frame =
            GameFrameCount(frame.0.saturating_add(span).saturating_add(APPLY_HORIZON));
        self.last_decision_frame = Some(frame);

        // Queue the change for broadcast: the caller stamps it onto every turn
        // it forwards until the session frame passes `applied_frame`. A newer
        // decision replaces an older still-broadcasting one -- its higher
        // `decision_seq` tells clients the latest buffer wins even when copies
        // of both interleave on the wire.
        self.decision_seq += 1;
        self.pending_directive = Some(BufferDirective {
            buffer_turns: new_buffer,
            apply_at_frame: applied_frame.0,
            decision_seq: self.decision_seq,
        });

        Some(Decision {
            buffer: self.buffer,
            applied_frame,
        })
    }

    /// The buffer directive to stamp onto a turn this relay is about to
    /// forward, if a decision is still being broadcast. Returns `None` -- the
    /// overwhelmingly common case, since buffer changes are rare -- once the
    /// session frame reaches the directive's apply frame: by then every slot
    /// has been observed past it, so the change is applied (or moot)
    /// everywhere and the directive retires.
    ///
    /// Stamping every forwarded turn until then (rather than a fixed number)
    /// is what guarantees coverage: a client never receives its own turns
    /// back, so it needs the stamp on a peer's turn -- and if a client's peers
    /// aren't producing turns yet, the session frame isn't advancing either,
    /// so the directive simply waits for them. Copies are cheap (a few bytes
    /// on turns already being sent) and idempotent at the client (same
    /// `decision_seq`).
    ///
    /// The caller sets the returned directive on the outgoing payload's
    /// `buffer_directive` field before fanning it out to local slots and peer
    /// relays. Only the authority ever returns a directive here: a
    /// non-authority relay makes no decisions, so its `pending_directive` is
    /// always `None` -- and its caller must preserve, not overwrite, a stamp
    /// already on the turn.
    pub fn active_directive(&mut self) -> Option<BufferDirective> {
        let directive = self.pending_directive?;
        if self
            .session_frame()
            .is_some_and(|frame| frame.0 >= directive.apply_at_frame)
        {
            self.pending_directive = None;
            return None;
        }
        Some(directive)
    }

    /// Decides a synced player-leave for `slot` and queues it for broadcast.
    /// Returns the queued [`LeaveDirective`] (for logging), or `None` when this
    /// relay is not the authority, a leave for the slot is already broadcasting,
    /// or there is no frame basis yet (no in-game turn observed for the session
    /// -- a lobby/pre-game drop, which the game handles natively, not here).
    ///
    /// `reason` is the native `pending_leave_reason` value every client will
    /// write (`0x40000006` dropped, else left). Call this on the authority --
    /// directly when a home client's link ends, or on a peer relay's
    /// `SlotDeparted` signal for a client the peer served.
    ///
    /// The apply frame is one past the departing slot's last observed frame --
    /// the exact step remaining clients stall at waiting for a turn that will
    /// never come, so the leave unstalls them right there -- **clamped down** to
    /// the home-authored reachability ceiling ([`Departure::reachable_frame`]) so
    /// a slot that inflates its own `game_frame_count` before leaving cannot
    /// schedule the leave past a frame the survivors can reach (which would
    /// strand them). In the honest case `last_frame ≤ ceiling`, so the clamp is a
    /// no-op; in the game's first turns or under cross-relay mesh lag the ceiling
    /// can sit a little below `last_frame`, producing a bounded, deterministic
    /// *early* drop (never a stall) — harmless because the ceiling is
    /// single-sourced, so every client agrees. The session frame is the basis
    /// only when the slot never produced a framed turn; it is never folded in as
    /// a max (see [`leave_base_frame`] for why that would strand stalled
    /// survivors) and is not clamped (no `last_frame` to inflate). Both the last
    /// frame and the ceiling come from the slot's departure record -- surviving
    /// `remove_slot` -- so every relay, including one promoted mid-handoff,
    /// derives the identical apply frame (clients dedup by slot and require that
    /// agreement).
    pub fn decide_leave(&mut self, slot: SlotId, reason: u32) -> Option<LeaveDirective> {
        // Record the departure regardless of the outcome below (even a hold), so
        // a later promotion can re-derive this slot's leave. This merges the
        // slot's own live frame into the record and retires the slot from
        // `slots`; the record is the single frame source from here on. Passing
        // `None` for the ceiling and the result preserves whatever the home
        // already authored.
        self.note_departure(slot, None, None, None, reason);

        if self.authority != Authority::SelfRelay {
            return None;
        }
        if self.decided_leaves.contains_key(&slot) {
            return None; // already decided or cached this slot's leave
        }
        let record = self.departures.get(&slot);
        let slot_last = record.and_then(|d| d.last_frame).map(|f| f.0);
        let reachable = record.and_then(|d| d.reachable_frame);
        let session = self.session_frame().map(|f| f.0);
        // No framed turn observed anywhere yet (pre-game / lobby): nothing to
        // schedule against, so hold — a `None` short-circuits decide_leave.
        let base = leave_base_frame(slot_last, session)?;
        // Clamp only a framed departure's base, and only when the home supplied a
        // ceiling; the session-frame fallback has no client-inflatable basis.
        let base = match (slot_last, reachable) {
            (Some(_), Some(ceiling)) => base.min(ceiling),
            _ => base,
        };
        self.next_leave_seq += 1;
        let directive = LeaveDirective {
            slot: u32::from(slot.0),
            reason,
            apply_at_frame: base.saturating_add(1),
            leave_seq: self.next_leave_seq,
        };
        self.decided_leaves.insert(slot, directive);
        Some(directive)
    }

    /// Records a slot departure without deciding a leave for it, and retires the
    /// slot's live state (see [`note_departure`]). Every relay calls this when it
    /// learns a slot left (its own home client, or a peer's `SlotDeparted`), so a
    /// later authority promotion can re-derive the leave even on a relay that was
    /// never the authority. `last_frame` is the departing slot's last observed
    /// frame at its home relay (`None` if it never produced a framed turn); it is
    /// max-merged with this relay's own observation of the slot, so whichever
    /// view is fuller wins. `reachable` is the home-authored apply-frame ceiling
    /// (single-sourced, first non-`None` kept). `result` is the departing slot's
    /// home-authored end-of-game result echo (single-sourced, first non-`None`
    /// kept). The reason keeps the first observation.
    pub fn record_departure(
        &mut self,
        slot: SlotId,
        last_frame: Option<GameFrameCount>,
        reachable: Option<u32>,
        result: Option<ResultEcho>,
        reason: u32,
    ) {
        self.note_departure(slot, last_frame, reachable, result, reason);
    }

    /// Records the end-of-game result `slot` reported, returning whether this was
    /// the **first** report from the slot. A repeat returns `false` and keeps the
    /// first `echo`, so the caller fires at most one result notice per slot
    /// (anti-flooding, the same first-writer-wins posture as
    /// [`observe_leave`](Self::observe_leave)). The full `echo` is retained so the
    /// slot's departure record and `SlotDeparted` frame can embed it when the slot
    /// leaves. The report does not retire the slot's live state — a result is not
    /// a departure — so the caller's frame stamps still read the slot's framed
    /// history.
    #[must_use]
    pub fn record_result(&mut self, slot: SlotId, echo: ResultEcho) -> bool {
        use std::collections::hash_map::Entry;
        match self.results.entry(slot) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(echo);
                true
            }
        }
    }

    /// The result `slot` reported for this session, if any — read on the slot's
    /// home relay when the slot departs, to seed the departure record and the
    /// `SlotDeparted` frame with the retained result.
    pub fn result_for(&self, slot: SlotId) -> Option<&ResultEcho> {
        self.results.get(&slot)
    }

    /// Caches a synced leave this relay observed authored by the session's
    /// authority (a peer relay's `LeaveDirective` off the mesh), so a later
    /// promotion re-broadcasts it verbatim. First writer wins; a conflicting
    /// duplicate for the same slot (a different apply frame or reason) is logged
    /// -- that would mean two relays decided the same slot's leave differently, an
    /// authority bug. Keeps `next_leave_seq` at least the observed seq so a
    /// promoted relay's own numbering never collides with what clients hold.
    ///
    /// Returns whether this was a **first insert** for the slot — the moment the
    /// directive cache gains the slot — so the caller fires exactly one departure
    /// notice per (session, slot) on this relay (a redundant copy, a second mesh
    /// path, or a reconcile-on-join re-send all return `false`).
    #[must_use]
    pub fn observe_leave(&mut self, leave: &LeaveDirective) -> bool {
        use std::collections::hash_map::Entry;
        let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
            // A slot id past `u8` range can't name any real slot; a silent
            // truncation would alias it onto a valid one. Drop it (defensive —
            // the wire values are validated upstream, so this shouldn't occur).
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                slot = leave.slot,
                "leave directive names a slot id out of range; ignoring",
            );
            return false;
        };
        let inserted = match self.decided_leaves.entry(slot) {
            Entry::Occupied(existing) => {
                if existing.get() != leave {
                    tracing::warn!(
                        tenant = self.key.tenant.as_ref(),
                        session = self.key.session.0,
                        slot = leave.slot,
                        cached_apply = existing.get().apply_at_frame,
                        observed_apply = leave.apply_at_frame,
                        "conflicting synced leave for a slot already cached; keeping the first",
                    );
                }
                false
            }
            Entry::Vacant(vacant) => {
                vacant.insert(*leave);
                true
            }
        };
        if leave.leave_seq > self.next_leave_seq {
            self.next_leave_seq = leave.leave_seq;
        }
        inserted
    }

    /// This slot's last observed game frame, or `None` before its first framed
    /// turn — or after its departure was recorded, which retires the slot's live
    /// state (the frame lives on in the departure record). Read at a departure
    /// trigger, before recording, to fill a `SlotDeparted`'s `last_frame`.
    pub fn slot_frame(&self, slot: SlotId) -> Option<GameFrameCount> {
        self.slots.get(&slot).and_then(|s| s.frame)
    }

    /// This relay's known leave state for re-announcing to a freshly (re)joined
    /// mesh link: every recorded departure (slot, last frame, reachable ceiling,
    /// embedded result, reason) and every cached leave, unconditionally. A redialed
    /// link starts knowing nothing, so resending these lets it reconverge — all
    /// idempotent (dedup by slot on receipt). Nothing is filtered as "already
    /// applied everywhere": the relay cannot tell that state apart from "everyone
    /// still stalled waiting" (see [`drain_handoff_leaves`](Self::drain_handoff_leaves)),
    /// and the cost of a redundant re-announce is a few deduped frames, bounded by
    /// the slot count.
    #[allow(clippy::type_complexity)]
    fn leave_reconcile(
        &self,
    ) -> (
        Vec<(
            SlotId,
            Option<GameFrameCount>,
            Option<u32>,
            Option<ResultEcho>,
            u32,
        )>,
        Vec<LeaveDirective>,
    ) {
        let departures = self
            .departures
            .iter()
            .map(|(slot, departure)| {
                (
                    *slot,
                    departure.last_frame,
                    departure.reachable_frame,
                    departure.result.clone(),
                    departure.reason,
                )
            })
            .collect();
        let directives = self.decided_leaves.values().copied().collect();
        (departures, directives)
    }

    /// Records a departure and retires the slot's live state. The shared step
    /// behind [`record_departure`](Self::record_departure) and
    /// [`decide_leave`](Self::decide_leave).
    ///
    /// The record's `last_frame` is the **max-merge** of every observation: the
    /// caller-provided frame (a `SlotDeparted`'s carried frame, or `None`), the
    /// slot's own frame in `slots`, and any prior record — so whichever of the
    /// home relay's carried value and this relay's own view is fuller wins, and a
    /// re-announce can only raise it. The `reason` keeps the first observation
    /// (a departure has one reason; a duplicate signal doesn't rewrite it).
    ///
    /// `reachable` is the home-authored apply-frame ceiling (see
    /// [`Departure::reachable_frame`]). It is **single-sourced** — only the
    /// departing slot's home computes it, and it is carried verbatim — so this
    /// keeps the first non-`None` value seen and never recomputes or merges it
    /// (a later `decide_leave`/re-announce passing `None` must not clobber it).
    ///
    /// `result` is the departing slot's home-authored end-of-game result echo,
    /// single-sourced and kept the same first-non-`None`-wins way as `reachable`
    /// (the home seeds it from the report it retained; a peer receives it in the
    /// `SlotDeparted` frame). A result can never arrive after a slot's departure,
    /// so once seeded it never changes.
    ///
    /// Removing the slot from `slots` here — on *every* relay, not just the
    /// slot's home — is what lets `session_frame()` follow the survivors: a
    /// departed slot's frozen frame left in place would pin the minimum for the
    /// rest of the game, freezing the buffer machinery's dwell clock and keeping
    /// a pending buffer directive from ever retiring. The
    /// `observe_frame`/`ingest` guards keep late in-flight traffic from
    /// resurrecting the entry.
    fn note_departure(
        &mut self,
        slot: SlotId,
        last_frame: Option<GameFrameCount>,
        reachable: Option<u32>,
        result: Option<ResultEcho>,
        reason: u32,
    ) {
        use std::collections::hash_map::Entry;
        let own = self.slots.remove(&slot).and_then(|s| s.frame);
        let merged = match (last_frame, own) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        match self.departures.entry(slot) {
            Entry::Occupied(mut existing) => {
                let record = existing.get_mut();
                record.last_frame = match (record.last_frame, merged) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                // First non-`None` wins — single-sourced from the home.
                record.reachable_frame = record.reachable_frame.or(reachable);
                record.result = record.result.take().or(result);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Departure {
                    last_frame: merged,
                    reachable_frame: reachable,
                    result,
                    reason,
                });
            }
        }
        // A departed slot stops being required by the desync comparator: drop it
        // from the compare set so ordinals it would never report can still
        // complete on the survivors. Harmless on a non-authority relay (the
        // comparator is empty there) and idempotent for a slot never seen.
        self.sync.remove_member(slot);
    }

    /// Removes a slot's condition history (the client disconnected). Called
    /// when a home client leaves so its stale stats don't outlive its
    /// connection -- mirroring `unpublish_conditions`. A slot whose departure was
    /// already announced is already gone (recording a departure retires the
    /// slot), so this is a harmless no-op there; it still covers cleanup paths
    /// that are not departures. The slot's departure record (and any cached
    /// leave) is kept -- those outlive the connection so a promotion can still
    /// re-derive the leave.
    pub fn remove_slot(&mut self, slot: SlotId) {
        self.slots.remove(&slot);
    }

    /// Sets the session's observer slots (from the coordinator descriptor),
    /// replacing whatever was recorded before. Any newly-observer slot is dropped
    /// from the desync compare set — an observer must never be a required
    /// reporter. Called on every descriptor apply, so a changed observer set
    /// replaces rather than accumulates.
    pub fn set_observers(&mut self, observers: HashSet<SlotId>) {
        for slot in &observers {
            self.sync.remove_member(*slot);
        }
        self.observers = observers;
    }

    /// Feeds one turn's commands into the desync comparator, returning a
    /// [`SyncDivergence`] if this turn's sync command confirmed one. A cheap no-op
    /// unless this relay is the session authority and the comparator is still live
    /// (not dormant, and `slot` is a compared, non-observer, non-departed slot).
    ///
    /// **Caller contract: exactly once per distinct `(slot, seq)` turn.** The
    /// comparator's per-slot ordinal counting is not idempotent the way
    /// [`observe_frame`](Self::observe_frame)'s monotone max is — a turn handed
    /// to this method twice (the mesh legitimately delivers the same turn to
    /// the authority via more than one path) would be counted twice and
    /// silently misalign that slot's ordinals. The one call site
    /// (`deliver_turn_to_locals` in `mesh.rs`) is placed immediately after that
    /// function's own duplicate check for exactly this reason — don't add
    /// another call site upstream of it.
    ///
    /// It re-walks the command bytes itself looking for `0x37` sync commands. The
    /// bytes were bounds-checked at the ingress client edge — mesh hops trust that
    /// and do not re-validate — but this walk stays independent and defensive (it
    /// parses with the shared length table and stops on any anomaly rather than
    /// trusting a length): the authority reaches its own desync verdict from the
    /// bytes, it does not rely on a peer's parse, and the data is still nominally
    /// attacker-adjacent.
    ///
    /// `game_frame` is the turn's `game_frame_count` (carried into the notice as
    /// the interval the mismatch was confirmed at); `commands` is the raw command
    /// stream.
    pub fn observe_sync(
        &mut self,
        slot: SlotId,
        game_frame: Option<u32>,
        commands: &[u8],
    ) -> Option<SyncDivergence> {
        if self.authority != Authority::SelfRelay {
            return None;
        }
        // The session's negotiated buffer bounds may have grown to the
        // defensive absurd-bounds backstop (see `SYNC_ABSURD_BUFFER_MAX`) —
        // checked on every call since bounds can change mid-session
        // (`sync`/`apply_descriptor`); cheap, and `disable_for_absurd_bounds`
        // only logs once. Ordinary policy never approaches this.
        if self.bounds.max >= SYNC_ABSURD_BUFFER_MAX {
            self.sync
                .disable_for_absurd_bounds(&self.key, self.bounds.max);
        }
        // No-op fast paths: a dormant comparator has reached a terminal
        // verdict (or was just disabled above), and observers/departed slots
        // are never compared.
        if self.sync.dormant
            || self.observers.contains(&slot)
            || self.departures.contains_key(&slot)
        {
            return None;
        }
        let margin = sync_eval_margin(self.bounds.max);

        // Walk the command stream for this turn's sync command. A real client
        // emits **exactly one** `0x37` per outgoing turn, and the comparator's
        // ordinal counting depends on that (each turn advances a slot's ordinal
        // by one). A turn carrying more than one is not something an honest
        // client produces — packing several into one turn is precisely the
        // lever a malicious client would use to inflate its own frontier and
        // seed the join-placement calibration in a single turn (and to evade
        // its own detection by racing ordinals past the eviction window). So
        // only the first `0x37` is fed to the comparator; any extras are
        // ignored (they neither advance the slot's ordinal nor feed
        // calibration) and counted for a rate-limited anomaly warn. The walk
        // still parses with the shared length table and stops cleanly on any
        // malformed length without panicking.
        let mut offset = 0;
        let mut sync_seen = false;
        let mut extra_syncs = 0u32;
        let mut divergence = None;
        while offset < commands.len() {
            let Some(len) = command_length(&commands[offset..]) else {
                break; // an opcode the table doesn't know: stop, don't guess
            };
            if len == 0 || offset + len > commands.len() {
                break; // a length that overruns the buffer: stop
            }
            if commands[offset] == SYNC_COMMAND && len == SYNC_COMMAND_LEN {
                if sync_seen {
                    // A second (or later) sync command in the same turn: ignore
                    // it, and remember that this turn was anomalous.
                    extra_syncs += 1;
                } else {
                    sync_seen = true;
                    let command = &commands[offset..offset + SYNC_COMMAND_LEN];
                    let ring = command[1] >> 4;
                    let kind = command[1] & 0x0F;
                    let mut value = SyncValue::default();
                    value.copy_from_slice(&command[2..2 + SYNC_HASH16_LEN]);
                    // `[4..7]` (fog/vision, per-sender and pairwise-only in the
                    // native check) is deliberately never read — see `SyncValue`.
                    divergence = self
                        .sync
                        .record(&self.key, slot, ring, kind, value, game_frame, margin);
                }
            }
            offset += len;
        }
        if extra_syncs > 0 {
            self.sync.multi_sync_warns += 1;
            if should_warn(self.sync.multi_sync_warns) {
                tracing::warn!(
                    tenant = self.key.tenant.as_ref(),
                    session = self.key.session.0,
                    slot = slot.0,
                    extra_syncs,
                    count = self.sync.multi_sync_warns,
                    "turn carried more than one sync command; an honest client emits exactly \
                     one per turn — fed only the first to the comparator and ignored the rest",
                );
            }
        }
        divergence
    }
}

/// The base frame a synced leave schedules from: the departing slot's last
/// observed frame, falling back to the session's slowest frame **only** when the
/// slot never produced a framed turn, or `None` when neither exists (no framed
/// turn observed anywhere -- a lobby departure with no coordinate to schedule
/// against). The apply frame is one past this.
///
/// Deliberately *not* the max of the two. Survivors' stamped frames run ahead of
/// the departed slot's last frame before they stall (a client leads the slowest
/// slot by up to the buffer cushion), so a survivors-only session frame can
/// exceed the departed slot's last frame -- while each stalled survivor's
/// simulation is pinned at `last_frame + 1`, where it applies the leave the
/// moment one arrives. Folding the session frame in would schedule the leave
/// past that stall point: a frame the stalled survivors can never reach, a
/// permanent stall. Shared by [`DecisionMaker::decide_leave`] and the promotion
/// re-derivation so both reproduce the identical frame from the same departure
/// record.
fn leave_base_frame(slot_last: Option<u32>, session: Option<u32>) -> Option<u32> {
    slot_last.or(session)
}

/// The per-session decision-maker map behind [`DecisionMakers`]. A plain
/// (non-async) mutex mirrors `MeshLinks` and `routing::Sessions`: every critical
/// section is a short, await-free insert or lookup, so the lock is never held
/// across a turn's delivery.
type MakerMap = HashMap<SessionKey, DecisionMaker>;

/// The tenant's correlation ids for one session, as a relay knows them from the
/// coordinator's [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor).
/// Kept relay-side (not shared with the coordinator's own `session::SessionRefs`
/// type) so this crate has no dependency on the coordinator crate; the shapes
/// mirror each other because both describe the same wire fields.
#[derive(Debug, Clone, Default)]
struct SessionExternalRefs {
    /// The tenant's own id for the session (ShieldBattery's `gameId`).
    external_id: Option<String>,
    /// The tenant's own id for the player in each slot that carried one.
    slots: HashMap<SlotId, String>,
}

/// A notice a relay sends up its coordinator control connection about a running
/// game: a player departed, the game desynced, or a client reported its result.
/// All ride one channel (the leave sites, the sync comparator, and the result
/// ingress feed the same sender), so the reconnect buffering that guarantees a
/// queued notice survives a coordinator restart is written once, not per kind.
/// The coordinator client wraps each into the matching
/// [`RelayToCoordinator`](rally_point_proto::control::RelayToCoordinator) frame
/// when it forwards it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayNotice {
    /// A player permanently departed a running game (left vs. dropped).
    Departure(DepartureNotice),
    /// The game's sims diverged — a relay-observed desync.
    Desync(DesyncNotice),
    /// A client reported its end-of-game result, forwarded opaque.
    Result(ResultNotice),
    /// This relay tore down its last local state for a session. Fired after the
    /// session's departures have already gone up this same ordered channel, so
    /// the coordinator — which waits for every serving relay to report it — can
    /// treat a delivered close as proof no earlier notice is still in flight.
    SessionClosed {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session this relay closed.
        session: SessionId,
    },
}

/// A registry of per-session decision-makers, one per session this relay is
/// (or may become) the authority for. Shared across the slot-link and mesh-link
/// tasks that feed conditions in.
///
/// It also owns an optional **notice notifier** — the sender half of an
/// unbounded channel drained by the coordinator control connection. The leave
/// sites ([`decide_leave`], [`observe_leave`], and the promotion re-derivation
/// in [`set_authority`]/[`sync_maker`]) fire a [`DepartureNotice`] onto it the
/// moment a synced leave for a slot first enters this relay's cache, and the
/// desync comparator ([`observe_sync`]) fires a [`DesyncNotice`] when it confirms
/// a divergence — so the coordinator learns "player X left vs. was dropped" and
/// "this game desynced at ordinal N". The notifier is set once at startup when a
/// coordinator is configured and is simply absent when the relay runs standalone
/// (no coordinator to notify), where firing is a no-op.
///
/// It also holds each session's **correlation ids** ([`SessionExternalRefs`]),
/// populated from the coordinator's descriptor at apply time
/// ([`set_session_refs`](Self::set_session_refs)) so a departure notice can be
/// self-describing (carry its own `external_id`/`external_ref`) without the
/// coordinator's in-memory session-refs store surviving to notice time — a
/// coordinator restart wipes that store, but the descriptor a relay already
/// applied does not.
///
/// `Default` (empty maps, no notifier) is what `Arc::<DecisionMakers>::default`
/// builds where a registry is created without going through
/// [`new_decision_makers`] — the same empty state.
#[derive(Default)]
pub struct DecisionMakers {
    makers: parking_lot::Mutex<MakerMap>,
    /// Set once at startup, drains into the coordinator control connection.
    /// Absent for a standalone relay. Unbounded so queueing a notice while the
    /// coordinator link is down never blocks the turn path — the drain end holds
    /// the channel across reconnects and flushes pending notices on redial.
    /// Carries the [`RelayNotice`] union so departures, desyncs, and results
    /// share one pipe.
    notices: OnceLock<UnboundedSender<RelayNotice>>,
    /// Correlation ids per session, from the coordinator's descriptor. Absent
    /// for a session whose descriptor never carried them (a standalone relay,
    /// or a coordinator that predates the fields) — a departure notice for such
    /// a session simply carries no `external_id`/`external_ref`, and the
    /// coordinator falls back to its own store.
    refs: parking_lot::Mutex<HashMap<SessionKey, SessionExternalRefs>>,
}

impl DecisionMakers {
    /// Locks the per-session map. Kept method-shaped (rather than exposing the
    /// mutex directly) so every existing `registry.lock()` call site is
    /// unchanged by the registry gaining the departure notifier.
    pub fn lock(&self) -> parking_lot::MutexGuard<'_, MakerMap> {
        self.makers.lock()
    }

    /// Installs the notice notifier — the sender half of the channel the
    /// coordinator control connection drains (departures and desyncs both). Set
    /// once at startup; a second call is ignored (the first sender wins), matching
    /// the "one coordinator link per relay" reality.
    pub fn set_notice_notifier(&self, sender: UnboundedSender<RelayNotice>) {
        let _ = self.notices.set(sender);
    }

    /// Fires a notice up the coordinator control connection, if a notifier is
    /// installed. A no-op on a standalone relay. The channel is unbounded, so this
    /// never blocks; a send error means the drain end is gone (no coordinator
    /// subscriber), which for a standalone relay is expected.
    fn emit_notice(&self, notice: RelayNotice) {
        if let Some(sender) = self.notices.get() {
            let _ = sender.send(notice);
        }
    }

    /// Fires a departure notice (see [`emit_notice`](Self::emit_notice)).
    fn notify_departure(&self, notice: DepartureNotice) {
        self.emit_notice(RelayNotice::Departure(notice));
    }

    /// Fires a desync notice (see [`emit_notice`](Self::emit_notice)).
    fn notify_desync(&self, notice: DesyncNotice) {
        self.emit_notice(RelayNotice::Desync(notice));
    }

    /// Fires a result notice (see [`emit_notice`](Self::emit_notice)).
    fn notify_result(&self, notice: ResultNotice) {
        self.emit_notice(RelayNotice::Result(notice));
    }

    /// Fires a session-closed notice (see [`emit_notice`](Self::emit_notice)).
    fn notify_session_closed(&self, tenant: TenantId, session: SessionId) {
        self.emit_notice(RelayNotice::SessionClosed { tenant, session });
    }

    /// Records `key`'s correlation ids from a coordinator descriptor, replacing
    /// whatever was recorded before. Called on every descriptor apply (not just
    /// the first), so a changed descriptor's refs replace rather than
    /// accumulate alongside a stale copy.
    pub fn set_session_refs(
        &self,
        key: &SessionKey,
        external_id: Option<String>,
        slots: HashMap<SlotId, String>,
    ) {
        self.refs
            .lock()
            .insert(key.clone(), SessionExternalRefs { external_id, slots });
    }

    /// Forgets `key`'s correlation ids (the session ended). Idempotent; mirrors
    /// the maker's own removal so this map doesn't outlive the sessions it
    /// describes.
    fn forget_session_refs(&self, key: &SessionKey) {
        self.refs.lock().remove(key);
    }

    /// `key`'s correlation ids, if a coordinator descriptor ever carried them.
    fn session_refs(&self, key: &SessionKey) -> Option<SessionExternalRefs> {
        self.refs.lock().get(key).cloned()
    }

    /// The end-of-game result embedded in `slot`'s departure record for `key`, if
    /// the relay has a maker holding a departure that carried one. Read while
    /// building a [`DepartureNotice`] so the notice embeds the same result every
    /// relay folded into its record.
    fn departure_result(&self, key: &SessionKey, slot: SlotId) -> Option<ResultEcho> {
        self.makers
            .lock()
            .get(key)
            .and_then(|maker| maker.departures.get(&slot).and_then(|d| d.result.clone()))
    }
}

/// Creates an empty decision-maker registry for a relay with no sessions yet,
/// and no notice notifier installed (a standalone relay, or before startup
/// wiring calls [`DecisionMakers::set_notice_notifier`]).
pub fn new_decision_makers() -> DecisionMakers {
    DecisionMakers {
        makers: parking_lot::Mutex::new(HashMap::new()),
        notices: OnceLock::new(),
        refs: parking_lot::Mutex::new(HashMap::new()),
    }
}

/// Builds the departure notice for a synced leave that just first entered this
/// relay's cache: classifies left-vs-dropped from the native `reason`, and
/// carries the raw reason and the deciding relay's `leave_seq` for the
/// coordinator's telemetry. The slot comes straight off the directive (the
/// relay-authoritative departing slot).
///
/// Also stamps the session's correlation ids, if this relay's descriptor ever
/// carried them ([`DecisionMakers::set_session_refs`]) — `None` for a
/// standalone relay, a coordinator that predates the fields, or a session this
/// relay never received a descriptor for. Stamping them here (rather than
/// leaving the coordinator to look them up) is what makes the notice
/// self-describing: the descriptor a relay already applied survives a
/// coordinator restart even though the coordinator's own in-memory copy does
/// not.
fn departure_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    leave: &LeaveDirective,
) -> DepartureNotice {
    let slot = SlotId(leave.slot as u8);
    let refs = registry.session_refs(key);
    DepartureNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        kind: if leave.reason == LEAVE_REASON_DROPPED {
            DepartureKind::Dropped
        } else {
            DepartureKind::Left
        },
        reason: leave.reason,
        leave_seq: leave.leave_seq,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        // The result this slot reported before departing, folded into its
        // departure record (home-seeded, carried across the mesh). Embedding it
        // makes the departure webhook atomic terminal truth; `None` proves the
        // slot departed without ever reporting.
        result: registry.departure_result(key, slot),
    }
}

/// Builds the desync notice for a divergence the comparator just confirmed:
/// carries the sync ordinal + confirming frame, the majority/minority verdict,
/// and a wall-clock detection timestamp (unix epoch ms). Stamps the session's
/// `external_id` and each diverged slot's `external_ref` the same way (and from
/// the same store) as [`departure_notice`], so the notice is self-describing
/// across a coordinator restart. The timestamp is read here rather than in the
/// pure comparator, which holds no clock.
fn desync_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    divergence: &SyncDivergence,
) -> DesyncNotice {
    let refs = registry.session_refs(key);
    let detected_at_ms = now_ms();
    DesyncNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        sync_ordinal: divergence.sync_ordinal,
        game_frame: divergence.game_frame,
        detected_at_ms,
        no_majority: divergence.no_majority,
        diverged: divergence
            .diverged
            .iter()
            .map(|slot| DivergedSlot {
                slot: *slot,
                external_ref: refs.as_ref().and_then(|r| r.slots.get(slot).cloned()),
            })
            .collect(),
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
    }
}

/// Builds the standalone result notice from the retained result `echo` a slot
/// reported: the opaque payload byte-for-byte, the wall-clock arrival stamp, and
/// the relay's view of where the report landed in the game timeline — all
/// captured into the echo by [`record_result`] when the report arrived, and the
/// same echo that will later ride the slot's departure. Stamps the session's
/// `external_id` and the slot's `external_ref` the same way (and from the same
/// store) as [`departure_notice`], so the notice is self-describing across a
/// coordinator restart.
fn result_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    echo: ResultEcho,
) -> ResultNotice {
    let refs = registry.session_refs(key);
    ResultNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        payload: echo.payload,
        arrival_ms: echo.arrival_ms,
        session_frame: echo.session_frame,
        slot_frame: echo.slot_frame,
    }
}

/// The current wall clock in unix epoch milliseconds — a result report's or a
/// desync's `arrival_ms`/`detected_at_ms` stamp.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Creates a decision-maker for `key`, or reconciles an existing one with the
/// coordinator's current `bounds` and the freshly computed `authority`. Called
/// on every descriptor push: the relay set serving a session changes as
/// players join and leave, and the authority verdict (and bounds) must follow
/// the descriptor rather than stay frozen at whatever the first push said --
/// a frozen verdict could leave a session with two authorities or none.
/// Condition history survives a re-push (see [`DecisionMaker::sync`]).
///
/// A promotion can *freshly derive* a leave for a departure no relay ever
/// cached before (the directive never escaped the dead authority) -- that is
/// as much a first insert into this relay's cache as `decide_leave`/
/// `observe_leave` firing one, so it fires exactly one departure notice too;
/// a verbatim re-broadcast of an already-cached directive fires nothing (the
/// relay that cached it first already reported it).
#[must_use]
pub fn sync_maker(
    registry: &DecisionMakers,
    key: &SessionKey,
    bounds: BufferBounds,
    authority: Authority,
) -> Vec<LeaveDirective> {
    use std::collections::hash_map::Entry;
    let (leaves, fresh) = {
        let mut makers = registry.lock();
        match makers.entry(key.clone()) {
            Entry::Occupied(mut existing) => existing.get_mut().sync(bounds, authority),
            Entry::Vacant(vacant) => {
                vacant.insert(DecisionMaker::new(
                    key.clone(),
                    bounds,
                    ControlLaw::default(),
                    authority,
                ));
                (Vec::new(), Vec::new())
            }
        }
    };
    for leave in &fresh {
        registry.notify_departure(departure_notice(registry, key, leave));
    }
    leaves
}

/// Applies a fresh authority verdict to a session's decision-maker, if the
/// relay has one, logging a change of authority and returning the synced leaves a
/// *promotion* must (re)broadcast (empty on any other transition, or when no
/// maker exists). The presence-driven handoff path: called when a relay's
/// live-player report flips some relay's liveness, between (and independent of)
/// descriptor pushes. A no-op when no maker exists — a maker is only ever created
/// by a descriptor, which carries the bounds a maker cannot exist without. The
/// caller pushes the returned leaves down local survivors and across the mesh.
///
/// A promotion that freshly derives a leave (no relay ever cached this
/// departure's directive before) fires exactly one departure notice for it,
/// same as `decide_leave`/`observe_leave`; a verbatim re-broadcast of an
/// already-cached directive fires nothing.
#[must_use]
pub fn set_authority(
    registry: &DecisionMakers,
    key: &SessionKey,
    authority: Authority,
) -> Vec<LeaveDirective> {
    let (leaves, fresh) = {
        let mut guard = registry.lock();
        let Some(maker) = guard.get_mut(key) else {
            return Vec::new();
        };
        if maker.authority == authority {
            return Vec::new();
        }
        maker.set_authority(authority)
    };
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        authority = ?authority,
        rebroadcast_leaves = leaves.len(),
        "presence moved the session's buffer authority",
    );
    for leave in &fresh {
        registry.notify_departure(departure_notice(registry, key, leave));
    }
    leaves
}

/// Records a slot departure into the session's decision-maker, if the relay has
/// one, so a later authority promotion can re-derive the leave. Every relay calls
/// this on a departure it learns of (its own home client, or a peer's
/// `SlotDeparted`). A no-op when no maker exists.
pub fn record_departure(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    last_frame: Option<GameFrameCount>,
    reachable: Option<u32>,
    result: Option<ResultEcho>,
    reason: u32,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.record_departure(slot, last_frame, reachable, result, reason);
    }
}

/// Records a client's end-of-game result report into the session's
/// decision-maker, firing exactly one result notice up the coordinator connection
/// on the first report from `slot`. A repeat from the same slot inserts nothing
/// and fires nothing. A no-op when no maker exists (a session this relay does not
/// serve). `slot` is the authenticated connection's slot the report arrived on,
/// never a value from the payload; `payload` is forwarded opaque.
///
/// The retained result echo captures the relay's own view of *when* the report
/// landed — a wall-clock arrival stamp plus the session's consensus frame and the
/// reporting slot's newest observed frame at arrival, all read here while the
/// maker is locked (the report does not retire the slot, so its framed history is
/// still live). The same echo is retained on the maker so the slot's later
/// departure embeds it into the departure notice; the standalone notice fired
/// here is the early, redundant delivery.
pub fn record_result(registry: &DecisionMakers, key: &SessionKey, slot: SlotId, payload: Vec<u8>) {
    let echo = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return;
        };
        let echo = ResultEcho {
            payload,
            arrival_ms: now_ms(),
            session_frame: maker.session_frame().map(|f| f.0),
            slot_frame: maker.slot_frame(slot).map(|f| f.0),
        };
        if !maker.record_result(slot, echo.clone()) {
            return;
        }
        echo
    };
    registry.notify_result(result_notice(registry, key, slot, echo));
}

/// The end-of-game result `slot` reported for `key`, if the relay has a maker
/// that retained one. Read on the reporting slot's home relay when the slot
/// departs — *before* the departure is recorded — to seed both the departure
/// record and the `SlotDeparted` frame the peers receive with the retained
/// result. `None` when no maker exists or the slot never reported.
pub fn result_for(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> Option<ResultEcho> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.result_for(slot).cloned())
}

/// The reachability ceiling for a leave's apply frame at `slot`'s departure —
/// the highest game frame every surviving slot has provably executed (see
/// [`DecisionMaker::reachable_frame`]). Read on the departing slot's home relay,
/// *before* the departure is recorded (which retires the slot's live state), to
/// fill both the departure record and the `SlotDeparted` frame the peers
/// receive, so every relay clamps to the identical value. `None` when no maker
/// exists or no survivor has framed history yet.
pub fn reachable_frame(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> Option<u32> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.reachable_frame(slot))
}

/// Caches a synced leave a peer relay's authority authored (received off the
/// mesh) into the session's decision-maker, if the relay has one, so a later
/// promotion re-broadcasts it verbatim. A no-op when no maker exists.
///
/// On a **first insert** for the slot — the leave newly entering this relay's
/// cache — fires one departure notice up the coordinator connection. A redundant
/// copy (a second mesh path, a reconcile-on-join re-send) inserts nothing and
/// fires nothing, so the coordinator sees at most one notice per relay per slot.
pub fn observe_leave(registry: &DecisionMakers, key: &SessionKey, leave: &LeaveDirective) {
    let inserted = match registry.lock().get_mut(key) {
        Some(maker) => maker.observe_leave(leave),
        None => false,
    };
    if inserted {
        registry.notify_departure(departure_notice(registry, key, leave));
    }
}

/// The last game frame observed on `slot`'s validated turns for the session, if
/// the relay has a maker. Read at a departure trigger — before the departure is
/// recorded, which retires the slot's live state — to fill a `SlotDeparted`'s
/// `last_frame`.
pub fn slot_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
) -> Option<GameFrameCount> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.slot_frame(slot))
}

/// Fires a session-closed notice up the coordinator connection: this relay has
/// torn down its last local state for `key`. A no-op on a standalone relay (no
/// notifier). Fire it *after* the session's departures have already been emitted
/// on the same channel, so the coordinator's in-order dispatch treats a delivered
/// close as proof no earlier notice for the session is still in flight.
pub fn session_closed(registry: &DecisionMakers, key: &SessionKey) {
    registry.notify_session_closed(key.tenant.clone(), key.session);
}

/// This relay's known leave state for `key` — every recorded departure and every
/// cached leave — for re-announcing to a freshly (re)joined mesh link. Empty when
/// no maker exists. See [`DecisionMaker::leave_reconcile`].
#[allow(clippy::type_complexity)]
pub fn leave_reconcile(
    registry: &DecisionMakers,
    key: &SessionKey,
) -> (
    Vec<(
        SlotId,
        Option<GameFrameCount>,
        Option<u32>,
        Option<ResultEcho>,
        u32,
    )>,
    Vec<LeaveDirective>,
) {
    registry
        .lock()
        .get(key)
        .map(|maker| maker.leave_reconcile())
        .unwrap_or_default()
}

/// Removes a session's decision-maker (the session has ended). Idempotent.
/// Also forgets the session's correlation ids, so the refs map doesn't outlive
/// the sessions it describes.
pub fn deregister_maker(registry: &DecisionMakers, key: &SessionKey) {
    registry.lock().remove(key);
    registry.forget_session_refs(key);
}

/// Records a `game_frame_count` observed on one of `slot`'s validated turns,
/// if the relay has a maker for the session. The per-slot observations are
/// what the session's consensus coordinate (the minimum across slots) is
/// computed from, so this is called for every framed turn a link forwards. A
/// no-op when no maker exists (no policy pushed yet).
pub fn observe_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    frame: GameFrameCount,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.observe_frame(slot, frame);
    }
}

/// The seq-aware sibling of [`observe_frame`]: records the same per-slot frame
/// **and** the turn's transport seq into the slot's bounded frame history, so a
/// later leave can clamp its apply frame to a survivor-reachable ceiling (see
/// [`DecisionMaker::reachable_frame`]). **Every production frame-observation on
/// the leave path calls this**, never the seq-less `observe_frame` (which is
/// test-only), so the clamp always has history to work from. A no-op when no
/// maker exists.
pub fn observe_turn_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    seq: u64,
    frame: GameFrameCount,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.observe_turn_frame(slot, seq, frame);
    }
}

/// Records the session's observer slots (from the coordinator descriptor) into
/// the decision-maker, if the relay has one. Excludes them from the desync
/// comparator. A no-op when no maker exists. Called on every descriptor apply.
pub fn set_observers(registry: &DecisionMakers, key: &SessionKey, observers: HashSet<SlotId>) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.set_observers(observers);
    }
}

/// Feeds one forwarded turn's commands into the session's desync comparator, if
/// the relay has a maker, and fires a [`DesyncNotice`] up the coordinator
/// connection when a divergence is confirmed. Called at the same turn choke
/// points as [`observe_frame`], for every turn (client edge, mesh hop, oversize
/// divert). A cheap no-op unless this relay is the session authority: the maker's
/// [`observe_sync`](DecisionMaker::observe_sync) returns immediately for a
/// non-authority relay before walking any bytes.
///
/// `game_frame` is the turn's `game_frame_count`; `commands` its raw command
/// bytes (already validated at the ingress edge — this walk is the authority's
/// own independent parse, not a trust in a peer's).
pub fn observe_sync(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    game_frame: Option<u32>,
    commands: &[u8],
) {
    let divergence = match registry.lock().get_mut(key) {
        Some(maker) => maker.observe_sync(slot, game_frame, commands),
        None => None,
    };
    if let Some(divergence) = divergence {
        log_desync(key, &divergence);
        registry.notify_desync(desync_notice(registry, key, &divergence));
    }
}

/// Feeds one home-client `conditions` sample into the session's decision-maker
/// if the relay has one, logging any decision it fires. Returns the
/// [`Decision`], if any — the broadcast the decision queues is emitted later by
/// [`active_directive`] at fan-out. A no-op returning `None` when no maker
/// exists for the session (no policy pushed yet), so a slot link can call it
/// unconditionally.
pub fn ingest_local_conditions(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &LinkConditions,
) -> Option<Decision> {
    let decision = registry.lock().get_mut(key)?.ingest_local(conditions)?;
    log_decision(key, decision);
    Some(decision)
}

/// Feeds a peer relay's `conditions` sidecar (reached over a mesh hop of
/// `mesh_rtt_us`) into the session's decision-maker if the relay has one,
/// logging any decision it fires. Returns the [`Decision`], if any. A no-op
/// returning `None` when no maker exists for the session.
pub fn ingest_remote_conditions(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &LinkConditions,
    mesh_rtt_us: u32,
) -> Option<Decision> {
    let decision = registry
        .lock()
        .get_mut(key)?
        .ingest_remote(conditions, mesh_rtt_us)?;
    log_decision(key, decision);
    Some(decision)
}

/// The buffer directive to stamp onto a turn forwarded for this session, if
/// the relay is the authority and has a change it is still broadcasting.
/// Returns `None` — the common case — when no change is pending, the change
/// has been applied everywhere, or no maker exists for the session.
pub fn active_directive(registry: &DecisionMakers, key: &SessionKey) -> Option<BufferDirective> {
    registry.lock().get_mut(key)?.active_directive()
}

/// Decides a synced player-leave for `slot` on the session's authority relay and
/// queues it for broadcast, logging it. Returns the queued [`LeaveDirective`], or
/// `None` when this relay isn't the authority / has no maker / can't schedule yet
/// (see [`DecisionMaker::decide_leave`]). Records the departure as a side effect
/// (merging the slot's own frame into its record and retiring its live state),
/// so the apply frame derives the same way no matter which relay decides.
pub fn decide_leave(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
) -> Option<LeaveDirective> {
    let directive = registry.lock().get_mut(key)?.decide_leave(slot, reason)?;
    log_leave(key, &directive);
    // `decide_leave` returns `Some` only on the authority's first decision for
    // the slot (it dedups internally), so this is the one departure notice the
    // authoring relay sends for it.
    registry.notify_departure(departure_notice(registry, key, &directive));
    Some(directive)
}

/// Records the `decision_seq` of an authority-stamped directive this relay is
/// forwarding, if the relay has a maker for the session, so a later promotion
/// to authority continues the session's decision numbering (see
/// [`DecisionMaker::observe_directive`]). A no-op when no maker exists.
pub fn observe_directive(registry: &DecisionMakers, key: &SessionKey, seq: u32) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.observe_directive(seq);
    }
}

/// Logs a buffer change the authority just decided — the observable that the
/// runtime decision-maker is live and what it chose, correlated by session.
fn log_decision(key: &SessionKey, decision: Decision) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        buffer = decision.buffer.0,
        apply_at_frame = decision.applied_frame.0,
        "latency-buffer decision",
    );
}

/// Logs a synced player-leave the authority just decided — the observable that a
/// coordinated leave is being broadcast, and which slot at which frame.
fn log_leave(key: &SessionKey, leave: &LeaveDirective) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = leave.slot,
        reason = leave.reason,
        apply_at_frame = leave.apply_at_frame,
        leave_seq = leave.leave_seq,
        "synced player-leave decision",
    );
}

/// Logs a desync the comparator just confirmed — the observable that the relay
/// detected a divergence, at which sync ordinal/frame, and who diverged. A warn
/// because a desync is an abnormal, result-affecting event.
fn log_desync(key: &SessionKey, divergence: &SyncDivergence) {
    let diverged: Vec<u8> = divergence.diverged.iter().map(|slot| slot.0).collect();
    tracing::warn!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        sync_ordinal = divergence.sync_ordinal,
        game_frame = divergence.game_frame,
        no_majority = divergence.no_majority,
        ?diverged,
        "relay-side desync detected",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;
    use rally_point_proto::messages::SlotConditions;

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("sb-test").unwrap(),
            session: SessionId(1),
        }
    }

    fn bounds(min: u32, max: u32) -> BufferBounds {
        BufferBounds { min, max }
    }

    fn law() -> ControlLaw {
        ControlLaw::default()
    }

    fn conditions(slot: u8, rtt_us: u32, lost: u64, sent: u64) -> LinkConditions {
        LinkConditions {
            slots: vec![SlotConditions {
                slot: slot as u32,
                rtt_us,
                lost_packets: lost,
                sent_packets: sent,
            }],
        }
    }

    fn multi_conditions(slots: &[(u8, u32, u64, u64)]) -> LinkConditions {
        LinkConditions {
            slots: slots
                .iter()
                .map(|&(s, rtt, lost, sent)| SlotConditions {
                    slot: s as u32,
                    rtt_us: rtt,
                    lost_packets: lost,
                    sent_packets: sent,
                })
                .collect(),
        }
    }

    /// One slot-link packet's worth of input: frames observed off the packet's
    /// validated turns, then the sampled conditions ingested.
    fn ingest_at(maker: &mut DecisionMaker, c: &LinkConditions, frame: u32) -> Option<Decision> {
        for slot in &c.slots {
            maker.observe_frame(SlotId(slot.slot as u8), GameFrameCount(frame));
        }
        maker.ingest_local(c)
    }

    /// One mesh datagram's worth of input: frames observed off the forwarded
    /// turns, then the peer's conditions sidecar ingested with its mesh hop.
    fn ingest_remote_at(
        maker: &mut DecisionMaker,
        c: &LinkConditions,
        mesh_rtt_us: u32,
        frame: u32,
    ) -> Option<Decision> {
        for slot in &c.slots {
            maker.observe_frame(SlotId(slot.slot as u8), GameFrameCount(frame));
        }
        maker.ingest_remote(c, mesh_rtt_us)
    }

    // -- Target formula --

    /// At 150ms RTT, 0% loss: target == ceil(150000/41666.67) + 0 = 4.
    #[test]
    fn target_at_150ms_zero_loss() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert_eq!(maker.target(), Some(4));
    }

    /// At 150ms RTT, 5% loss: loss_risk = 0.05 ** 150000 = 7500us.
    /// Separated: ceil(150000/41666.67) + ceil(7500/41666.67) = 4 + 1 = 5.
    #[test]
    fn target_loss_recovery_is_quantized_to_whole_turns() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        let _ = ingest_at(&mut maker, &conditions(0, 150_000, 5, 200), 2);
        assert_eq!(maker.target(), Some(5));
    }

    /// At 50ms RTT, 0% loss: target = ceil(50000/41666.67) = 2.
    #[test]
    fn target_at_low_latency() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
        assert_eq!(maker.target(), Some(2));
    }

    /// At 10ms RTT: target = ceil(10000/41666.67) = 1. The ceil naturally
    /// gives 1 for any positive RTT -- no separate floor.
    #[test]
    fn target_floor_falls_out_of_ceil() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 10_000, 0, 100), 1);
        assert_eq!(maker.target(), Some(1));
    }

    /// No RTT measurement (rtt_us == 0): target is None (hold).
    #[test]
    fn target_none_when_no_rtt() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 0, 0, 100), 1);
        assert_eq!(maker.target(), None);
    }

    // -- Pairwise path --

    /// Two slots at 100ms and 200ms: path = (200000 + 100000) / 2 = 150000.
    #[test]
    fn worst_pair_path_uses_two_highest_rtts() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(
            &mut maker,
            &multi_conditions(&[(0, 100_000, 0, 100), (1, 200_000, 0, 100)]),
            1,
        );
        assert_eq!(maker.target(), Some(4));
    }

    /// One outlier at 300ms, rest at 20ms: path = (300000 + 20000) / 2 = 160000.
    #[test]
    fn single_outlier_does_not_over_provision() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(
            &mut maker,
            &multi_conditions(&[
                (0, 20_000, 0, 100),
                (1, 300_000, 0, 100),
                (2, 20_000, 0, 100),
            ]),
            1,
        );
        assert_eq!(maker.target(), Some(4));
    }

    // -- Mesh hop --

    /// A remote slot's effective RTT includes the mesh hop.
    #[test]
    fn mesh_hop_increases_target_for_cross_relay_paths() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
        ingest_remote_at(&mut maker, &conditions(1, 50_000, 0, 100), 100_000, 2);
        // eff_local = 50000, eff_remote = 150000.
        // path = (150000 + 50000) / 2 = 100000. target = ceil(100000/41666.67) = 3.
        assert_eq!(maker.target(), Some(3));
    }

    /// Without the mesh hop, two 50ms slots would give target 2.
    #[test]
    fn mesh_hop_adds_turns_above_same_relay_baseline() {
        let mut local = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(
            &mut local,
            &multi_conditions(&[(0, 50_000, 0, 100), (1, 50_000, 0, 100)]),
            1,
        );
        let local_target = local.target().unwrap();

        let mut meshed = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut meshed, &conditions(0, 50_000, 0, 100), 1);
        ingest_remote_at(&mut meshed, &conditions(1, 50_000, 0, 100), 100_000, 2);
        let meshed_target = meshed.target().unwrap();

        assert!(meshed_target > local_target);
    }

    // -- Loss on high-latency links --

    /// Same 20% loss on 50ms vs 300ms: the high-latency link needs more turns.
    #[test]
    fn loss_on_high_latency_link_adds_more_turns() {
        let mut low = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut low, &conditions(0, 50_000, 0, 100), 1);
        ingest_at(&mut low, &conditions(0, 50_000, 20, 200), 2);
        let low_target = low.target().unwrap();

        let mut high = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut high, &conditions(0, 300_000, 0, 100), 1);
        ingest_at(&mut high, &conditions(0, 300_000, 20, 200), 2);
        let high_target = high.target().unwrap();

        assert!(high_target > low_target);
        assert_eq!(low_target, 3); // 2 + 1
        assert_eq!(high_target, 10); // 8 + 2
    }

    // -- Jitter awareness --

    /// The decision-maker uses the recent max RTT, not the smoothed mean.
    #[test]
    fn jitter_uses_recent_max_rtt() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        for frame in 1..=4 {
            ingest_at(&mut maker, &conditions(0, 100_000, 0, 100), frame);
        }
        ingest_at(&mut maker, &conditions(0, 200_000, 0, 100), 5);

        assert_eq!(maker.target(), Some(5));
    }

    /// Without the spike, the target would be lower.
    #[test]
    fn jitter_spike_raises_target_above_baseline() {
        let mut spiky = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        for frame in 1..=4 {
            ingest_at(&mut spiky, &conditions(0, 100_000, 0, 100), frame);
        }
        ingest_at(&mut spiky, &conditions(0, 200_000, 0, 100), 5);

        let mut stable = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        for frame in 1..=5 {
            ingest_at(&mut stable, &conditions(0, 100_000, 0, 100), frame);
        }

        assert!(spiky.target().unwrap() > stable.target().unwrap());
    }

    // -- Raise fast, lower slow (asymmetric dwell) --

    /// Raise jumps to the target immediately, not incrementally.
    #[test]
    fn raise_jumps_to_target() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert_eq!(d.unwrap().buffer, BufferSize(4));
        assert_eq!(maker.buffer(), BufferSize(4));
    }

    /// Lower decrements by one step, not to the target.
    #[test]
    fn lower_decrements_by_one_step() {
        let mut maker = DecisionMaker {
            buffer: BufferSize(5),
            ..DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay)
        };
        let d = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 1);
        assert_eq!(d.unwrap().buffer, BufferSize(4));
        assert_eq!(maker.buffer(), BufferSize(4));
    }

    // -- Asymmetric dwell: raises immediate, lowers gated --

    /// A raise fires immediately even within the dwell -- you can't dwell
    /// through a stall. A lower is suppressed until the dwell elapses.
    #[test]
    fn raise_fires_immediately_lower_gated_by_dwell() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // 150ms -> target 4. Raise to 4 at frame 1.
        let d1 = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert_eq!(d1.unwrap().buffer, BufferSize(4));

        // Conditions worsen at frame 2 (within 120-turn dwell). Raise fires
        // immediately -- no dwell on raises.
        let d2 = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 2);
        assert_eq!(
            d2.unwrap().buffer,
            BufferSize(8),
            "raise should fire immediately"
        );
        assert_eq!(maker.buffer(), BufferSize(8));

        // Conditions improve at frame 3 (within dwell from the raise at 2).
        // Lower is suppressed -- and the ring buffer still holds the 300ms
        // spike, so the target stays at 8 anyway.
        let d3 = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 3);
        assert_eq!(d3, None, "lower should be suppressed within dwell");
        assert_eq!(maker.buffer(), BufferSize(8));

        // Flush the 300ms spike from the ring buffer (32 samples) so the
        // recent max drops to 50ms. Frames 4--35.
        for frame in 4..=35 {
            let _ = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), frame);
        }
        // Now the target is 2 (50ms), but we're still within the dwell.
        assert_eq!(maker.target(), Some(2));

        // After the dwell (frame 2 + 120 = 122, so frame 123). Lower fires.
        let d4 = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 123);
        assert!(d4.is_some(), "lower should fire after dwell");
        assert_eq!(maker.buffer(), BufferSize(7));
    }

    /// Anti-flap: an oscillating target raises on the first worsening, then
    /// holds (lowers suppressed) through the dwell.
    #[test]
    fn anti_flap_raises_on_worsening_holds_on_improvement() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // 150ms -> target 4. Raise to 4 at frame 1.
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert_eq!(d.unwrap().buffer, BufferSize(4));

        // Target drops to 2 (50ms) at frame 2 -- lower suppressed.
        let d = ingest_at(&mut maker, &conditions(0, 50_000, 0, 100), 2);
        assert_eq!(d, None);

        // Target spikes to 8 (300ms) at frame 3 -- raise fires immediately.
        let d = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 3);
        assert_eq!(
            d.unwrap().buffer,
            BufferSize(8),
            "raise should fire despite dwell"
        );

        // The oscillation: one raise (to 4), one raise (to 8). No lowers.
        assert_eq!(maker.buffer(), BufferSize(8));
    }

    // -- Bounds clamping --

    /// Target exceeds max -> clamped to max.
    #[test]
    fn raise_clamps_to_max() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 3), law(), Authority::SelfRelay);
        let d = ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 1);
        assert_eq!(d.unwrap().buffer, BufferSize(3));
        assert_eq!(maker.buffer(), BufferSize(3));
    }

    /// Target below min -> clamped to min.
    #[test]
    fn lower_clamps_to_min() {
        let mut maker = DecisionMaker {
            buffer: BufferSize(3),
            ..DecisionMaker::new(key(), bounds(2, 20), law(), Authority::SelfRelay)
        };
        let d = ingest_at(&mut maker, &conditions(0, 10_000, 0, 100), 1);
        assert_eq!(d.unwrap().buffer, BufferSize(2));
        assert_eq!(maker.buffer(), BufferSize(2));
    }

    // -- Authority --

    /// A non-authority relay ingests conditions but makes no decision.
    #[test]
    fn non_authority_ingests_but_does_not_decide() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert_eq!(d, None, "non-authority makes no decision");
        assert_eq!(maker.session_frame(), Some(GameFrameCount(1)));
        assert_eq!(maker.target(), Some(4));
    }

    // -- Frame tracking --

    /// The session frame is the minimum of the per-slot observations -- the
    /// slowest participant's progress, which is what lockstep advances by.
    /// Each slot's own observation is monotonic.
    #[test]
    fn session_frame_is_the_minimum_across_slots() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        assert_eq!(maker.session_frame(), None, "no framed turn yet");

        maker.observe_frame(SlotId(0), GameFrameCount(10));
        assert_eq!(maker.session_frame(), Some(GameFrameCount(10)));

        maker.observe_frame(SlotId(1), GameFrameCount(4));
        assert_eq!(
            maker.session_frame(),
            Some(GameFrameCount(4)),
            "the slowest slot pins the coordinate",
        );

        // Per-slot observations are monotonic: an older frame arriving out of
        // order doesn't move a slot backward.
        maker.observe_frame(SlotId(1), GameFrameCount(3));
        assert_eq!(maker.session_frame(), Some(GameFrameCount(4)));

        maker.observe_frame(SlotId(1), GameFrameCount(12));
        assert_eq!(
            maker.session_frame(),
            Some(GameFrameCount(10)),
            "slot 0 is now the slowest",
        );
    }

    /// One slot claiming an absurd frame can't poison the coordinate: the
    /// minimum stays with the honest slots, so decision scheduling and the
    /// dwell clock are unaffected by a hostile client's `game_frame_count`.
    #[test]
    fn an_inflated_frame_claim_does_not_move_the_session_frame() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(100));
        maker.observe_frame(SlotId(1), GameFrameCount(u32::MAX));
        assert_eq!(maker.session_frame(), Some(GameFrameCount(100)));

        // A decision still schedules against the honest coordinate, not the
        // inflated claim: raise 0 -> 4 at frame 101 applies at 101 + 4 + 3.
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 101).unwrap();
        assert_eq!(d.applied_frame, GameFrameCount(101 + 4 + APPLY_HORIZON));
    }

    /// The applied frame is a horizon ahead of the session frame: the buffer
    /// span (covering observation lag and client spread, both of which scale
    /// with the cushion) plus the fixed delivery margin.
    #[test]
    fn applied_frame_is_a_buffer_spanned_horizon_ahead() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Raise 0 -> 4 at frame 50: span = max(0, 4) = 4.
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 50).unwrap();
        assert_eq!(d.applied_frame, GameFrameCount(50 + 4 + APPLY_HORIZON));
        assert!(d.applied_frame.0 > 50);
    }

    // -- Loss differencing --

    /// A stale sidecar (non-monotonic counters) produces no negative loss.
    #[test]
    fn stale_sidecar_no_spurious_loss() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 50), 2);
        assert_eq!(maker.target(), Some(4));
        assert_eq!(d, None);
    }

    /// Regression: lossy interval THEN clean interval must drop the target.
    /// Raises fire immediately; the lower waits for the dwell.
    #[test]
    fn lossy_then_clean_interval_drops_target() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Baseline at frame 1 (raises to 4, sets the dwell clock).
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);

        // 50% loss at frame 22 (raise fires immediately -- no dwell on raises).
        // loss_risk = 0.5 ** 150000 = 75000. Target = 4 + 2 = 6.
        let d1 = ingest_at(&mut maker, &conditions(0, 150_000, 50, 200), 2);
        assert_eq!(d1.unwrap().buffer, BufferSize(6));

        // Clean interval at frame 3 (loss_risk = 0, target = 4). But this is a
        // lower, and we're within the 120-turn dwell from the raise at frame 2.
        let d2 = ingest_at(&mut maker, &conditions(0, 150_000, 50, 300), 3);
        assert_eq!(d2, None, "lower suppressed within dwell");
        assert_eq!(maker.target(), Some(4));

        // After the dwell (frame 2 + 120 = 122, so frame 123). Lower fires.
        let d3 = ingest_at(&mut maker, &conditions(0, 150_000, 50, 300), 123);
        assert!(d3.is_some(), "lower should fire after dwell");
        assert_eq!(maker.buffer(), BufferSize(5));
    }

    // -- Directive broadcast --

    /// A decision queues a directive that `active_directive` stamps onto every
    /// forwarded turn until the session frame reaches its apply frame -- then
    /// it retires: every slot has been observed past the frame, so the change
    /// is applied (or moot) everywhere.
    #[test]
    fn a_directive_is_stamped_until_the_session_passes_its_apply_frame() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // No decision yet: nothing to stamp.
        assert_eq!(maker.active_directive(), None);

        // 150ms -> raise to 4 at frame 10.
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 10).expect("a raise fires");
        let stamp = maker
            .active_directive()
            .expect("a decision queues a directive");
        assert_eq!(stamp.buffer_turns, 4);
        assert_eq!(stamp.apply_at_frame, d.applied_frame.0);
        assert_eq!(stamp.decision_seq, 1);

        // Every forwarded turn carries it while the session hasn't reached the
        // apply frame -- there is no fixed budget for a quiet spell to exhaust.
        for _ in 0..100 {
            assert_eq!(maker.active_directive(), Some(stamp));
        }

        // The slowest slot passes the apply frame: the directive retires.
        maker.observe_frame(SlotId(0), GameFrameCount(d.applied_frame.0));
        assert_eq!(maker.active_directive(), None, "applied everywhere");
        assert_eq!(maker.active_directive(), None, "and stays retired");
    }

    /// The broadcast outlives a one-sided stretch of traffic: while one slot
    /// is stalled, the session frame (the minimum) doesn't advance, so the
    /// directive keeps stamping every turn the other slot produces until the
    /// stalled slot is back and past the apply frame.
    #[test]
    fn a_directive_outlives_a_one_sided_stall() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(10));
        maker.observe_frame(SlotId(1), GameFrameCount(10));
        // Slot 1's link degrades (300ms): raise to 8, applied at 10 + 8 + 3.
        let d = ingest_at(&mut maker, &conditions(1, 300_000, 0, 100), 10).expect("a raise fires");

        // Slot 0 keeps producing turns well past the apply frame while slot 1
        // is stalled. The session frame stays pinned at the stalled slot, so
        // every one of slot 0's forwarded turns still carries the stamp.
        for frame in 11..(d.applied_frame.0 + 50) {
            maker.observe_frame(SlotId(0), GameFrameCount(frame));
            assert!(maker.active_directive().is_some(), "still broadcasting");
        }

        // Slot 1 recovers and passes the apply frame: the directive retires.
        maker.observe_frame(SlotId(1), GameFrameCount(d.applied_frame.0));
        assert_eq!(maker.active_directive(), None);
    }

    /// A newer decision supersedes an older still-broadcasting one, and its
    /// higher `decision_seq` is what lets clients rank interleaved copies.
    #[test]
    fn a_new_decision_supersedes_a_still_broadcasting_one() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        let first = maker.active_directive().expect("the first raise queues");
        assert_eq!(first.buffer_turns, 4);
        assert_eq!(first.decision_seq, 1);

        // Conditions worsen: a raise to 8 fires, replacing the pending directive.
        ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 2);
        let second = maker
            .active_directive()
            .expect("the new directive is pending");
        assert_eq!(second.buffer_turns, 8, "the latest buffer wins");
        assert!(
            second.decision_seq > first.decision_seq,
            "copies of both may interleave on the wire; the seq ranks them",
        );
    }

    /// A non-authority relay makes no decision, so it never has a directive to
    /// stamp -- it only forwards the authority's already-stamped turns.
    #[test]
    fn a_non_authority_never_stamps_a_directive() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        // It ingests conditions (and would compute a target) but makes no decision.
        ingest_at(&mut maker, &conditions(0, 300_000, 0, 100), 1);
        assert!(maker.target().is_some(), "it still tracks conditions");
        assert_eq!(maker.active_directive(), None, "but never stamps");
    }

    /// A held decision (target unchanged, or a dwell-suppressed lower) queues
    /// no directive -- only an actual buffer change is broadcast.
    #[test]
    fn a_held_decision_queues_no_directive() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Raise to 4, then let the session pass the apply frame so the
        // directive retires and nothing is pending.
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
        maker.observe_frame(SlotId(0), GameFrameCount(d.applied_frame.0));
        assert_eq!(maker.active_directive(), None);

        // Same conditions again: target unchanged, no decision, nothing queued.
        let held = ingest_at(
            &mut maker,
            &conditions(0, 150_000, 0, 100),
            d.applied_frame.0 + 1,
        );
        assert_eq!(held, None, "target unchanged holds");
        assert_eq!(maker.active_directive(), None, "a hold queues no directive");
    }

    // -- Slot removal --

    /// `remove_slot` clears a departing client's history.
    #[test]
    fn remove_slot_clears_history() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
        assert!(maker.slots.contains_key(&SlotId(0)));
        assert!(maker.target().is_some());
        maker.remove_slot(SlotId(0));
        assert!(!maker.slots.contains_key(&SlotId(0)));
        assert_eq!(maker.target(), None, "no slots means no target");
    }

    // -- Registry --

    /// `sync_maker` creates on the first push and reconciles bounds and
    /// authority on a re-push -- the descriptor is declarative, so who decides
    /// follows the current relay set instead of staying frozen at creation.
    #[test]
    fn sync_maker_reconciles_bounds_and_authority_on_a_repush() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        {
            let makers = registry.lock();
            let maker = makers.get(&k).unwrap();
            assert_eq!(maker.bounds, bounds(0, 5));
            assert_eq!(maker.authority, Authority::SelfRelay);
        }

        // A lower-id relay joined the session: this relay is no longer the
        // authority, and the coordinator widened the bounds.
        let _ = sync_maker(&registry, &k, bounds(0, 99), Authority::Peer);
        let makers = registry.lock();
        let maker = makers.get(&k).unwrap();
        assert_eq!(maker.bounds, bounds(0, 99), "bounds follow the descriptor");
        assert_eq!(
            maker.authority,
            Authority::Peer,
            "authority follows the current relay set",
        );
    }

    /// A relay demoted by a re-push stops broadcasting: only the authority
    /// stamps, so its pending directive is dropped -- while its condition
    /// history survives (it describes the links, not the descriptor).
    #[test]
    fn losing_authority_drops_the_pending_directive_but_keeps_history() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        {
            let mut makers = registry.lock();
            let maker = makers.get_mut(&k).unwrap();
            ingest_at(maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
        }
        assert!(active_directive(&registry, &k).is_some());

        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        assert_eq!(
            active_directive(&registry, &k),
            None,
            "a demoted relay stops stamping",
        );
        let makers = registry.lock();
        assert!(
            makers.get(&k).unwrap().target().is_some(),
            "condition history survives the demotion",
        );
    }

    /// `deregister_maker` removes a session's decision-maker.
    #[test]
    fn deregister_maker_removes_session() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        assert!(registry.lock().contains_key(&k));
        deregister_maker(&registry, &k);
        assert!(!registry.lock().contains_key(&k));
    }

    // -- Departure notifier --

    /// Unwraps the next queued notice as a departure, panicking on anything else.
    /// The leave-path tests only ever expect departures on the shared notice
    /// channel, so this keeps their assertions reading against `DepartureNotice`.
    fn recv_departure(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<RelayNotice>,
    ) -> DepartureNotice {
        match rx.try_recv().expect("a queued notice") {
            RelayNotice::Departure(notice) => notice,
            RelayNotice::Desync(_) => panic!("expected a departure notice, got a desync"),
            RelayNotice::Result(_) => panic!("expected a departure notice, got a result"),
            RelayNotice::SessionClosed { .. } => {
                panic!("expected a departure notice, got a session-closed")
            }
        }
    }

    /// Deciding a leave on the authority fires exactly one departure notice for
    /// the slot, classified from the reason; a duplicate signal for the same slot
    /// decides nothing and so fires no second notice.
    #[test]
    fn decide_leave_fires_one_departure_notice_on_the_authority() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        // A framed turn from slot 0 gives decide_leave a basis to schedule.
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(50));

        let leave = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("a leave is decided");
        let notice = recv_departure(&mut rx);
        assert_eq!(notice.tenant, k.tenant);
        assert_eq!(notice.session, k.session);
        assert_eq!(notice.slot, SlotId(1));
        assert_eq!(notice.kind, DepartureKind::Dropped, "0x40000006 is a drop");
        assert_eq!(notice.reason, DROPPED);
        assert_eq!(notice.leave_seq, leave.leave_seq);
        assert!(rx.try_recv().is_err(), "just the one");

        // A duplicate departure signal for the slot decides nothing (already
        // cached), so no second notice fires.
        assert_eq!(decide_leave(&registry, &k, SlotId(1), DROPPED), None);
        assert!(
            rx.try_recv().is_err(),
            "no re-fire for an already-decided slot",
        );
    }

    /// A non-authority relay observing a peer authority's leave off the mesh
    /// fires exactly one notice on the first insert, classified "left" for a
    /// non-drop reason; a redundant re-observe (a second mesh path or a
    /// reconcile-on-join re-send) fires nothing.
    #[test]
    fn observe_leave_fires_one_departure_notice_on_first_insert() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        let leave = LeaveDirective {
            slot: 2,
            reason: 3,
            apply_at_frame: 90,
            leave_seq: 7,
        };
        observe_leave(&registry, &k, &leave);
        let notice = recv_departure(&mut rx);
        assert_eq!(notice.slot, SlotId(2));
        assert_eq!(
            notice.kind,
            DepartureKind::Left,
            "reason 3 is a clean leave"
        );
        assert_eq!(notice.reason, 3);
        assert_eq!(notice.leave_seq, 7);
        assert!(rx.try_recv().is_err());

        // A redundant copy is not a first insert, so it fires nothing.
        observe_leave(&registry, &k, &leave);
        assert!(rx.try_recv().is_err(), "no re-fire for a redundant copy");
    }

    /// With no notifier installed (a standalone relay), the leave path still
    /// works and firing is a silent no-op — nothing to send to.
    #[test]
    fn a_standalone_relay_decides_leaves_without_a_notifier() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(10));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
    }

    /// Promotion re-derivation must ALSO fire a departure notice, not just
    /// `decide_leave`/`observe_leave`. This is the case a 2-relay topology hits
    /// when the authority dies: the *only* other relay recorded the departure
    /// (off the mesh `SlotDeparted`) but, as a peer, never decided — so no
    /// directive ever entered *any* relay's cache and no notice ever fired for
    /// this slot anywhere. The freshly promoted relay's re-derivation is the
    /// first (and only) time this slot's directive enters a cache, so it must
    /// fire the one notice itself, with the recorded reason/kind — otherwise
    /// the departure is silently lost end to end.
    #[test]
    fn promotion_re_derivation_fires_exactly_one_departure_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        // Starts as a peer: it records a departure off a mesh `SlotDeparted` but
        // never decides (not the authority), so nothing is cached and nothing
        // fires yet.
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        record_departure(
            &registry,
            &k,
            SlotId(1),
            Some(GameFrameCount(50)),
            None,
            None,
            3,
        );
        assert!(rx.try_recv().is_err(), "recording alone fires nothing");

        // Promoted (the dead authority was the only other relay in the
        // topology): the departure has no cached directive anywhere, so this
        // relay derives it fresh — a first insert into its cache — and must
        // fire the one notice for it.
        let leaves = set_authority(&registry, &k, Authority::SelfRelay);
        assert_eq!(leaves.len(), 1, "the re-derived leave still broadcasts");

        let notice = recv_departure(&mut rx);
        assert_eq!(notice.slot, SlotId(1));
        assert_eq!(
            notice.kind,
            DepartureKind::Left,
            "reason 3 is a clean leave"
        );
        assert_eq!(notice.reason, 3);
        assert_eq!(notice.leave_seq, leaves[0].leave_seq);
        assert!(rx.try_recv().is_err(), "just the one");
    }

    /// The verbatim-re-broadcast half of the same rule: a directive already in
    /// the cache before promotion must NOT re-fire — the relay that cached it
    /// first (via `decide_leave` or `observe_leave`) already reported it, so a
    /// promotion re-announcing it verbatim would double-count the departure.
    #[test]
    fn promotion_does_not_refire_an_already_cached_directive() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        // Authored while the authority: decide_leave fires the one notice.
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        observe_frame(&registry, &k, SlotId(1), GameFrameCount(50));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
        assert!(rx.try_recv().is_ok(), "decide_leave fires the one notice");

        // Demoted, then re-promoted: the cached directive re-broadcasts
        // verbatim, not fresh — no second notice.
        let _ = set_authority(&registry, &k, Authority::Peer);
        let _ = set_authority(&registry, &k, Authority::SelfRelay);
        assert!(
            rx.try_recv().is_err(),
            "a verbatim re-broadcast of an already-cached leave must not re-fire",
        );
    }

    // -- Departure notice correlation ids --

    /// Once a coordinator descriptor's correlation ids are recorded
    /// (`set_session_refs`, what `apply_descriptor` does in production), the
    /// authoring relay's `decide_leave` stamps them into the notice.
    #[test]
    fn decide_leave_stamps_session_refs_into_the_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);

        registry.set_session_refs(
            &k,
            Some("game-99".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-7".to_owned())]),
        );

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let notice = recv_departure(&mut rx);
        assert_eq!(notice.external_id, Some("game-99".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-7".to_owned()));
    }

    /// `observe_leave` (the non-authority path) stamps the same way.
    #[test]
    fn observe_leave_stamps_session_refs_into_the_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);

        registry.set_session_refs(
            &k,
            Some("game-1".to_owned()),
            HashMap::from([(SlotId(2), "sb-user-2".to_owned())]),
        );

        let leave = LeaveDirective {
            slot: 2,
            reason: DROPPED,
            apply_at_frame: 88,
            leave_seq: 7,
        };
        observe_leave(&registry, &k, &leave);

        let notice = recv_departure(&mut rx);
        assert_eq!(notice.external_id, Some("game-1".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-2".to_owned()));
    }

    /// Promotion re-derivation stamps refs too — the exact 2-relay case where
    /// no relay ever cached the directive before, so this is the only notice
    /// that will ever fire for it, and it must not be refless just because it
    /// takes the re-derivation path rather than `decide_leave` directly.
    #[test]
    fn promotion_re_derivation_stamps_session_refs_into_the_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        registry.set_session_refs(
            &k,
            Some("game-2".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-9".to_owned())]),
        );
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        record_departure(
            &registry,
            &k,
            SlotId(1),
            Some(GameFrameCount(50)),
            None,
            None,
            3,
        );
        assert!(rx.try_recv().is_err(), "recording alone fires nothing");

        let _ = set_authority(&registry, &k, Authority::SelfRelay);
        let notice = recv_departure(&mut rx);
        assert_eq!(notice.external_id, Some("game-2".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-9".to_owned()));
    }

    /// With no refs ever recorded for the session (a standalone relay, or a
    /// coordinator that predates the fields), a notice simply carries `None` —
    /// not an error, and the coordinator's own fallback then applies.
    #[test]
    fn a_notice_carries_no_refs_when_none_were_ever_recorded() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let notice = recv_departure(&mut rx);
        assert!(notice.external_id.is_none());
        assert!(notice.external_ref.is_none());
    }

    // -- Result notifier --

    /// Unwraps the next queued notice as a result, panicking on anything else.
    fn recv_result(rx: &mut tokio::sync::mpsc::UnboundedReceiver<RelayNotice>) -> ResultNotice {
        match rx.try_recv().expect("a queued notice") {
            RelayNotice::Result(notice) => notice,
            other => panic!("expected a result notice, got {other:?}"),
        }
    }

    /// A slot's first end-of-game result fires exactly one result notice, stamped
    /// with the reporting slot, the opaque payload, and the relay's own frame
    /// view (the session's slowest-slot frame and the reporting slot's own newest
    /// frame). A second report from the same slot records nothing and fires no
    /// second notice — the one-report-per-slot dedup.
    #[test]
    fn record_result_fires_one_notice_per_slot() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        // Framed turns give the notice a session/slot frame basis: the session
        // coordinate is the slowest slot's frame (40), the reporting slot's own
        // is its newest (52).
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        observe_frame(&registry, &k, SlotId(1), GameFrameCount(52));

        record_result(&registry, &k, SlotId(1), vec![0xDE, 0xAD]);
        let notice = recv_result(&mut rx);
        assert_eq!(notice.tenant, k.tenant);
        assert_eq!(notice.session, k.session);
        assert_eq!(notice.slot, SlotId(1));
        assert_eq!(notice.payload, vec![0xDE, 0xAD]);
        assert_eq!(notice.session_frame, Some(40), "the slowest slot's frame");
        assert_eq!(
            notice.slot_frame,
            Some(52),
            "the reporting slot's own frame"
        );
        assert!(notice.arrival_ms > 0, "a wall-clock arrival stamp is set");
        assert!(rx.try_recv().is_err(), "just the one");

        // A second report from the same slot records nothing (first-writer-wins)
        // and so fires no second notice.
        record_result(&registry, &k, SlotId(1), vec![0xBE, 0xEF]);
        assert!(
            rx.try_recv().is_err(),
            "no re-fire for an already-reported slot",
        );
    }

    /// A result notice stamps the session's correlation ids the same way a
    /// departure does, so it is self-describing across a coordinator restart.
    #[test]
    fn record_result_stamps_session_refs_into_the_notice() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        registry.set_session_refs(
            &k,
            Some("game-3".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-5".to_owned())]),
        );

        record_result(&registry, &k, SlotId(1), vec![0x01]);
        let notice = recv_result(&mut rx);
        assert_eq!(notice.external_id, Some("game-3".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-5".to_owned()));
    }

    /// A result for a session this relay does not serve (no maker) records
    /// nothing and fires no notice, rather than erroring.
    #[test]
    fn record_result_on_a_relay_without_a_maker_is_a_no_op() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        record_result(&registry, &k, SlotId(0), vec![0x01]);
        assert!(rx.try_recv().is_err(), "no maker, so no notice");
    }

    /// The retained result is embedded into the slot's departure notice: after a
    /// slot reports, its later departure carries the same result (payload + stamps)
    /// the standalone notice did, so the departure webhook is atomic terminal
    /// truth. `result_for` exposes the retained echo for the home relay to seed the
    /// departure record with.
    #[test]
    fn a_reported_result_is_embedded_into_the_slots_departure_notice() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        observe_frame(&registry, &k, SlotId(1), GameFrameCount(52));

        // Slot 1 reports its result: the standalone result notice fires, and the
        // echo is retained.
        record_result(&registry, &k, SlotId(1), vec![0xDE, 0xAD]);
        let result_notice = recv_result(&mut rx);
        assert_eq!(result_notice.payload, vec![0xDE, 0xAD]);

        // Slot 1 departs — the home relay seeds the departure record with its
        // retained result, exactly as `announce_departure` does.
        let retained = result_for(&registry, &k, SlotId(1)).expect("the result is retained");
        record_departure(
            &registry,
            &k,
            SlotId(1),
            Some(GameFrameCount(52)),
            None,
            Some(retained),
            DROPPED,
        );
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let departure = recv_departure(&mut rx);
        let embedded = departure.result.expect("the departure carries the result");
        assert_eq!(embedded.payload, vec![0xDE, 0xAD]);
        assert_eq!(embedded.session_frame, Some(40));
        assert_eq!(embedded.slot_frame, Some(52));
        assert_eq!(embedded.arrival_ms, result_notice.arrival_ms);
    }

    /// A departure for a slot that never reported carries no embedded result —
    /// `None` is the proof there provably never was one.
    #[test]
    fn a_departure_without_a_reported_result_embeds_none() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let departure = recv_departure(&mut rx);
        assert!(
            departure.result.is_none(),
            "a slot that never reported has no embedded result",
        );
    }

    /// The embedded result folds first-non-`None`-wins, exactly like the
    /// reachability ceiling: whichever relay first seeds a result (the home) owns
    /// it, and a later `record_departure` — a re-announce, or the home's own
    /// `decide_leave` passing `None` — never clobbers it.
    #[test]
    fn an_embedded_result_folds_first_non_none_wins() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));

        // A peer's `SlotDeparted` carries the home-authored result first.
        let first = ResultEcho {
            payload: vec![0x01, 0x02],
            arrival_ms: 111,
            session_frame: Some(40),
            slot_frame: Some(50),
        };
        record_departure(
            &registry,
            &k,
            SlotId(1),
            Some(GameFrameCount(50)),
            None,
            Some(first.clone()),
            DROPPED,
        );

        // A later re-announce carrying a *different* result must not overwrite it.
        let second = ResultEcho {
            payload: vec![0x09],
            arrival_ms: 222,
            session_frame: Some(41),
            slot_frame: Some(51),
        };
        record_departure(
            &registry,
            &k,
            SlotId(1),
            Some(GameFrameCount(50)),
            None,
            Some(second),
            DROPPED,
        );

        // A `None`-carrying re-record (the home's own `decide_leave`) preserves it.
        record_departure(&registry, &k, SlotId(1), None, None, None, DROPPED);

        let kept = registry
            .lock()
            .get(&k)
            .unwrap()
            .departures
            .get(&SlotId(1))
            .unwrap()
            .result
            .clone();
        assert_eq!(kept, Some(first), "the first-seeded result wins");
    }

    /// `session_closed` fires one `SessionClosed` notice naming the tenant and
    /// session, so the coordinator can count serving relays that have torn down.
    #[test]
    fn session_closed_fires_a_session_closed_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        session_closed(&registry, &k);
        match rx.try_recv().expect("a queued notice") {
            RelayNotice::SessionClosed { tenant, session } => {
                assert_eq!(tenant, k.tenant);
                assert_eq!(session, k.session);
            }
            other => panic!("expected a session-closed notice, got {other:?}"),
        }
    }

    /// `set_session_refs` replaces rather than accumulates on a re-apply (a
    /// changed descriptor), and `deregister_maker` forgets a session's refs so
    /// the map doesn't outlive the session it describes.
    #[test]
    fn set_session_refs_replaces_on_reapply_and_deregister_forgets() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);

        registry.set_session_refs(
            &k,
            Some("game-old".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-old".to_owned())]),
        );
        // A re-applied descriptor with fresh refs replaces the old ones.
        registry.set_session_refs(
            &k,
            Some("game-new".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-new".to_owned())]),
        );

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
        let notice = recv_departure(&mut rx);
        assert_eq!(notice.external_id, Some("game-new".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-new".to_owned()));

        // Deregistering the maker also forgets the refs: a later decide_leave
        // on a freshly re-created maker for the same key sees none.
        deregister_maker(&registry, &k);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
        let notice2 = recv_departure(&mut rx);
        assert!(
            notice2.external_id.is_none(),
            "deregistering forgot the old session's refs",
        );
    }

    // -- Synced player-leave (decide_leave) --

    const DROPPED: u32 = 0x4000_0006;

    /// The apply frame is one past the departing slot's last observed frame.
    #[test]
    fn decide_leave_schedules_one_past_the_departed_slots_last_frame() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Two slots; the departing slot (1) is the furthest ahead.
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.observe_frame(SlotId(1), GameFrameCount(50));

        let d = maker
            .decide_leave(SlotId(1), DROPPED)
            .expect("a leave is scheduled");
        assert_eq!(d.slot, 1);
        assert_eq!(d.reason, DROPPED);
        assert_eq!(
            d.apply_at_frame, 51,
            "one past the departed slot's last frame"
        );
        assert_eq!(d.leave_seq, 1);
    }

    /// The departed slot's own last frame is the basis even when a fast survivor
    /// has stamped far ahead — a stalled survivor's simulation pins at
    /// `last_frame + 1`, so scheduling from the survivors' frames would put the
    /// leave past a frame the stalled ones can reach.
    #[test]
    fn decide_leave_schedules_from_the_departed_slot_not_the_survivors() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(80)); // a fast survivor
        maker.observe_frame(SlotId(1), GameFrameCount(30)); // the departing slot, behind
        let d = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(
            d.apply_at_frame, 31,
            "one past the departed slot's frame, not the survivor's"
        );
    }

    /// No framed turn observed anywhere (pre-game / lobby): nothing to schedule.
    #[test]
    fn decide_leave_holds_without_a_frame_basis() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        assert_eq!(maker.decide_leave(SlotId(1), DROPPED), None);
    }

    /// A slot that never produced a framed turn has no frame of its own; the
    /// session frame (the survivors' slowest) is the fallback basis.
    #[test]
    fn decide_leave_falls_back_to_the_session_frame_for_a_never_framed_slot() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(40)); // a framed survivor
        // Slot 1 departs having never framed a turn.
        let d = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(d.apply_at_frame, 41, "one past the session frame fallback");
    }

    // -- Leave apply-frame clamp (Finding A): an inflated departing frame must
    //    not schedule the leave past a frame the survivors can reach. Frames are
    //    stamped one-per-turn (`frame = 100 + seq`); a survivor legitimately
    //    *leads* the departing slot by the buffer depth before it stalls. --

    /// Feeds a run of framed turns for `slot`, one frame per turn (frame = 100 +
    /// seq), through the seq-aware production path that populates frame history.
    fn feed_turns(maker: &mut DecisionMaker, slot: u8, seqs: std::ops::RangeInclusive<u64>) {
        for seq in seqs {
            maker.observe_turn_frame(SlotId(slot), seq, GameFrameCount(100 + seq as u32));
        }
    }

    /// The exact production flow on the departing slot's home relay: read the
    /// last frame and the reachability ceiling, record the departure with both,
    /// then decide the (clamped) leave.
    fn home_decide_leave(maker: &mut DecisionMaker, slot: u8) -> LeaveDirective {
        let last = maker.slot_frame(SlotId(slot));
        let ceiling = maker.reachable_frame(SlotId(slot));
        maker.record_departure(SlotId(slot), last, ceiling, None, DROPPED);
        maker
            .decide_leave(SlotId(slot), DROPPED)
            .expect("a leave is scheduled")
    }

    /// Steady state, honest departure: the survivor leads by the buffer depth
    /// before stalling, so it has *provably executed* the departed slot's last
    /// frame — the ceiling equals `last_frame` and the clamp is a no-op (no
    /// regression from the pre-clamp behavior).
    #[test]
    fn decide_leave_does_not_clamp_an_honest_lead_ahead_departure() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        // Survivor slot 0 has run 6 turns (the buffer depth) past the departing
        // slot's last frame before stalling: seqs 0..=21 (frames 100..=121).
        feed_turns(&mut maker, 0, 0..=21);
        // The departing slot 1's last framed turn is seq 15 / frame 115.
        feed_turns(&mut maker, 1, 0..=15);
        assert_eq!(
            maker.reachable_frame(SlotId(1)),
            Some(115),
            "ceiling equals the departed slot's last executed frame",
        );
        let d = home_decide_leave(&mut maker, 1);
        assert_eq!(d.apply_at_frame, 116, "one past last_frame, unclamped");
    }

    /// Steady state, malicious departure: the slot stamps `u32::MAX` on its last
    /// turn then leaves. The ceiling comes from the honest survivor, not the
    /// claim, so the leave is clamped to a survivor-reachable frame instead of
    /// `u32::MAX` (which would have stalled every survivor forever).
    #[test]
    fn decide_leave_clamps_an_inflated_departing_frame_to_a_reachable_ceiling() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        feed_turns(&mut maker, 0, 0..=21); // honest survivor, leads by the buffer
        feed_turns(&mut maker, 1, 0..=14); // the malicious slot's honest prefix
        maker.observe_turn_frame(SlotId(1), 15, GameFrameCount(u32::MAX)); // the lie
        assert_eq!(
            maker.slot_frame(SlotId(1)),
            Some(GameFrameCount(u32::MAX)),
            "the slot claims u32::MAX",
        );
        assert_eq!(
            maker.reachable_frame(SlotId(1)),
            Some(115),
            "the ceiling comes from the survivor, not the departing slot's claim",
        );
        let d = home_decide_leave(&mut maker, 1);
        assert_eq!(
            d.apply_at_frame, 116,
            "clamped to a survivor-reachable frame, not u32::MAX + 1",
        );
    }

    /// A moderate (2x) inflation is clamped the same way — the ceiling doesn't
    /// depend on how large the lie is.
    #[test]
    fn decide_leave_clamps_a_moderate_inflation_too() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        feed_turns(&mut maker, 0, 0..=21);
        feed_turns(&mut maker, 1, 0..=14);
        maker.observe_turn_frame(SlotId(1), 15, GameFrameCount(230)); // ~2x the real ~115
        let d = home_decide_leave(&mut maker, 1);
        assert_eq!(
            d.apply_at_frame, 116,
            "clamped to the survivor-reachable ceiling"
        );
    }

    /// The exact case the audit's fallback would have reopened: an in-game but
    /// *early* (seq < buffer_max) inflated-frame departure. The threshold
    /// saturates to 0, so the ceiling is the survivor's earliest reachable frame
    /// — the leave is clamped, never left unclamped at `u32::MAX` (a stall).
    #[test]
    fn decide_leave_clamps_an_early_game_inflation_no_stall() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        feed_turns(&mut maker, 0, 0..=3); // only a few turns in (< buffer_max = 6)
        feed_turns(&mut maker, 1, 0..=2);
        maker.observe_turn_frame(SlotId(1), 3, GameFrameCount(u32::MAX));
        assert_eq!(
            maker.reachable_frame(SlotId(1)),
            Some(100),
            "early game: the ceiling is the earliest reachable frame",
        );
        let d = home_decide_leave(&mut maker, 1);
        assert_eq!(
            d.apply_at_frame, 101,
            "clamped — the unclamped fallback would have stalled at u32::MAX",
        );
    }

    /// An honest *early-game* departure takes a bounded, deterministic early-drop
    /// (the ceiling sits a few frames below `last_frame` because the buffer
    /// hasn't filled), never a stall: the apply frame is at or before the natural
    /// stall point, so every survivor can reach it.
    #[test]
    fn decide_leave_early_game_honest_departure_is_a_bounded_early_drop_no_stall() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        feed_turns(&mut maker, 0, 0..=3);
        feed_turns(&mut maker, 1, 0..=3); // honest last frame 103
        let d = home_decide_leave(&mut maker, 1);
        assert_eq!(
            d.apply_at_frame, 101,
            "a bounded few frames early (101 vs the honest 104)"
        );
        assert!(
            d.apply_at_frame <= 104,
            "at or before the natural stall (last_frame + 1) — reachable, never a stall",
        );
    }

    /// Determinism: the same home-authored departure record (an inflated
    /// `last_frame` plus the reachability ceiling) yields the *identical* clamped
    /// apply frame on the deciding authority and on a relay promoted to re-derive
    /// it — the agreement clients require (they dedup a leave by slot).
    #[test]
    fn the_clamped_apply_frame_is_reproduced_by_a_peer_and_a_promoted_authority() {
        let last = Some(GameFrameCount(u32::MAX));
        let ceiling = Some(115u32);

        // The authority deciding directly from the record.
        let mut authority = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay);
        authority.record_departure(SlotId(1), last, ceiling, None, DROPPED);
        let a = authority
            .decide_leave(SlotId(1), DROPPED)
            .expect("the authority decides the leave");
        assert_eq!(a.apply_at_frame, 116);

        // A peer that only recorded the carried departure, then is promoted: the
        // handoff re-derivation reproduces the identical apply frame.
        let mut peer = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::Peer);
        peer.record_departure(SlotId(1), last, ceiling, None, DROPPED);
        let (leaves, _fresh) = peer.set_authority(Authority::SelfRelay);
        let p = leaves
            .iter()
            .find(|l| l.slot == 1)
            .expect("promotion re-derives slot 1's leave");
        assert_eq!(
            p.apply_at_frame, 116,
            "same clamped apply frame from the same carried record",
        );
    }

    /// A non-authority relay never decides a leave (only the authority does).
    #[test]
    fn decide_leave_is_a_no_op_on_a_non_authority() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        assert_eq!(maker.decide_leave(SlotId(1), DROPPED), None);
    }

    /// A second decision for a slot already leaving is ignored (idempotent
    /// trigger — e.g. a duplicate drop signal).
    #[test]
    fn decide_leave_ignores_a_slot_already_leaving() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        assert!(maker.decide_leave(SlotId(1), DROPPED).is_some());
        assert_eq!(
            maker.decide_leave(SlotId(1), DROPPED),
            None,
            "no re-decide for the same slot"
        );
    }

    /// Two slots leaving are two independent decisions with distinct seqs — the
    /// relay pushes each down its own control-stream frame.
    #[test]
    fn decide_leave_handles_multiple_slots_independently() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(55));
        maker.observe_frame(SlotId(1), GameFrameCount(60));
        maker.observe_frame(SlotId(2), GameFrameCount(70));
        let d1 = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        let d2 = maker.decide_leave(SlotId(2), DROPPED).unwrap();
        assert_eq!(d1.slot, 1);
        assert_eq!(d2.slot, 2);
        assert_ne!(d1.leave_seq, d2.leave_seq, "distinct leave seqs");
    }

    /// A demotion keeps the cached leave, and a re-promotion re-broadcasts it
    /// *verbatim* — the same apply frame, even though the session frame has since
    /// advanced past what a fresh re-derivation would compute. Survivors that
    /// already applied it did so at that exact frame, so it must not move.
    #[test]
    fn promotion_re_broadcasts_a_cached_leave_verbatim() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        let first = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(first.apply_at_frame, 51);

        // Demote — the cache survives — then the surviving slot's stamps advance
        // well past the apply frame.
        assert_eq!(
            maker.set_authority(Authority::Peer),
            (Vec::new(), Vec::new())
        );
        maker.observe_frame(SlotId(0), GameFrameCount(200));

        // Re-promote: the cached directive is re-emitted verbatim — apply frame
        // AND leave_seq untouched, not a fresh derivation, so it is not in the
        // `fresh` set either (no second notice for an already-cached leave).
        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(
            leaves,
            vec![first],
            "the cached leave re-broadcasts verbatim"
        );
        assert!(
            fresh.is_empty(),
            "a verbatim re-broadcast is not a fresh insert"
        );

        // And decide_leave for that slot is now a no-op (still cached).
        assert_eq!(maker.decide_leave(SlotId(1), DROPPED), None);
    }

    /// The overshoot regression: survivors' stamped frames advanced past the
    /// departed slot's last frame before they stalled, so a survivors-only
    /// session frame exceeds it — the re-derived apply frame must still be
    /// `last_frame + 1` (where the stalled survivors are pinned), never
    /// `session + 1` (a frame they would never reach).
    #[test]
    fn re_derivation_does_not_overshoot_when_survivors_ran_ahead() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        // The survivor's stamps run ahead of the departed slot's last frame.
        maker.observe_frame(SlotId(0), GameFrameCount(55));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);
        assert_eq!(
            maker.session_frame(),
            Some(GameFrameCount(55)),
            "the survivors-only session frame exceeds the departed slot's last frame",
        );

        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            leaves[0].apply_at_frame, 51,
            "one past the departed slot's frame — the survivors' lead must not push it",
        );
        assert_eq!(fresh, leaves, "a re-derived leave is a fresh insert");
    }

    /// A promotion re-derives a departure the previous authority never decided:
    /// the departure was recorded (via `record_departure`) but no directive was
    /// cached, so the promoted relay decides it fresh from the stored last frame.
    #[test]
    fn promotion_re_derives_a_departure_with_no_cached_directive() {
        // This relay was never the authority: it recorded a peer's SlotDeparted
        // but decided nothing (decide_leave is a no-op on a non-authority).
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);
        assert_eq!(
            maker.decide_leave(SlotId(1), DROPPED),
            None,
            "no decision as a peer"
        );

        // Promoted: it derives the leave fresh from the stored last frame 50.
        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].slot, 1);
        assert_eq!(
            leaves[0].apply_at_frame, 51,
            "one past the stored last frame"
        );
        assert_eq!(
            fresh, leaves,
            "a departure with no cached directive is a fresh insert on promotion, \
             which is exactly the case the departure notifier must catch",
        );
    }

    /// Recording a departure captures the slot's frame into its record and
    /// retires the slot's live state; the teardown-time `remove_slot` that
    /// follows at the trigger site is a harmless no-op, and the record still
    /// drives a later promotion's re-derivation.
    #[test]
    fn promotion_re_derivation_survives_the_slots_retirement() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        // The trigger site reads the frame, records the departure (which merges
        // the frame into the record and retires the slot), then runs its
        // teardown remove_slot — now a no-op for this slot.
        let read = maker.slot_frame(SlotId(1));
        maker.record_departure(SlotId(1), read, None, None, DROPPED);
        assert_eq!(
            maker.slot_frame(SlotId(1)),
            None,
            "recording retires the live state"
        );
        maker.remove_slot(SlotId(1));

        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            leaves[0].apply_at_frame, 51,
            "the departure record drives re-derivation after the slot is gone",
        );
        assert_eq!(fresh, leaves);
    }

    /// A promotion re-broadcasts a cached leave even when the survivors' session
    /// frame is at/past its apply frame. The observed frames are survivors' SEND
    /// stamps, which lead their execution by the latency buffer's depth: a
    /// survivor stalled waiting for this very leave has stamps at or past
    /// `apply_at` too, so stamps-past-apply does not mean applied — a skip here
    /// could withhold the one re-delivery that unstalls a survivor the original
    /// push missed. Re-delivery to survivors that did apply it is deduped by slot.
    #[test]
    fn promotion_re_broadcasts_even_when_survivor_stamps_pass_apply() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        let leave = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(leave.apply_at_frame, 51);

        assert_eq!(
            maker.set_authority(Authority::Peer),
            (Vec::new(), Vec::new())
        );
        // The surviving slot's stamps reach the apply frame — exactly what a
        // stalled, un-served survivor's leading stamps look like.
        maker.observe_frame(SlotId(0), GameFrameCount(51));
        assert_eq!(maker.session_frame(), Some(GameFrameCount(51)));
        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(
            leaves,
            vec![leave],
            "the cached leave re-broadcasts regardless of the survivors' stamps",
        );
        assert!(fresh.is_empty(), "already cached — not a fresh insert");
    }

    /// A demotion no longer clears the cached leaves — the cache is exactly what a
    /// later promotion re-broadcasts.
    #[test]
    fn demotion_keeps_the_cached_leaves() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert!(maker.decided_leaves.contains_key(&SlotId(1)));

        assert_eq!(
            maker.set_authority(Authority::Peer),
            (Vec::new(), Vec::new())
        );
        assert!(
            maker.decided_leaves.contains_key(&SlotId(1)),
            "the cache survives demotion",
        );
    }

    /// `observe_leave` caches a peer authority's directive and advances
    /// `next_leave_seq` past it, so this relay's own later numbering never
    /// collides. A conflicting duplicate keeps the first (and warns).
    #[test]
    fn observe_leave_caches_and_advances_the_seq() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        let observed = LeaveDirective {
            slot: 2,
            reason: DROPPED,
            apply_at_frame: 88,
            leave_seq: 7,
        };
        assert!(maker.observe_leave(&observed), "first insert for the slot");
        assert_eq!(maker.decided_leaves.get(&SlotId(2)), Some(&observed));
        assert_eq!(
            maker.next_leave_seq, 7,
            "seq kept at least the observed seq"
        );

        // A conflicting duplicate for the same slot keeps the first.
        let conflicting = LeaveDirective {
            apply_at_frame: 999,
            ..observed
        };
        assert!(
            !maker.observe_leave(&conflicting),
            "a conflicting duplicate is not a first insert",
        );
        assert_eq!(
            maker.decided_leaves.get(&SlotId(2)),
            Some(&observed),
            "the first cached leave wins a conflict",
        );

        // Promoted, its own first leave numbers above the observed seq.
        maker.observe_frame(SlotId(0), GameFrameCount(100));
        let _ = maker.set_authority(Authority::SelfRelay);
        let own = maker.decide_leave(SlotId(0), DROPPED).unwrap();
        assert!(
            own.leave_seq > 7,
            "own numbering continues above the observed seq"
        );
    }

    /// The authority's inbound `SlotDeparted` path — record the departure (which
    /// max-merges the carried frame with our own observation), then decide —
    /// schedules from the carried frame when our own observation lags it.
    #[test]
    fn slot_departed_ingest_uses_the_carried_frame_when_our_observation_lags() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Our own view of the departing slot lags (frame 30); a survivor is at 45.
        maker.observe_frame(SlotId(0), GameFrameCount(45));
        maker.observe_frame(SlotId(1), GameFrameCount(30));

        // The peer's SlotDeparted carries the home relay's fuller view (60): the
        // departure record max-merges it over our lagging 30.
        maker.record_departure(SlotId(1), Some(GameFrameCount(60)), None, None, DROPPED);
        let leave = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(
            leave.apply_at_frame, 61,
            "one past the carried last frame, not our lagging observation",
        );
    }

    /// When the carried frame is *lower* than our own observation of the slot,
    /// the max-merge keeps our higher value, so the apply frame reflects it.
    #[test]
    fn slot_departed_ingest_keeps_a_higher_own_frame_over_a_lower_carried_one() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(1), GameFrameCount(70)); // our fuller view
        maker.observe_frame(SlotId(0), GameFrameCount(80));

        // A stale SlotDeparted carries a lower frame (55): the merge keeps 70.
        maker.record_departure(SlotId(1), Some(GameFrameCount(55)), None, None, DROPPED);
        let leave = maker.decide_leave(SlotId(1), DROPPED).unwrap();
        assert_eq!(
            leave.apply_at_frame, 71,
            "one past our higher observed frame"
        );
    }

    /// A non-authority relay records a departure but decides nothing.
    #[test]
    fn slot_departed_ingest_records_without_deciding_on_a_non_authority() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);
        assert_eq!(
            maker.decide_leave(SlotId(1), DROPPED),
            None,
            "no decision as a peer"
        );
        // But the departure is recorded, so a later promotion re-derives it.
        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].apply_at_frame, 51);
        assert_eq!(fresh, leaves, "re-derived on promotion — a fresh insert");
    }

    // -- Departed-slot lifecycle (slot leaves the live roster, never resurrects) --

    /// A departure retires the slot from the live roster on every relay, so the
    /// session frame follows the survivors instead of staying pinned at the
    /// departed slot's frozen last frame.
    #[test]
    fn a_departure_retires_the_slot_from_the_session_frame() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(0), GameFrameCount(60));
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        assert_eq!(maker.session_frame(), Some(GameFrameCount(50)));

        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);
        assert_eq!(
            maker.session_frame(),
            Some(GameFrameCount(60)),
            "the survivors alone drive the session frame after a departure",
        );
    }

    /// A late frame observation for a departed slot (its final turns racing the
    /// departure across the mesh) must not resurrect the slot's live state — the
    /// re-created entry would re-pin the session frame at the departed slot.
    #[test]
    fn observe_frame_ignores_a_departed_slot() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        maker.observe_frame(SlotId(0), GameFrameCount(60));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);

        maker.observe_frame(SlotId(1), GameFrameCount(52));
        assert!(!maker.slots.contains_key(&SlotId(1)), "no resurrection");
        assert_eq!(
            maker.session_frame(),
            Some(GameFrameCount(60)),
            "the late observation does not re-pin the session frame",
        );
    }

    /// A stale conditions sample for a departed slot (an in-flight datagram that
    /// raced the departure) must not re-create its condition state either.
    #[test]
    fn conditions_ingest_does_not_resurrect_a_departed_slot() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.observe_frame(SlotId(0), GameFrameCount(60));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);

        let _ = maker.ingest_local(&conditions(1, 150_000, 0, 100));
        assert!(!maker.slots.contains_key(&SlotId(1)), "no resurrection");
        assert_eq!(
            maker.target(),
            None,
            "no live slot has conditions to size from"
        );
    }

    /// The Join-time reconcile always includes a cached leave — even when the
    /// survivors' session frame is at/past its apply frame. As in the promotion
    /// case, the observed frames are send stamps that lead execution by the
    /// buffer depth, so they cannot distinguish "every survivor applied it" from
    /// "every survivor is stalled waiting for it"; the reconcile re-announces
    /// unconditionally and receipt dedups by slot.
    #[test]
    fn reconcile_always_includes_a_cached_leave() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        // Both slots observed off mesh turns; slot 1 is homed on the peer relay.
        maker.observe_frame(SlotId(0), GameFrameCount(40));
        maker.observe_frame(SlotId(1), GameFrameCount(50));
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), None, None, DROPPED);
        let leave = LeaveDirective {
            slot: 1,
            reason: DROPPED,
            apply_at_frame: 51,
            leave_seq: 1,
        };
        let _ = maker.observe_leave(&leave);

        let (_, directives) = maker.leave_reconcile();
        assert_eq!(directives, vec![leave]);

        // The survivor's stamps reach and pass the apply frame: the directive is
        // still re-announced (and the departure record with it).
        maker.observe_frame(SlotId(0), GameFrameCount(75));
        let (departures, directives) = maker.leave_reconcile();
        assert_eq!(directives, vec![leave], "re-announced regardless of stamps");
        assert_eq!(departures.len(), 1, "the departure record is announced too");
        let (leaves, fresh) = maker.set_authority(Authority::SelfRelay);
        assert_eq!(
            leaves,
            vec![leave],
            "and a promotion re-broadcasts it just the same",
        );
        assert!(
            fresh.is_empty(),
            "already cached via observe_leave — not a fresh insert on promotion",
        );
    }

    // -- Desync comparator (SyncTracker via DecisionMaker::observe_sync) --

    /// The two `hash16` bytes stand in for a sim state hash; distinct arrays
    /// are distinct sims.
    const SYNC_A: SyncValue = [1, 2];
    const SYNC_B: SyncValue = [9, 8];
    const SYNC_C: SyncValue = [4, 4];

    /// Builds a 7-byte `0x37` sync command: opcode, `(ring << 4) | kind`, the
    /// 2-byte `hash16`, then fixed zero filler for `[4..7]` (the per-sender
    /// fog/vision bytes the comparator never reads — see `SyncValue`; a value
    /// here is irrelevant to the code under test except in the dedicated
    /// `sync_command_with_fog` regression test below).
    fn sync_command(ring: u8, kind: u8, value: SyncValue) -> Vec<u8> {
        sync_command_with_fog(ring, kind, value, [0, 0, 0])
    }

    /// [`sync_command`], but with explicit `[4..7]` filler — for the
    /// regression test proving those bytes are never compared.
    fn sync_command_with_fog(ring: u8, kind: u8, value: SyncValue, fog: [u8; 3]) -> Vec<u8> {
        let mut command = vec![SYNC_COMMAND, ((ring & 0x0F) << 4) | (kind & 0x0F)];
        command.extend_from_slice(&value);
        command.extend_from_slice(&fog);
        command
    }

    /// Feeds one slot's sync command at a chosen ring nibble, kind, and frame.
    /// Returns the divergence if this feed confirmed one.
    fn feed_ring_kind(
        maker: &mut DecisionMaker,
        slot: u8,
        ring: u8,
        kind: u8,
        value: SyncValue,
        frame: u32,
    ) -> Option<SyncDivergence> {
        maker.observe_sync(SlotId(slot), Some(frame), &sync_command(ring, kind, value))
    }

    /// [`feed_ring_kind`] with the kind SC:R's native check ties to `ring`'s
    /// parity (even → 1, odd → 2) — what an honest client always sends.
    fn feed_ring(
        maker: &mut DecisionMaker,
        slot: u8,
        ring: u8,
        value: SyncValue,
        frame: u32,
    ) -> Option<SyncDivergence> {
        let kind = expected_kind_for_ordinal(u64::from(ring));
        feed_ring_kind(maker, slot, ring, kind, value, frame)
    }

    /// Feeds one slot's sync command with the ring nibble its true ordinal
    /// expects (`ordinal % 16`) and the kind that ordinal's parity implies.
    /// The frame is a distinct-per-ordinal marker. Feeding a slot's ordinals
    /// out of order (or interleaved with another slot's) exercises the same
    /// nibble-corrected placement a real reordered or racing-ahead slot would.
    fn feed(
        maker: &mut DecisionMaker,
        slot: u8,
        ordinal: u8,
        value: SyncValue,
    ) -> Option<SyncDivergence> {
        feed_ring(maker, slot, ordinal % 16, value, 1000 + u32::from(ordinal))
    }

    /// Advances `slot`'s ordinal from 0 up to (but not including) `through`,
    /// reporting `value` at every step. Used to push the tracker's frontier
    /// past the evaluation margin without needing every compared slot to
    /// individually advance — the margin only cares about the single furthest
    /// member's progress, so racing one slot ahead is enough to make earlier
    /// ordinals eligible for evaluation. Returns the last divergence observed,
    /// if any (there is at most one, since the comparator fires exactly one
    /// notice per event).
    fn advance(
        maker: &mut DecisionMaker,
        slot: u8,
        value: SyncValue,
        through: u8,
    ) -> Option<SyncDivergence> {
        let mut divergence = None;
        for ordinal in 0..through {
            if let Some(d) = feed(maker, slot, ordinal, value) {
                divergence = Some(d);
            }
        }
        divergence
    }

    /// A representative buffer policy, well under [`SYNC_ABSURD_BUFFER_MAX`],
    /// so these tests exercise the comparator exactly as it runs with
    /// detection live.
    fn authority_maker() -> DecisionMaker {
        DecisionMaker::new(key(), bounds(0, 6), law(), Authority::SelfRelay)
    }

    /// The evaluation margin [`authority_maker`]'s bounds (`max = 6`) implies
    /// — computed via the real formula ([`sync_eval_margin`]) so these tests
    /// can't silently drift from it.
    fn authority_margin() -> u64 {
        sync_eval_margin(6)
    }

    #[test]
    fn all_agree_retires_the_ordinal_silently() {
        let mut m = authority_maker();
        feed(&mut m, 1, 0, SYNC_A);
        // Slot 0 alone races ahead; ordinal 0 isn't evaluated until the
        // frontier clears the margin, at which point it retires silently
        // (matching values).
        let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8);
        assert_eq!(divergence, None, "matching values retire silently");
        assert_eq!(m.sync.base_ordinal, 1, "ordinal 0 retired");
        assert!(!m.sync.pending.contains_key(&0));
    }

    #[test]
    fn three_slot_majority_identifies_the_diverged_minority() {
        let mut m = authority_maker();
        feed(&mut m, 1, 0, SYNC_A);
        feed(&mut m, 2, 0, SYNC_B); // slot 2's sim diverged
        // Slot 0 alone races ahead to clear the evaluation margin for ordinal 0.
        let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
            .expect("clearing the margin evaluates ordinal 0");
        assert_eq!(divergence.sync_ordinal, 0);
        assert!(!divergence.no_majority);
        assert_eq!(divergence.diverged, vec![SlotId(2)]);
        assert_eq!(divergence.game_frame, Some(1000), "ordinal 0's frame");
        // The minority is dropped from the compare set.
        assert!(!m.sync.members.contains_key(&SlotId(2)));
        assert!(m.sync.members.contains_key(&SlotId(0)));
        assert!(!m.sync.dormant, "survivors keep being watched");
    }

    #[test]
    fn one_v_one_disagreement_is_no_majority_and_goes_dormant() {
        let mut m = authority_maker();
        feed(&mut m, 1, 0, SYNC_B);
        let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
            .expect("clearing the margin evaluates ordinal 0");
        assert_eq!(divergence.sync_ordinal, 0);
        assert!(divergence.no_majority, "1v1 has no majority");
        assert!(divergence.diverged.is_empty(), "no minority named");
        assert!(
            m.sync.dormant,
            "truth is unrecoverable — dormant for the session"
        );
        assert_eq!(
            feed(&mut m, 1, 1, SYNC_B),
            None,
            "a dormant comparator no-ops"
        );
    }

    #[test]
    fn even_split_is_no_majority() {
        let mut m = authority_maker();
        feed(&mut m, 1, 0, SYNC_A);
        feed(&mut m, 2, 0, SYNC_B);
        feed(&mut m, 3, 0, SYNC_B);
        let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8)
            .expect("clearing the margin evaluates ordinal 0");
        assert!(divergence.no_majority, "2-2 has no strict majority");
        assert!(divergence.diverged.is_empty());
        assert!(m.sync.dormant);
    }

    #[test]
    fn a_second_divergence_fires_again_at_its_own_ordinal() {
        let mut m = authority_maker();
        // Ordinal 0: slot 3 diverges from the 0/1/2 majority.
        feed(&mut m, 1, 0, SYNC_A);
        feed(&mut m, 2, 0, SYNC_A);
        feed(&mut m, 3, 0, SYNC_B);
        let first =
            advance(&mut m, 0, SYNC_A, 8).expect("slot 0 clearing the margin fires the first");
        assert_eq!(first.sync_ordinal, 0);
        assert_eq!(first.diverged, vec![SlotId(3)]);

        // Survivors {0,1,2} continue. Ordinal 1: slot 2 now diverges. Slot 0's
        // ordinal-1 report already landed during the `advance` above.
        feed(&mut m, 1, 1, SYNC_A);
        feed(&mut m, 2, 1, SYNC_C);
        let second = feed(&mut m, 0, 8, SYNC_A).expect("a second divergence at ordinal 1");
        assert_eq!(second.sync_ordinal, 1, "a distinct, later ordinal");
        assert!(!second.no_majority);
        assert_eq!(second.diverged, vec![SlotId(2)]);
        assert!(!m.sync.members.contains_key(&SlotId(2)));
    }

    #[test]
    fn an_observer_slot_is_excluded_from_comparison() {
        let mut m = authority_maker();
        m.set_observers(HashSet::from([SlotId(1)]));
        // Slot 1 is an observer with a wildly different checksum; it must never
        // join the compare set, so no divergence ever fires from it.
        feed(&mut m, 0, 0, SYNC_A);
        assert_eq!(feed(&mut m, 1, 0, SYNC_B), None, "observer feed is a no-op");
        assert!(
            !m.sync.members.contains_key(&SlotId(1)),
            "observer never joins"
        );
        assert!(!m.sync.dormant);
    }

    #[test]
    fn a_departed_slot_is_no_longer_required() {
        let mut m = authority_maker();
        feed(&mut m, 1, 0, SYNC_A);
        feed(&mut m, 2, 0, SYNC_A);
        // Slot 0 alone clears the margin for ordinal 0; all three agree.
        assert_eq!(
            advance(&mut m, 0, SYNC_A, 8),
            None,
            "all agree at ordinal 0"
        );
        assert_eq!(m.sync.base_ordinal, 1);

        // Ordinal 1: slot 1 reports, slot 2 departs before ever reporting it.
        feed(&mut m, 1, 1, SYNC_A);
        m.record_departure(SlotId(2), None, None, None, DROPPED);
        assert!(!m.sync.members.contains_key(&SlotId(2)));

        // Slot 0 continues; ordinal 1 completes on the two survivors once the
        // frontier clears the margin for base = 1 (slot 0's own ordinal-1
        // report already landed during the `advance` above).
        let divergence = feed(&mut m, 0, 8, SYNC_A);
        assert_eq!(divergence, None, "no mismatch — retires silently");
        assert_eq!(m.sync.base_ordinal, 2, "ordinal 1 retired without slot 2");
    }

    /// Hole 3 (reordering): two adjacent turns from the same slot arrive
    /// swapped. Nibble-corrected placement lands each at its true ordinal
    /// regardless, so the honest agreement across slots never looks like a
    /// mismatch — and the correction is flagged for observability.
    #[test]
    fn a_reordered_adjacent_pair_is_placed_correctly_and_warns() {
        let mut m = authority_maker();
        // Slot 1 reports ordinals 0..5 normally, matching slot 0's values.
        for ordinal in 0..6 {
            feed(&mut m, 1, ordinal, SYNC_A);
        }
        // Slot 0 reports 0..3 normally, but 4 and 5 arrive swapped — 5 first.
        for ordinal in 0..4 {
            feed(&mut m, 0, ordinal, SYNC_A);
        }
        feed_ring(&mut m, 0, 5, SYNC_A, 1005); // ordinal 5 arrives first
        feed_ring(&mut m, 0, 4, SYNC_A, 1004); // ordinal 4 arrives late
        assert!(
            m.sync.corrections >= 1,
            "the out-of-order arrival was corrected and counted",
        );

        // Slot 0 races on so the margin clears every ordinal through 5.
        let divergence = (6..14)
            .filter_map(|ordinal| feed(&mut m, 0, ordinal, SYNC_A))
            .last();
        assert_eq!(
            divergence, None,
            "the reordered pair still compares equal at its true ordinal — no false divergence",
        );
        assert_eq!(m.sync.base_ordinal, 6, "ordinals 0..5 all retired cleanly");
    }

    /// Hole 2, the exact production failure: at sync activation, one slot's
    /// early turns beat the other's first-ever arrival to the relay (routine
    /// under asymmetric latency + buffer depth, invisible on a symmetric
    /// loopback test). The old frontier-floor scheme landed the late slot's
    /// true ordinal 0 at whatever the frontier happened to be (here, 4) — a
    /// permanent misalignment that turns every later honest turn into a false
    /// mismatch. Nibble-corrected placement anchors the late slot at its true
    /// ordinal instead. Two slots only, so this is also the 1v1 shape of the
    /// production failure.
    #[test]
    fn a_late_joining_slot_lands_at_its_true_ordinal_not_the_frontier() {
        let mut m = authority_maker();
        for ordinal in 0..4 {
            feed(&mut m, 0, ordinal, SYNC_A);
        }
        // Slot 1's first-ever report is genuinely ordinal 0 (ring 0), arriving
        // only now. Nibble-corrected placement anchors it there, not at 4.
        feed_ring(&mut m, 1, 0, SYNC_A, 2000);
        assert_eq!(
            m.sync.members[&SlotId(1)].since,
            0,
            "slot 1's join ordinal is its true ordinal 0, not the frontier it joined at",
        );

        feed(&mut m, 1, 1, SYNC_A);
        feed(&mut m, 1, 2, SYNC_A);
        feed(&mut m, 1, 3, SYNC_A);

        // Both slots continue in lockstep agreement; nothing should ever look
        // like a divergence.
        let mut divergence = None;
        for ordinal in 4u8..12 {
            if let Some(d) = feed(&mut m, 0, ordinal, SYNC_A) {
                divergence = Some(d);
            }
            if let Some(d) = feed(&mut m, 1, ordinal, SYNC_A) {
                divergence = Some(d);
            }
        }
        assert_eq!(
            divergence, None,
            "the late join aligned correctly — no false desync"
        );
    }

    /// A deep join (>7 ordinals from the frontier — a gap the shipped dev-tenant
    /// policy 1..=12 allows, past the ±7 nibble ceiling) still lands on its true
    /// ordinal **once a rate is corroborated by ≥3 distinct slots**. This is the
    /// honest-case counterpart to the calibration-poisoning defense: with a
    /// corroborated rate (which a lone slot cannot swing), the frame projection is
    /// trustworthy again and the deep join is placed correctly rather than
    /// deferred.
    #[test]
    fn a_deep_join_lands_on_its_true_ordinal_once_three_slots_corroborate_the_rate() {
        let mut m = DecisionMaker::new(key(), bounds(1, 12), law(), Authority::SelfRelay);
        let margin = sync_eval_margin(12);
        assert_eq!(margin, 14);

        // Three slots advance together for ten ordinals at ~2 frames/turn, so
        // every ordinal 0..10 is reported by ≥3 distinct slots with agreeing
        // frames — a corroborated (median) rate a single slot cannot move.
        for ordinal in 0u8..10 {
            let frame = 5000 + 2 * u32::from(ordinal);
            for slot in [0u8, 2, 3] {
                feed_ring(&mut m, slot, ordinal, SYNC_A, frame);
            }
        }
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            10,
            "frontier at 10"
        );
        assert_eq!(
            m.sync.frame_rate(),
            Some(2.0),
            "≥3 slots corroborated the rate"
        );

        // Slot 1's first-ever report is genuinely ordinal 0 (ring 0), ten
        // ordinals behind the frontier — past the nibble ceiling — with a frame
        // close to ordinal 0's corroborated frame (5000). The corroborated
        // projection lands it on its true ordinal, not the frontier.
        feed_ring(&mut m, 1, 0, SYNC_A, 5001);
        assert_eq!(
            m.sync.members[&SlotId(1)].since,
            0,
            "the corroborated anchor placed slot 1 at its true ordinal 0, not the frontier (10)",
        );

        // Everyone agrees; racing slot 0 past the depth-12 margin retires ordinal
        // 0 silently — no false divergence from the deep join.
        let mut divergence = None;
        for ordinal in 10u8..(margin as u8) {
            if let Some(d) = feed_ring(&mut m, 0, ordinal, SYNC_A, 5000 + 2 * u32::from(ordinal)) {
                divergence = Some(d);
            }
        }
        assert_eq!(divergence, None, "no false divergence from the deep join");
    }

    /// Finding B, the whole point: an attacker controlling only its own slot
    /// cannot frame a joining victim by seeding calibration. The attacker races
    /// the frontier ahead (one `0x37` per turn) and stamps whatever frames it
    /// likes; when the honest victim joins at its true ordinal 0, there is no
    /// corroborated rate (a lone slot can't make one), so the victim is DEFERRED
    /// — never placed a full ring cycle ahead at ~16 and never named diverged.
    #[test]
    fn an_attacker_cannot_frame_a_joining_victim_by_seeding_calibration_alone() {
        let mut m = DecisionMaker::new(key(), bounds(1, 12), law(), Authority::SelfRelay);
        // The attacker (slot 0) races ten ordinals ahead, stamping a frame
        // sequence designed to project a low-frame joiner up near ordinal 16.
        for ordinal in 0u8..10 {
            feed_ring(&mut m, 0, ordinal % 16, SYNC_A, 9000 + u32::from(ordinal));
        }
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            10,
            "attacker raced the frontier to 10"
        );
        assert!(
            m.sync.frame_rate().is_none(),
            "a lone slot cannot corroborate a rate to poison",
        );

        // The honest victim joins at its true ordinal 0. No corroboration + the
        // nibble would land it above the frontier (a full cycle off) → deferred.
        assert_eq!(feed_ring(&mut m, 1, 0, SYNC_A, 9002), None);
        assert!(
            !m.sync.members.contains_key(&SlotId(1)),
            "the victim is deferred, never misplaced a full ring cycle ahead at ~16",
        );
        // It keeps reporting; without ≥3 corroborators it stays deferred and is
        // never named as the diverged slot.
        for _ in 0..5 {
            assert_eq!(
                feed_ring(&mut m, 1, 0, SYNC_A, 9002),
                None,
                "still deferred — never a divergence naming the honest victim",
            );
        }
        assert!(!m.sync.members.contains_key(&SlotId(1)));
    }

    /// A 2-reporter ordinal never corroborates (the threshold is ≥3), so an
    /// attacker's outlier frame at a 2-reporter ordinal can't poison a rate — the
    /// median that would reject it never even gets computed, because no rate
    /// forms from two reporters at all.
    #[test]
    fn a_two_reporter_ordinal_with_an_attacker_outlier_does_not_corroborate() {
        let mut m = DecisionMaker::new(key(), bounds(1, 12), law(), Authority::SelfRelay);
        // One honest slot and one attacker stamping wild frames report ordinals
        // 0..6 — two reporters each, below the ≥3 corroboration threshold.
        for ordinal in 0u8..6 {
            feed_ring(&mut m, 0, ordinal, SYNC_A, 5000 + 2 * u32::from(ordinal));
            feed_ring(&mut m, 1, ordinal, SYNC_A, 900_000 + u32::from(ordinal));
        }
        assert!(
            m.sync.corroborated_latest.is_none(),
            "two reporters never corroborate an ordinal",
        );
        assert!(
            m.sync.frame_rate().is_none(),
            "no rate forms — nothing for the attacker's outlier to poison",
        );
    }

    /// When a joining report carries no `game_frame` at all, the frame anchor
    /// is unavailable and join placement falls back to frontier+nibble (the
    /// round-2 behavior) — exercised within the ±7 range where that fallback
    /// is still sound on its own.
    #[test]
    fn a_join_with_no_frame_falls_back_to_frontier_and_nibble() {
        let mut m = authority_maker();
        for ordinal in 0u8..4 {
            feed(&mut m, 0, ordinal, SYNC_A);
        }
        let divergence = m.observe_sync(
            SlotId(1),
            None,
            &sync_command(4, expected_kind_for_ordinal(4), SYNC_A),
        );
        assert_eq!(divergence, None);
        assert_eq!(
            m.sync.members[&SlotId(1)].since,
            4,
            "no frame to anchor on — falls back to the frontier, nibble-corrected",
        );
    }

    /// A joining report carries a frame, but the tracker doesn't have a rate
    /// yet (only one calibration point exists) — falls back to
    /// frontier+nibble exactly like the no-frame case, ignoring the frame
    /// entirely rather than projecting from an unreliable single point.
    #[test]
    fn a_join_with_a_frame_but_no_rate_yet_falls_back_to_frontier_and_nibble() {
        let mut m = authority_maker();
        // Slot 0 reports exactly once — one calibration point, not enough to
        // compute a rate.
        feed(&mut m, 0, 0, SYNC_A);
        // Slot 1 joins with a frame that would, under any rate assumption,
        // suggest a wildly different ordinal — but with no rate to project
        // from, this still falls back to the frontier (1), nibble-corrected.
        let divergence = feed_ring(&mut m, 1, 1, SYNC_A, 999_999);
        assert_eq!(divergence, None);
        assert_eq!(
            m.sync.members[&SlotId(1)].since,
            1,
            "no rate yet — falls back to the frontier, nibble-corrected, ignoring the frame",
        );
    }

    /// A turn carrying more than one `0x37` counts as a **single** ordinal
    /// advance. An honest client emits exactly one sync command per outgoing
    /// turn; packing several into one turn is the lever a malicious client
    /// would use to inflate its own frontier (and seed join-placement
    /// calibration) in a single turn — and to race its own ordinals past the
    /// eviction window to evade detection. Only the first is fed to the
    /// comparator; the extras are ignored and flagged.
    #[test]
    fn multiple_sync_commands_in_one_turn_advance_the_ordinal_by_one() {
        let mut m = authority_maker();
        // Three sync commands packed into a single turn (one observe_sync call).
        let mut commands = sync_command(0, expected_kind_for_ordinal(0), SYNC_A);
        commands.extend(sync_command(1, expected_kind_for_ordinal(1), SYNC_A));
        commands.extend(sync_command(2, expected_kind_for_ordinal(2), SYNC_A));
        let divergence = m.observe_sync(SlotId(0), Some(1000), &commands);
        assert_eq!(divergence, None);
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            1,
            "only the first sync command counts — the ordinal advances by one, not three",
        );
        assert_eq!(
            m.sync.base_ordinal, 0,
            "the frontier did not vault the window"
        );
        assert_eq!(
            m.sync.multi_sync_warns, 1,
            "the extra sync commands were flagged once"
        );
    }

    /// The eviction-evasion shape of the same lever: a slot cannot flood enough
    /// `0x37`s in one turn to push the comparator's `base_ordinal` past
    /// ordinals its honest peers haven't been compared at yet. With one sync
    /// command per turn honored, a single turn moves the frontier by one, so
    /// the eviction window can't be jumped in a burst.
    #[test]
    fn a_one_turn_sync_flood_cannot_vault_the_eviction_window() {
        let mut m = authority_maker();
        // An honest slot reports ordinal 0 and stops there.
        feed(&mut m, 1, 0, SYNC_A);
        // The attacker packs a full window-plus of sync commands into one turn.
        let mut flood = Vec::new();
        for ring in 0..(SYNC_WINDOW as u8 + 4) {
            flood.extend(sync_command(
                ring % 16,
                expected_kind_for_ordinal(u64::from(ring % 16)),
                SYNC_B,
            ));
        }
        let divergence = m.observe_sync(SlotId(0), Some(2000), &flood);
        assert_eq!(divergence, None, "no eviction, no premature verdict");
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            1,
            "the flood advanced the attacker's ordinal by one, not the whole window",
        );
        assert_eq!(
            m.sync.base_ordinal, 0,
            "ordinal 0 (where the honest slot reported) is still awaiting evaluation, not evicted",
        );
        assert!(
            m.sync
                .pending
                .get(&0)
                .is_some_and(|r| r.contains_key(&SlotId(1))),
            "the honest slot's ordinal-0 report is still pending, not evicted past",
        );
    }

    #[test]
    fn an_ordinal_is_not_evaluated_until_the_frontier_clears_the_margin() {
        let mut m = authority_maker();
        feed(&mut m, 0, 0, SYNC_A);
        feed(&mut m, 1, 0, SYNC_A);
        assert_eq!(m.sync.base_ordinal, 0, "not yet evaluated");
        assert!(m.sync.pending.contains_key(&0));

        let margin = authority_margin() as u8;
        for ordinal in 1..(margin - 1) {
            feed(&mut m, 0, ordinal, SYNC_A);
            assert_eq!(m.sync.base_ordinal, 0, "still short of the margin");
        }
        feed(&mut m, 0, margin - 1, SYNC_A);
        assert_eq!(
            m.sync.base_ordinal, 1,
            "the margin cleared — ordinal 0 retired"
        );
    }

    /// The margin scales with the session's negotiated buffer bounds (not a
    /// fixed constant): with the shipped dev-tenant policy (1..=12), ordinal
    /// `k` isn't evaluated until the frontier reaches `k + 14`
    /// (`max(8, 12 + 2)`), not the shallow-policy 8.
    #[test]
    fn the_evaluation_margin_scales_with_the_session_s_buffer_bounds() {
        let mut m = DecisionMaker::new(key(), bounds(1, 12), law(), Authority::SelfRelay);
        let margin = sync_eval_margin(12);
        assert_eq!(
            margin, 14,
            "max(8, 12 + 2) -- the shipped dev-tenant policy"
        );

        feed(&mut m, 0, 0, SYNC_A);
        feed(&mut m, 1, 0, SYNC_A);
        // One short of the margin: still held.
        for ordinal in 1..(margin as u8 - 1) {
            feed(&mut m, 0, ordinal, SYNC_A);
            assert_eq!(m.sync.base_ordinal, 0, "still short of the deeper margin");
        }
        // The margin clears: ordinal 0 retires.
        feed(&mut m, 0, margin as u8 - 1, SYNC_A);
        assert_eq!(
            m.sync.base_ordinal, 1,
            "the deeper margin cleared — ordinal 0 retired"
        );
    }

    #[test]
    fn a_slot_that_joins_mid_stream_anchors_its_join_ordinal_to_where_it_actually_joined() {
        let mut m = authority_maker();
        // The very first sync command this tracker ever sees anchors the
        // frontier at the ring's face value — the promotion-mid-stream case,
        // where the authority has no earlier context to correct against.
        feed_ring(&mut m, 0, 10, SYNC_A, 3000);
        assert_eq!(m.sync.members[&SlotId(0)].since, 10);

        // Slot 0 advances a few more ordinals, moving the frontier forward.
        for ring in 11..14 {
            feed_ring(&mut m, 0, ring, SYNC_A, 3000 + u32::from(ring));
        }
        assert_eq!(m.sync.members[&SlotId(0)].next_expected, 14);

        // Slot 1 joins for the first time now: nibble-corrected placement
        // lands it at the current frontier (14), not retroactively at ordinal
        // 0 or at slot 0's own anchor (10) — it was never present for those.
        feed_ring(&mut m, 1, 14, SYNC_A, 4000);
        assert_eq!(
            m.sync.members[&SlotId(1)].since,
            14,
            "slot 1's join ordinal is where it actually joined",
        );
        assert!(
            m.sync.members[&SlotId(1)].since > 10,
            "not required for ordinals before its true join",
        );
    }

    /// The belt-and-suspenders path: even if a duplicate somehow reached the
    /// tracker itself (the mesh-level dedup in `deliver_turn_to_locals` is
    /// what should normally prevent this), a repeated report at the same
    /// placed ordinal must not be double-counted.
    #[test]
    fn a_duplicate_report_at_the_same_ordinal_is_ignored_not_double_counted() {
        let mut m = authority_maker();
        feed_ring(&mut m, 0, 0, SYNC_A, 1000);
        feed_ring(&mut m, 0, 0, SYNC_A, 1000);
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            1,
            "a repeated report at the same ordinal must not advance the count twice",
        );
        assert_eq!(m.sync.pending.get(&0).map(HashMap::len), Some(1));
    }

    #[test]
    fn a_non_authority_relay_does_not_compare() {
        let mut m = DecisionMaker::new(key(), bounds(0, 6), law(), Authority::Peer);
        assert_eq!(feed(&mut m, 0, 0, SYNC_A), None);
        assert_eq!(feed(&mut m, 1, 0, SYNC_B), None);
        assert_eq!(feed(&mut m, 0, 1, SYNC_A), None);
        assert!(m.sync.members.is_empty(), "a peer records nothing");
    }

    #[test]
    fn promotion_resets_the_comparator_state() {
        let mut m = authority_maker();
        feed(&mut m, 0, 0, SYNC_A);
        feed(&mut m, 1, 0, SYNC_A);
        assert!(
            !m.sync.members.is_empty(),
            "state accumulated while authority"
        );

        // Demote (state kept, comparator inert), then promote — which starts the
        // comparator fresh, no per-ordinal state carried across the handoff.
        let _ = m.set_authority(Authority::Peer);
        let _ = m.set_authority(Authority::SelfRelay);
        assert!(m.sync.members.is_empty(), "promotion reset the compare set");
        assert_eq!(m.sync.base_ordinal, 0, "and the frontier");
    }

    #[test]
    fn the_in_flight_window_is_bounded_by_eviction() {
        let mut m = authority_maker();
        // Slot 1 reports only ordinal 0, then stalls; slot 0 races far ahead. The
        // ordinals slot 1 never reports can't complete, so the oldest are evicted
        // rather than accumulating without bound.
        feed(&mut m, 1, 0, SYNC_A);
        for ordinal in 0..(SYNC_WINDOW as u8 + 6) {
            feed(&mut m, 0, ordinal, SYNC_A);
        }
        assert!(m.sync.evict_warns > 0, "a stalled slot triggered eviction");
        assert!(
            m.sync.pending.len() <= SYNC_WINDOW,
            "the in-flight window stays bounded ({} pending)",
            m.sync.pending.len(),
        );
    }

    #[test]
    fn a_turn_without_a_sync_command_is_ignored() {
        let mut m = authority_maker();
        // A non-sync command stream (a Vision 0x0D, 3 bytes) records nothing.
        assert_eq!(m.observe_sync(SlotId(0), Some(1), &[0x0D, 0, 0]), None);
        assert!(m.sync.members.is_empty());
        // A truncated/garbage tail after a valid command stops the walk without
        // panicking.
        let mut stream = sync_command(0, expected_kind_for_ordinal(0), SYNC_A);
        stream.push(0xFF); // an opcode the table rejects
        assert_eq!(m.observe_sync(SlotId(0), Some(1), &stream), None);
        assert_eq!(
            m.sync
                .members
                .get(&SlotId(0))
                .map(|member| member.next_expected),
            Some(1),
            "the sync command counted",
        );
    }

    /// A session whose negotiated buffer bounds reach the absurd-bounds
    /// backstop disables desync detection outright — a defensive ceiling far
    /// above any real policy, not a live constraint (depth itself no longer
    /// threatens correctness; see the module docs and
    /// [`BufferBounds`](rally_point_proto::control::BufferBounds)).
    #[test]
    fn absurd_buffer_bounds_disable_the_comparator() {
        let mut m = DecisionMaker::new(
            key(),
            bounds(0, SYNC_ABSURD_BUFFER_MAX),
            law(),
            Authority::SelfRelay,
        );
        // A first sync command trips the check and disables the comparator —
        // even from two slots that would otherwise plainly disagree.
        assert_eq!(feed(&mut m, 0, 0, SYNC_A), None);
        assert!(m.sync.dormant, "absurd bounds disable detection outright");
        assert_eq!(feed(&mut m, 1, 0, SYNC_B), None, "still a no-op");
    }

    /// End-to-end through the registry: a divergence fires a `DesyncNotice` on the
    /// notice channel, stamped with the session's correlation ids.
    #[test]
    fn observe_sync_fires_a_desync_notice_with_stamped_refs() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 6), Authority::SelfRelay);
        registry.set_session_refs(
            &k,
            Some("game-77".to_owned()),
            HashMap::from([(SlotId(2), "sb-user-diverged".to_owned())]),
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_notice_notifier(tx);

        // 0,1 agree, 2 diverges, all at ordinal 0.
        observe_sync(
            &registry,
            &k,
            SlotId(0),
            Some(500),
            &sync_command(0, expected_kind_for_ordinal(0), SYNC_A),
        );
        observe_sync(
            &registry,
            &k,
            SlotId(1),
            Some(500),
            &sync_command(0, expected_kind_for_ordinal(0), SYNC_A),
        );
        observe_sync(
            &registry,
            &k,
            SlotId(2),
            Some(500),
            &sync_command(0, expected_kind_for_ordinal(0), SYNC_B),
        );
        assert!(rx.try_recv().is_err(), "held until the margin clears");

        // Slot 0 alone races ahead to clear the margin.
        for ordinal in 1u8..(sync_eval_margin(6) as u8) {
            observe_sync(
                &registry,
                &k,
                SlotId(0),
                Some(500 + u32::from(ordinal)),
                &sync_command(
                    ordinal,
                    expected_kind_for_ordinal(u64::from(ordinal)),
                    SYNC_A,
                ),
            );
        }

        let RelayNotice::Desync(notice) = rx.try_recv().expect("a desync notice fires") else {
            panic!("a desync notice");
        };
        assert_eq!(notice.tenant, k.tenant);
        assert_eq!(notice.session, k.session);
        assert_eq!(notice.sync_ordinal, 0);
        assert_eq!(notice.game_frame, Some(500));
        assert!(!notice.no_majority);
        assert_eq!(notice.external_id, Some("game-77".to_owned()));
        assert_eq!(notice.diverged.len(), 1);
        assert_eq!(notice.diverged[0].slot, SlotId(2));
        assert_eq!(
            notice.diverged[0].external_ref,
            Some("sb-user-diverged".to_owned()),
        );
        assert!(notice.detected_at_ms > 0);
    }

    /// SC:R's initial latency-depth flush burst emits several `0x37`s all
    /// stamped identically (same ring, same content) before the first
    /// per-turn record advances the ring — the same-ordinal duplicate-ignore
    /// already absorbs this without any special-casing (live-relay
    /// confirmed): each repeat lands back at the same placed ordinal via
    /// ordinary nibble correction.
    #[test]
    fn a_startup_burst_of_identical_ring_1_reports_causes_no_false_divergence() {
        let mut m = authority_maker();
        // Slot 0's burst: four identical ring-1 reports (kind 2 — ring 1 is
        // odd), exactly the shape the enable path + flush burst produces.
        for _ in 0..4 {
            feed_ring(&mut m, 0, 1, SYNC_A, 1000);
        }
        // Slot 1's own burst, three copies.
        for _ in 0..3 {
            feed_ring(&mut m, 1, 1, SYNC_A, 1000);
        }
        assert_eq!(
            m.sync.members[&SlotId(0)].next_expected,
            2,
            "the repeated burst never advanced past its true ordinal",
        );
        assert_eq!(m.sync.members[&SlotId(1)].next_expected, 2);

        // Both slots continue normally in lockstep agreement, racing the
        // margin far enough to retire the burst's ordinal.
        let margin = authority_margin() as u8;
        let mut divergence = None;
        for ring in 2..(margin + 2) {
            if let Some(d) = feed_ring(&mut m, 0, ring, SYNC_A, 1000 + u32::from(ring)) {
                divergence = Some(d);
            }
            if let Some(d) = feed_ring(&mut m, 1, ring, SYNC_A, 1000 + u32::from(ring)) {
                divergence = Some(d);
            }
        }
        assert_eq!(
            divergence, None,
            "the burst absorbed cleanly — no false divergence",
        );
    }

    /// The exact live false positive this fix repairs: SC:R's fog/vision
    /// bytes (`[4..7]`) are per-sender, vision-masked values the native check
    /// only ever compares pairwise against the receiver's own local fog
    /// buffer — they legitimately differ between honest players in the same
    /// game. The relay must never treat that difference as a desync: only
    /// `hash16` (`[2:3]`) feeds the comparison.
    #[test]
    fn fog_byte_divergence_with_matching_hash16_is_not_a_divergence() {
        let mut m = authority_maker();
        // Two slots whose hash16 always agrees, but whose fog/vision filler
        // bytes never do — exactly the shape a healthy game produces.
        for ordinal in 0u8..(authority_margin() as u8) {
            let ring = ordinal % 16;
            let kind = expected_kind_for_ordinal(u64::from(ordinal));
            let frame = 1000 + u32::from(ordinal);
            let a = sync_command_with_fog(ring, kind, SYNC_A, [1, 2, 3]);
            let b = sync_command_with_fog(ring, kind, SYNC_A, [9, 8, 7]);
            assert_eq!(m.observe_sync(SlotId(0), Some(frame), &a), None);
            assert_eq!(m.observe_sync(SlotId(1), Some(frame), &b), None);
        }
        assert_eq!(
            m.sync.base_ordinal, 1,
            "ordinal 0 retired — the differing fog bytes never entered the comparison",
        );
    }

    /// A report whose kind disagrees with its placed ordinal's expected
    /// parity is an alignment-drift anomaly, not a desync: it's excluded from
    /// the `hash16` comparison entirely and just warned about.
    #[test]
    fn a_kind_parity_mismatch_is_an_anomaly_not_a_divergence() {
        let mut m = authority_maker();
        // Slot 1 agrees with slot 0's hash16 at ordinal 0, but reports kind 2
        // for an even ordinal (should be 1) — excluded from the comparison
        // rather than treated as a mismatch (there is no majority/minority
        // split here; a real one is covered by the malformed-kind and
        // ordinary-divergence tests).
        feed_ring_kind(&mut m, 1, 0, SYNC_KIND_HEADER, SYNC_A, 1000);
        let divergence = advance(&mut m, 0, SYNC_A, authority_margin() as u8);
        assert_eq!(
            divergence, None,
            "the kind-mismatched report is excluded, not compared",
        );
        assert!(
            m.sync.kind_parity_warns >= 1,
            "the parity mismatch was flagged",
        );
    }

    /// A `0x37` whose low nibble is neither 1 nor 2 is a malformed sync
    /// command — defensive rejection, since validated bytes shouldn't produce
    /// this. The report is skipped entirely: no member bookkeeping, no
    /// calibration, nothing.
    #[test]
    fn a_malformed_kind_is_skipped_not_recorded() {
        let mut m = authority_maker();
        for bad_kind in [0u8, 3, 7, 15] {
            let divergence = feed_ring_kind(&mut m, 0, 0, bad_kind, SYNC_A, 1000);
            assert_eq!(divergence, None);
        }
        assert!(
            m.sync.members.is_empty(),
            "a malformed kind never creates a member",
        );
        assert!(
            m.sync.malformed_kind_warns >= 1,
            "the malformed kind was flagged",
        );
    }
}
