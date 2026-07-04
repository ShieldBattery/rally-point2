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

use std::collections::HashMap;
use std::sync::OnceLock;

use rally_point_proto::control::{BufferBounds, DepartureKind, DepartureNotice};
use rally_point_proto::ids::{GameFrameCount, SlotId};
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
}

/// One observed slot departure, kept for authority-handoff re-derivation. Holds
/// exactly what deriving the leave's apply frame needs: the departing slot's
/// last observed frame (`None` if it never produced a framed turn -- a lobby
/// departure with no frame basis) and the native leave reason to author. The
/// frame is the max-merge of every observation of this departure (the home
/// relay's carried value, this relay's own view, any re-announce), so the
/// fullest view wins; the reason keeps the first observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Departure {
    last_frame: Option<GameFrameCount>,
    reason: u32,
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
    /// never come, so the leave unstalls them right there. The session frame is
    /// the basis only when the slot never produced a framed turn; it is never
    /// folded in as a max (see [`leave_base_frame`] for why that would strand
    /// stalled survivors). The last frame comes from the slot's departure record
    /// -- captured and merged by [`note_departure`], surviving `remove_slot` --
    /// so every relay derives the identical apply frame from the same record
    /// (clients dedup by slot and require that agreement).
    pub fn decide_leave(&mut self, slot: SlotId, reason: u32) -> Option<LeaveDirective> {
        // Record the departure regardless of the outcome below (even a hold), so
        // a later promotion can re-derive this slot's leave. This merges the
        // slot's own live frame into the record and retires the slot from
        // `slots`; the record is the single frame source from here on.
        self.note_departure(slot, None, reason);

        if self.authority != Authority::SelfRelay {
            return None;
        }
        if self.decided_leaves.contains_key(&slot) {
            return None; // already decided or cached this slot's leave
        }
        let slot_last = self
            .departures
            .get(&slot)
            .and_then(|d| d.last_frame)
            .map(|f| f.0);
        let session = self.session_frame().map(|f| f.0);
        // No framed turn observed anywhere yet (pre-game / lobby): nothing to
        // schedule against, so hold — a `None` short-circuits decide_leave.
        let base = leave_base_frame(slot_last, session)?;
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
    /// view is fuller wins. The reason keeps the first observation.
    pub fn record_departure(
        &mut self,
        slot: SlotId,
        last_frame: Option<GameFrameCount>,
        reason: u32,
    ) {
        self.note_departure(slot, last_frame, reason);
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
        let slot = SlotId(leave.slot as u8);
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
    /// mesh link: every recorded departure (slot, last frame, reason) and every
    /// cached leave, unconditionally. A redialed link starts knowing nothing, so
    /// resending these lets it reconverge — all idempotent (dedup by slot on
    /// receipt). Nothing is filtered as "already applied everywhere": the relay
    /// cannot tell that state apart from "everyone still stalled waiting" (see
    /// [`drain_handoff_leaves`](Self::drain_handoff_leaves)), and the cost of a
    /// redundant re-announce is a few deduped frames, bounded by the slot count.
    #[allow(clippy::type_complexity)]
    fn leave_reconcile(
        &self,
    ) -> (
        Vec<(SlotId, Option<GameFrameCount>, u32)>,
        Vec<LeaveDirective>,
    ) {
        let departures = self
            .departures
            .iter()
            .map(|(slot, departure)| (*slot, departure.last_frame, departure.reason))
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
    /// Removing the slot from `slots` here — on *every* relay, not just the
    /// slot's home — is what lets `session_frame()` follow the survivors: a
    /// departed slot's frozen frame left in place would pin the minimum for the
    /// rest of the game, freezing the buffer machinery's dwell clock and keeping
    /// a pending buffer directive from ever retiring. The
    /// `observe_frame`/`ingest` guards keep late in-flight traffic from
    /// resurrecting the entry.
    fn note_departure(&mut self, slot: SlotId, last_frame: Option<GameFrameCount>, reason: u32) {
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
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Departure {
                    last_frame: merged,
                    reason,
                });
            }
        }
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

/// A registry of per-session decision-makers, one per session this relay is
/// (or may become) the authority for. Shared across the slot-link and mesh-link
/// tasks that feed conditions in.
///
/// It also owns an optional **departure notifier** — the sender half of an
/// unbounded channel drained by the coordinator control connection. The leave
/// sites ([`decide_leave`], [`observe_leave`], and the promotion re-derivation
/// in [`set_authority`]/[`sync_maker`]) fire a [`DepartureNotice`] onto it the
/// moment a synced leave for a slot first enters this relay's cache, so the
/// coordinator learns "player X left vs. was dropped". The notifier is set once
/// at startup when a coordinator is configured and is simply absent when the
/// relay runs standalone (no coordinator to notify), where firing is a no-op.
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
    departures: OnceLock<UnboundedSender<DepartureNotice>>,
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

    /// Installs the departure notifier — the sender half of the channel the
    /// coordinator control connection drains. Set once at startup; a second call
    /// is ignored (the first sender wins), matching the "one coordinator link
    /// per relay" reality.
    pub fn set_departure_notifier(&self, sender: UnboundedSender<DepartureNotice>) {
        let _ = self.departures.set(sender);
    }

    /// Fires a departure notice up the coordinator control connection, if a
    /// notifier is installed. A no-op on a standalone relay. The channel is
    /// unbounded, so this never blocks; a send error means the drain end is gone
    /// (no coordinator subscriber), which for a standalone relay is expected.
    fn notify_departure(&self, notice: DepartureNotice) {
        if let Some(sender) = self.departures.get() {
            let _ = sender.send(notice);
        }
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
}

/// Creates an empty decision-maker registry for a relay with no sessions yet,
/// and no departure notifier installed (a standalone relay, or before startup
/// wiring calls [`DecisionMakers::set_departure_notifier`]).
pub fn new_decision_makers() -> DecisionMakers {
    DecisionMakers {
        makers: parking_lot::Mutex::new(HashMap::new()),
        departures: OnceLock::new(),
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
    }
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
    reason: u32,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.record_departure(slot, last_frame, reason);
    }
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

/// This relay's known leave state for `key` — every recorded departure and every
/// cached leave — for re-announcing to a freshly (re)joined mesh link. Empty when
/// no maker exists. See [`DecisionMaker::leave_reconcile`].
#[allow(clippy::type_complexity)]
pub fn leave_reconcile(
    registry: &DecisionMakers,
    key: &SessionKey,
) -> (
    Vec<(SlotId, Option<GameFrameCount>, u32)>,
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

    /// Deciding a leave on the authority fires exactly one departure notice for
    /// the slot, classified from the reason; a duplicate signal for the same slot
    /// decides nothing and so fires no second notice.
    #[test]
    fn decide_leave_fires_one_departure_notice_on_the_authority() {
        let registry = new_decision_makers();
        let k = key();
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_departure_notifier(tx);

        // A framed turn from slot 0 gives decide_leave a basis to schedule.
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(50));

        let leave = decide_leave(&registry, &k, SlotId(1), DROPPED).expect("a leave is decided");
        let notice = rx.try_recv().expect("exactly one departure notice");
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
        registry.set_departure_notifier(tx);

        let leave = LeaveDirective {
            slot: 2,
            reason: 3,
            apply_at_frame: 90,
            leave_seq: 7,
        };
        observe_leave(&registry, &k, &leave);
        let notice = rx.try_recv().expect("one notice on the first insert");
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
        registry.set_departure_notifier(tx);

        // Starts as a peer: it records a departure off a mesh `SlotDeparted` but
        // never decides (not the authority), so nothing is cached and nothing
        // fires yet.
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        record_departure(&registry, &k, SlotId(1), Some(GameFrameCount(50)), 3);
        assert!(rx.try_recv().is_err(), "recording alone fires nothing");

        // Promoted (the dead authority was the only other relay in the
        // topology): the departure has no cached directive anywhere, so this
        // relay derives it fresh — a first insert into its cache — and must
        // fire the one notice for it.
        let leaves = set_authority(&registry, &k, Authority::SelfRelay);
        assert_eq!(leaves.len(), 1, "the re-derived leave still broadcasts");

        let notice = rx
            .try_recv()
            .expect("exactly one departure notice fires on the re-derivation");
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
        registry.set_departure_notifier(tx);

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
        registry.set_departure_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);

        registry.set_session_refs(
            &k,
            Some("game-99".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-7".to_owned())]),
        );

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let notice = rx.try_recv().expect("one notice");
        assert_eq!(notice.external_id, Some("game-99".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-7".to_owned()));
    }

    /// `observe_leave` (the non-authority path) stamps the same way.
    #[test]
    fn observe_leave_stamps_session_refs_into_the_notice() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_departure_notifier(tx);
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

        let notice = rx.try_recv().expect("one notice");
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
        registry.set_departure_notifier(tx);

        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
        registry.set_session_refs(
            &k,
            Some("game-2".to_owned()),
            HashMap::from([(SlotId(1), "sb-user-9".to_owned())]),
        );
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        record_departure(&registry, &k, SlotId(1), Some(GameFrameCount(50)), 3);
        assert!(rx.try_recv().is_err(), "recording alone fires nothing");

        let _ = set_authority(&registry, &k, Authority::SelfRelay);
        let notice = rx.try_recv().expect("one notice on the re-derivation");
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
        registry.set_departure_notifier(tx);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);

        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());

        let notice = rx.try_recv().expect("one notice");
        assert!(notice.external_id.is_none());
        assert!(notice.external_ref.is_none());
    }

    /// `set_session_refs` replaces rather than accumulates on a re-apply (a
    /// changed descriptor), and `deregister_maker` forgets a session's refs so
    /// the map doesn't outlive the session it describes.
    #[test]
    fn set_session_refs_replaces_on_reapply_and_deregister_forgets() {
        let registry = new_decision_makers();
        let k = key();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        registry.set_departure_notifier(tx);
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
        let notice = rx.try_recv().expect("one notice");
        assert_eq!(notice.external_id, Some("game-new".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-new".to_owned()));

        // Deregistering the maker also forgets the refs: a later decide_leave
        // on a freshly re-created maker for the same key sees none.
        deregister_maker(&registry, &k);
        let _ = sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        observe_frame(&registry, &k, SlotId(0), GameFrameCount(40));
        assert!(decide_leave(&registry, &k, SlotId(1), DROPPED).is_some());
        let notice2 = rx.try_recv().expect("one notice");
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);
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
        maker.record_departure(SlotId(1), read, DROPPED);
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(60)), DROPPED);
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(55)), DROPPED);
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);
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

        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);
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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);

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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);

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
        maker.record_departure(SlotId(1), Some(GameFrameCount(50)), DROPPED);
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
}
