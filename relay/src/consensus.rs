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

use rally_point_proto::control::BufferBounds;
use rally_point_proto::ids::{GameFrameCount, SlotId};
use rally_point_proto::messages::{BufferDirective, LinkConditions};

use crate::routing::SessionKey;

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
    pub fn session_frame(&self) -> Option<GameFrameCount> {
        self.slots.values().filter_map(|s| s.frame).min()
    }

    /// Records a `game_frame_count` observed on one of `slot`'s validated
    /// turns. Monotonic per slot -- an older frame arriving out of order
    /// doesn't move the observation backward.
    pub fn observe_frame(&mut self, slot: SlotId, frame: GameFrameCount) {
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
    pub fn sync(&mut self, bounds: BufferBounds, authority: Authority) {
        self.bounds = bounds;
        self.set_authority(authority);
    }

    /// Applies a fresh authority verdict without touching the bounds. This is
    /// the presence-driven half of authority tracking: between descriptor
    /// pushes, the verdict moves as relays' players come and go, while the
    /// bounds stay whatever the coordinator last set. A relay losing authority
    /// drops any directive it was still broadcasting — only the authority
    /// stamps — while `decision_seq` is kept, so a later re-promotion keeps
    /// numbering above everything clients have seen.
    pub fn set_authority(&mut self, authority: Authority) {
        if self.authority != authority {
            self.authority = authority;
            if authority == Authority::Peer {
                self.pending_directive = None;
            }
        }
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

    /// Removes a slot's condition history (the client disconnected). Called
    /// when a home client leaves so its stale stats don't outlive its
    /// connection -- mirroring `unpublish_conditions`.
    pub fn remove_slot(&mut self, slot: SlotId) {
        self.slots.remove(&slot);
    }
}

/// A registry of per-session decision-makers, one per session this relay is
/// (or may become) the authority for. Shared across the slot-link and
/// mesh-link tasks that feed conditions in. A plain (non-async) mutex mirrors
/// `MeshLinks` and `routing::Sessions`: every critical section is a short,
/// await-free insert or lookup, so the lock is never held across a turn's
/// delivery.
pub type DecisionMakers = parking_lot::Mutex<HashMap<SessionKey, DecisionMaker>>;

/// Creates an empty decision-maker registry for a relay with no sessions yet.
pub fn new_decision_makers() -> DecisionMakers {
    parking_lot::Mutex::new(HashMap::new())
}

/// Creates a decision-maker for `key`, or reconciles an existing one with the
/// coordinator's current `bounds` and the freshly computed `authority`. Called
/// on every descriptor push: the relay set serving a session changes as
/// players join and leave, and the authority verdict (and bounds) must follow
/// the descriptor rather than stay frozen at whatever the first push said --
/// a frozen verdict could leave a session with two authorities or none.
/// Condition history survives a re-push (see [`DecisionMaker::sync`]).
pub fn sync_maker(
    registry: &DecisionMakers,
    key: &SessionKey,
    bounds: BufferBounds,
    authority: Authority,
) {
    use std::collections::hash_map::Entry;
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
        }
    }
}

/// Applies a fresh authority verdict to a session's decision-maker, if the
/// relay has one, logging a change of authority. The presence-driven handoff
/// path: called when a relay's live-player report flips some relay's liveness,
/// between (and independent of) descriptor pushes. A no-op when no maker
/// exists — a maker is only ever created by a descriptor, which carries the
/// bounds a maker cannot exist without.
pub fn set_authority(registry: &DecisionMakers, key: &SessionKey, authority: Authority) {
    if let Some(maker) = registry.lock().get_mut(key)
        && maker.authority != authority
    {
        maker.set_authority(authority);
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            authority = ?authority,
            "presence moved the session's buffer authority",
        );
    }
}

/// Removes a session's decision-maker (the session has ended). Idempotent.
pub fn deregister_maker(registry: &DecisionMakers, key: &SessionKey) {
    registry.lock().remove(key);
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
        sync_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        {
            let makers = registry.lock();
            let maker = makers.get(&k).unwrap();
            assert_eq!(maker.bounds, bounds(0, 5));
            assert_eq!(maker.authority, Authority::SelfRelay);
        }

        // A lower-id relay joined the session: this relay is no longer the
        // authority, and the coordinator widened the bounds.
        sync_maker(&registry, &k, bounds(0, 99), Authority::Peer);
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
        sync_maker(&registry, &k, bounds(0, 20), Authority::SelfRelay);
        {
            let mut makers = registry.lock();
            let maker = makers.get_mut(&k).unwrap();
            ingest_at(maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
        }
        assert!(active_directive(&registry, &k).is_some());

        sync_maker(&registry, &k, bounds(0, 20), Authority::Peer);
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
        sync_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        assert!(registry.lock().contains_key(&k));
        deregister_maker(&registry, &k);
        assert!(!registry.lock().contains_key(&k));
    }
}
