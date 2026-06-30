//! The latency-buffer decision-maker: the relay-side core of the runtime
//! consensus authority.
//!
//! This is the *decision* half of D9 -- which relay decides, from what data,
//! and the control law that turns network conditions into a buffer-size change.
//! It is pure and synchronous: no I/O, no async, no locks of its own. The
//! [`DecisionMaker`] is fed conditions and game-frame observations by its caller
//! and returns a [`Decision`] describing what (if anything) to broadcast. The
//! broadcast wire format -- native `0x55` (clamped `[0,2]`, with an out-of-band
//! latency-label trap past 2) vs. a custom control command -- is a deliberate
//! open design step (see the SC:R replacement guide S4 / S5.3); this module
//! emits the *decision* and the target frame, not the bytes.
//!
//! # Authority and authority handoff
//!
//! The relays sit in a fixed priority order; the highest still serving live
//! players is the decision-maker. (Multiple relays serving one game is the
//! *normal* case -- players in different regions each connect to a nearby
//! relay, and the mesh carries turns between them. "Handoff" is specifically
//! when the authority relay drops out -- its players have all left -- and
//! authority falls to the next relay in the order, with no coordinator
//! round-trip.) That handoff needs the coordinator-assigned priority order and
//! a presence signal, both of which land with the mesh wiring + coordinator
//! (Phase 3). So authority is taken as an **injected input**: a single relay
//! passes `Authority::SelfRelay` and the decision core runs unchanged once
//! peer conditions flow in.
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
//! past the point where a mid-turn latency change is safe. The decision-maker
//! schedules the change a fixed horizon ahead of the latest frame it has seen
//! -- long enough that every client receives the broadcast before that frame
//! arrives, short enough that a worsening condition isn't delayed.

use std::collections::HashMap;

use rally_point_proto::control::BufferBounds;
use rally_point_proto::ids::{GameFrameCount, SlotId};
use rally_point_proto::messages::LinkConditions;

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
/// `applied_frame` is scheduled a horizon ahead of the latest observed frame
/// so the broadcast reaches every client before that frame arrives.
///
/// This is the decision, not the broadcast: the wire format (native `0x55`
/// vs. a custom control command) and the origination `(slot, seq)` a relay uses
/// to inject the command into the per-slot stream without colliding with a
/// client's own seq space are a deliberate design step (see module docs + the
/// SC:R replacement guide). The caller translates a `Decision` into bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The buffer size to apply, clamped to the coordinator's bounds.
    pub buffer: BufferSize,
    /// The frame at which every client must apply the new buffer. Guaranteed
    /// `> latest_observed_frame` at decision time (the horizon is added to the
    /// max frame the authority has seen).
    pub applied_frame: GameFrameCount,
}

/// How far ahead of the latest observed frame a buffer change is scheduled.
///
/// Long enough that the broadcast reaches every client before the target frame
/// arrives (the mesh forwards in arrival order with no reordering latency, and
/// redundancy covers loss); short enough that a worsening condition isn't
/// delayed past a turn or two. In turns: at the 24/sec turn rate, one turn is
/// ~42ms, so a horizon of a few turns is well under a quarter-second of
/// scheduling slack -- comfortable for any reasonable mesh RTT, tight enough
/// that a player feeling lag sees relief promptly.
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
/// counter differencing for loss, mesh-hop RTT for cross-relay paths), the
/// current buffer size, the last frame a decision was made at (for min-dwell
/// on lowers), and the max frame observed (to schedule the horizon relative to
/// the game's actual leading edge).
///
/// One instance per session the relay is the authority for. Fed conditions and
/// frame observations by `run_slot_link` (home-client conditions, via
/// [`ingest_local`](Self::ingest_local)) and `run_mesh_link` (peer-relay
/// conditions, via [`ingest_remote`](Self::ingest_remote)) -- but only when
/// `Authority::SelfRelay`.
pub struct DecisionMaker {
    key: SessionKey,
    bounds: BufferBounds,
    law: ControlLaw,
    authority: Authority,

    /// The current buffer size, clamped to bounds. Starts at `bounds.min`.
    buffer: BufferSize,
    /// Per-slot condition history.
    slots: HashMap<SlotId, SlotState>,
    /// The latest `game_frame_count` observed across all conditions-bearing
    /// payloads for this session.
    max_frame: GameFrameCount,
    /// The `max_frame` at which the last decision was *made* (not applied --
    /// the applied frame is `max_frame + APPLY_HORIZON`). Used to gate lowers:
    /// a lower is suppressed until `max_frame - last_decision_frame >=
    /// min_dwell_turns`. Raises are never suppressed (you can't dwell through
    /// a stall).
    last_decision_frame: Option<GameFrameCount>,
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
            max_frame: GameFrameCount(0),
            last_decision_frame: None,
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

    /// The latest `game_frame_count` observed for this session.
    pub fn max_frame(&self) -> GameFrameCount {
        self.max_frame
    }

    /// Whether this relay is the decision-making authority for this session.
    pub fn is_authority(&self) -> bool {
        self.authority == Authority::SelfRelay
    }

    /// Ingests this relay's own home-client `LinkConditions` (conditions the
    /// relay observed directly on its local clients) and the `game_frame_count`
    /// the carrying datagram was observed at.
    ///
    /// Local slots have `mesh_rtt = 0` (no mesh hop -- this relay). RTT samples are pushed into the per-slot ring buffer for
    /// jitter-aware sizing. Cumulative loss counters are rotated so the next
    /// decision can difference them. `max_frame` advances to `frame` if newer.
    ///
    /// Returns a [`Decision`] if the control law fires a change, `None` if it
    /// holds (target unchanged, or min-dwell suppressing a lower, or this
    /// relay is not the authority). The caller translates a returned decision
    /// into a broadcast.
    pub fn ingest_local(
        &mut self,
        conditions: &LinkConditions,
        frame: GameFrameCount,
    ) -> Option<Decision> {
        self.ingest(conditions, 0, frame)
    }

    /// Ingests a peer relay's `LinkConditions` sidecar (conditions the peer
    /// relay observed on its own home clients, forwarded across the mesh) and
    /// the `game_frame_count` the carrying datagram was observed at.
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
        frame: GameFrameCount,
    ) -> Option<Decision> {
        self.ingest(conditions, mesh_rtt_us, frame)
    }

    /// Shared ingestion: pushes RTT samples, rotates loss counters, sets the
    /// mesh hop, then runs `decide` if this relay is the authority.
    fn ingest(
        &mut self,
        conditions: &LinkConditions,
        mesh_rtt_us: u32,
        frame: GameFrameCount,
    ) -> Option<Decision> {
        if frame > self.max_frame {
            self.max_frame = frame;
        }

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
                && self.max_frame.0.saturating_sub(last.0) < self.law.min_dwell_turns
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

        self.buffer = BufferSize(new_buffer);
        let applied_frame = GameFrameCount(self.max_frame.0.saturating_add(APPLY_HORIZON));
        self.last_decision_frame = Some(self.max_frame);

        Some(Decision {
            buffer: self.buffer,
            applied_frame,
        })
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

/// Creates a decision-maker for `key` if one doesn't exist, bound to `bounds`
/// and `authority`. The caller (the slot-link or mesh-link task that first
/// sees the session) supplies the bounds the coordinator pushed and the
/// authority verdict. Idempotent: a second call for an existing session is a
/// no-op (the first call's bounds and authority win), so a slot-link task and
/// a mesh-link task racing to create the same session can't clobber each other.
pub fn ensure_maker(
    registry: &DecisionMakers,
    key: &SessionKey,
    bounds: BufferBounds,
    authority: Authority,
) {
    let mut makers = registry.lock();
    makers.entry(key.clone()).or_insert_with(|| {
        DecisionMaker::new(key.clone(), bounds, ControlLaw::default(), authority)
    });
}

/// Removes a session's decision-maker (the session has ended). Idempotent.
pub fn deregister_maker(registry: &DecisionMakers, key: &SessionKey) {
    registry.lock().remove(key);
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

    // -- Target formula --

    /// At 150ms RTT, 0% loss: target == ceil(150000/41666.67) + 0 = 4.
    #[test]
    fn target_at_150ms_zero_loss() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        assert_eq!(maker.target(), Some(4));
    }

    /// At 150ms RTT, 5% loss: loss_risk = 0.05 ** 150000 = 7500us.
    /// Separated: ceil(150000/41666.67) + ceil(7500/41666.67) = 4 + 1 = 5.
    #[test]
    fn target_loss_recovery_is_quantized_to_whole_turns() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        let _ = maker.ingest_local(&conditions(0, 150_000, 5, 200), GameFrameCount(2));
        assert_eq!(maker.target(), Some(5));
    }

    /// At 50ms RTT, 0% loss: target = ceil(50000/41666.67) = 2.
    #[test]
    fn target_at_low_latency() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(1));
        assert_eq!(maker.target(), Some(2));
    }

    /// At 10ms RTT: target = ceil(10000/41666.67) = 1. The ceil naturally
    /// gives 1 for any positive RTT -- no separate floor.
    #[test]
    fn target_floor_falls_out_of_ceil() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 10_000, 0, 100), GameFrameCount(1));
        assert_eq!(maker.target(), Some(1));
    }

    /// No RTT measurement (rtt_us == 0): target is None (hold).
    #[test]
    fn target_none_when_no_rtt() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 0, 0, 100), GameFrameCount(1));
        assert_eq!(maker.target(), None);
    }

    // -- Pairwise path --

    /// Two slots at 100ms and 200ms: path = (200000 + 100000) / 2 = 150000.
    #[test]
    fn worst_pair_path_uses_two_highest_rtts() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(
            &multi_conditions(&[(0, 100_000, 0, 100), (1, 200_000, 0, 100)]),
            GameFrameCount(1),
        );
        assert_eq!(maker.target(), Some(4));
    }

    /// One outlier at 300ms, rest at 20ms: path = (300000 + 20000) / 2 = 160000.
    #[test]
    fn single_outlier_does_not_over_provision() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(
            &multi_conditions(&[
                (0, 20_000, 0, 100),
                (1, 300_000, 0, 100),
                (2, 20_000, 0, 100),
            ]),
            GameFrameCount(1),
        );
        assert_eq!(maker.target(), Some(4));
    }

    // -- Mesh hop --

    /// A remote slot's effective RTT includes the mesh hop.
    #[test]
    fn mesh_hop_increases_target_for_cross_relay_paths() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(1));
        maker.ingest_remote(&conditions(1, 50_000, 0, 100), 100_000, GameFrameCount(2));
        // eff_local = 50000, eff_remote = 150000.
        // path = (150000 + 50000) / 2 = 100000. target = ceil(100000/41666.67) = 3.
        assert_eq!(maker.target(), Some(3));
    }

    /// Without the mesh hop, two 50ms slots would give target 2.
    #[test]
    fn mesh_hop_adds_turns_above_same_relay_baseline() {
        let mut local = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        local.ingest_local(
            &multi_conditions(&[(0, 50_000, 0, 100), (1, 50_000, 0, 100)]),
            GameFrameCount(1),
        );
        let local_target = local.target().unwrap();

        let mut meshed = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        meshed.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(1));
        meshed.ingest_remote(&conditions(1, 50_000, 0, 100), 100_000, GameFrameCount(2));
        let meshed_target = meshed.target().unwrap();

        assert!(meshed_target > local_target);
    }

    // -- Loss on high-latency links --
    // -- Loss on high-latency links --

    /// Same 20% loss on 50ms vs 300ms: the high-latency link needs more turns.
    #[test]
    fn loss_on_high_latency_link_adds_more_turns() {
        let mut low = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        low.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(1));
        low.ingest_local(&conditions(0, 50_000, 20, 200), GameFrameCount(2));
        let low_target = low.target().unwrap();

        let mut high = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        high.ingest_local(&conditions(0, 300_000, 0, 100), GameFrameCount(1));
        high.ingest_local(&conditions(0, 300_000, 20, 200), GameFrameCount(2));
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
            maker.ingest_local(&conditions(0, 100_000, 0, 100), GameFrameCount(frame));
        }
        maker.ingest_local(&conditions(0, 200_000, 0, 100), GameFrameCount(5));

        assert_eq!(maker.target(), Some(5));
    }

    /// Without the spike, the target would be lower.
    #[test]
    fn jitter_spike_raises_target_above_baseline() {
        let mut spiky = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        for frame in 1..=4 {
            spiky.ingest_local(&conditions(0, 100_000, 0, 100), GameFrameCount(frame));
        }
        spiky.ingest_local(&conditions(0, 200_000, 0, 100), GameFrameCount(5));

        let mut stable = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        for frame in 1..=5 {
            stable.ingest_local(&conditions(0, 100_000, 0, 100), GameFrameCount(frame));
        }

        assert!(spiky.target().unwrap() > stable.target().unwrap());
    }

    // -- Raise fast, lower slow (asymmetric dwell) --

    /// Raise jumps to the target immediately, not incrementally.
    #[test]
    fn raise_jumps_to_target() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        let d = maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
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
        let d = maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(1));
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
        let d1 = maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        assert_eq!(d1.unwrap().buffer, BufferSize(4));

        // Conditions worsen at frame 2 (within 120-turn dwell). Raise fires
        // immediately -- no dwell on raises.
        let d2 = maker.ingest_local(&conditions(0, 300_000, 0, 100), GameFrameCount(2));
        assert_eq!(
            d2.unwrap().buffer,
            BufferSize(8),
            "raise should fire immediately"
        );
        assert_eq!(maker.buffer(), BufferSize(8));

        // Conditions improve at frame 3 (within dwell from the raise at 2).
        // Lower is suppressed -- and the ring buffer still holds the 300ms
        // spike, so the target stays at 8 anyway.
        let d3 = maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(3));
        assert_eq!(d3, None, "lower should be suppressed within dwell");
        assert_eq!(maker.buffer(), BufferSize(8));

        // Flush the 300ms spike from the ring buffer (32 samples) so the
        // recent max drops to 50ms. Frames 4--35.
        for frame in 4..=35 {
            let _ = maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(frame));
        }
        // Now the target is 2 (50ms), but we're still within the dwell.
        assert_eq!(maker.target(), Some(2));

        // After the dwell (frame 2 + 120 = 122, so frame 123). Lower fires.
        let d4 = maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(123));
        assert!(d4.is_some(), "lower should fire after dwell");
        assert_eq!(maker.buffer(), BufferSize(7));
    }

    /// Anti-flap: an oscillating target raises on the first worsening, then
    /// holds (lowers suppressed) through the dwell.
    #[test]
    fn anti_flap_raises_on_worsening_holds_on_improvement() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // 150ms -> target 4. Raise to 4 at frame 1.
        let d = maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        assert_eq!(d.unwrap().buffer, BufferSize(4));

        // Target drops to 2 (50ms) at frame 2 -- lower suppressed.
        let d = maker.ingest_local(&conditions(0, 50_000, 0, 100), GameFrameCount(2));
        assert_eq!(d, None);

        // Target spikes to 8 (300ms) at frame 3 -- raise fires immediately.
        let d = maker.ingest_local(&conditions(0, 300_000, 0, 100), GameFrameCount(3));
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
        let d = maker.ingest_local(&conditions(0, 300_000, 0, 100), GameFrameCount(1));
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
        let d = maker.ingest_local(&conditions(0, 10_000, 0, 100), GameFrameCount(1));
        assert_eq!(d.unwrap().buffer, BufferSize(2));
        assert_eq!(maker.buffer(), BufferSize(2));
    }

    // -- Authority --

    /// A non-authority relay ingests conditions but makes no decision.
    #[test]
    fn non_authority_ingests_but_does_not_decide() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer);
        let d = maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        assert_eq!(d, None, "non-authority makes no decision");
        assert_eq!(maker.max_frame(), GameFrameCount(1));
        assert_eq!(maker.target(), Some(4));
    }

    // -- Frame tracking --

    /// `max_frame` tracks the latest observed frame.
    #[test]
    fn max_frame_tracks_latest() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 10_000, 0, 100), GameFrameCount(5));
        assert_eq!(maker.max_frame(), GameFrameCount(5));
        maker.ingest_local(&conditions(0, 10_000, 0, 100), GameFrameCount(3));
        assert_eq!(maker.max_frame(), GameFrameCount(5));
        maker.ingest_local(&conditions(0, 10_000, 0, 100), GameFrameCount(10));
        assert_eq!(maker.max_frame(), GameFrameCount(10));
    }

    /// The applied frame is always `max_frame + APPLY_HORIZON`.
    #[test]
    fn applied_frame_is_horizon_ahead_of_max() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        let d = maker
            .ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(50))
            .unwrap();
        assert_eq!(d.applied_frame, GameFrameCount(53));
        assert!(d.applied_frame.0 > 50);
    }

    // -- Loss differencing --

    /// A stale sidecar (non-monotonic counters) produces no negative loss.
    #[test]
    fn stale_sidecar_no_spurious_loss() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        let d = maker.ingest_local(&conditions(0, 150_000, 0, 50), GameFrameCount(2));
        assert_eq!(maker.target(), Some(4));
        assert_eq!(d, None);
    }

    /// Regression: lossy interval THEN clean interval must drop the target.
    /// Raises fire immediately; the lower waits for the dwell.
    #[test]
    fn lossy_then_clean_interval_drops_target() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        // Baseline at frame 1 (raises to 4, sets the dwell clock).
        maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));

        // 50% loss at frame 22 (raise fires immediately -- no dwell on raises).
        // loss_risk = 0.5 ** 150000 = 75000. Target = 4 + 2 = 6.
        let d1 = maker.ingest_local(&conditions(0, 150_000, 50, 200), GameFrameCount(2));
        assert_eq!(d1.unwrap().buffer, BufferSize(6));

        // Clean interval at frame 3 (loss_risk = 0, target = 4). But this is a
        // lower, and we're within the 120-turn dwell from the raise at frame 2.
        let d2 = maker.ingest_local(&conditions(0, 150_000, 50, 300), GameFrameCount(3));
        assert_eq!(d2, None, "lower suppressed within dwell");
        assert_eq!(maker.target(), Some(4));

        // After the dwell (frame 2 + 120 = 122, so frame 123). Lower fires.
        let d3 = maker.ingest_local(&conditions(0, 150_000, 50, 300), GameFrameCount(123));
        assert!(d3.is_some(), "lower should fire after dwell");
        assert_eq!(maker.buffer(), BufferSize(5));
    }

    // -- Slot removal --

    /// `remove_slot` clears a departing client's history.
    #[test]
    fn remove_slot_clears_history() {
        let mut maker = DecisionMaker::new(key(), bounds(0, 20), law(), Authority::SelfRelay);
        maker.ingest_local(&conditions(0, 150_000, 0, 100), GameFrameCount(1));
        assert!(maker.slots.contains_key(&SlotId(0)));
        assert!(maker.target().is_some());
        maker.remove_slot(SlotId(0));
        assert!(!maker.slots.contains_key(&SlotId(0)));
        assert_eq!(maker.target(), None, "no slots means no target");
    }

    // -- Registry --

    /// `ensure_maker` is idempotent -- a second call doesn't clobber.
    #[test]
    fn ensure_maker_is_idempotent() {
        let registry = new_decision_makers();
        let k = key();
        ensure_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        ensure_maker(&registry, &k, bounds(0, 99), Authority::Peer);
        let makers = registry.lock();
        let maker = makers.get(&k).unwrap();
        assert_eq!(maker.bounds, bounds(0, 5));
        assert_eq!(maker.authority, Authority::SelfRelay);
    }

    /// `deregister_maker` removes a session's decision-maker.
    #[test]
    fn deregister_maker_removes_session() {
        let registry = new_decision_makers();
        let k = key();
        ensure_maker(&registry, &k, bounds(0, 5), Authority::SelfRelay);
        assert!(registry.lock().contains_key(&k));
        deregister_maker(&registry, &k);
        assert!(!registry.lock().contains_key(&k));
    }
}
