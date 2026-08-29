//! Scenario simulation for the redundancy re-carry policy: real [`AckManager`]
//! pairs driven through synthetic network weather, comparing how refill
//! policies ([`RecarryPolicy`]) spend bytes and recover losses.
//!
//! The question this bench exists to answer: how should a packet's redundancy
//! refill be bounded so that bundle bytes stay flat when the path is squeezed,
//! without giving up the next-packet recovery that makes isolated loss
//! invisible? The failure mode it must reproduce is the production episode
//! shape: a last-mile fade inflates RTT, the unacked window grows with RTT,
//! the unbounded refill re-carries the whole window every packet, and the
//! extra bytes deepen the very queue that inflated RTT — byte amplification
//! exactly when the path can least afford it.
//!
//! Unlike the relay's `buffer_law_sim` (which models counters feeding the
//! control law), this bench runs the *real* transport bookkeeping: both
//! endpoints are live [`AckManager`]s, packets are really built, acked,
//! retired, and force-retired through the same code paths production uses, so
//! a policy's simulated behavior is its shipped behavior. The network in
//! between is stylized:
//!
//! - **Forward path** (the direction under test — a relay's fan-out edge to
//!   one client): base one-way delay, per-packet loss (iid, burst, or a full
//!   blackout window), and optionally a **congestion-window bottleneck** — a
//!   byte cap on what may be in flight, with a FIFO queue in front of it. A
//!   packet waits in the queue until the cap has room, so queue delay grows
//!   with offered bytes: the coupling that lets an unbounded policy melt down
//!   and a bounded one drain.
//! - **Reverse path**: the peer's ack packets ride back over an independently
//!   configured (typically healthy) path, matching the production episode
//!   where the downlink faded while the uplink stayed clean.
//! - **Ack-beacon backstop**: the receiver's contiguous delivered prefix is
//!   shipped back periodically and force-retires the sender's window
//!   ([`AckManager::retire_payloads_through`]), exactly as the reliable
//!   beacon stream does in production.
//!
//! `cargo test -p rally-point-transport recarry_sim -- --ignored --nocapture`
//! prints the per-scenario policy comparison tables for tuning sessions; the
//! non-ignored tests pin the properties the chosen policy is trusted for.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckManager, CarrySpacing, RecarryPolicy};

/// One game turn at the SC:R rate, in milliseconds.
const TURN_MS: f64 = 1000.0 / 24.0;

/// The datagram budget handed to `build_outgoing` — quinn's
/// `max_datagram_size()` for a typical path MTU.
const DATAGRAM_BUDGET: usize = 1350;

/// Per-datagram overhead charged to the bottleneck beyond the encoded packet:
/// UDP/IP headers plus QUIC short-header framing and AEAD tag.
const DATAGRAM_OVERHEAD_BYTES: f64 = 50.0;

/// How long after a lost packet's send the bottleneck frees its in-flight
/// bytes — standing in for QUIC's loss declaration (time-threshold ~9/8 RTT).
const LOSS_RELEASE_PENALTY_MS: f64 = 60.0;

/// Deterministic xorshift64* PRNG, mirroring `buffer_law_sim`'s: reproducible
/// runs without a rand dev-dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, 1)`.
    fn chance(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Per-packet loss on one path.
enum LossModel {
    None,
    /// Independent per-packet loss probability.
    Iid(f64),
    /// Gilbert-Elliott: good/bad states; loss only in bad. Approximates the
    /// bursty shape of wifi/last-mile fades.
    Burst {
        enter_bad: f64,
        exit_bad: f64,
        loss_in_bad: f64,
        bad: bool,
    },
    /// Total loss inside the window, `base` outside it.
    Blackout {
        from_ms: f64,
        to_ms: f64,
        base: f64,
    },
    /// Elevated iid loss inside a window, a lower base rate outside it — the
    /// episode shape of a periodic last-mile fade.
    Window {
        from_ms: f64,
        to_ms: f64,
        in_window: f64,
        outside: f64,
    },
}

impl LossModel {
    fn lost(&mut self, now_ms: f64, rng: &mut Rng) -> bool {
        match self {
            LossModel::None => false,
            LossModel::Iid(p) => rng.chance() < *p,
            LossModel::Burst {
                enter_bad,
                exit_bad,
                loss_in_bad,
                bad,
            } => {
                if *bad {
                    if rng.chance() < *exit_bad {
                        *bad = false;
                    }
                } else if rng.chance() < *enter_bad {
                    *bad = true;
                }
                *bad && rng.chance() < *loss_in_bad
            }
            LossModel::Blackout {
                from_ms,
                to_ms,
                base,
            } => {
                if now_ms >= *from_ms && now_ms < *to_ms {
                    true
                } else {
                    rng.chance() < *base
                }
            }
            LossModel::Window {
                from_ms,
                to_ms,
                in_window,
                outside,
            } => {
                let p = if now_ms >= *from_ms && now_ms < *to_ms {
                    *in_window
                } else {
                    *outside
                };
                rng.chance() < p
            }
        }
    }
}

/// A congestion-window bottleneck on the forward path: bytes admitted to the
/// wire only while the in-flight total is under `cwnd_bytes(now)`; excess
/// waits in a FIFO whose depth is the queue delay. In-flight bytes release
/// when the (simulated) QUIC ack returns, so an inflated round trip slows the
/// release rate and offered bytes above `cwnd / RTT` grow the queue without
/// bound — the production feedback loop this bench exists to reproduce.
struct Bottleneck {
    /// The cap, as a function of time — lets a scenario crush it for an
    /// episode window and restore it after, matching the observed prod shape
    /// (Cubic pinned at its floor for the fade's duration).
    cwnd_bytes: fn(now_ms: f64) -> f64,
    queue: VecDeque<QueuedSend>,
    queue_bytes: f64,
    /// Tail-drop threshold for the sender-side queue.
    queue_cap_bytes: f64,
    in_flight_bytes: f64,
    /// Queue drops, for the run report.
    dropped: u64,
}

struct QueuedSend {
    bytes: f64,
    packet: Packet,
}

/// One direction of the network.
struct PathModel {
    owd_ms: f64,
    /// Extra one-way delay applied inside a `(from_ms, to_ms)` window — the
    /// exogenous last-mile bufferbloat of a fade episode, which is what
    /// slows in-flight release and makes a crushed congestion window bind.
    bloat: Option<(f64, f64, f64)>,
    loss: LossModel,
    bottleneck: Option<Bottleneck>,
}

impl PathModel {
    fn owd_at(&self, now_ms: f64) -> f64 {
        match self.bloat {
            Some((from, to, extra)) if now_ms >= from && now_ms < to => self.owd_ms + extra,
            _ => self.owd_ms,
        }
    }
}

/// Event kinds, processed in time order.
enum EventKind {
    /// The sender's per-turn builds: fresh payloads for this tick.
    SenderTick,
    /// The receiver's per-turn build: its ack-carrying packet plus a beacon
    /// cursor snapshot.
    ReceiverTick,
    /// A forward-path packet arrives at the receiver.
    DeliverForward(Packet),
    /// A reverse-path packet arrives at the sender.
    DeliverReverse(Packet),
    /// The bottleneck releases in-flight bytes (an ack returned, or a loss was
    /// declared) and may admit queued packets.
    CwndRelease(f64),
    /// The receiver's delivered-prefix cursors reach the sender.
    BeaconArrive(Vec<(SlotId, u64)>),
}

struct Event {
    at_us: u64,
    order: u64,
    kind: EventKind,
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        (self.at_us, self.order) == (other.at_us, other.order)
    }
}
impl Eq for Event {}
impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.at_us, self.order).cmp(&(other.at_us, other.order))
    }
}

/// Per-slot receive-side tracking: the contiguous delivered prefix (what the
/// beacon reports) plus out-of-order arrivals above it.
#[derive(Default)]
struct PrefixTracker {
    /// Highest seq such that all seqs `0..=delivered_through` have arrived, or
    /// `None` when seq 0 itself hasn't.
    delivered_through: Option<u64>,
    above: BTreeSet<u64>,
}

impl PrefixTracker {
    fn record(&mut self, seq: u64) {
        let next = self.delivered_through.map_or(0, |d| d + 1);
        if seq < next {
            return;
        }
        self.above.insert(seq);
        let mut next = next;
        while self.above.remove(&next) {
            self.delivered_through = Some(next);
            next += 1;
        }
    }
}

/// The scenario definition a run executes.
struct Scenario {
    name: &'static str,
    duration_ms: f64,
    /// Fresh payloads the sender originates per turn tick (3 models a 4-player
    /// downlink fan-out; 1 models a client uplink).
    fresh_per_tick: u32,
    /// The window whose payloads get their own latency report — the fade
    /// episode, when the scenario has one. Whole-run percentiles average the
    /// episode away; these are the turns players actually felt.
    episode_window: Option<(f64, f64)>,
    forward: fn() -> PathModel,
    reverse: fn() -> PathModel,
}

/// What one run measured.
struct RunStats {
    delivered_latencies_turns: Vec<f64>,
    /// Latencies of just the payloads created inside the scenario's episode
    /// window — what players felt during the fade, unwashed by the healthy
    /// remainder of the run.
    episode_latencies_turns: Vec<f64>,
    /// Mean encoded packet size over forward packets built inside the episode
    /// window (numerator/denominator pair).
    episode_fwd_bytes: f64,
    episode_fwd_packets: u64,
    undelivered: u64,
    total_payloads: u64,
    fwd_packets: u64,
    fwd_bytes: f64,
    max_fwd_packet_bytes: usize,
    queue_drops: u64,
    wire_losses: u64,
    max_prefix_lag_turns: u64,
    /// For blackout scenarios: milliseconds from the end of the outage until
    /// every payload created before it had been delivered.
    backlog_clear_after_ms: Option<f64>,
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

impl RunStats {
    fn percentile(&self, p: f64) -> f64 {
        percentile(&self.delivered_latencies_turns, p)
    }

    fn mean_bytes_per_packet(&self) -> f64 {
        if self.fwd_packets == 0 {
            return 0.0;
        }
        self.fwd_bytes / self.fwd_packets as f64
    }

    fn episode_mean_bytes_per_packet(&self) -> f64 {
        if self.episode_fwd_packets == 0 {
            return 0.0;
        }
        self.episode_fwd_bytes / self.episode_fwd_packets as f64
    }

    /// Folds another seed's run into this one: latencies pool, counters sum,
    /// maxima take the worse run.
    fn merge(&mut self, other: RunStats) {
        self.delivered_latencies_turns
            .extend(other.delivered_latencies_turns);
        self.episode_latencies_turns
            .extend(other.episode_latencies_turns);
        self.episode_fwd_bytes += other.episode_fwd_bytes;
        self.episode_fwd_packets += other.episode_fwd_packets;
        self.undelivered += other.undelivered;
        self.total_payloads += other.total_payloads;
        self.fwd_packets += other.fwd_packets;
        self.fwd_bytes += other.fwd_bytes;
        self.max_fwd_packet_bytes = self.max_fwd_packet_bytes.max(other.max_fwd_packet_bytes);
        self.queue_drops += other.queue_drops;
        self.wire_losses += other.wire_losses;
        self.max_prefix_lag_turns = self.max_prefix_lag_turns.max(other.max_prefix_lag_turns);
        self.backlog_clear_after_ms =
            match (self.backlog_clear_after_ms, other.backlog_clear_after_ms) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
    }
}

/// A tiny turn payload with a plausibly-sized command blob.
fn turn_payload(slot: u8, seq: u64, rng: &mut Rng) -> Payload {
    // Mostly small orders, occasionally a chunky selection/build batch —
    // roughly the shape of live BW command streams.
    let len = match rng.next_u64() % 100 {
        0..=69 => 10,
        70..=94 => 28,
        _ => 110,
    };
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0u8; len].into(),
        ..Default::default()
    }
}

/// The network side of one run — both path models, the event heap, the PRNG,
/// and the stats ledger — bundled so the dispatch helpers don't each thread
/// half a dozen mutable borrows.
struct Net {
    forward: PathModel,
    reverse: PathModel,
    rng: Rng,
    events: BinaryHeap<Reverse<Event>>,
    order: u64,
    episode_window: Option<(f64, f64)>,
    stats: RunStats,
}

impl Net {
    fn push(&mut self, at_ms: f64, kind: EventKind) {
        self.order += 1;
        self.events.push(Reverse(Event {
            at_us: (at_ms * 1000.0) as u64,
            order: self.order,
            kind,
        }));
    }

    /// Sends one already-built forward packet through loss/bottleneck,
    /// charging stats and scheduling its delivery and cwnd release.
    fn dispatch_forward(&mut self, now_ms: f64, packet: Packet) {
        use prost::Message;
        let encoded = packet.encoded_len();
        self.stats.fwd_packets += 1;
        self.stats.fwd_bytes += encoded as f64;
        self.stats.max_fwd_packet_bytes = self.stats.max_fwd_packet_bytes.max(encoded);
        if let Some((from, to)) = self.episode_window
            && now_ms >= from
            && now_ms < to
        {
            self.stats.episode_fwd_packets += 1;
            self.stats.episode_fwd_bytes += encoded as f64;
        }
        let wire_bytes = encoded as f64 + DATAGRAM_OVERHEAD_BYTES;

        let Some(b) = &mut self.forward.bottleneck else {
            self.transmit(now_ms, wire_bytes, packet);
            return;
        };
        let cwnd = (b.cwnd_bytes)(now_ms);
        if b.in_flight_bytes + wire_bytes <= cwnd && b.queue.is_empty() {
            b.in_flight_bytes += wire_bytes;
            self.transmit(now_ms, wire_bytes, packet);
        } else if b.queue_bytes + wire_bytes > b.queue_cap_bytes {
            b.dropped += 1;
            self.stats.queue_drops += 1;
        } else {
            b.queue_bytes += wire_bytes;
            b.queue.push_back(QueuedSend {
                bytes: wire_bytes,
                packet,
            });
        }
    }

    /// Puts one packet on the forward wire: rolls loss, schedules delivery,
    /// and — when a bottleneck is charging in-flight bytes — schedules their
    /// release (the simulated QUIC ack, or the loss declaration).
    fn transmit(&mut self, now_ms: f64, wire_bytes: f64, packet: Packet) {
        let lost = self.forward.loss.lost(now_ms, &mut self.rng);
        let owd = self.forward.owd_at(now_ms);
        let ack_rtt = owd + self.reverse.owd_at(now_ms);
        let tracked = self.forward.bottleneck.is_some();
        if lost {
            self.stats.wire_losses += 1;
            if tracked {
                self.push(
                    now_ms + ack_rtt + LOSS_RELEASE_PENALTY_MS,
                    EventKind::CwndRelease(wire_bytes),
                );
            }
        } else {
            self.push(now_ms + owd, EventKind::DeliverForward(packet));
            if tracked {
                // The QUIC-level ack returns and frees the window.
                self.push(now_ms + ack_rtt + 5.0, EventKind::CwndRelease(wire_bytes));
            }
        }
    }

    /// Drains the bottleneck queue into any cwnd room. Split from
    /// [`dispatch_forward`](Self::dispatch_forward) so a release event can
    /// admit several waiters.
    fn drain_queue(&mut self, now_ms: f64) {
        loop {
            let Some(b) = &mut self.forward.bottleneck else {
                return;
            };
            let cwnd = (b.cwnd_bytes)(now_ms);
            let Some(front) = b.queue.front() else {
                return;
            };
            if b.in_flight_bytes + front.bytes > cwnd {
                return;
            }
            let QueuedSend { bytes, packet } = b.queue.pop_front().expect("front exists");
            b.queue_bytes -= bytes;
            b.in_flight_bytes += bytes;
            self.transmit(now_ms, bytes, packet);
        }
    }
}

fn run(scenario: &Scenario, policy: RecarryPolicy, seed: u64) -> RunStats {
    let mut sender = AckManager::with_policy(policy);
    let mut receiver = AckManager::new();

    let forward = (scenario.forward)();
    let reverse = (scenario.reverse)();
    let rng = Rng::new(seed);

    // Origin state: per-slot next seq, creation time of every payload.
    let mut next_seq = vec![0u64; scenario.fresh_per_tick as usize];
    let mut created_ms: BTreeMap<(u8, u64), f64> = BTreeMap::new();
    let mut delivered: BTreeSet<(u8, u64)> = BTreeSet::new();
    let mut prefixes: BTreeMap<u8, PrefixTracker> = BTreeMap::new();

    let mut net = Net {
        forward,
        reverse,
        rng,
        events: BinaryHeap::new(),
        order: 0,
        episode_window: scenario.episode_window,
        stats: RunStats {
            delivered_latencies_turns: Vec::new(),
            episode_latencies_turns: Vec::new(),
            episode_fwd_bytes: 0.0,
            episode_fwd_packets: 0,
            undelivered: 0,
            total_payloads: 0,
            fwd_packets: 0,
            fwd_bytes: 0.0,
            max_fwd_packet_bytes: 0,
            queue_drops: 0,
            wire_losses: 0,
            max_prefix_lag_turns: 0,
            backlog_clear_after_ms: None,
        },
    };

    net.push(0.0, EventKind::SenderTick);
    net.push(TURN_MS / 2.0, EventKind::ReceiverTick);

    // For the blackout recovery metric: the outage window, when one exists.
    let blackout_window = match (scenario.forward)().loss {
        LossModel::Blackout { from_ms, to_ms, .. } => Some((from_ms, to_ms)),
        _ => None,
    };
    let mut latest_pre_blackout_delivery: f64 = 0.0;

    let end_us = (scenario.duration_ms * 1000.0) as u64;
    while let Some(Reverse(event)) = net.events.pop() {
        if event.at_us > end_us {
            break;
        }
        let now_ms = event.at_us as f64 / 1000.0;
        match event.kind {
            EventKind::SenderTick => {
                for slot in 0..scenario.fresh_per_tick {
                    let seq = next_seq[slot as usize];
                    next_seq[slot as usize] += 1;
                    let payload = turn_payload(slot as u8, seq, &mut net.rng);
                    created_ms.insert((slot as u8, seq), now_ms);
                    net.stats.total_payloads += 1;
                    let packet = sender
                        .build_outgoing(Some(payload), DATAGRAM_BUDGET)
                        .expect("seq space is ample for a sim run");
                    net.dispatch_forward(now_ms, packet);
                }
                // Track the worst prefix lag: newest created seq vs slot 0's
                // delivered prefix, in turns (one seq per tick).
                let newest = next_seq[0] - 1;
                let prefix = prefixes
                    .get(&0)
                    .and_then(|p| p.delivered_through)
                    .map_or(0, |d| d + 1);
                net.stats.max_prefix_lag_turns = net
                    .stats
                    .max_prefix_lag_turns
                    .max(newest.saturating_sub(prefix));
                net.push(now_ms + TURN_MS, EventKind::SenderTick);
            }
            EventKind::ReceiverTick => {
                // The receiver's own turn packet carries its ack state (its own
                // turns are irrelevant to the direction under test).
                let packet = receiver
                    .build_outgoing(None, DATAGRAM_BUDGET)
                    .expect("seq space is ample for a sim run");
                if !net.reverse.loss.lost(now_ms, &mut net.rng) {
                    let at = now_ms + net.reverse.owd_at(now_ms);
                    net.push(at, EventKind::DeliverReverse(packet));
                }
                // Beacon cursor snapshot rides the reliable stream: delayed,
                // never lost.
                let cursors: Vec<(SlotId, u64)> = prefixes
                    .iter()
                    .filter_map(|(slot, p)| p.delivered_through.map(|d| (SlotId(*slot), d)))
                    .collect();
                if !cursors.is_empty() {
                    let at = now_ms + net.reverse.owd_at(now_ms);
                    net.push(at, EventKind::BeaconArrive(cursors));
                }
                net.push(now_ms + TURN_MS, EventKind::ReceiverTick);
            }
            EventKind::DeliverForward(packet) => {
                for payload in &packet.payloads {
                    let key = (payload.slot as u8, payload.seq);
                    if delivered.insert(key) {
                        let created = created_ms[&key];
                        let latency_turns = (now_ms - created) / TURN_MS;
                        net.stats.delivered_latencies_turns.push(latency_turns);
                        if let Some((from, to)) = net.episode_window
                            && created >= from
                            && created < to
                        {
                            net.stats.episode_latencies_turns.push(latency_turns);
                        }
                        prefixes.entry(key.0).or_default().record(key.1);
                        if let Some((_, to)) = blackout_window
                            && created < to
                        {
                            latest_pre_blackout_delivery = latest_pre_blackout_delivery.max(now_ms);
                        }
                    }
                }
                receiver
                    .handle_incoming(&packet)
                    .expect("sim packets are well-formed");
            }
            EventKind::DeliverReverse(packet) => {
                sender
                    .handle_incoming(&packet)
                    .expect("sim packets are well-formed");
            }
            EventKind::CwndRelease(bytes) => {
                if let Some(b) = &mut net.forward.bottleneck {
                    b.in_flight_bytes = (b.in_flight_bytes - bytes).max(0.0);
                }
                net.drain_queue(now_ms);
            }
            EventKind::BeaconArrive(cursors) => {
                for (slot, through) in cursors {
                    sender.retire_payloads_through(slot, through);
                }
            }
        }
    }

    let mut stats = net.stats;
    // Payloads created in the final stretch may legitimately still be in
    // flight when the horizon cuts the run; only earlier ones count as
    // undelivered.
    let settled_before_ms = scenario.duration_ms - 2_000.0;
    stats.undelivered = created_ms
        .iter()
        .filter(|(key, created)| **created < settled_before_ms && !delivered.contains(*key))
        .count() as u64;
    if let Some((_, to)) = blackout_window {
        stats.backlog_clear_after_ms = Some((latest_pre_blackout_delivery - to).max(0.0));
    }
    stats
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

fn clean_path() -> PathModel {
    PathModel {
        owd_ms: 8.0,
        bloat: None,
        loss: LossModel::None,
        bottleneck: None,
    }
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "healthy",
            duration_ms: 60_000.0,
            fresh_per_tick: 3,
            episode_window: None,
            forward: clean_path,
            reverse: clean_path,
        },
        Scenario {
            name: "iid-2pct",
            duration_ms: 120_000.0,
            fresh_per_tick: 3,
            episode_window: None,
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: None,
                loss: LossModel::Iid(0.02),
                bottleneck: None,
            },
            reverse: clean_path,
        },
        Scenario {
            name: "bursty-fade",
            duration_ms: 120_000.0,
            fresh_per_tick: 3,
            episode_window: None,
            // ~4-packet mean bursts, ~2% of packets in bad state.
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: None,
                loss: LossModel::Burst {
                    enter_bad: 0.005,
                    exit_bad: 0.25,
                    loss_in_bad: 0.9,
                    bad: false,
                },
                bottleneck: None,
            },
            reverse: clean_path,
        },
        Scenario {
            name: "blackout-500ms",
            duration_ms: 60_000.0,
            fresh_per_tick: 3,
            episode_window: None,
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: None,
                loss: LossModel::Blackout {
                    from_ms: 30_000.0,
                    to_ms: 30_500.0,
                    base: 0.0,
                },
                bottleneck: None,
            },
            reverse: clean_path,
        },
        // The production episode: for 30s the last mile bloats (+140ms one-way,
        // matching the observed ~300ms smoothed RTT) and loses ~3% of packets,
        // while Cubic sits crushed at its floor. The crushed window over the
        // inflated round trip passes ~10 kB/s; the fresh turn stream alone
        // needs ~8.5 kB/s, so whether the link survives the episode is decided
        // almost entirely by what redundancy adds on top.
        Scenario {
            name: "squeeze-episode",
            duration_ms: 120_000.0,
            fresh_per_tick: 3,
            episode_window: Some((30_000.0, 60_000.0)),
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: Some((30_000.0, 60_000.0, 140.0)),
                loss: LossModel::Window {
                    from_ms: 30_000.0,
                    to_ms: 60_000.0,
                    in_window: 0.03,
                    outside: 0.003,
                },
                bottleneck: Some(Bottleneck {
                    cwnd_bytes: |now_ms| {
                        if (30_000.0..60_000.0).contains(&now_ms) {
                            2904.0
                        } else {
                            100_000.0
                        }
                    },
                    queue: VecDeque::new(),
                    queue_bytes: 0.0,
                    queue_cap_bytes: 60_000.0,
                    in_flight_bytes: 0.0,
                    dropped: 0,
                }),
            },
            reverse: clean_path,
        },
        // A harsher squeeze: deeper bufferbloat and heavier loss. Verifies the
        // chosen schedule has margin past the milder episode's capacity edge
        // rather than sitting exactly on it.
        Scenario {
            name: "squeeze-harsh",
            duration_ms: 120_000.0,
            fresh_per_tick: 3,
            episode_window: Some((30_000.0, 60_000.0)),
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: Some((30_000.0, 60_000.0, 220.0)),
                loss: LossModel::Window {
                    from_ms: 30_000.0,
                    to_ms: 60_000.0,
                    in_window: 0.05,
                    outside: 0.003,
                },
                bottleneck: Some(Bottleneck {
                    cwnd_bytes: |now_ms| {
                        if (30_000.0..60_000.0).contains(&now_ms) {
                            2904.0
                        } else {
                            100_000.0
                        }
                    },
                    queue: VecDeque::new(),
                    queue_bytes: 0.0,
                    queue_cap_bytes: 60_000.0,
                    in_flight_bytes: 0.0,
                    dropped: 0,
                }),
            },
            reverse: clean_path,
        },
        // The same squeeze on a client uplink (one fresh payload per tick).
        Scenario {
            name: "squeeze-uplink",
            duration_ms: 120_000.0,
            fresh_per_tick: 1,
            episode_window: Some((30_000.0, 60_000.0)),
            forward: || PathModel {
                owd_ms: 8.0,
                bloat: Some((30_000.0, 60_000.0, 140.0)),
                loss: LossModel::Window {
                    from_ms: 30_000.0,
                    to_ms: 60_000.0,
                    in_window: 0.03,
                    outside: 0.003,
                },
                bottleneck: Some(Bottleneck {
                    cwnd_bytes: |now_ms| {
                        if (30_000.0..60_000.0).contains(&now_ms) {
                            2904.0
                        } else {
                            100_000.0
                        }
                    },
                    queue: VecDeque::new(),
                    queue_bytes: 0.0,
                    queue_cap_bytes: 60_000.0,
                    in_flight_bytes: 0.0,
                    dropped: 0,
                }),
            },
            reverse: clean_path,
        },
    ]
}

fn policies() -> Vec<(&'static str, RecarryPolicy)> {
    let budgeted = |budget| RecarryPolicy {
        redundancy_byte_budget: Some(budget),
        spacing: None,
    };
    let spaced = |budget, dense, max| RecarryPolicy {
        redundancy_byte_budget: Some(budget),
        spacing: Some(CarrySpacing {
            dense_carries: dense,
            max_spacing: max,
        }),
    };
    vec![
        ("carry-all (pre-policy)", RecarryPolicy::unbounded()),
        ("budget-384", budgeted(384)),
        ("b384 d2/m8 (shipped)", RecarryPolicy::default()),
        ("b384 d2/m12", spaced(384, 2, 12)),
        ("b384 d2/m16", spaced(384, 2, 16)),
        ("b384 d2/m24", spaced(384, 2, 24)),
        ("b384 d3/m12", spaced(384, 3, 12)),
        ("b384 d3/m16", spaced(384, 3, 16)),
        ("b384 d3/m24", spaced(384, 3, 24)),
        ("b256 d2/m16", spaced(256, 2, 16)),
        ("b256 d3/m16", spaced(256, 3, 16)),
        (
            "spaced-only d2/m16",
            RecarryPolicy {
                redundancy_byte_budget: None,
                spacing: Some(CarrySpacing {
                    dense_carries: 2,
                    max_spacing: 16,
                }),
            },
        ),
    ]
}

/// Prints the policy comparison across every scenario. Tuning aid, not a test:
/// `cargo test -p rally-point-transport recarry_sim -- --ignored --nocapture`.
#[test]
#[ignore = "tuning aid: prints comparison tables"]
fn dump_policy_comparison() {
    for scenario in scenarios() {
        println!("\n=== {} === (3 seeds pooled)", scenario.name);
        println!(
            "{:<26} {:>7} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8} {:>9} {:>7} {:>7} {:>7} {:>9}",
            "policy",
            "lat p50",
            "p99",
            "max",
            "ep p99",
            "ep max",
            "ep B/pk",
            "undeliv",
            "bytes/pkt",
            "max B",
            "qdrops",
            "lagmax",
            "clear ms",
        );
        for (name, policy) in policies() {
            let mut stats = run(&scenario, policy, 0xC0FFEE);
            for seed in [0xBEEF_u64, 0xF00D_5EED] {
                stats.merge(run(&scenario, policy, seed));
            }
            println!(
                "{:<26} {:>7.2} {:>7.2} {:>7.2} {:>8.2} {:>8.2} {:>8.1} {:>8} {:>9.1} {:>7} {:>7} {:>7} {:>9}",
                name,
                stats.percentile(0.50),
                stats.percentile(0.99),
                stats.percentile(1.0),
                percentile(&stats.episode_latencies_turns, 0.99),
                percentile(&stats.episode_latencies_turns, 1.0),
                stats.episode_mean_bytes_per_packet(),
                stats.undelivered,
                stats.mean_bytes_per_packet(),
                stats.max_fwd_packet_bytes,
                stats.queue_drops,
                stats.max_prefix_lag_turns,
                stats
                    .backlog_clear_after_ms
                    .map_or("-".to_string(), |ms| format!("{ms:.0}")),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pinned properties
// ---------------------------------------------------------------------------

/// Every policy, including the bounded ones, must deliver every payload under
/// sustained random loss — bounding bytes must never become starvation.
#[test]
fn every_policy_delivers_everything_under_sustained_loss() {
    let scenario = Scenario {
        name: "iid-5pct-short",
        duration_ms: 30_000.0,
        fresh_per_tick: 3,
        episode_window: None,
        forward: || PathModel {
            owd_ms: 8.0,
            bloat: None,
            loss: LossModel::Iid(0.05),
            bottleneck: None,
        },
        reverse: clean_path,
    };
    for (name, policy) in policies() {
        let stats = run(&scenario, policy, 7);
        assert_eq!(
            stats.undelivered, 0,
            "{name}: settled payloads left undelivered under sustained 5% loss \
             (of {} total)",
            stats.total_payloads,
        );
    }
}

/// The byte budget must actually bound bundle size: no forward packet may
/// exceed the fresh payload's worst case plus the budget plus header slack.
#[test]
fn a_byte_budget_bounds_every_bundle() {
    let scenario = Scenario {
        name: "squeeze-bound-check",
        duration_ms: 60_000.0,
        fresh_per_tick: 3,
        episode_window: None,
        forward: || PathModel {
            owd_ms: 8.0,
            bloat: None,
            loss: LossModel::Iid(0.03),
            bottleneck: Some(Bottleneck {
                cwnd_bytes: |_| 2904.0,
                queue: VecDeque::new(),
                queue_bytes: 0.0,
                queue_cap_bytes: 60_000.0,
                in_flight_bytes: 0.0,
                dropped: 0,
            }),
        },
        reverse: clean_path,
    };
    let policy = RecarryPolicy::default();
    let budget = policy
        .redundancy_byte_budget
        .expect("the shipped policy carries a byte budget");
    let stats = run(&scenario, policy, 11);
    // Worst-case fresh element (~120B commands + framing) + budget + packet
    // header.
    let bound = 140 + budget + 16;
    assert!(
        stats.max_fwd_packet_bytes <= bound,
        "bundle of {} bytes exceeds the {bound}-byte bound",
        stats.max_fwd_packet_bytes,
    );
}

/// The shipped policy must hold the capacity-edge fade the production episode
/// exhibited: a 30s crushed-cwnd + bufferbloat + loss window on a 4-player
/// fan-out edge stays a few turns behind at worst, with no sender-side queue
/// overflow — where the unbounded refill runs seconds behind and sheds
/// thousands of bundles.
#[test]
fn the_shipped_policy_stays_stable_through_a_capacity_edge_fade() {
    let scenario = scenarios()
        .into_iter()
        .find(|s| s.name == "squeeze-episode")
        .expect("the squeeze scenario exists");
    for seed in [0xC0FFEE_u64, 0xBEEF, 0xF00D_5EED] {
        let stats = run(&scenario, RecarryPolicy::default(), seed);
        assert_eq!(
            stats.queue_drops, 0,
            "seed {seed}: the shipped policy overflowed the sender queue",
        );
        let ep_p99 = percentile(&stats.episode_latencies_turns, 0.99);
        assert!(
            ep_p99 < 10.0,
            "seed {seed}: episode p99 of {ep_p99} turns says the fade ran away",
        );
    }
}

/// Dense initial carries must preserve next-packet recovery: an isolated lost
/// packet's payloads ride the immediately following packets, keeping worst-case
/// added latency within a few turns even with spacing enabled.
#[test]
fn spacing_still_recovers_isolated_loss_within_dense_carries() {
    let scenario = Scenario {
        name: "sparse-loss",
        duration_ms: 60_000.0,
        fresh_per_tick: 3,
        episode_window: None,
        forward: || PathModel {
            owd_ms: 8.0,
            bloat: None,
            loss: LossModel::Iid(0.005),
            bottleneck: None,
        },
        reverse: clean_path,
    };
    let stats = run(&scenario, RecarryPolicy::default(), 23);
    assert_eq!(stats.undelivered, 0);
    // An isolated loss is recovered by the next fan-out packet (~1/3 turn on a
    // 3-fresh-per-tick link) — even p100 stays within two turns of the
    // no-loss baseline (~0.6 turns: half a turn of owd + delivery quantum).
    assert!(
        stats.percentile(1.0) < 2.5,
        "worst-case latency {} turns says isolated losses are not being \
         recovered by the dense carries",
        stats.percentile(1.0),
    );
}
