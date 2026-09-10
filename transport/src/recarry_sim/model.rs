//! Synthetic network primitives for the recarry-policy bench: the PRNG, the
//! loss models, the congestion-window bottleneck, the discrete-event
//! scheduler, and the receive-side prefix tracker. [`Net`] bundles all of it
//! — plus the per-run stats ledger — into the mutable state one run drives;
//! grouping it here keeps the event/network plumbing apart from the scenario
//! table and the test assertions that consume it.

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, VecDeque};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use super::scenarios::RunStats;

/// Per-datagram overhead charged to the bottleneck beyond the encoded packet:
/// UDP/IP headers plus QUIC short-header framing and AEAD tag.
const DATAGRAM_OVERHEAD_BYTES: f64 = 50.0;

/// How long after a lost packet's send the bottleneck frees its in-flight
/// bytes — standing in for QUIC's loss declaration (time-threshold ~9/8 RTT).
const LOSS_RELEASE_PENALTY_MS: f64 = 60.0;

/// Deterministic xorshift64* PRNG, mirroring `buffer_law_sim`'s: reproducible
/// runs without a rand dev-dependency.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
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
pub(super) enum LossModel {
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
    pub(super) fn lost(&mut self, now_ms: f64, rng: &mut Rng) -> bool {
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
pub(super) struct Bottleneck {
    /// The cap, as a function of time — lets a scenario crush it for an
    /// episode window and restore it after, matching the observed prod shape
    /// (Cubic pinned at its floor for the fade's duration).
    pub(super) cwnd_bytes: fn(now_ms: f64) -> f64,
    pub(super) queue: VecDeque<QueuedSend>,
    pub(super) queue_bytes: f64,
    /// Tail-drop threshold for the sender-side queue.
    pub(super) queue_cap_bytes: f64,
    pub(super) in_flight_bytes: f64,
    /// Queue drops, for the run report.
    pub(super) dropped: u64,
}

pub(super) struct QueuedSend {
    bytes: f64,
    packet: Packet,
}

/// One direction of the network.
pub(super) struct PathModel {
    pub(super) owd_ms: f64,
    /// Extra one-way delay applied inside a `(from_ms, to_ms)` window — the
    /// exogenous last-mile bufferbloat of a fade episode, which is what
    /// slows in-flight release and makes a crushed congestion window bind.
    pub(super) bloat: Option<(f64, f64, f64)>,
    pub(super) loss: LossModel,
    pub(super) bottleneck: Option<Bottleneck>,
}

impl PathModel {
    pub(super) fn owd_at(&self, now_ms: f64) -> f64 {
        match self.bloat {
            Some((from, to, extra)) if now_ms >= from && now_ms < to => self.owd_ms + extra,
            _ => self.owd_ms,
        }
    }
}

/// Event kinds, processed in time order.
pub(super) enum EventKind {
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

pub(super) struct Event {
    pub(super) at_us: u64,
    order: u64,
    pub(super) kind: EventKind,
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
pub(super) struct PrefixTracker {
    /// Highest seq such that all seqs `0..=delivered_through` have arrived, or
    /// `None` when seq 0 itself hasn't.
    pub(super) delivered_through: Option<u64>,
    above: BTreeSet<u64>,
}

impl PrefixTracker {
    pub(super) fn record(&mut self, seq: u64) {
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

/// A tiny turn payload with a plausibly-sized command blob.
pub(super) fn turn_payload(slot: u8, seq: u64, rng: &mut Rng) -> Payload {
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
pub(super) struct Net {
    pub(super) forward: PathModel,
    pub(super) reverse: PathModel,
    pub(super) rng: Rng,
    pub(super) events: BinaryHeap<Reverse<Event>>,
    pub(super) order: u64,
    pub(super) episode_window: Option<(f64, f64)>,
    pub(super) stats: RunStats,
}

impl Net {
    pub(super) fn push(&mut self, at_ms: f64, kind: EventKind) {
        self.order += 1;
        self.events.push(Reverse(Event {
            at_us: (at_ms * 1000.0) as u64,
            order: self.order,
            kind,
        }));
    }

    /// Sends one already-built forward packet through loss/bottleneck,
    /// charging stats and scheduling its delivery and cwnd release.
    pub(super) fn dispatch_forward(&mut self, now_ms: f64, packet: Packet) {
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
    pub(super) fn drain_queue(&mut self, now_ms: f64) {
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
