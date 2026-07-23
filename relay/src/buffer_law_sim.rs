//! Scenario simulation for the latency-buffer control law: synthetic network
//! weather (random loss, loss bursts, jitter spikes, recovery) streamed
//! through a [`DecisionMaker`] turn by turn, with assertions on the properties
//! the buffer is tuned for rather than on individual decisions:
//!
//! - **Stability.** Buffer changes are disruptive twice over -- each one
//!   alters the input latency players have adjusted to, and a shrink that is
//!   immediately re-raised (a *reversal*) means the cushion briefly ran below
//!   what conditions demanded. Sustained-but-noisy conditions must park the
//!   buffer, not oscillate it on the shrink-dwell cadence.
//! - **Coverage.** A quiet buffer is trivial if it is simply huge, so
//!   stability is checked against a per-turn *underrun* proxy: how often the
//!   cushion in force was smaller than that turn's simulated delivery need
//!   (path plus loss re-carries). Underruns are the stalls players feel.
//! - **Recovery.** After conditions improve, the buffer must actually come
//!   back down -- monotonically, without ping-ponging -- rather than staying
//!   stuck at the high-water mark (the classic complaint about SC:R's own
//!   dynamic latency).
//!
//! The network model is deliberately stylized -- independent per-packet loss
//! (optionally in bursts), RTT spikes riding on loss, a fixed packets-per-turn
//! rate -- not a packet-level transport simulation. It is the *law's* test
//! bench: the ingest cadence, counter shapes, and frame progression match what
//! the routing layer feeds the decision-maker in production.
//!
//! `cargo test -p rally-point-relay buffer_law_sim -- --ignored --nocapture`
//! prints per-scenario traces (buffer vs. target vs. weather over time) for
//! tuning sessions; the non-ignored tests encode the properties themselves.

use std::collections::HashSet;

use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{GameFrameCount, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, SlotConditions};

use crate::consensus::{Authority, ControlLaw, DecisionMaker};
use crate::routing::SessionKey;

/// One game turn at the SC:R rate, in microseconds.
const TURN_US: f64 = 1_000_000.0 / 24.0;

/// Game datagrams per turn per link the counter simulation assumes. QUIC path
/// stats count acks and control traffic too, so production denominators are a
/// little richer; 3 keeps the simulated loss-rate estimates conservative.
const PACKETS_PER_TURN: u32 = 3;

/// Deterministic xorshift64* PRNG so every scenario is reproducible without
/// pulling a rand dependency into the relay's dev-deps.
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

    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }
}

/// One stretch of simulated network weather for the whole session. Both
/// simulated players share the weather; per-link randomness still differs.
#[derive(Debug, Clone, Copy)]
struct Weather {
    turns: u32,
    /// Mean RTT per link (us).
    rtt_us: u32,
    /// Fractional RTT jitter: each sample varies by ±this fraction.
    jitter: f64,
    /// Per-packet drop probability while the link's loss process is active.
    loss: f64,
    /// Probability per turn of a quiet link entering a loss burst; 1.0 makes
    /// the loss uniform (always active), 0.0 disables loss entirely.
    burst_start: f64,
    /// Probability per turn of an active burst ending.
    burst_end: f64,
}

impl Weather {
    fn clean(turns: u32, rtt_us: u32) -> Self {
        Self {
            turns,
            rtt_us,
            jitter: 0.10,
            loss: 0.0,
            burst_start: 0.0,
            burst_end: 1.0,
        }
    }

    /// Uniform random per-packet loss -- the clumsy-style shaper case.
    fn random_loss(turns: u32, rtt_us: u32, loss: f64) -> Self {
        Self {
            turns,
            rtt_us,
            jitter: 0.15,
            loss,
            burst_start: 1.0,
            burst_end: 0.0,
        }
    }

    /// Loss arriving in bursts a few hundred ms long every few seconds --
    /// the bad-wifi / congested-path case.
    fn bursty(turns: u32, rtt_us: u32, loss_in_burst: f64) -> Self {
        Self {
            turns,
            rtt_us,
            jitter: 0.15,
            loss: loss_in_burst,
            burst_start: 0.02, // a burst every ~2s on average
            burst_end: 0.12,   // mean burst length ~8 turns (~350ms)
        }
    }
}

/// One simulated client link: cumulative counters plus the loss/spike state
/// that shapes its conditions samples.
struct Link {
    sent: u64,
    lost: u64,
    /// Whether the loss process is currently dropping packets.
    in_burst: bool,
    /// Turns of elevated RTT remaining after recent loss (queueing/re-carry
    /// latency around drops, the shape a throttling shaper produces).
    spike_turns: u32,
    /// The most recent RTT sample (us), for the underrun proxy.
    last_rtt: u32,
}

impl Link {
    fn new() -> Self {
        Self {
            sent: 0,
            lost: 0,
            in_burst: false,
            spike_turns: 0,
            last_rtt: 0,
        }
    }

    /// Advances one turn under `weather`, returning the number of this turn's
    /// packets that were dropped.
    fn step(&mut self, weather: &Weather, rng: &mut Rng) -> u32 {
        if self.in_burst {
            if rng.chance(weather.burst_end) {
                self.in_burst = false;
            }
        } else if rng.chance(weather.burst_start) {
            self.in_burst = true;
        }

        let mut dropped = 0;
        for _ in 0..PACKETS_PER_TURN {
            self.sent += 1;
            if self.in_burst && rng.chance(weather.loss) {
                self.lost += 1;
                dropped += 1;
            }
        }
        if dropped > 0 {
            self.spike_turns = self.spike_turns.max(4);
        }

        let jitter = 1.0 + weather.jitter * (rng.unit() * 2.0 - 1.0);
        let spike = if self.spike_turns > 0 {
            self.spike_turns -= 1;
            1.0 + 0.6 * rng.unit()
        } else {
            1.0
        };
        self.last_rtt = (f64::from(weather.rtt_us) * jitter * spike) as u32;
        dropped
    }

    fn conditions(&self, slot: u8) -> SlotConditions {
        SlotConditions {
            slot: u32::from(slot),
            rtt_us: self.last_rtt,
            lost_packets: self.lost,
            sent_packets: self.sent,
            connection_epoch: None,
        }
    }
}

/// A buffer change the simulated session observed: the turn the decision was
/// made, and the size it moved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Change {
    turn: u32,
    buffer: u32,
}

struct SimResult {
    /// Every buffer change the law decided, in order. The first is the
    /// session's initial adaptation up from the seeded minimum.
    changes: Vec<Change>,
    /// Turn-indexed buffer in force (decisions applied at their scheduled
    /// apply frame, as clients would).
    buffer_by_turn: Vec<u32>,
    /// Turns whose simulated delivery need exceeded the buffer in force.
    underrun_turns: u32,
}

impl SimResult {
    /// Shrinks that were re-raised within `window` turns -- the flap
    /// signature. A healthy law produces none: a shrink it cannot sustain is
    /// a shrink it should not have made.
    fn reversals_within(&self, window: u32) -> usize {
        let mut count = 0;
        let mut prev_buffer = SIM_BOUNDS_MIN;
        for (index, change) in self.changes.iter().enumerate() {
            let is_shrink = change.buffer < prev_buffer;
            if is_shrink
                && let Some(next) = self.changes.get(index + 1)
                && next.buffer > change.buffer
                && next.turn.saturating_sub(change.turn) < window
            {
                count += 1;
            }
            prev_buffer = change.buffer;
        }
        count
    }

    /// Buffer changes inside a turn range (half-open).
    fn changes_between(&self, from: u32, to: u32) -> Vec<Change> {
        self.changes
            .iter()
            .copied()
            .filter(|c| c.turn >= from && c.turn < to)
            .collect()
    }

    fn buffer_at(&self, turn: u32) -> u32 {
        self.buffer_by_turn[turn as usize]
    }
}

/// Streams `phases` of weather through a fresh two-player session and records
/// what the control law did.
fn run(law: ControlLaw, phases: &[Weather], seed: u64) -> SimResult {
    let key = SessionKey {
        tenant: TenantId::new("sb-sim").unwrap(),
        session: SessionId(1),
    };
    let bounds = BufferBounds {
        min: SIM_BOUNDS_MIN,
        max: 24,
    };
    let mut maker = DecisionMaker::new(key, bounds, law, Authority::SelfRelay, HashSet::new());

    let mut rng = Rng::new(seed);
    let mut links = [Link::new(), Link::new()];
    let mut changes = Vec::new();
    let mut buffer_by_turn = Vec::new();
    let mut underrun_turns = 0u32;
    // Decisions apply at their scheduled frame, like clients apply them.
    let mut pending: Vec<(u32, u32)> = Vec::new(); // (apply_frame, buffer)
    let mut buffer_in_force = 0u32;
    // Re-carry backlog per link: a dropped turn-carry is re-carried one turn
    // later, so consecutive drops stack whole turns of extra delivery time.
    let mut recarry = [0u32; 2];

    let total_turns: u32 = phases.iter().map(|w| w.turns).sum();
    let mut turn = 0u32;
    for weather in phases {
        for _ in 0..weather.turns {
            turn += 1;

            let mut dropped = [0u32; 2];
            for (index, link) in links.iter_mut().enumerate() {
                dropped[index] = link.step(weather, &mut rng);
                maker.observe_frame(SlotId(index as u8), GameFrameCount(turn));
            }
            let conditions = LinkConditions {
                slots: vec![links[0].conditions(0), links[1].conditions(1)],
            };
            if let Some(decision) = maker.ingest_local(&conditions) {
                pending.push((decision.applied_frame.0, decision.buffer.0));
                changes.push(Change {
                    turn,
                    buffer: decision.buffer.0,
                });
            }
            pending.retain(|&(apply_frame, buffer)| {
                if turn >= apply_frame {
                    buffer_in_force = buffer;
                    false
                } else {
                    true
                }
            });
            buffer_by_turn.push(buffer_in_force);

            // Underrun proxy. Path: half of each link's RTT. Loss: a dropped
            // turn-carry arrives with the next turn's packet, one whole turn
            // later, and consecutive drops stack -- the same quantization the
            // target formula prices in.
            for (backlog, dropped) in recarry.iter_mut().zip(dropped) {
                if dropped >= PACKETS_PER_TURN {
                    *backlog += 1;
                } else {
                    *backlog = 0;
                }
            }
            let path_us = (f64::from(links[0].last_rtt) + f64::from(links[1].last_rtt)) / 2.0;
            let need =
                (path_us / TURN_US).ceil() as u32 + recarry.iter().copied().max().unwrap_or(0);
            if buffer_in_force > 0 && need > buffer_in_force {
                underrun_turns += 1;
            }
        }
    }
    debug_assert_eq!(turn, total_turns);

    SimResult {
        changes,
        buffer_by_turn,
        underrun_turns,
    }
}

/// Seconds expressed in turns at the 24/sec rate.
const fn seconds(s: u32) -> u32 {
    s * 24
}

/// The simulated sessions' buffer floor (also the seed buffer, as in
/// production, where the buffer starts at `bounds.min`).
const SIM_BOUNDS_MIN: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean, stable network: after the initial adaptation the buffer must
    /// simply sit still.
    #[test]
    fn clean_network_holds_one_buffer() {
        for seed in [3, 17, 4242] {
            let result = run(
                ControlLaw::default(),
                &[Weather::clean(seconds(180), 150_000)],
                seed,
            );
            assert!(
                result.changes.len() <= 2,
                "seed {seed}: a clean network churned past its adaptation: {:?}",
                result.changes,
            );
            assert_eq!(result.reversals_within(seconds(3)), 0, "seed {seed}");
        }
    }

    /// The clumsy case that motivated the sustained-shrink rule: sustained
    /// uniform packet loss. The buffer must adapt up and then *park* -- no
    /// shrink-and-re-raise churn on the dwell cadence -- while still covering
    /// delivery (bounded underruns).
    #[test]
    fn sustained_random_loss_parks_the_buffer() {
        for seed in [7, 99, 1234] {
            let phases = [
                Weather::clean(seconds(20), 150_000),
                Weather::random_loss(seconds(120), 150_000, 0.10),
            ];
            let result = run(ControlLaw::default(), &phases, seed);

            assert_eq!(
                result.reversals_within(seconds(3)),
                0,
                "seed {seed}: the buffer flapped: {:?}",
                result.changes,
            );
            // Once the loss phase has been running a few seconds, the buffer
            // is adapted; from there it must be effectively parked. Allow a
            // couple of late escalations (loss keeps randomly clustering) but
            // nothing like the one-change-per-dwell flap this replaces.
            let settled = result.changes_between(seconds(30), seconds(140));
            assert!(
                settled.len() <= 2,
                "seed {seed}: churn while parked: {settled:?}",
            );
            // The parked buffer actually covers the weather. The proxy counts
            // a turn whenever *either* link's delivery need exceeded the
            // cushion; 2% of a 2-minute lossy stretch is a handful of brief
            // hiccups, not the recurring micro-stutter of an undersized buffer.
            let lossy_turns = seconds(120);
            assert!(
                result.underrun_turns <= lossy_turns / 50,
                "seed {seed}: {} underrun turns of {lossy_turns}",
                result.underrun_turns,
            );
        }
    }

    /// After the loss clears, the buffer must come back down -- monotonically,
    /// within a bounded time -- rather than sticking at the high-water mark or
    /// oscillating on the way down.
    #[test]
    fn recovery_descends_monotonically_and_promptly() {
        for seed in [11, 555, 90210] {
            let phases = [
                Weather::clean(seconds(20), 150_000),
                Weather::random_loss(seconds(60), 150_000, 0.10),
                Weather::clean(seconds(120), 150_000),
            ];
            let result = run(ControlLaw::default(), &phases, seed);

            let recovery_start = seconds(20 + 60);
            let recovery = result.changes_between(recovery_start, seconds(200));
            assert!(
                recovery
                    .windows(2)
                    .all(|pair| pair[1].buffer < pair[0].buffer),
                "seed {seed}: non-monotonic recovery: {recovery:?}",
            );

            // The descent is bounded: the shrink lookback (~25s) has to age the
            // loss-era peaks out, then one dwell (~5s) per step down. 55s
            // covers the ~5 steps this weather needs with margin. The endpoint
            // is the clean steady state the first phase found.
            let clean_buffer = result.buffer_at(seconds(19));
            let recovered = result.buffer_at(recovery_start + seconds(55));
            assert!(
                recovered <= clean_buffer + 1,
                "seed {seed}: stuck high after recovery: {recovered} vs clean {clean_buffer}",
            );
            assert_eq!(result.reversals_within(seconds(3)), 0, "seed {seed}");
        }
    }

    /// Loss arriving in short bursts every couple of seconds -- the bad-wifi
    /// shape. The gaps between bursts are exactly what an instantaneous
    /// estimator mistakes for recovery; the law must ride through them.
    #[test]
    fn bursty_loss_does_not_flap() {
        for seed in [23, 808, 31337] {
            let phases = [
                Weather::clean(seconds(20), 150_000),
                Weather::bursty(seconds(150), 150_000, 0.35),
            ];
            let result = run(ControlLaw::default(), &phases, seed);

            assert_eq!(
                result.reversals_within(seconds(3)),
                0,
                "seed {seed}: flapped between bursts: {:?}",
                result.changes,
            );
            // The first ~40s cover adaptation (legitimate escalating raises as
            // burst clusters reveal the weather). After that the buffer must
            // be near-parked: bursty weather may still earn an occasional
            // escalation or a step of descent, but nothing like the dwell
            // cadence's worst case (a change every ~5s would be ~22 for this
            // window).
            let settled = result.changes_between(seconds(60), seconds(170));
            assert!(
                settled.len() <= 4,
                "seed {seed}: churn while settled: {settled:?}",
            );
        }
    }

    /// Trace dump for tuning sessions: per-2s rows of weather, target, and
    /// buffer for each scenario. Run with
    /// `cargo test -p rally-point-relay buffer_law_sim -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual tuning aid, prints traces"]
    fn dump_traces() {
        let scenarios: [(&str, Vec<Weather>); 3] = [
            (
                "uniform 10% loss @150ms",
                vec![
                    Weather::clean(seconds(20), 150_000),
                    Weather::random_loss(seconds(120), 150_000, 0.10),
                    Weather::clean(seconds(60), 150_000),
                ],
            ),
            (
                "bursty 35% loss @150ms",
                vec![
                    Weather::clean(seconds(20), 150_000),
                    Weather::bursty(seconds(120), 150_000, 0.35),
                    Weather::clean(seconds(60), 150_000),
                ],
            ),
            ("clean 300ms", vec![Weather::clean(seconds(120), 300_000)]),
        ];

        for (name, phases) in &scenarios {
            let result = run(ControlLaw::default(), phases, 7);
            println!("== {name} ==");
            let mut boundary = 0;
            for weather in phases {
                boundary += weather.turns;
                println!(
                    "   phase to {:>4}s: rtt {}ms loss {:.0}% (burst {:.2}/{:.2})",
                    boundary / 24,
                    weather.rtt_us / 1000,
                    weather.loss * 100.0,
                    weather.burst_start,
                    weather.burst_end,
                );
            }
            for (turn, buffer) in result.buffer_by_turn.iter().enumerate().step_by(48) {
                println!("   t={:>4}s buffer={}", turn / 24, buffer);
            }
            println!(
                "   changes after adaptation: {:?}\n   underrun turns: {}\n",
                result.changes, result.underrun_turns,
            );
        }
    }
}
