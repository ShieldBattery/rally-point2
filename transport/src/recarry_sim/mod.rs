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

mod model;
mod scenarios;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use rally_point_proto::ids::SlotId;

use crate::ack_manager::{AckManager, RecarryPolicy};

use model::{Bottleneck, EventKind, LossModel, Net, PathModel, PrefixTracker, Rng, turn_payload};
use scenarios::{RunStats, Scenario, clean_path, percentile, policies, scenarios};

/// One game turn at the SC:R rate, in milliseconds.
const TURN_MS: f64 = 1000.0 / 24.0;

/// The datagram budget handed to `build_outgoing` — noq's
/// `max_datagram_size()` for a typical path MTU.
const DATAGRAM_BUDGET: usize = 1350;

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
                    // The simulated QUIC endpoint accepts every datagram (loss
                    // and queueing happen beyond it), so every build records.
                    sender.record_sent(&packet);
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
                receiver.record_sent(&packet);
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
