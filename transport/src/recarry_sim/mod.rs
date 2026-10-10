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
//! - **Sender model**: the tuning scenarios send a fresh turn every tick and
//!   nothing else, the uninterrupted stream the refill is tuned against. The
//!   stalling scenarios model a rollback client instead: it stops producing
//!   turns once it runs a prediction limit past the delivered prefix the
//!   beacon reports, and sends maintenance flushes on the drivers' rule (due
//!   a flush interval after the last send that re-carried anything), which
//!   is how a client blacked out on its uplink recovers.
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
use scenarios::{
    RunStats, Scenario, SenderModel, clean_path, percentile, policies, representative_policies,
    scenarios, squeezed_uplink_blackout, uplink_blackout,
};

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
            flush_packets: 0,
            flush_bytes: 0.0,
            max_flush_packet_bytes: 0,
        },
    };

    net.push(0.0, EventKind::SenderTick);
    net.push(TURN_MS / 2.0, EventKind::ReceiverTick);

    // The stall model's view of the session: slot 0's delivered prefix as the
    // latest beacon told the sender, as a count of turns.
    let mut heard_delivered_turns = 0u64;
    let mut flush_deadline_ms = scenario.sender.flush_interval_ms;
    if let Some(deadline) = flush_deadline_ms {
        net.push(deadline, EventKind::SenderFlush);
    }

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
                let stalled = scenario
                    .sender
                    .stall_lag_turns
                    .is_some_and(|lag| next_seq[0] > heard_delivered_turns + lag);
                let fresh_this_tick = if stalled { 0 } else { scenario.fresh_per_tick };
                for slot in 0..fresh_this_tick {
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
                    // A send that re-carried anything pushes the flush out,
                    // as the drivers do.
                    if packet.payloads.len() > 1
                        && let Some(interval) = scenario.sender.flush_interval_ms
                    {
                        let deadline = now_ms + interval;
                        flush_deadline_ms = Some(deadline);
                        net.push(deadline, EventKind::SenderFlush);
                    }
                    net.dispatch_forward(now_ms, packet);
                }
                // Track the worst prefix lag: newest created seq vs slot 0's
                // delivered prefix, in turns (one seq per tick while the
                // sender isn't stalled).
                let newest = next_seq[0].saturating_sub(1);
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
                    if slot == SlotId(0) {
                        heard_delivered_turns = heard_delivered_turns.max(through + 1);
                    }
                }
            }
            EventKind::SenderFlush => {
                let (Some(deadline), Some(interval)) =
                    (flush_deadline_ms, scenario.sender.flush_interval_ms)
                else {
                    continue;
                };
                // Compared in the event clock's microseconds, which truncate.
                if event.at_us < (deadline * 1000.0) as u64 {
                    continue;
                }
                if sender.payloads_in_flight() > 0 {
                    use prost::Message;
                    let packet = sender
                        .build_outgoing(None, DATAGRAM_BUDGET)
                        .expect("seq space is ample for a sim run");
                    sender.record_sent(&packet);
                    let encoded = packet.encoded_len();
                    net.stats.flush_packets += 1;
                    net.stats.flush_bytes += encoded as f64;
                    net.stats.max_flush_packet_bytes =
                        net.stats.max_flush_packet_bytes.max(encoded);
                    net.dispatch_forward(now_ms, packet);
                }
                let next = now_ms + interval;
                flush_deadline_ms = Some(next);
                net.push(next, EventKind::SenderFlush);
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
            "{:<26} {:>7} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8} {:>9} {:>7} {:>7} {:>7} {:>9} {:>8} {:>8}",
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
            "flushes",
            "fl B/pk",
        );
        for (name, policy) in policies() {
            let mut stats = run(&scenario, policy, 0xC0FFEE);
            for seed in [0xBEEF_u64, 0xF00D_5EED] {
                stats.merge(run(&scenario, policy, seed));
            }
            println!(
                "{:<26} {:>7.2} {:>7.2} {:>7.2} {:>8.2} {:>8.2} {:>8.1} {:>8} {:>9.1} {:>7} {:>7} {:>7} {:>9} {:>8} {:>8.1}",
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
                stats.flush_packets,
                stats.mean_bytes_per_flush(),
            );
        }
    }
}

/// One uplink blackout length of the stalled-sender sweep, with the plain and
/// the squeezed path that black out for it.
struct StallBlackout {
    ms: u32,
    plain: fn() -> PathModel,
    squeezed: fn() -> PathModel,
}

/// Uplink blackouts of these lengths, on a plain and a squeezed path, for the
/// stalled-sender sweep. The lengths are spaced off the 150 ms flush grid so
/// the path returns at a different point in the flush cycle each time.
const STALL_BLACKOUTS: [StallBlackout; 7] = [
    StallBlackout {
        ms: 300,
        plain: uplink_blackout::<300>,
        squeezed: squeezed_uplink_blackout::<300>,
    },
    StallBlackout {
        ms: 700,
        plain: uplink_blackout::<700>,
        squeezed: squeezed_uplink_blackout::<700>,
    },
    StallBlackout {
        ms: 1_100,
        plain: uplink_blackout::<1_100>,
        squeezed: squeezed_uplink_blackout::<1_100>,
    },
    StallBlackout {
        ms: 1_500,
        plain: uplink_blackout::<1_500>,
        squeezed: squeezed_uplink_blackout::<1_500>,
    },
    StallBlackout {
        ms: 1_900,
        plain: uplink_blackout::<1_900>,
        squeezed: squeezed_uplink_blackout::<1_900>,
    },
    StallBlackout {
        ms: 2_300,
        plain: uplink_blackout::<2_300>,
        squeezed: squeezed_uplink_blackout::<2_300>,
    },
    StallBlackout {
        ms: 2_700,
        plain: uplink_blackout::<2_700>,
        squeezed: squeezed_uplink_blackout::<2_700>,
    },
];

/// A stalling rollback client on `forward`, run long enough past the outage
/// for everything to settle.
fn stall_scenario(name: &'static str, forward: fn() -> PathModel) -> Scenario {
    Scenario {
        name,
        duration_ms: 40_000.0,
        fresh_per_tick: 1,
        episode_window: None,
        forward,
        reverse: clean_path,
        sender: SenderModel::STALLING,
    }
}

/// Prints how long a stalled sender's backlog takes to land after uplink
/// blackouts of each swept length, and what its flushes cost. Tuning aid:
/// `cargo test -p rally-point-transport recarry_sim -- --ignored --nocapture`.
#[test]
#[ignore = "tuning aid: prints the stalled-sender sweep"]
fn dump_stall_recovery() {
    println!(
        "\n=== stalled sender, shipped policy (3 seeds, worst) ===\n{:<10} {:>12} {:>14} {:>12} {:>14}",
        "blackout", "clear ms", "squeeze clear", "flush B max", "squeeze fl max",
    );
    for StallBlackout {
        ms,
        plain,
        squeezed,
    } in STALL_BLACKOUTS
    {
        let mut plain_stats = run(
            &stall_scenario("plain", plain),
            RecarryPolicy::default(),
            0xC0FFEE,
        );
        let mut squeezed_stats = run(
            &stall_scenario("squeezed", squeezed),
            RecarryPolicy::default(),
            0xC0FFEE,
        );
        for seed in [0xBEEF_u64, 0xF00D_5EED] {
            plain_stats.merge(run(
                &stall_scenario("plain", plain),
                RecarryPolicy::default(),
                seed,
            ));
            squeezed_stats.merge(run(
                &stall_scenario("squeezed", squeezed),
                RecarryPolicy::default(),
                seed,
            ));
        }
        println!(
            "{:<10} {:>12.0} {:>14.0} {:>12} {:>14}",
            ms,
            plain_stats.backlog_clear_after_ms.unwrap_or(f64::NAN),
            squeezed_stats.backlog_clear_after_ms.unwrap_or(f64::NAN),
            plain_stats.max_flush_packet_bytes,
            squeezed_stats.max_flush_packet_bytes,
        );
    }
}

// ---------------------------------------------------------------------------
// Pinned properties
// ---------------------------------------------------------------------------

/// A sender stalled behind its own lost turns sends nothing but flushes, and
/// every peer waits on its oldest lost turn. Once the uplink returns, the
/// backlog must land within a couple of flush intervals plus the path's
/// one-way delay, whatever the blackout's length or where it ends in the
/// flush cycle, on a plain uplink and a squeezed one alike. Gating flushes
/// by the turn-rate spacing schedule instead left the backlog waiting up to
/// `max_spacing` flush intervals: 0.8-1.9 s across this sweep. The flushes
/// that do it stay inside the byte budget and never overflow the squeezed
/// path's queue.
#[test]
fn a_stalled_senders_backlog_lands_promptly_after_an_uplink_blackout() {
    let policy = RecarryPolicy::default();
    let budget = policy
        .redundancy_byte_budget
        .expect("the shipped policy carries a byte budget");
    let flush_interval = SenderModel::STALLING
        .flush_interval_ms
        .expect("the stalling sender flushes");
    for StallBlackout {
        ms,
        plain,
        squeezed,
    } in STALL_BLACKOUTS
    {
        for (path, forward) in [("plain", plain), ("squeezed", squeezed)] {
            // The worst one-way delay the path has when the outage ends.
            let owd = forward().owd_at(scenarios::BLACKOUT_FROM_MS + f64::from(ms));
            let bound = 2.0 * flush_interval + owd;
            for seed in [0xC0FFEE_u64, 0xBEEF, 0xF00D_5EED] {
                let stats = run(&stall_scenario(path, forward), policy, seed);
                let clear = stats
                    .backlog_clear_after_ms
                    .expect("a blackout scenario measures its backlog");
                assert!(
                    clear <= bound,
                    "{path} {ms} ms blackout, seed {seed}: the backlog landed {clear:.0} ms \
                     after the uplink returned (bound {bound:.0} ms)",
                );
                assert_eq!(
                    stats.undelivered, 0,
                    "{path} {ms} ms blackout, seed {seed}: payloads left undelivered",
                );
                assert_eq!(
                    stats.queue_drops, 0,
                    "{path} {ms} ms blackout, seed {seed}: the flushes overflowed the queue",
                );
                // A packet header plus the byte budget: a flush has no fresh
                // payload, so redundancy is all it carries.
                assert!(
                    stats.max_flush_packet_bytes <= 16 + budget,
                    "{path} {ms} ms blackout, seed {seed}: a {}-byte flush exceeds the budget",
                    stats.max_flush_packet_bytes,
                );
            }
        }
    }
}

/// Every bounding regime — unbounded, byte budget alone, and the shipped
/// budget plus spacing — must deliver every payload under sustained random
/// loss: bounding bytes must never become starvation. The tuning variations
/// within each regime are swept in the comparison dump.
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
        sender: SenderModel::CONTINUOUS,
    };
    for (name, policy) in representative_policies() {
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
        sender: SenderModel::CONTINUOUS,
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
        sender: SenderModel::CONTINUOUS,
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
