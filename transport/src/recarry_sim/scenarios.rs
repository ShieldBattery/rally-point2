//! The scenario table and run-report types: the network shapes a run drives
//! [`super::model::Net`] through ([`Scenario`]), the aggregated measurements
//! one run produces ([`RunStats`]), and the [`RecarryPolicy`] variants under
//! comparison ([`policies`]). Kept apart from the event/network plumbing in
//! `model` so the "what's being compared" definitions read on their own.

use std::collections::VecDeque;

use crate::ack_manager::{CarrySpacing, RecarryPolicy};

use super::model::{Bottleneck, LossModel, PathModel};

/// The scenario definition a run executes.
pub(super) struct Scenario {
    pub(super) name: &'static str,
    pub(super) duration_ms: f64,
    /// Fresh payloads the sender originates per turn tick (3 models a 4-player
    /// downlink fan-out; 1 models a client uplink).
    pub(super) fresh_per_tick: u32,
    /// The window whose payloads get their own latency report — the fade
    /// episode, when the scenario has one. Whole-run percentiles average the
    /// episode away; these are the turns players actually felt.
    pub(super) episode_window: Option<(f64, f64)>,
    pub(super) forward: fn() -> PathModel,
    pub(super) reverse: fn() -> PathModel,
}

/// What one run measured.
pub(super) struct RunStats {
    pub(super) delivered_latencies_turns: Vec<f64>,
    /// Latencies of just the payloads created inside the scenario's episode
    /// window — what players felt during the fade, unwashed by the healthy
    /// remainder of the run.
    pub(super) episode_latencies_turns: Vec<f64>,
    /// Mean encoded packet size over forward packets built inside the episode
    /// window (numerator/denominator pair).
    pub(super) episode_fwd_bytes: f64,
    pub(super) episode_fwd_packets: u64,
    pub(super) undelivered: u64,
    pub(super) total_payloads: u64,
    pub(super) fwd_packets: u64,
    pub(super) fwd_bytes: f64,
    pub(super) max_fwd_packet_bytes: usize,
    pub(super) queue_drops: u64,
    pub(super) wire_losses: u64,
    pub(super) max_prefix_lag_turns: u64,
    /// For blackout scenarios: milliseconds from the end of the outage until
    /// every payload created before it had been delivered.
    pub(super) backlog_clear_after_ms: Option<f64>,
}

pub(super) fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

impl RunStats {
    pub(super) fn percentile(&self, p: f64) -> f64 {
        percentile(&self.delivered_latencies_turns, p)
    }

    pub(super) fn mean_bytes_per_packet(&self) -> f64 {
        if self.fwd_packets == 0 {
            return 0.0;
        }
        self.fwd_bytes / self.fwd_packets as f64
    }

    pub(super) fn episode_mean_bytes_per_packet(&self) -> f64 {
        if self.episode_fwd_packets == 0 {
            return 0.0;
        }
        self.episode_fwd_bytes / self.episode_fwd_packets as f64
    }

    /// Folds another seed's run into this one: latencies pool, counters sum,
    /// maxima take the worse run.
    pub(super) fn merge(&mut self, other: RunStats) {
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

pub(super) fn clean_path() -> PathModel {
    PathModel {
        owd_ms: 8.0,
        bloat: None,
        loss: LossModel::None,
        bottleneck: None,
    }
}

pub(super) fn scenarios() -> Vec<Scenario> {
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
        // An outage-grade squeeze: deeper bufferbloat and heavier loss push
        // effective capacity below what the fresh turn stream needs, so every
        // policy runs far behind and lockstep must stall — no redundancy
        // discipline can rescue an inelastic flow from a path that cannot
        // carry it. This is a boundary probe, not a margin claim: what it
        // shows is the degradation *shape* — the budget still bounds every
        // bundle (where spacing alone lets bundles grow back to the MTU), and
        // recovery after the fade lifts stays prompt.
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

pub(super) fn policies() -> Vec<(&'static str, RecarryPolicy)> {
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
