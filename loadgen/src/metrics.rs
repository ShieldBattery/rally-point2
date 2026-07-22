//! What a run measures and how it is summarized.
//!
//! Player tasks return raw per-stream samples (fan-out latencies, inter-arrival
//! gaps) and outcome tallies; session tasks fold their players together; the
//! conductor folds every session into a [`RunReport`] and prints percentile
//! summaries (and, optionally, writes them as JSON for cross-run comparison).
//!
//! Latencies are microseconds against the process's own monotonic clock. Every
//! player in a session shares that clock, so a turn's send instant recorded by
//! one player is directly comparable against another player's receive instant for
//! the same `(slot, frame)` coordinate — that difference is the fan-out latency.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

/// The percentile value (0–100) of an ascending-sorted sample set, by nearest
/// rank. An empty set is 0.
pub fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct / 100.0 * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

/// A summarized distribution over a sample set (microseconds): the percentiles a
/// run compares on, plus the count and mean.
#[derive(Debug, Clone, Serialize)]
pub struct Distribution {
    pub count: usize,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
    pub mean: u64,
}

impl Distribution {
    /// Summarizes `samples` (consumed so it can be sorted in place).
    pub fn from_samples(mut samples: Vec<u64>) -> Self {
        samples.sort_unstable();
        let count = samples.len();
        let sum: u128 = samples.iter().map(|&v| u128::from(v)).sum();
        let mean = if count == 0 {
            0
        } else {
            (sum / count as u128) as u64
        };
        Self {
            count,
            p50: percentile(&samples, 50.0),
            p90: percentile(&samples, 90.0),
            p99: percentile(&samples, 99.0),
            max: samples.last().copied().unwrap_or(0),
            mean,
        }
    }
}

/// How a player's link driver ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ending {
    /// The relay closed the link cleanly after the player's leave was processed.
    Clean,
    /// The driver ended with an error, or the teardown wait timed out. The
    /// pessimistic default before an outcome is known.
    #[default]
    Errored,
    /// The player never connected to its relay.
    DialFailed,
    /// The player connected but never observed the relay's session-start
    /// directive within the wait window.
    NoSessionStart,
}

/// One player's raw contribution to a run's metrics.
#[derive(Debug, Default)]
pub struct PlayerReport {
    pub fan_out_latency_us: Vec<u64>,
    pub inter_arrival_gap_us: Vec<u64>,
    pub stalls: u64,
    pub turns_sent: u64,
    pub turns_received: u64,
    /// Distinct expected `(origin slot, frame)` deliveries observed by this
    /// player during the measured frame range.
    pub turn_deliveries_distinct: u64,
    /// Repeated `(origin slot, frame)` deliveries. The client transport normally
    /// deduplicates these; a non-zero value exposes an accounting or identity
    /// regression rather than increasing the distinct-delivery total.
    pub turn_deliveries_duplicate: u64,
    /// Time from session-create completion to this player's session-start
    /// receipt, if it saw one.
    pub time_to_session_start_us: Option<u64>,
    pub ending: Ending,
}

/// Exact end-to-end delivery accounting for one created session.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeliveryReport {
    pub expected: u64,
    pub distinct: u64,
    pub missing: u64,
    pub duplicate: u64,
    pub complete: bool,
    pub timed_out: bool,
}

impl PlayerReport {
    /// A player that never got as far as connecting.
    pub fn dial_failed() -> Self {
        Self {
            ending: Ending::DialFailed,
            ..Self::default()
        }
    }
}

/// One session's outcome.
#[derive(Debug)]
pub enum SessionReport {
    /// The session was created; each of its players ran to completion.
    Created {
        create_latency_us: u64,
        provisioning_holds: u64,
        players: Vec<PlayerReport>,
        delivery: DeliveryReport,
    },
    /// The create request failed. `status` is the HTTP status if the coordinator
    /// answered, or `None` for a transport-level failure.
    CreateFailed { status: Option<u16> },
}

/// The whole run's summarized metrics, ready to print or serialize.
#[derive(Debug, Serialize)]
pub struct RunReport {
    /// The offered workload that produced this report. Keeping it beside the
    /// aggregates makes two saved JSON files self-describing: a latency or CPU
    /// comparison is only meaningful when these inputs match.
    pub workload: Workload,
    /// Whole conductor wall time, including ramp-up and teardown.
    pub elapsed_ms: u64,
    /// Actual player turns emitted divided by whole conductor wall time. This is
    /// a run-level throughput sanity check, not a steady-state rate (the elapsed
    /// interval deliberately includes the arrival ramp).
    pub turns_sent_per_sec: f64,
    /// Actual per-player turn deliveries divided by whole conductor wall time.
    pub turns_received_per_sec: f64,
    pub sessions_requested: usize,
    pub sessions_created: usize,
    pub sessions_create_failed: usize,
    pub create_failures_by_status: BTreeMap<String, u64>,
    pub provisioning_holds: u64,
    pub players_total: usize,
    pub players_session_start_seen: usize,
    pub endings_clean: usize,
    pub endings_errored: usize,
    pub endings_dial_failed: usize,
    pub endings_no_session_start: usize,
    pub turns_sent: u64,
    pub turns_received: u64,
    pub turn_deliveries_expected: u64,
    pub turn_deliveries_distinct: u64,
    pub turn_deliveries_missing: u64,
    pub turn_deliveries_duplicate: u64,
    pub sessions_delivery_complete: usize,
    pub sessions_delivery_timed_out: usize,
    pub sessions_delivery_incomplete: usize,
    pub stalls: u64,
    pub create_latency_us: Distribution,
    pub time_to_session_start_us: Distribution,
    pub fan_out_latency_us: Distribution,
    pub inter_arrival_gap_us: Distribution,
}

/// Inputs that materially shape relay work during one load run.
#[derive(Debug, Clone, Serialize)]
pub struct Workload {
    pub run_id: String,
    pub sessions: usize,
    pub arrival_rate: f64,
    pub players_per_session: usize,
    pub game_secs: u64,
    pub turn_rate: u32,
    pub turn_bytes: usize,
    pub slot_regions: Vec<String>,
    pub desync_fraction: f64,
    pub ipv4_only: bool,
}

impl RunReport {
    /// Folds every session's raw report into the run summary.
    pub fn aggregate(workload: Workload, elapsed: Duration, reports: Vec<SessionReport>) -> Self {
        let sessions_requested = workload.sessions;
        let mut sessions_created = 0;
        let mut sessions_create_failed = 0;
        let mut create_failures_by_status: BTreeMap<String, u64> = BTreeMap::new();
        let mut provisioning_holds = 0;
        let mut players_total = 0;
        let mut players_session_start_seen = 0;
        let mut endings_clean = 0;
        let mut endings_errored = 0;
        let mut endings_dial_failed = 0;
        let mut endings_no_session_start = 0;
        let mut turns_sent = 0;
        let mut turns_received = 0;
        let mut turn_deliveries_expected = 0u64;
        let mut turn_deliveries_distinct = 0u64;
        let mut turn_deliveries_missing = 0u64;
        let mut turn_deliveries_duplicate = 0u64;
        let mut sessions_delivery_complete = 0;
        let mut sessions_delivery_timed_out = 0;
        let mut sessions_delivery_incomplete = 0;
        let mut stalls = 0;

        let mut create_latency_us = Vec::new();
        let mut time_to_session_start_us = Vec::new();
        let mut fan_out_latency_us = Vec::new();
        let mut inter_arrival_gap_us = Vec::new();

        for report in reports {
            match report {
                SessionReport::Created {
                    create_latency_us: latency,
                    provisioning_holds: holds,
                    players,
                    delivery,
                } => {
                    sessions_created += 1;
                    provisioning_holds += holds;
                    create_latency_us.push(latency);
                    turn_deliveries_expected =
                        turn_deliveries_expected.saturating_add(delivery.expected);
                    turn_deliveries_distinct =
                        turn_deliveries_distinct.saturating_add(delivery.distinct);
                    turn_deliveries_missing =
                        turn_deliveries_missing.saturating_add(delivery.missing);
                    turn_deliveries_duplicate =
                        turn_deliveries_duplicate.saturating_add(delivery.duplicate);
                    if delivery.complete {
                        sessions_delivery_complete += 1;
                    } else {
                        sessions_delivery_incomplete += 1;
                    }
                    if delivery.timed_out {
                        sessions_delivery_timed_out += 1;
                    }
                    for player in players {
                        players_total += 1;
                        turns_sent += player.turns_sent;
                        turns_received += player.turns_received;
                        stalls += player.stalls;
                        fan_out_latency_us.extend(player.fan_out_latency_us);
                        inter_arrival_gap_us.extend(player.inter_arrival_gap_us);
                        if let Some(t) = player.time_to_session_start_us {
                            players_session_start_seen += 1;
                            time_to_session_start_us.push(t);
                        }
                        match player.ending {
                            Ending::Clean => endings_clean += 1,
                            Ending::Errored => endings_errored += 1,
                            Ending::DialFailed => endings_dial_failed += 1,
                            Ending::NoSessionStart => endings_no_session_start += 1,
                        }
                    }
                }
                SessionReport::CreateFailed { status } => {
                    sessions_create_failed += 1;
                    let key = match status {
                        Some(code) => code.to_string(),
                        None => "transport".to_owned(),
                    };
                    *create_failures_by_status.entry(key).or_default() += 1;
                }
            }
        }

        let elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        let elapsed_secs = elapsed.as_secs_f64();
        let (turns_sent_per_sec, turns_received_per_sec) = if elapsed_secs > 0.0 {
            (
                turns_sent as f64 / elapsed_secs,
                turns_received as f64 / elapsed_secs,
            )
        } else {
            (0.0, 0.0)
        };

        Self {
            workload,
            elapsed_ms,
            turns_sent_per_sec,
            turns_received_per_sec,
            sessions_requested,
            sessions_created,
            sessions_create_failed,
            create_failures_by_status,
            provisioning_holds,
            players_total,
            players_session_start_seen,
            endings_clean,
            endings_errored,
            endings_dial_failed,
            endings_no_session_start,
            turns_sent,
            turns_received,
            turn_deliveries_expected,
            turn_deliveries_distinct,
            turn_deliveries_missing,
            turn_deliveries_duplicate,
            sessions_delivery_complete,
            sessions_delivery_timed_out,
            sessions_delivery_incomplete,
            stalls,
            create_latency_us: Distribution::from_samples(create_latency_us),
            time_to_session_start_us: Distribution::from_samples(time_to_session_start_us),
            fan_out_latency_us: Distribution::from_samples(fan_out_latency_us),
            inter_arrival_gap_us: Distribution::from_samples(inter_arrival_gap_us),
        }
    }

    /// A readable multi-line summary of the run.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "=== rally-point-loadgen run summary ===");
        let _ = writeln!(
            out,
            "workload: run={} arrival={:.2}/s players/session={} game={}s turns={}Hz bytes={} regions={:?}",
            self.workload.run_id,
            self.workload.arrival_rate,
            self.workload.players_per_session,
            self.workload.game_secs,
            self.workload.turn_rate,
            self.workload.turn_bytes,
            self.workload.slot_regions,
        );
        let _ = writeln!(
            out,
            "elapsed: {:.3}s; throughput: {:.1} turns sent/s, {:.1} deliveries/s",
            self.elapsed_ms as f64 / 1_000.0,
            self.turns_sent_per_sec,
            self.turns_received_per_sec,
        );
        let _ = writeln!(
            out,
            "sessions: {} requested, {} created, {} create-failed",
            self.sessions_requested, self.sessions_created, self.sessions_create_failed
        );
        if !self.create_failures_by_status.is_empty() {
            let _ = writeln!(
                out,
                "  create failures by status: {:?}",
                self.create_failures_by_status
            );
        }
        let _ = writeln!(out, "provisioning holds: {}", self.provisioning_holds);
        let _ = writeln!(
            out,
            "players: {} total, {} saw session-start",
            self.players_total, self.players_session_start_seen
        );
        let _ = writeln!(
            out,
            "endings: {} clean, {} errored, {} dial-failed, {} no-session-start",
            self.endings_clean,
            self.endings_errored,
            self.endings_dial_failed,
            self.endings_no_session_start
        );
        let _ = writeln!(
            out,
            "turns: {} sent, {} received; stalls: {}",
            self.turns_sent, self.turns_received, self.stalls
        );
        let _ = writeln!(
            out,
            "deliveries: {} expected, {} distinct, {} missing, {} duplicate",
            self.turn_deliveries_expected,
            self.turn_deliveries_distinct,
            self.turn_deliveries_missing,
            self.turn_deliveries_duplicate,
        );
        let _ = writeln!(
            out,
            "delivery sessions: {} complete, {} incomplete, {} timed-out",
            self.sessions_delivery_complete,
            self.sessions_delivery_incomplete,
            self.sessions_delivery_timed_out,
        );
        let _ = writeln!(out, "-- latencies (microseconds) --");
        render_distribution(&mut out, "create", &self.create_latency_us);
        render_distribution(
            &mut out,
            "time-to-session-start",
            &self.time_to_session_start_us,
        );
        render_distribution(&mut out, "turn fan-out", &self.fan_out_latency_us);
        render_distribution(
            &mut out,
            "inbound inter-arrival gap",
            &self.inter_arrival_gap_us,
        );
        out
    }
}

/// Appends one distribution's summary line to `out`.
fn render_distribution(out: &mut String, label: &str, dist: &Distribution) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "  {label:<26} n={:<6} p50={:<8} p90={:<8} p99={:<8} max={:<8} mean={}",
        dist.count, dist.p50, dist.p90, dist.p99, dist.max, dist.mean
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_nearest_rank_and_handles_empty() {
        assert_eq!(percentile(&[], 50.0), 0);

        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 50.0), 50);
        assert_eq!(percentile(&sorted, 90.0), 90);
        assert_eq!(percentile(&sorted, 99.0), 99);
        assert_eq!(percentile(&sorted, 100.0), 100);
        // A percentile at or below the first rank lands on the smallest value.
        assert_eq!(percentile(&sorted, 0.0), 1);

        let single = [42];
        assert_eq!(percentile(&single, 50.0), 42);
        assert_eq!(percentile(&single, 99.0), 42);
    }

    #[test]
    fn distribution_summarizes_from_unsorted_samples() {
        let dist = Distribution::from_samples(vec![5, 1, 3, 2, 4]);
        assert_eq!(dist.count, 5);
        assert_eq!(dist.p50, 3);
        assert_eq!(dist.max, 5);
        assert_eq!(dist.mean, 3);

        let empty = Distribution::from_samples(vec![]);
        assert_eq!(empty.count, 0);
        assert_eq!(empty.max, 0);
        assert_eq!(empty.mean, 0);
    }

    #[test]
    fn run_report_keeps_workload_and_actual_wall_clock_rates() {
        let workload = Workload {
            run_id: "comparison-a".to_owned(),
            sessions: 1,
            arrival_rate: 2.0,
            players_per_session: 2,
            game_secs: 30,
            turn_rate: 24,
            turn_bytes: 16,
            slot_regions: vec!["us-west".to_owned(), "us-east".to_owned()],
            desync_fraction: 0.0,
            ipv4_only: false,
        };
        let report = RunReport::aggregate(
            workload,
            Duration::from_secs(2),
            vec![SessionReport::Created {
                create_latency_us: 10,
                provisioning_holds: 0,
                players: vec![PlayerReport {
                    turns_sent: 20,
                    turns_received: 30,
                    ending: Ending::Clean,
                    ..PlayerReport::default()
                }],
                delivery: DeliveryReport {
                    expected: 30,
                    distinct: 29,
                    missing: 1,
                    duplicate: 2,
                    complete: false,
                    timed_out: true,
                },
            }],
        );

        assert_eq!(report.workload.run_id, "comparison-a");
        assert_eq!(report.elapsed_ms, 2_000);
        assert_eq!(report.turns_sent_per_sec, 10.0);
        assert_eq!(report.turns_received_per_sec, 15.0);
        assert_eq!(report.turn_deliveries_expected, 30);
        assert_eq!(report.turn_deliveries_distinct, 29);
        assert_eq!(report.turn_deliveries_missing, 1);
        assert_eq!(report.turn_deliveries_duplicate, 2);
        assert_eq!(report.sessions_delivery_complete, 0);
        assert_eq!(report.sessions_delivery_incomplete, 1);
        assert_eq!(report.sessions_delivery_timed_out, 1);

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["turn_deliveries_expected"], 30);
        assert_eq!(json["turn_deliveries_distinct"], 29);
        assert_eq!(json["turn_deliveries_missing"], 1);
        assert_eq!(json["turn_deliveries_duplicate"], 2);
        assert_eq!(json["sessions_delivery_complete"], 0);
        assert_eq!(json["sessions_delivery_timed_out"], 1);

        let rendered = report.render();
        assert!(rendered.contains("deliveries: 30 expected, 29 distinct, 1 missing, 2 duplicate"));
        assert!(rendered.contains("delivery sessions: 0 complete, 1 incomplete, 1 timed-out"));
    }
}
