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
    /// Time from session-create completion to this player's session-start
    /// receipt, if it saw one.
    pub time_to_session_start_us: Option<u64>,
    pub ending: Ending,
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
    },
    /// The create request failed. `status` is the HTTP status if the coordinator
    /// answered, or `None` for a transport-level failure.
    CreateFailed { status: Option<u16> },
}

/// The whole run's summarized metrics, ready to print or serialize.
#[derive(Debug, Serialize)]
pub struct RunReport {
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
    pub stalls: u64,
    pub create_latency_us: Distribution,
    pub time_to_session_start_us: Distribution,
    pub fan_out_latency_us: Distribution,
    pub inter_arrival_gap_us: Distribution,
}

impl RunReport {
    /// Folds every session's raw report into the run summary.
    pub fn aggregate(sessions_requested: usize, reports: Vec<SessionReport>) -> Self {
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
                } => {
                    sessions_created += 1;
                    provisioning_holds += holds;
                    create_latency_us.push(latency);
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

        Self {
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
}
