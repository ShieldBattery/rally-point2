//! Self-reported Fargate task resource stats: a periodic background task that
//! reads this relay's own ECS Task Metadata `/stats` endpoint and logs a
//! structured CPU/memory/network line, so a load test (and production) can see
//! per-task resource use without any AWS-side config. Independent of
//! CloudWatch Container Insights — it reads the task-local metadata endpoint
//! directly rather than any AWS-side aggregation.
//!
//! Fargate injects `ECS_CONTAINER_METADATA_URI_V4`, a base URL such as
//! `http://169.254.170.2/v4/<id>`; `GET <that base>/stats` returns the calling
//! container's live Docker stats as JSON, no auth required. A single-container
//! task (the relay) means that JSON is always this process's own stats. The
//! env var is absent everywhere else (dev/loopback, any non-Fargate run), which
//! is exactly when [`spawn_if_enabled`] does nothing.
//!
//! CPU% and network throughput are rates, not point values, so they need two
//! consecutive samples: [`derive`] is a pure function of `(previous sample,
//! current sample, elapsed time)`, kept separate from the GET/parse/loop shell
//! so it's unit-testable without a live metadata endpoint.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::routing::Sessions;

/// Env var Fargate injects with the task metadata endpoint's base URL.
/// Present only under Fargate (or ECS-on-EC2 in awsvpc mode); its absence is
/// what makes the reporter a no-op everywhere else.
const METADATA_URI_ENV: &str = "ECS_CONTAINER_METADATA_URI_V4";

/// Path suffix appended to the metadata base URL for the current container's
/// live Docker stats.
const STATS_PATH: &str = "/stats";

/// Timeout on one metadata GET (connect through body). Generous for a
/// same-host link-local request, but bounded so one hung request can't wedge
/// every future tick — the loop always keeps ticking regardless.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Bytes per mebibyte, for converting the raw byte counters Docker reports
/// into the MiB units the log line reports.
const MIB: f64 = 1024.0 * 1024.0;

type StatsClient = Client<HttpConnector, Full<Bytes>>;

/// Starts the periodic task-stats reporter if `interval_secs` is nonzero and
/// this process is running as a Fargate task; otherwise logs one debug line
/// and returns without spawning anything.
///
/// `interval_secs` is `--task-stats-interval-secs` / `RELAY_TASK_STATS_INTERVAL_SECS`.
/// `relay_id` stamps each line so a multi-relay run's samples are attributable
/// (absent from the line when the relay has no configured id). `sessions` and
/// `turn_ring` are cloned into the spawned task and read on every tick (their
/// locks never held across an await), so each log line pairs a resource sample
/// with the relay's session count and its replay-ring occupancy at that moment
/// — the ring is the largest deliberately-held per-session memory, so the line
/// shows directly how much of the working set it accounts for. `control_stats` adds
/// the coordinator control connection's observables to the same line — its outbound
/// queue depths (control-plane pressure) and its descriptor apply lag (how far
/// descriptor delivery trailed staging) — and stays all-zero on a relay with no
/// coordinator connection.
pub fn spawn_if_enabled(
    interval_secs: u64,
    relay_id: Option<u64>,
    sessions: Sessions,
    turn_ring: crate::turn_ring::TurnRing,
    control_stats: crate::coordinator_client::ControlConnStats,
) {
    if interval_secs == 0 {
        tracing::debug!("task-stats reporter disabled: interval is 0");
        return;
    }
    let Ok(metadata_uri) = std::env::var(METADATA_URI_ENV) else {
        tracing::debug!("task-stats reporter disabled: no ECS metadata endpoint");
        return;
    };
    let stats_url = format!("{}{STATS_PATH}", metadata_uri.trim_end_matches('/'));
    let uri: Uri = match stats_url.parse() {
        Ok(uri) => uri,
        Err(error) => {
            tracing::warn!(
                %error,
                url = %stats_url,
                "task-stats reporter disabled: metadata stats URL did not parse",
            );
            return;
        }
    };
    let client: StatsClient = Client::builder(TokioExecutor::new()).build_http();
    tokio::spawn(run(
        client,
        uri,
        Duration::from_secs(interval_secs),
        relay_id,
        sessions,
        turn_ring,
        control_stats,
    ));
}

/// The poll loop: GET the stats endpoint every `interval`, compute the
/// deltas against the previous sample, and log a structured line. A failed or
/// timed-out GET, or a response that doesn't parse, is logged at debug and
/// skipped — one bad read never stops the loop, it just leaves the next
/// successful read to reseed the baseline.
async fn run(
    client: StatsClient,
    uri: Uri,
    interval: Duration,
    relay_id: Option<u64>,
    sessions: Sessions,
    turn_ring: crate::turn_ring::TurnRing,
    control_stats: crate::coordinator_client::ControlConnStats,
) {
    tracing::info!(
        interval_secs = interval.as_secs(),
        "task-stats reporter started"
    );
    let mut prev: Option<(Sample, std::time::Instant)> = None;
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let now = std::time::Instant::now();
        let curr = match tokio::time::timeout(FETCH_TIMEOUT, fetch(&client, &uri)).await {
            Ok(Ok(sample)) => sample,
            Ok(Err(error)) => {
                tracing::debug!(%error, "task-stats read failed; skipping this tick");
                continue;
            }
            Err(_) => {
                tracing::debug!("task-stats read timed out; skipping this tick");
                continue;
            }
        };

        let Some((prev_sample, prev_at)) = prev else {
            tracing::debug!("task-stats reporter: baseline sample recorded");
            prev = Some((curr, now));
            continue;
        };
        let derived = derive(Some(&prev_sample), &curr, now.duration_since(prev_at));
        let sessions = crate::routing::session_count(&sessions);
        let ring = turn_ring.totals();
        let control = control_stats.snapshot();
        tracing::info!(
            relay_id,
            cpu_pct = ?derived.cpu_pct,
            mem_mib = derived.mem_working_set_mib,
            mem_limit_mib = derived.mem_limit_mib,
            net_rx_mibps = ?derived.net_rx_mibps,
            net_tx_mibps = ?derived.net_tx_mibps,
            sessions,
            ring_turns = ring.turns,
            ring_cmd_mib = ring.command_bytes as f64 / MIB,
            control_notice_depth = control.notices,
            control_flight_depth = control.flights,
            control_blob_mib = control.pending_blob_bytes as f64 / MIB,
            control_descriptor_apply_lag_ms = control.descriptor_apply_lag_ms,
            control_descriptor_set_len = control.descriptor_set_len,
            "relay task stats",
        );
        prev = Some((curr, now));
    }
}

/// GETs and parses one `/stats` sample. The caller applies the overall
/// timeout; this only shapes the transport/parse failure into one error type.
async fn fetch(client: &StatsClient, uri: &Uri) -> Result<Sample, FetchError> {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))
        .map_err(FetchError::Request)?;
    let response = client
        .request(request)
        .await
        .map_err(FetchError::Transport)?;
    if !response.status().is_success() {
        return Err(FetchError::Status(response.status().as_u16()));
    }
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(FetchError::Body)?
        .to_bytes();
    let parsed: StatsResponse = serde_json::from_slice(&body).map_err(FetchError::Parse)?;
    Ok(Sample::from_stats_response(&parsed))
}

/// Why one `/stats` GET failed. Every variant is recoverable — the loop logs
/// and keeps ticking regardless of which one fired.
#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("building the stats request failed: {0}")]
    Request(hyper::http::Error),
    #[error("the stats GET transport failed: {0}")]
    Transport(hyper_util::client::legacy::Error),
    #[error("the stats endpoint returned status {0}")]
    Status(u16),
    #[error("reading the stats response body failed: {0}")]
    Body(hyper::Error),
    #[error("parsing the stats response failed: {0}")]
    Parse(serde_json::Error),
}

/// The Docker container-stats JSON shape, narrowed to the fields this reporter
/// reads. Unknown fields (the real payload carries many more, e.g. `blkio_stats`,
/// `pids_stats`) are ignored by default rather than rejected.
#[derive(Debug, Deserialize)]
struct StatsResponse {
    cpu_stats: CpuStats,
    memory_stats: MemoryStats,
    #[serde(default)]
    networks: HashMap<String, NetworkStats>,
}

#[derive(Debug, Deserialize)]
struct CpuStats {
    cpu_usage: CpuUsage,
    system_cpu_usage: u64,
    #[serde(default)]
    online_cpus: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CpuUsage {
    total_usage: u64,
    #[serde(default)]
    percpu_usage: Option<Vec<u64>>,
}

#[derive(Debug, Deserialize)]
struct MemoryStats {
    usage: u64,
    limit: u64,
    #[serde(default)]
    stats: MemoryDetailStats,
}

#[derive(Debug, Default, Deserialize)]
struct MemoryDetailStats {
    #[serde(default)]
    inactive_file: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NetworkStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

/// The raw counters this reporter needs out of one `/stats` sample, after
/// resolving the `online_cpus` fallback and summing network bytes across every
/// interface. [`derive`] only ever sees this narrowed shape, never the full
/// JSON structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Sample {
    cpu_total_usage: u64,
    cpu_system_usage: u64,
    online_cpus: u64,
    mem_usage: u64,
    mem_inactive_file: u64,
    mem_limit: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
}

impl Sample {
    fn from_stats_response(resp: &StatsResponse) -> Self {
        let online_cpus = resp.cpu_stats.online_cpus.unwrap_or_else(|| {
            resp.cpu_stats
                .cpu_usage
                .percpu_usage
                .as_ref()
                .map_or(0, |percpu| percpu.len() as u64)
        });
        let (net_rx_bytes, net_tx_bytes) =
            resp.networks
                .values()
                .fold((0u64, 0u64), |(rx, tx), iface| {
                    (
                        rx.saturating_add(iface.rx_bytes),
                        tx.saturating_add(iface.tx_bytes),
                    )
                });
        Sample {
            cpu_total_usage: resp.cpu_stats.cpu_usage.total_usage,
            cpu_system_usage: resp.cpu_stats.system_cpu_usage,
            online_cpus,
            mem_usage: resp.memory_stats.usage,
            mem_inactive_file: resp.memory_stats.stats.inactive_file.unwrap_or(0),
            mem_limit: resp.memory_stats.limit,
            net_rx_bytes,
            net_tx_bytes,
        }
    }
}

/// The metrics one log line reports, derived from a sample (and, for the rate
/// fields, the previous one).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Derived {
    /// `None` with no previous sample, or when the system-time counter didn't
    /// advance (a non-positive delta) — never a fabricated rate.
    cpu_pct: Option<f64>,
    mem_working_set_mib: f64,
    mem_limit_mib: f64,
    /// `None` with no previous sample, or a non-positive elapsed time.
    net_rx_mibps: Option<f64>,
    /// `None` under the same conditions as `net_rx_mibps`.
    net_tx_mibps: Option<f64>,
}

/// Computes the metrics for one log line from `curr` and, when available, the
/// sample taken `elapsed` earlier. Pure and total: never panics on any input
/// (subtraction is checked/saturating throughout), which is what makes it
/// unit-testable against synthetic counters without a live metadata endpoint.
///
/// CPU% follows the standard Docker-stats formula: the fraction of the
/// system's elapsed CPU time this container's cumulative usage consumed,
/// scaled by the online CPU count. `system_cpu_usage` and `total_usage` are
/// both cumulative counters, so a non-advancing or reversed system counter
/// (the delta is zero or would underflow) makes CPU% unknowable for this tick
/// rather than a divide-by-zero or a nonsensical value — `cpu_pct` is `None`
/// in that case. The same shape governs the network rates: a byte counter
/// that doesn't advance, or an elapsed time of zero, yields `None` rather than
/// a fabricated rate.
fn derive(prev: Option<&Sample>, curr: &Sample, elapsed: Duration) -> Derived {
    let cpu_pct = prev.and_then(|prev| {
        let system_delta = curr.cpu_system_usage.checked_sub(prev.cpu_system_usage)?;
        if system_delta == 0 {
            return None;
        }
        let cpu_delta = curr.cpu_total_usage.saturating_sub(prev.cpu_total_usage);
        Some((cpu_delta as f64 / system_delta as f64) * curr.online_cpus as f64 * 100.0)
    });

    let mem_working_set = curr.mem_usage.saturating_sub(curr.mem_inactive_file);

    let elapsed_secs = elapsed.as_secs_f64();
    let net_rates = if elapsed_secs > 0.0 {
        prev.map(|prev| {
            let rx_delta = curr.net_rx_bytes.saturating_sub(prev.net_rx_bytes);
            let tx_delta = curr.net_tx_bytes.saturating_sub(prev.net_tx_bytes);
            (
                rx_delta as f64 / MIB / elapsed_secs,
                tx_delta as f64 / MIB / elapsed_secs,
            )
        })
    } else {
        None
    };

    Derived {
        cpu_pct,
        mem_working_set_mib: mem_working_set as f64 / MIB,
        mem_limit_mib: curr.mem_limit as f64 / MIB,
        net_rx_mibps: net_rates.map(|(rx, _)| rx),
        net_tx_mibps: net_rates.map(|(_, tx)| tx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CPU% ---

    #[test]
    fn cpu_pct_is_none_with_no_previous_sample() {
        let curr = Sample {
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: 12_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(None, &curr, Duration::from_secs(2));
        assert_eq!(derived.cpu_pct, None);
    }

    #[test]
    fn cpu_pct_computes_from_two_synthetic_samples() {
        // 500ms of container CPU time out of 2s of system CPU time, on 4
        // online CPUs: (0.5e9 / 2e9) * 4 * 100 = 100%.
        let prev = Sample {
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: 10_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: 12_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, Duration::from_secs(2));
        assert_eq!(derived.cpu_pct, Some(100.0));
    }

    #[test]
    fn cpu_pct_is_none_on_a_zero_system_delta() {
        let prev = Sample {
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: 10_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: 10_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, Duration::from_secs(2));
        assert_eq!(derived.cpu_pct, None);
    }

    #[test]
    fn cpu_pct_is_none_on_a_negative_system_delta() {
        // A reversed/reset system counter must not underflow into a huge
        // bogus percentage.
        let prev = Sample {
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: 12_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: 10_000_000_000,
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, Duration::from_secs(2));
        assert_eq!(derived.cpu_pct, None);
    }

    // --- memory working set ---

    #[test]
    fn memory_working_set_subtracts_inactive_file_and_converts_to_mib() {
        // usage 200 MiB, inactive_file 100 MiB -> working set 100 MiB; limit
        // exactly 512 MiB.
        let curr = Sample {
            mem_usage: 200 * 1024 * 1024,
            mem_inactive_file: 100 * 1024 * 1024,
            mem_limit: 512 * 1024 * 1024,
            ..Default::default()
        };
        let derived = derive(None, &curr, Duration::from_secs(2));
        assert_eq!(derived.mem_working_set_mib, 100.0);
        assert_eq!(derived.mem_limit_mib, 512.0);
    }

    #[test]
    fn memory_working_set_saturates_when_inactive_file_exceeds_usage() {
        // Never observed in practice, but the subtraction must not underflow.
        let curr = Sample {
            mem_usage: 10,
            mem_inactive_file: 20,
            ..Default::default()
        };
        let derived = derive(None, &curr, Duration::from_secs(2));
        assert_eq!(derived.mem_working_set_mib, 0.0);
    }

    // --- network rate ---

    #[test]
    fn network_rate_is_none_with_no_previous_sample() {
        let curr = Sample {
            net_rx_bytes: 3 * 1024 * 1024,
            net_tx_bytes: 2 * 1024 * 1024,
            ..Default::default()
        };
        let derived = derive(None, &curr, Duration::from_secs(2));
        assert_eq!(derived.net_rx_mibps, None);
        assert_eq!(derived.net_tx_mibps, None);
    }

    #[test]
    fn network_rate_computes_delta_over_elapsed_time() {
        // rx grows by 2 MiB and tx by 1 MiB over 2 seconds -> 1.0 and 0.5 MiB/s.
        let prev = Sample {
            net_rx_bytes: 1024 * 1024,
            net_tx_bytes: 1024 * 1024,
            ..Default::default()
        };
        let curr = Sample {
            net_rx_bytes: 3 * 1024 * 1024,
            net_tx_bytes: 2 * 1024 * 1024,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, Duration::from_secs(2));
        assert_eq!(derived.net_rx_mibps, Some(1.0));
        assert_eq!(derived.net_tx_mibps, Some(0.5));
    }

    #[test]
    fn network_rate_is_none_on_a_zero_elapsed_time() {
        let prev = Sample {
            net_rx_bytes: 1024 * 1024,
            net_tx_bytes: 1024 * 1024,
            ..Default::default()
        };
        let curr = Sample {
            net_rx_bytes: 3 * 1024 * 1024,
            net_tx_bytes: 2 * 1024 * 1024,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, Duration::ZERO);
        assert_eq!(derived.net_rx_mibps, None);
        assert_eq!(derived.net_tx_mibps, None);
    }

    // --- JSON parse ---

    #[test]
    fn parses_a_representative_docker_stats_payload() {
        let json = r#"{
            "read": "2026-07-18T00:00:00.000000000Z",
            "cpu_stats": {
                "cpu_usage": {
                    "total_usage": 1500000000,
                    "percpu_usage": [400000000, 380000000, 360000000, 360000000]
                },
                "system_cpu_usage": 12000000000,
                "online_cpus": 4,
                "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
            },
            "memory_stats": {
                "usage": 209715200,
                "limit": 536870912,
                "stats": {
                    "inactive_file": 104857600,
                    "active_anon": 12345
                }
            },
            "networks": {
                "eth0": { "rx_bytes": 1048576, "tx_bytes": 524288, "rx_packets": 100 },
                "eth1": { "rx_bytes": 2097152, "tx_bytes": 1048576 }
            },
            "pids_stats": { "current": 12 }
        }"#;

        let parsed: StatsResponse = serde_json::from_str(json).unwrap();
        let sample = Sample::from_stats_response(&parsed);

        assert_eq!(sample.cpu_total_usage, 1_500_000_000);
        assert_eq!(sample.cpu_system_usage, 12_000_000_000);
        assert_eq!(sample.online_cpus, 4);
        assert_eq!(sample.mem_usage, 209_715_200);
        assert_eq!(sample.mem_inactive_file, 104_857_600);
        assert_eq!(sample.mem_limit, 536_870_912);
        // Summed across both interfaces: rx 1 MiB + 2 MiB, tx 512 KiB + 1 MiB.
        assert_eq!(sample.net_rx_bytes, 1_048_576 + 2_097_152);
        assert_eq!(sample.net_tx_bytes, 524_288 + 1_048_576);
    }

    #[test]
    fn falls_back_to_percpu_usage_length_when_online_cpus_is_absent() {
        let json = r#"{
            "cpu_stats": {
                "cpu_usage": {
                    "total_usage": 1000,
                    "percpu_usage": [100, 100, 100]
                },
                "system_cpu_usage": 5000
            },
            "memory_stats": { "usage": 100, "limit": 200 },
            "networks": {}
        }"#;

        let parsed: StatsResponse = serde_json::from_str(json).unwrap();
        let sample = Sample::from_stats_response(&parsed);

        assert_eq!(sample.online_cpus, 3);
    }

    #[test]
    fn defaults_missing_optional_fields_to_zero() {
        // No `networks`, no `memory_stats.stats`, no `online_cpus`, no
        // `percpu_usage` — every optional field absent at once.
        let json = r#"{
            "cpu_stats": {
                "cpu_usage": { "total_usage": 1000 },
                "system_cpu_usage": 5000
            },
            "memory_stats": { "usage": 100, "limit": 200 }
        }"#;

        let parsed: StatsResponse = serde_json::from_str(json).unwrap();
        let sample = Sample::from_stats_response(&parsed);

        assert_eq!(sample.online_cpus, 0);
        assert_eq!(sample.mem_inactive_file, 0);
        assert_eq!(sample.net_rx_bytes, 0);
        assert_eq!(sample.net_tx_bytes, 0);
    }
}
