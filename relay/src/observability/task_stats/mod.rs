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
//! CPU% and network throughput are rates, not point values, so they use the
//! provider's `read` timestamps across two distinct samples: [`derive`] is kept
//! separate from the GET/parse/loop shell so cached-sample and counter-reset
//! behavior is unit-testable without a live metadata endpoint.

mod derive;
mod fetch;
#[cfg(test)]
mod tests;

use derive::{derive, derive_work};
use fetch::{Sample, TaskLimits, fetch, fetch_task_limits};

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::observability::flight_recorder::{FlightRecorder, RelayWorkSnapshot};
use crate::routing::Sessions;
use crate::session::turn_ring::RingTotals;

/// Env var Fargate injects with the task metadata endpoint's base URL.
/// Present only under Fargate (or ECS-on-EC2 in awsvpc mode); its absence is
/// what makes the reporter a no-op everywhere else.
const METADATA_URI_ENV: &str = "ECS_CONTAINER_METADATA_URI_V4";

/// Path suffix appended to the metadata base URL for the current container's
/// live Docker stats.
const STATS_PATH: &str = "/stats";

/// Path suffix for task-level metadata. Unlike the container `/stats`
/// response, this exposes the Fargate task's actual CPU and memory allocation.
const TASK_PATH: &str = "/task";

/// Timeout on one metadata GET (connect through body). Generous for a
/// same-host link-local request, but bounded so one hung request can't wedge
/// every future tick — the loop always keeps ticking regardless.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Bytes per mebibyte, for converting the raw byte counters Docker reports
/// into the MiB units the log line reports.
const MIB: f64 = 1024.0 * 1024.0;

type StatsClient = Client<HttpConnector, Full<Bytes>>;

/// Relay-local observables paired with every Docker resource sample.
struct ReporterContext {
    relay_id: Option<u64>,
    sessions: Sessions,
    turn_ring: crate::session::turn_ring::TurnRing,
    control_stats: crate::coordinator::client::ControlConnStats,
    flight_recorder: FlightRecorder,
}

/// Relay-lifetime work counters sampled alongside one Docker resource sample.
/// Local validation/delivery counters come from the flight recorder; distinct
/// mesh-origin turns come from the replay ring's already-locked record path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WorkSnapshot {
    client_turns_validated: u64,
    local_turn_deliveries: u64,
    oversize_diverts: u64,
    mesh_ingress_turns: u64,
}

impl WorkSnapshot {
    fn from_sources(relay: RelayWorkSnapshot, ring: RingTotals) -> Self {
        Self {
            client_turns_validated: relay.client_turns_validated,
            local_turn_deliveries: relay.local_turn_deliveries,
            oversize_diverts: relay.oversize_diverts,
            mesh_ingress_turns: ring.mesh_origin_turns,
        }
    }

    fn ingress_turns(self) -> u64 {
        self.client_turns_validated
            .saturating_add(self.mesh_ingress_turns)
    }
}

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
/// `flight_recorder` supplies relay-lifetime local work counters for
/// CPU-efficiency denominators; its session flushes do not reset those totals.
/// `turn_ring` also supplies the relay-lifetime count of distinct mesh-origin
/// turns, collected under its existing record lock.
pub fn spawn_if_enabled(
    interval_secs: u64,
    relay_id: Option<u64>,
    sessions: Sessions,
    turn_ring: crate::session::turn_ring::TurnRing,
    control_stats: crate::coordinator::client::ControlConnStats,
    flight_recorder: FlightRecorder,
) {
    if interval_secs == 0 {
        tracing::debug!("task-stats reporter disabled: interval is 0");
        return;
    }
    let Ok(metadata_uri) = std::env::var(METADATA_URI_ENV) else {
        tracing::debug!("task-stats reporter disabled: no ECS metadata endpoint");
        return;
    };
    let metadata_base = metadata_uri.trim_end_matches('/');
    let stats_url = format!("{metadata_base}{STATS_PATH}");
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
    let task_url = format!("{metadata_base}{TASK_PATH}");
    let task_uri: Uri = match task_url.parse() {
        Ok(uri) => uri,
        Err(error) => {
            tracing::warn!(
                %error,
                url = %task_url,
                "task-stats reporter disabled: task metadata URL did not parse",
            );
            return;
        }
    };
    let client: StatsClient = Client::builder(TokioExecutor::new()).build_http();
    tokio::spawn(run(
        client,
        uri,
        task_uri,
        Duration::from_secs(interval_secs),
        ReporterContext {
            relay_id,
            sessions,
            turn_ring,
            control_stats,
            flight_recorder,
        },
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
    task_uri: Uri,
    interval: Duration,
    context: ReporterContext,
) {
    tracing::info!(
        interval_secs = interval.as_secs(),
        "task-stats reporter started"
    );
    let mut task_limits = TaskLimits::default();
    let mut prev: Option<(Sample, WorkSnapshot, std::time::Instant)> = None;
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        // Task allocations are immutable for a running Fargate task. Retry
        // transient or incomplete metadata responses until both limits are
        // known, then keep the cached values for the reporter's lifetime.
        if !task_limits.is_complete() {
            match tokio::time::timeout(FETCH_TIMEOUT, fetch_task_limits(&client, &task_uri)).await {
                Ok(Ok(observed)) => {
                    task_limits.merge(observed);
                    if task_limits.is_complete() {
                        tracing::info!(
                            task_cpu_vcpus = task_limits.cpu_vcpus.unwrap_or_default(),
                            task_mem_limit_mib = task_limits.memory_mib.unwrap_or_default(),
                            "task-stats task limits recorded",
                        );
                    } else {
                        tracing::debug!(
                            task_cpu_vcpus = ?task_limits.cpu_vcpus,
                            task_mem_limit_mib = ?task_limits.memory_mib,
                            "task metadata limits incomplete; will retry",
                        );
                    }
                }
                Ok(Err(error)) => {
                    tracing::debug!(%error, "task metadata limits read failed; will retry");
                }
                Err(_) => {
                    tracing::debug!("task metadata limits read timed out; will retry");
                }
            }
        }
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
        let ring = context.turn_ring.totals();
        let work = WorkSnapshot::from_sources(context.flight_recorder.relay_work_snapshot(), ring);

        let Some((prev_sample, prev_work, prev_at)) = prev else {
            tracing::debug!("task-stats reporter: baseline sample recorded");
            prev = Some((curr, work, now));
            continue;
        };
        let elapsed = now.duration_since(prev_at);
        let derived = derive(Some(&prev_sample), &curr, task_limits);
        let work_derived = derive_work(
            &prev_work,
            &work,
            derived.cpu_cores_used,
            derived.provider_interval_ns,
            elapsed,
        );
        let sessions = crate::routing::session_count(&context.sessions);
        let control = context.control_stats.snapshot();
        tracing::info!(
            relay_id = context.relay_id,
            cpu_pct = ?derived.cpu_pct,
            cpu_cores_used = ?derived.cpu_cores_used,
            cpu_total_usage_ns = curr.cpu_total_usage,
            provider_read_unix_ns = ?curr.provider_read_unix_ns,
            provider_interval_ms = ?derived.provider_interval_ms,
            provider_sample_stale = derived.provider_sample_stale,
            task_cpu_vcpus = ?task_limits.cpu_vcpus,
            mem_mib = derived.mem_working_set_mib,
            mem_limit_mib = derived.mem_limit_mib.unwrap_or_default(),
            mem_limit_known = derived.mem_limit_mib.is_some(),
            net_rx_mibps = ?derived.net_rx_mibps,
            net_tx_mibps = ?derived.net_tx_mibps,
            work_interval_ms = elapsed.as_secs_f64() * 1_000.0,
            cpu_work_intervals_aligned = work_derived.cpu_work_intervals_aligned,
            validated_turns_per_sec = ?work_derived.validated_turns_per_sec,
            mesh_ingress_turns_per_sec = ?work_derived.mesh_ingress_turns_per_sec,
            ingress_turns_per_sec = ?work_derived.ingress_turns_per_sec,
            local_deliveries_per_sec = ?work_derived.local_deliveries_per_sec,
            oversize_diverts_per_sec = ?work_derived.oversize_diverts_per_sec,
            // Compatibility aliases for the original task-stats schema. These
            // now share the explicit estimate/alignment semantics below.
            cpu_ns_per_validated_turn = ?work_derived.estimated_cpu_ns_per_validated_turn,
            cpu_ns_per_ingress_turn = ?work_derived.estimated_cpu_ns_per_ingress_turn,
            cpu_ns_per_local_delivery = ?work_derived.estimated_cpu_ns_per_local_delivery,
            estimated_cpu_ns_per_validated_turn = ?work_derived.estimated_cpu_ns_per_validated_turn,
            estimated_cpu_ns_per_ingress_turn = ?work_derived.estimated_cpu_ns_per_ingress_turn,
            estimated_cpu_ns_per_local_delivery = ?work_derived.estimated_cpu_ns_per_local_delivery,
            validated_turns_total = work.client_turns_validated,
            mesh_ingress_turns_total = work.mesh_ingress_turns,
            ingress_turns_total = work.ingress_turns(),
            local_deliveries_total = work.local_turn_deliveries,
            oversize_diverts_total = work.oversize_diverts,
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
        // A repeated provider timestamp is a cached sample, not a zero-work
        // interval. Retain the last distinct resource/work baseline so the next
        // provider refresh spans the full matching interval. A backwards
        // timestamp or reset counter, on the other hand, reseeds the baseline so
        // a bad sample cannot suppress rates forever.
        if curr.provider_read_unix_ns != prev_sample.provider_read_unix_ns {
            prev = Some((curr, work, now));
        }
    }
}
