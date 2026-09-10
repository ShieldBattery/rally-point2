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

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::flight_recorder::{FlightRecorder, RelayWorkSnapshot};
use crate::routing::Sessions;
use crate::turn_ring::RingTotals;

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

/// Cgroup v1 represents "no container-level memory limit" with a value just
/// below `i64::MAX`. Keep the cutoff deliberately broad: no useful Fargate
/// task limit is remotely close to an exbibyte, while this also recognizes
/// page-size variants of the sentinel.
const CGROUP_UNLIMITED_MIN_BYTES: u64 = 1 << 60;

/// CPU and relay-work counters come from independent samplers. Per-work CPU
/// estimates are useful only when those samplers cover approximately the same
/// interval; require the shorter interval to be at least 80% of the longer.
const CPU_WORK_INTERVAL_TOLERANCE_DIVISOR: u128 = 5;

type StatsClient = Client<HttpConnector, Full<Bytes>>;

/// Relay-local observables paired with every Docker resource sample.
struct ReporterContext {
    relay_id: Option<u64>,
    sessions: Sessions,
    turn_ring: crate::turn_ring::TurnRing,
    control_stats: crate::coordinator_client::ControlConnStats,
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
    turn_ring: crate::turn_ring::TurnRing,
    control_stats: crate::coordinator_client::ControlConnStats,
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

/// GETs and parses one `/stats` sample. The caller applies the overall
/// timeout; this only shapes the transport/parse failure into one error type.
async fn fetch(client: &StatsClient, uri: &Uri) -> Result<Sample, FetchError> {
    let body = fetch_body(client, uri).await?;
    let parsed: StatsResponse = serde_json::from_slice(&body).map_err(FetchError::Parse)?;
    Sample::from_stats_response(&parsed).map_err(FetchError::Timestamp)
}

/// Reads the task-level allocation. Fargate applies CPU/memory at the task
/// cgroup, so the container stats response can legitimately advertise an
/// unlimited container even though the task itself has a finite allocation.
/// The caller retries until both limits are valid, then caches them.
async fn fetch_task_limits(client: &StatsClient, uri: &Uri) -> Result<TaskLimits, FetchError> {
    let body = fetch_body(client, uri).await?;
    let parsed: TaskMetadataResponse = serde_json::from_slice(&body).map_err(FetchError::Parse)?;
    Ok(TaskLimits::from_response(parsed))
}

async fn fetch_body(client: &StatsClient, uri: &Uri) -> Result<Bytes, FetchError> {
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
    Ok(body)
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
    #[error("parsing the stats provider timestamp failed: {0}")]
    Timestamp(time::error::Parse),
}

/// Task-level limits from `${ECS_CONTAINER_METADATA_URI_V4}/task`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct TaskLimits {
    cpu_vcpus: Option<f64>,
    memory_mib: Option<f64>,
}

impl TaskLimits {
    fn from_response(response: TaskMetadataResponse) -> Self {
        let Some(limits) = response.limits else {
            return Self::default();
        };
        Self {
            cpu_vcpus: limits.cpu.filter(|value| value.is_finite() && *value > 0.0),
            memory_mib: limits
                .memory
                .filter(|value| value.is_finite() && *value > 0.0),
        }
    }

    fn merge(&mut self, observed: Self) {
        self.cpu_vcpus = self.cpu_vcpus.or(observed.cpu_vcpus);
        self.memory_mib = self.memory_mib.or(observed.memory_mib);
    }

    fn is_complete(self) -> bool {
        self.cpu_vcpus.is_some() && self.memory_mib.is_some()
    }
}

#[derive(Debug, Deserialize)]
struct TaskMetadataResponse {
    #[serde(rename = "Limits", default)]
    limits: Option<TaskLimitsResponse>,
}

#[derive(Debug, Deserialize)]
struct TaskLimitsResponse {
    #[serde(rename = "CPU", default)]
    cpu: Option<f64>,
    #[serde(rename = "Memory", default)]
    memory: Option<f64>,
}

/// The Docker container-stats JSON shape, narrowed to the fields this reporter
/// reads. Unknown fields (the real payload carries many more, e.g. `blkio_stats`,
/// `pids_stats`) are ignored by default rather than rejected.
#[derive(Debug, Deserialize)]
struct StatsResponse {
    read: String,
    #[serde(default)]
    preread: Option<String>,
    cpu_stats: CpuStats,
    #[serde(default)]
    precpu_stats: Option<CpuStats>,
    memory_stats: MemoryStats,
    #[serde(default)]
    networks: HashMap<String, NetworkStats>,
}

#[derive(Debug, Deserialize)]
struct CpuStats {
    cpu_usage: CpuUsage,
    #[serde(default)]
    system_cpu_usage: Option<u64>,
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
    /// Provider collection time, not the time at which this relay happened to
    /// fetch the cached response. Nanoseconds since the Unix epoch preserve the
    /// RFC 3339 payload's full precision while keeping rate math allocation-free.
    provider_read_unix_ns: i128,
    provider_preread_unix_ns: Option<i128>,
    cpu_total_usage: u64,
    cpu_previous_total_usage: Option<u64>,
    cpu_system_usage: Option<u64>,
    cpu_previous_system_usage: Option<u64>,
    online_cpus: u64,
    mem_usage: u64,
    mem_inactive_file: u64,
    mem_limit: u64,
    net_rx_bytes: Option<u64>,
    net_tx_bytes: Option<u64>,
}

impl Sample {
    fn from_stats_response(resp: &StatsResponse) -> Result<Self, time::error::Parse> {
        let provider_read_unix_ns = parse_provider_timestamp(&resp.read)?;
        let provider_preread_unix_ns = resp
            .preread
            .as_deref()
            .map(parse_provider_timestamp)
            .transpose()?;
        let online_cpus = resp.cpu_stats.online_cpus.unwrap_or_else(|| {
            resp.cpu_stats
                .cpu_usage
                .percpu_usage
                .as_ref()
                .map_or(0, |percpu| percpu.len() as u64)
        });
        let network_totals = (!resp.networks.is_empty()).then(|| {
            resp.networks
                .values()
                .fold((0u64, 0u64), |(rx, tx), iface| {
                    (
                        rx.saturating_add(iface.rx_bytes),
                        tx.saturating_add(iface.tx_bytes),
                    )
                })
        });
        Ok(Sample {
            provider_read_unix_ns,
            provider_preread_unix_ns,
            cpu_total_usage: resp.cpu_stats.cpu_usage.total_usage,
            cpu_previous_total_usage: resp
                .precpu_stats
                .as_ref()
                .map(|stats| stats.cpu_usage.total_usage),
            cpu_system_usage: resp.cpu_stats.system_cpu_usage,
            cpu_previous_system_usage: resp
                .precpu_stats
                .as_ref()
                .and_then(|stats| stats.system_cpu_usage),
            online_cpus,
            mem_usage: resp.memory_stats.usage,
            mem_inactive_file: resp.memory_stats.stats.inactive_file.unwrap_or(0),
            mem_limit: resp.memory_stats.limit,
            net_rx_bytes: network_totals.map(|(rx, _)| rx),
            net_tx_bytes: network_totals.map(|(_, tx)| tx),
        })
    }
}

fn parse_provider_timestamp(value: &str) -> Result<i128, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339).map(OffsetDateTime::unix_timestamp_nanos)
}

/// The metrics one log line reports, derived from a sample (and, for the rate
/// fields, the previous one).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Derived {
    /// `None` with no previous sample, or when the system-time counter didn't
    /// advance (a non-positive delta) — never a fabricated rate.
    cpu_pct: Option<f64>,
    /// Container CPU nanoseconds divided by wall-clock nanoseconds. Unlike
    /// `cpu_pct`, this does not depend on the host-wide system CPU counter: 1.0
    /// means one full core and 0.5 means half a core.
    cpu_cores_used: Option<f64>,
    mem_working_set_mib: f64,
    mem_limit_mib: Option<f64>,
    provider_interval_ns: Option<u128>,
    provider_interval_ms: Option<f64>,
    provider_sample_stale: bool,
    /// `None` with no previous sample, or a non-positive elapsed time.
    net_rx_mibps: Option<f64>,
    /// `None` under the same conditions as `net_rx_mibps`.
    net_tx_mibps: Option<f64>,
}

/// Relay work rates and estimated CPU-time-per-work-unit for one successful
/// poll interval.
///
/// Docker's CPU counter and the relay's work counters are sampled by independent
/// clocks. Their cumulative totals are the canonical measurements. These CPU
/// ratios are estimates derived from the provider CPU rate and are emitted only
/// when the provider and local work intervals are close enough that pairing
/// them is meaningful. They include all relay work, not only turn handling.
/// Ingress is the sum of locally validated turns and distinct mesh-origin
/// turns. A local delivery also scales with roster placement and fanout, so
/// these ratios are intended to compare identical load-generator topologies
/// and traffic mixes, not unlike workloads with different player/session
/// shapes.
#[derive(Debug, Clone, Copy, PartialEq)]
struct WorkDerived {
    validated_turns_per_sec: Option<f64>,
    mesh_ingress_turns_per_sec: Option<f64>,
    ingress_turns_per_sec: Option<f64>,
    local_deliveries_per_sec: Option<f64>,
    oversize_diverts_per_sec: Option<f64>,
    cpu_work_intervals_aligned: bool,
    estimated_cpu_ns_per_validated_turn: Option<f64>,
    estimated_cpu_ns_per_ingress_turn: Option<f64>,
    estimated_cpu_ns_per_local_delivery: Option<f64>,
}

/// Differences two relay-lifetime work snapshots and pairs them with the latest
/// provider-derived CPU rate. Pure and total so load-test interpretation is
/// covered by unit tests without an ECS metadata endpoint.
fn derive_work(
    prev_work: &WorkSnapshot,
    curr_work: &WorkSnapshot,
    cpu_cores_used: Option<f64>,
    provider_interval_ns: Option<u128>,
    work_interval: Duration,
) -> WorkDerived {
    let validated = curr_work
        .client_turns_validated
        .saturating_sub(prev_work.client_turns_validated);
    let deliveries = curr_work
        .local_turn_deliveries
        .saturating_sub(prev_work.local_turn_deliveries);
    let oversize = curr_work
        .oversize_diverts
        .saturating_sub(prev_work.oversize_diverts);
    let mesh_ingress = curr_work
        .mesh_ingress_turns
        .saturating_sub(prev_work.mesh_ingress_turns);
    let ingress = validated.saturating_add(mesh_ingress);

    let elapsed_secs = work_interval.as_secs_f64();
    let rates = (elapsed_secs > 0.0).then_some((
        validated as f64 / elapsed_secs,
        mesh_ingress as f64 / elapsed_secs,
        ingress as f64 / elapsed_secs,
        deliveries as f64 / elapsed_secs,
        oversize as f64 / elapsed_secs,
    ));
    let work_interval_ns = work_interval.as_nanos();
    let cpu_work_intervals_aligned =
        provider_interval_ns.is_some_and(|provider| intervals_close(provider, work_interval_ns));
    // Even aligned counters are not atomically sampled, so this remains an
    // estimate: project the provider CPU rate over the nearby work interval.
    let estimated_cpu_delta = cpu_work_intervals_aligned
        .then(|| cpu_cores_used.map(|cores| cores * work_interval_ns as f64))
        .flatten();

    WorkDerived {
        validated_turns_per_sec: rates.map(|rates| rates.0),
        mesh_ingress_turns_per_sec: rates.map(|rates| rates.1),
        ingress_turns_per_sec: rates.map(|rates| rates.2),
        local_deliveries_per_sec: rates.map(|rates| rates.3),
        oversize_diverts_per_sec: rates.map(|rates| rates.4),
        cpu_work_intervals_aligned,
        estimated_cpu_ns_per_validated_turn: estimated_cpu_delta
            .and_then(|cpu| (validated > 0).then_some(cpu / validated as f64)),
        estimated_cpu_ns_per_ingress_turn: estimated_cpu_delta
            .and_then(|cpu| (ingress > 0).then_some(cpu / ingress as f64)),
        estimated_cpu_ns_per_local_delivery: estimated_cpu_delta
            .and_then(|cpu| (deliveries > 0).then_some(cpu / deliveries as f64)),
    }
}

fn intervals_close(left: u128, right: u128) -> bool {
    let longer = left.max(right);
    let shorter = left.min(right);
    longer > 0 && longer - shorter <= longer / CPU_WORK_INTERVAL_TOLERANCE_DIVISOR
}

/// Computes the metrics for one log line from `curr` and, when available, the
/// previous distinct provider sample. Pure and total: never panics on any input
/// (subtraction is checked/saturating throughout), which is what makes it
/// unit-testable against synthetic counters without a live metadata endpoint.
///
/// CPU% follows the standard Docker-stats formula: the fraction of the
/// system's elapsed CPU time this container's cumulative usage consumed,
/// scaled by the online CPU count. `system_cpu_usage` and `total_usage` are
/// both cumulative counters, so a non-advancing or reversed system counter
/// (the delta is zero or would underflow) makes CPU% unknowable for this tick
/// rather than a divide-by-zero or a nonsensical value — `cpu_pct` is `None`
/// in that case. `cpu_cores_used` instead divides the container's CPU-time
/// delta directly by the stats provider's `read` timestamp delta, avoiding
/// both host-counter noise and aliasing between the provider's cache cadence
/// and this reporter's poll cadence. A repeated provider timestamp makes all
/// rates `None`, rather than fabricating a zero interval. Network counters use
/// the same provider interval.
fn derive(prev: Option<&Sample>, curr: &Sample, task_limits: TaskLimits) -> Derived {
    let provider_interval_ns = match prev {
        Some(prev) => curr
            .provider_read_unix_ns
            .checked_sub(prev.provider_read_unix_ns),
        None => curr
            .provider_preread_unix_ns
            .and_then(|preread| curr.provider_read_unix_ns.checked_sub(preread)),
    }
    .and_then(|elapsed| u128::try_from(elapsed).ok())
    .filter(|elapsed| *elapsed > 0);

    let cpu_delta = match prev {
        Some(prev) => curr.cpu_total_usage.checked_sub(prev.cpu_total_usage),
        None => curr
            .cpu_previous_total_usage
            .and_then(|previous| curr.cpu_total_usage.checked_sub(previous)),
    };
    let system_delta = match prev {
        Some(prev) => curr
            .cpu_system_usage
            .zip(prev.cpu_system_usage)
            .and_then(|(current, previous)| current.checked_sub(previous)),
        None => curr
            .cpu_system_usage
            .zip(curr.cpu_previous_system_usage)
            .and_then(|(current, previous)| current.checked_sub(previous)),
    };

    let cpu_pct = provider_interval_ns.and_then(|_| {
        let system_delta = system_delta?;
        if system_delta == 0 {
            return None;
        }
        let cpu_delta = cpu_delta?;
        Some((cpu_delta as f64 / system_delta as f64) * curr.online_cpus as f64 * 100.0)
    });
    let cpu_cores_used = provider_interval_ns
        .zip(cpu_delta)
        .map(|(elapsed, delta)| delta as f64 / elapsed as f64);

    let mem_working_set = curr.mem_usage.saturating_sub(curr.mem_inactive_file);
    let container_mem_limit_mib = (curr.mem_limit > 0
        && curr.mem_limit < CGROUP_UNLIMITED_MIN_BYTES)
        .then_some(curr.mem_limit as f64 / MIB);

    let net_rates = provider_interval_ns.and_then(|elapsed_nanos| {
        prev.and_then(|prev| {
            let rx_delta = curr.net_rx_bytes?.checked_sub(prev.net_rx_bytes?)?;
            let tx_delta = curr.net_tx_bytes?.checked_sub(prev.net_tx_bytes?)?;
            let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;
            Some((
                rx_delta as f64 / MIB / elapsed_secs,
                tx_delta as f64 / MIB / elapsed_secs,
            ))
        })
    });

    Derived {
        cpu_pct,
        cpu_cores_used,
        mem_working_set_mib: mem_working_set as f64 / MIB,
        mem_limit_mib: task_limits.memory_mib.or(container_mem_limit_mib),
        provider_interval_ns,
        provider_interval_ms: provider_interval_ns.map(|nanos| nanos as f64 / 1_000_000.0),
        provider_sample_stale: prev
            .is_some_and(|prev| curr.provider_read_unix_ns == prev.provider_read_unix_ns),
        net_rx_mibps: net_rates.map(|(rx, _)| rx),
        net_tx_mibps: net_rates.map(|(_, tx)| tx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NANOS_PER_SEC: i128 = 1_000_000_000;

    fn sample_at(seconds: i128, mut sample: Sample) -> Sample {
        sample.provider_read_unix_ns = seconds * NANOS_PER_SEC;
        sample
    }

    // --- CPU% ---

    #[test]
    fn cpu_pct_is_none_with_no_previous_sample() {
        let curr = Sample {
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: Some(12_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(None, &curr, TaskLimits::default());
        assert_eq!(derived.cpu_pct, None);
        assert_eq!(derived.cpu_cores_used, None);
    }

    #[test]
    fn cpu_pct_computes_from_two_synthetic_samples() {
        // 500ms of container CPU time out of 2s of system CPU time, on 4
        // online CPUs: (0.5e9 / 2e9) * 4 * 100 = 100%.
        let prev = Sample {
            provider_read_unix_ns: 10 * NANOS_PER_SEC,
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: Some(10_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            provider_read_unix_ns: 12 * NANOS_PER_SEC,
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: Some(12_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, TaskLimits::default());
        assert_eq!(derived.cpu_pct, Some(100.0));
        assert_eq!(derived.cpu_cores_used, Some(0.25));
    }

    #[test]
    fn cpu_pct_is_none_on_a_zero_system_delta() {
        let prev = Sample {
            provider_read_unix_ns: 10 * NANOS_PER_SEC,
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: Some(10_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            provider_read_unix_ns: 12 * NANOS_PER_SEC,
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: Some(10_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, TaskLimits::default());
        assert_eq!(derived.cpu_pct, None);
    }

    #[test]
    fn cpu_pct_is_none_on_a_negative_system_delta() {
        // A reversed/reset system counter must not underflow into a huge
        // bogus percentage.
        let prev = Sample {
            provider_read_unix_ns: 10 * NANOS_PER_SEC,
            cpu_total_usage: 1_000_000_000,
            cpu_system_usage: Some(12_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let curr = Sample {
            provider_read_unix_ns: 12 * NANOS_PER_SEC,
            cpu_total_usage: 1_500_000_000,
            cpu_system_usage: Some(10_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };
        let derived = derive(Some(&prev), &curr, TaskLimits::default());
        assert_eq!(derived.cpu_pct, None);
    }

    #[test]
    fn cpu_cores_used_is_none_on_zero_elapsed_or_a_reset_container_counter() {
        let prev = Sample {
            provider_read_unix_ns: 10 * NANOS_PER_SEC,
            cpu_total_usage: 1_000,
            ..Default::default()
        };
        let advanced = Sample {
            provider_read_unix_ns: 10 * NANOS_PER_SEC,
            cpu_total_usage: 2_000,
            ..Default::default()
        };
        assert_eq!(
            derive(Some(&prev), &advanced, TaskLimits::default()).cpu_cores_used,
            None,
        );

        let reset = Sample {
            provider_read_unix_ns: 11 * NANOS_PER_SEC,
            cpu_total_usage: 500,
            ..Default::default()
        };
        assert_eq!(
            derive(Some(&prev), &reset, TaskLimits::default()).cpu_cores_used,
            None,
        );
    }

    #[test]
    fn cached_duplicate_is_stale_and_catch_up_uses_provider_elapsed() {
        let prev = sample_at(
            10,
            Sample {
                cpu_total_usage: 5_000_000_000,
                cpu_system_usage: Some(100_000_000_000),
                online_cpus: 4,
                ..Default::default()
            },
        );
        let duplicate = prev;

        let stale = derive(Some(&prev), &duplicate, TaskLimits::default());
        assert!(stale.provider_sample_stale);
        assert_eq!(stale.provider_interval_ms, None);
        assert_eq!(stale.cpu_cores_used, None);
        assert_eq!(stale.cpu_pct, None);

        // The provider next catches up by 10 CPU-seconds across 20 seconds of
        // its own clock. Dividing by the relay's 10-second poll interval would
        // falsely report one full core; provider time correctly reports 0.5.
        let catch_up = sample_at(
            30,
            Sample {
                cpu_total_usage: 15_000_000_000,
                cpu_system_usage: Some(180_000_000_000),
                online_cpus: 4,
                ..Default::default()
            },
        );
        let derived = derive(Some(&prev), &catch_up, TaskLimits::default());
        assert!(!derived.provider_sample_stale);
        assert_eq!(derived.provider_interval_ms, Some(20_000.0));
        assert_eq!(derived.cpu_cores_used, Some(0.5));
    }

    #[test]
    fn embedded_preread_and_precpu_supply_the_provider_interval() {
        let curr = Sample {
            provider_read_unix_ns: 20 * NANOS_PER_SEC,
            provider_preread_unix_ns: Some(10 * NANOS_PER_SEC),
            cpu_total_usage: 8_000_000_000,
            cpu_previous_total_usage: Some(3_000_000_000),
            cpu_system_usage: Some(50_000_000_000),
            cpu_previous_system_usage: Some(30_000_000_000),
            online_cpus: 4,
            ..Default::default()
        };

        let derived = derive(None, &curr, TaskLimits::default());
        assert_eq!(derived.provider_interval_ms, Some(10_000.0));
        assert_eq!(derived.cpu_cores_used, Some(0.5));
        assert_eq!(derived.cpu_pct, Some(100.0));
    }

    // --- relay work efficiency ---

    #[test]
    fn ingress_total_combines_local_and_mesh_without_overflow() {
        let work = WorkSnapshot {
            client_turns_validated: 7,
            mesh_ingress_turns: 5,
            ..Default::default()
        };
        assert_eq!(work.ingress_turns(), 12);

        let saturated = WorkSnapshot {
            client_turns_validated: u64::MAX,
            mesh_ingress_turns: 1,
            ..Default::default()
        };
        assert_eq!(saturated.ingress_turns(), u64::MAX);
    }

    #[test]
    fn work_rates_and_cpu_efficiency_difference_cumulative_snapshots() {
        let prev_work = WorkSnapshot {
            client_turns_validated: 100,
            local_turn_deliveries: 300,
            oversize_diverts: 4,
            mesh_ingress_turns: 10,
        };
        let curr_work = WorkSnapshot {
            client_turns_validated: 140,
            local_turn_deliveries: 420,
            oversize_diverts: 10,
            mesh_ingress_turns: 30,
        };
        let derived = derive_work(
            &prev_work,
            &curr_work,
            Some(0.3),
            Some(2_000_000_000),
            Duration::from_secs(2),
        );
        assert_eq!(derived.validated_turns_per_sec, Some(20.0));
        assert_eq!(derived.mesh_ingress_turns_per_sec, Some(10.0));
        assert_eq!(derived.ingress_turns_per_sec, Some(30.0));
        assert_eq!(derived.local_deliveries_per_sec, Some(60.0));
        assert_eq!(derived.oversize_diverts_per_sec, Some(3.0));
        assert!(derived.cpu_work_intervals_aligned);
        assert_eq!(
            derived.estimated_cpu_ns_per_validated_turn,
            Some(15_000_000.0),
        );
        assert_eq!(
            derived.estimated_cpu_ns_per_ingress_turn,
            Some(10_000_000.0),
        );
        assert_eq!(
            derived.estimated_cpu_ns_per_local_delivery,
            Some(5_000_000.0),
        );
    }

    #[test]
    fn mismatched_cpu_and_work_intervals_suppress_cpu_efficiency_estimates() {
        let prev_work = WorkSnapshot::default();
        let curr_work = WorkSnapshot {
            client_turns_validated: 10,
            local_turn_deliveries: 20,
            mesh_ingress_turns: 5,
            ..Default::default()
        };
        let derived = derive_work(
            &prev_work,
            &curr_work,
            Some(0.5),
            Some(20_000_000_000),
            Duration::from_secs(10),
        );

        assert_eq!(derived.validated_turns_per_sec, Some(1.0));
        assert_eq!(derived.ingress_turns_per_sec, Some(1.5));
        assert!(!derived.cpu_work_intervals_aligned);
        assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
    }

    #[test]
    fn zero_work_denominators_report_zero_rates_without_fabricated_cpu_ratios() {
        let work = WorkSnapshot {
            client_turns_validated: 100,
            local_turn_deliveries: 300,
            oversize_diverts: 4,
            mesh_ingress_turns: 25,
        };
        let derived = derive_work(
            &work,
            &work,
            Some(0.3),
            Some(2_000_000_000),
            Duration::from_secs(2),
        );
        assert_eq!(derived.validated_turns_per_sec, Some(0.0));
        assert_eq!(derived.mesh_ingress_turns_per_sec, Some(0.0));
        assert_eq!(derived.ingress_turns_per_sec, Some(0.0));
        assert_eq!(derived.local_deliveries_per_sec, Some(0.0));
        assert_eq!(derived.oversize_diverts_per_sec, Some(0.0));
        assert!(derived.cpu_work_intervals_aligned);
        assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
    }

    #[test]
    fn work_rates_survive_a_cpu_counter_reset_but_cpu_ratios_do_not() {
        let prev_work = WorkSnapshot::default();
        let curr_work = WorkSnapshot {
            client_turns_validated: 10,
            local_turn_deliveries: 20,
            oversize_diverts: 0,
            mesh_ingress_turns: 5,
        };
        let derived = derive_work(
            &prev_work,
            &curr_work,
            None,
            Some(1_000_000_000),
            Duration::from_secs(1),
        );
        assert_eq!(derived.validated_turns_per_sec, Some(10.0));
        assert_eq!(derived.mesh_ingress_turns_per_sec, Some(5.0));
        assert_eq!(derived.ingress_turns_per_sec, Some(15.0));
        assert_eq!(derived.local_deliveries_per_sec, Some(20.0));
        assert!(derived.cpu_work_intervals_aligned);
        assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
    }

    #[test]
    fn mesh_only_work_still_has_an_ingress_cpu_denominator() {
        let prev_work = WorkSnapshot {
            mesh_ingress_turns: 100,
            ..Default::default()
        };
        let curr_work = WorkSnapshot {
            mesh_ingress_turns: 110,
            ..Default::default()
        };
        let derived = derive_work(
            &prev_work,
            &curr_work,
            Some(0.000_000_5),
            Some(2_000_000_000),
            Duration::from_secs(2),
        );
        assert_eq!(derived.validated_turns_per_sec, Some(0.0));
        assert_eq!(derived.mesh_ingress_turns_per_sec, Some(5.0));
        assert_eq!(derived.ingress_turns_per_sec, Some(5.0));
        assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
        assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, Some(100.0));
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
        let derived = derive(None, &curr, TaskLimits::default());
        assert_eq!(derived.mem_working_set_mib, 100.0);
        assert_eq!(derived.mem_limit_mib, Some(512.0));
    }

    #[test]
    fn memory_working_set_saturates_when_inactive_file_exceeds_usage() {
        // Never observed in practice, but the subtraction must not underflow.
        let curr = Sample {
            mem_usage: 10,
            mem_inactive_file: 20,
            ..Default::default()
        };
        let derived = derive(None, &curr, TaskLimits::default());
        assert_eq!(derived.mem_working_set_mib, 0.0);
    }

    #[test]
    fn task_memory_limit_replaces_the_cgroup_unlimited_sentinel() {
        let curr = Sample {
            mem_limit: 9_223_372_036_854_771_712,
            ..Default::default()
        };

        let unknown = derive(None, &curr, TaskLimits::default());
        assert_eq!(unknown.mem_limit_mib, None);

        let task_limits = TaskLimits {
            cpu_vcpus: Some(0.5),
            memory_mib: Some(1024.0),
        };
        let allocated = derive(None, &curr, task_limits);
        assert_eq!(allocated.mem_limit_mib, Some(1024.0));
    }

    #[test]
    fn parses_task_level_cpu_and_memory_limits() {
        let parsed: TaskMetadataResponse = serde_json::from_str(
            r#"{
                "TaskARN": "arn:aws:ecs:us-west-2:123:task/cluster/id",
                "Limits": { "CPU": 0.5, "Memory": 1024 }
            }"#,
        )
        .unwrap();

        assert_eq!(
            TaskLimits::from_response(parsed),
            TaskLimits {
                cpu_vcpus: Some(0.5),
                memory_mib: Some(1024.0),
            },
        );
    }

    #[test]
    fn task_limits_merge_partial_responses_until_complete() {
        let mut limits = TaskLimits::default();
        assert!(!limits.is_complete());

        limits.merge(TaskLimits {
            cpu_vcpus: Some(0.5),
            memory_mib: None,
        });
        assert_eq!(limits.cpu_vcpus, Some(0.5));
        assert!(!limits.is_complete());

        limits.merge(TaskLimits {
            cpu_vcpus: None,
            memory_mib: Some(1024.0),
        });
        assert_eq!(
            limits,
            TaskLimits {
                cpu_vcpus: Some(0.5),
                memory_mib: Some(1024.0),
            },
        );
        assert!(limits.is_complete());
    }

    // --- network rate ---

    #[test]
    fn network_rate_is_none_with_no_previous_sample() {
        let curr = Sample {
            net_rx_bytes: Some(3 * 1024 * 1024),
            net_tx_bytes: Some(2 * 1024 * 1024),
            ..Default::default()
        };
        let derived = derive(None, &curr, TaskLimits::default());
        assert_eq!(derived.net_rx_mibps, None);
        assert_eq!(derived.net_tx_mibps, None);
    }

    #[test]
    fn network_rate_computes_delta_over_elapsed_time() {
        // rx grows by 2 MiB and tx by 1 MiB over 2 seconds -> 1.0 and 0.5 MiB/s.
        let prev = sample_at(
            10,
            Sample {
                net_rx_bytes: Some(1024 * 1024),
                net_tx_bytes: Some(1024 * 1024),
                ..Default::default()
            },
        );
        let curr = sample_at(
            12,
            Sample {
                net_rx_bytes: Some(3 * 1024 * 1024),
                net_tx_bytes: Some(2 * 1024 * 1024),
                ..Default::default()
            },
        );
        let derived = derive(Some(&prev), &curr, TaskLimits::default());
        assert_eq!(derived.net_rx_mibps, Some(1.0));
        assert_eq!(derived.net_tx_mibps, Some(0.5));
    }

    #[test]
    fn network_rate_is_none_on_a_zero_elapsed_time() {
        let prev = sample_at(
            10,
            Sample {
                net_rx_bytes: Some(1024 * 1024),
                net_tx_bytes: Some(1024 * 1024),
                ..Default::default()
            },
        );
        let curr = sample_at(
            10,
            Sample {
                net_rx_bytes: Some(3 * 1024 * 1024),
                net_tx_bytes: Some(2 * 1024 * 1024),
                ..Default::default()
            },
        );
        let derived = derive(Some(&prev), &curr, TaskLimits::default());
        assert_eq!(derived.net_rx_mibps, None);
        assert_eq!(derived.net_tx_mibps, None);
    }

    #[test]
    fn omitted_network_counters_do_not_create_a_spike_when_they_reappear() {
        let present = sample_at(
            10,
            Sample {
                net_rx_bytes: Some(1024 * 1024),
                net_tx_bytes: Some(1024 * 1024),
                ..Default::default()
            },
        );
        let omitted = sample_at(11, Sample::default());
        let reappeared = sample_at(
            12,
            Sample {
                net_rx_bytes: Some(100 * 1024 * 1024),
                net_tx_bytes: Some(50 * 1024 * 1024),
                ..Default::default()
            },
        );
        let next = sample_at(
            13,
            Sample {
                net_rx_bytes: Some(101 * 1024 * 1024),
                net_tx_bytes: Some(51 * 1024 * 1024),
                ..Default::default()
            },
        );

        let disappearance = derive(Some(&present), &omitted, TaskLimits::default());
        assert_eq!(disappearance.net_rx_mibps, None);
        assert_eq!(disappearance.net_tx_mibps, None);

        let reappearance = derive(Some(&omitted), &reappeared, TaskLimits::default());
        assert_eq!(reappearance.net_rx_mibps, None);
        assert_eq!(reappearance.net_tx_mibps, None);

        let stable = derive(Some(&reappeared), &next, TaskLimits::default());
        assert_eq!(stable.net_rx_mibps, Some(1.0));
        assert_eq!(stable.net_tx_mibps, Some(1.0));
    }

    // --- JSON parse ---

    #[test]
    fn parses_a_representative_docker_stats_payload() {
        let json = r#"{
            "read": "2026-07-18T00:00:00.000000000Z",
            "preread": "2026-07-17T23:59:50.000000000Z",
            "cpu_stats": {
                "cpu_usage": {
                    "total_usage": 1500000000,
                    "percpu_usage": [400000000, 380000000, 360000000, 360000000]
                },
                "system_cpu_usage": 12000000000,
                "online_cpus": 4,
                "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
            },
            "precpu_stats": {
                "cpu_usage": { "total_usage": 1000000000 },
                "system_cpu_usage": 10000000000,
                "online_cpus": 4
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
        let sample = Sample::from_stats_response(&parsed).unwrap();

        assert_eq!(
            sample.provider_read_unix_ns - sample.provider_preread_unix_ns.unwrap(),
            10 * NANOS_PER_SEC,
        );
        assert_eq!(sample.cpu_total_usage, 1_500_000_000);
        assert_eq!(sample.cpu_previous_total_usage, Some(1_000_000_000));
        assert_eq!(sample.cpu_system_usage, Some(12_000_000_000));
        assert_eq!(sample.online_cpus, 4);
        assert_eq!(sample.mem_usage, 209_715_200);
        assert_eq!(sample.mem_inactive_file, 104_857_600);
        assert_eq!(sample.mem_limit, 536_870_912);
        // Summed across both interfaces: rx 1 MiB + 2 MiB, tx 512 KiB + 1 MiB.
        assert_eq!(sample.net_rx_bytes, Some(1_048_576 + 2_097_152));
        assert_eq!(sample.net_tx_bytes, Some(524_288 + 1_048_576));
    }

    #[test]
    fn falls_back_to_percpu_usage_length_when_online_cpus_is_absent() {
        let json = r#"{
            "read": "2026-07-18T00:00:00Z",
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
        let sample = Sample::from_stats_response(&parsed).unwrap();

        assert_eq!(sample.online_cpus, 3);
    }

    #[test]
    fn omitted_system_cpu_counters_preserve_primary_cpu_cores() {
        let json = r#"{
            "read": "2026-07-18T00:00:20Z",
            "preread": "2026-07-18T00:00:10Z",
            "cpu_stats": {
                "cpu_usage": { "total_usage": 8000000000 },
                "online_cpus": 4
            },
            "precpu_stats": {
                "cpu_usage": { "total_usage": 3000000000 },
                "online_cpus": 4
            },
            "memory_stats": { "usage": 100, "limit": 200 }
        }"#;

        let parsed: StatsResponse = serde_json::from_str(json).unwrap();
        let sample = Sample::from_stats_response(&parsed).unwrap();
        let derived = derive(None, &sample, TaskLimits::default());

        assert_eq!(sample.cpu_system_usage, None);
        assert_eq!(sample.cpu_previous_system_usage, None);
        assert_eq!(derived.cpu_cores_used, Some(0.5));
        assert_eq!(derived.cpu_pct, None);
    }

    #[test]
    fn defaults_missing_optional_fields_to_unknown_or_zero_as_appropriate() {
        // No `networks`, no `memory_stats.stats`, no `online_cpus`, no
        // `percpu_usage` — every optional field absent at once.
        let json = r#"{
            "read": "2026-07-18T00:00:00Z",
            "cpu_stats": {
                "cpu_usage": { "total_usage": 1000 },
                "system_cpu_usage": 5000
            },
            "memory_stats": { "usage": 100, "limit": 200 }
        }"#;

        let parsed: StatsResponse = serde_json::from_str(json).unwrap();
        let sample = Sample::from_stats_response(&parsed).unwrap();

        assert_eq!(sample.online_cpus, 0);
        assert_eq!(sample.mem_inactive_file, 0);
        assert_eq!(sample.net_rx_bytes, None);
        assert_eq!(sample.net_tx_bytes, None);
    }
}
