//! Fetching and parsing the ECS metadata endpoints: the `/stats` (Docker
//! container stats) and `/task` (task-level CPU/memory allocation) GETs, the
//! JSON shapes they return, and the narrowed [`Sample`]/[`TaskLimits`] this
//! reporter actually needs out of them. Kept apart from `derive.rs` so the
//! I/O and deserialization live separately from the pure rate math.

use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::StatsClient;

/// GETs and parses one `/stats` sample. The caller applies the overall
/// timeout; this only shapes the transport/parse failure into one error type.
pub(super) async fn fetch(client: &StatsClient, uri: &Uri) -> Result<Sample, FetchError> {
    let body = fetch_body(client, uri).await?;
    let parsed: StatsResponse = serde_json::from_slice(&body).map_err(FetchError::Parse)?;
    Sample::from_stats_response(&parsed).map_err(FetchError::Timestamp)
}

/// Reads the task-level allocation. Fargate applies CPU/memory at the task
/// cgroup, so the container stats response can legitimately advertise an
/// unlimited container even though the task itself has a finite allocation.
/// The caller retries until both limits are valid, then caches them.
pub(super) async fn fetch_task_limits(
    client: &StatsClient,
    uri: &Uri,
) -> Result<TaskLimits, FetchError> {
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
pub(super) enum FetchError {
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
pub(super) struct TaskLimits {
    pub(super) cpu_vcpus: Option<f64>,
    pub(super) memory_mib: Option<f64>,
}

impl TaskLimits {
    pub(super) fn from_response(response: TaskMetadataResponse) -> Self {
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

    pub(super) fn merge(&mut self, observed: Self) {
        self.cpu_vcpus = self.cpu_vcpus.or(observed.cpu_vcpus);
        self.memory_mib = self.memory_mib.or(observed.memory_mib);
    }

    pub(super) fn is_complete(self) -> bool {
        self.cpu_vcpus.is_some() && self.memory_mib.is_some()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct TaskMetadataResponse {
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
pub(super) struct StatsResponse {
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
pub(super) struct Sample {
    /// Provider collection time, not the time at which this relay happened to
    /// fetch the cached response. Nanoseconds since the Unix epoch preserve the
    /// RFC 3339 payload's full precision while keeping rate math allocation-free.
    pub(super) provider_read_unix_ns: i128,
    pub(super) provider_preread_unix_ns: Option<i128>,
    pub(super) cpu_total_usage: u64,
    pub(super) cpu_previous_total_usage: Option<u64>,
    pub(super) cpu_system_usage: Option<u64>,
    pub(super) cpu_previous_system_usage: Option<u64>,
    pub(super) online_cpus: u64,
    pub(super) mem_usage: u64,
    pub(super) mem_inactive_file: u64,
    pub(super) mem_limit: u64,
    pub(super) net_rx_bytes: Option<u64>,
    pub(super) net_tx_bytes: Option<u64>,
}

impl Sample {
    pub(super) fn from_stats_response(resp: &StatsResponse) -> Result<Self, time::error::Parse> {
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
