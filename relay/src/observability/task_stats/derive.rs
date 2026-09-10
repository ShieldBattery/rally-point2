//! Pure derivation of one log line's metrics from raw samples: CPU%/cores,
//! memory working set, network rates ([`derive`]), and relay-work rates plus
//! estimated CPU-per-work-unit ([`derive_work`]). Kept free of I/O so both
//! are unit-testable against synthetic counters, no metadata endpoint needed.

use std::time::Duration;

use super::MIB;
use super::WorkSnapshot;
use super::fetch::{Sample, TaskLimits};

/// Cgroup v1 represents "no container-level memory limit" with a value just
/// below `i64::MAX`. Keep the cutoff deliberately broad: no useful Fargate
/// task limit is remotely close to an exbibyte, while this also recognizes
/// page-size variants of the sentinel.
const CGROUP_UNLIMITED_MIN_BYTES: u64 = 1 << 60;

/// CPU and relay-work counters come from independent samplers. Per-work CPU
/// estimates are useful only when those samplers cover approximately the same
/// interval; require the shorter interval to be at least 80% of the longer.
const CPU_WORK_INTERVAL_TOLERANCE_DIVISOR: u128 = 5;

/// The metrics one log line reports, derived from a sample (and, for the rate
/// fields, the previous one).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Derived {
    /// `None` with no previous sample, or when the system-time counter didn't
    /// advance (a non-positive delta) — never a fabricated rate.
    pub(super) cpu_pct: Option<f64>,
    /// Container CPU nanoseconds divided by wall-clock nanoseconds. Unlike
    /// `cpu_pct`, this does not depend on the host-wide system CPU counter: 1.0
    /// means one full core and 0.5 means half a core.
    pub(super) cpu_cores_used: Option<f64>,
    pub(super) mem_working_set_mib: f64,
    pub(super) mem_limit_mib: Option<f64>,
    pub(super) provider_interval_ns: Option<u128>,
    pub(super) provider_interval_ms: Option<f64>,
    pub(super) provider_sample_stale: bool,
    /// `None` with no previous sample, or a non-positive elapsed time.
    pub(super) net_rx_mibps: Option<f64>,
    /// `None` under the same conditions as `net_rx_mibps`.
    pub(super) net_tx_mibps: Option<f64>,
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
pub(super) struct WorkDerived {
    pub(super) validated_turns_per_sec: Option<f64>,
    pub(super) mesh_ingress_turns_per_sec: Option<f64>,
    pub(super) ingress_turns_per_sec: Option<f64>,
    pub(super) local_deliveries_per_sec: Option<f64>,
    pub(super) oversize_diverts_per_sec: Option<f64>,
    pub(super) cpu_work_intervals_aligned: bool,
    pub(super) estimated_cpu_ns_per_validated_turn: Option<f64>,
    pub(super) estimated_cpu_ns_per_ingress_turn: Option<f64>,
    pub(super) estimated_cpu_ns_per_local_delivery: Option<f64>,
}

/// Differences two relay-lifetime work snapshots and pairs them with the latest
/// provider-derived CPU rate. Pure and total so load-test interpretation is
/// covered by unit tests without an ECS metadata endpoint.
pub(super) fn derive_work(
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
pub(super) fn derive(prev: Option<&Sample>, curr: &Sample, task_limits: TaskLimits) -> Derived {
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
