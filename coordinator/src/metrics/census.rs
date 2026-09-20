//! The scrape-time census: every gauge value a `/metrics` scrape reports,
//! collected from the subsystem that owns it.
//!
//! This is the only file in `metrics` that knows what a `CoordinatorState` is.
//! Each subsystem answers one question about itself — the registry counts its
//! enrolled relays, the lifecycle censuses its session map, the provision gate
//! reports warm demand and coverage phase, the pair table snapshots its
//! measured directions, the tenant store counts its states — and this file only
//! composes those answers. Nothing here reaches into a store's internals, and
//! nothing downstream of it (the rendering) ever sees the state at all.

use std::collections::BTreeMap;

use rally_point_proto::control::RegionId;
use rally_point_proto::time::unix_secs_fail_closed;

use super::counters::region_label;
use crate::api::CoordinatorState;
use crate::lifecycle::{self, LifecycleMetrics};
use crate::registry;
use crate::tenant::{self, TenantStateCounts};

/// One scrape's worth of gauge values, in the shape the exposition formats them.
pub(super) struct CoordinatorCensus {
    /// Relays known to the coordinator, keyed by `(region label, state)` where
    /// the state is `live`, `draining`, or `launching`. Sorted by the key, so the
    /// exposition's series order is deterministic.
    pub(super) relays: BTreeMap<(String, String), u64>,
    /// The lifecycle map's per-tenant session counts and pending-queue depths.
    pub(super) lifecycle: LifecycleMetrics,
    /// The relay count each configured region is currently kept warm for, in
    /// configured-region order.
    pub(super) warm: Vec<(RegionId, u64)>,
    /// Measured backbone round-trips as `(origin, target, milliseconds)`, sorted
    /// by origin then target.
    pub(super) backbone: Vec<(String, String, u64)>,
    /// Whether each configured region's coverage bootstrap is backing off, in
    /// configured-region order.
    pub(super) beacon_backoff: Vec<(RegionId, bool)>,
    /// Whether a durable flight-recording sink is configured.
    pub(super) flight_store_configured: bool,
    /// Enrolled tenants by operational state.
    pub(super) tenants: TenantStateCounts,
    /// Non-terminal notices dropped from a full session dispatch queue.
    pub(super) dropped_notices: u64,
}

impl CoordinatorCensus {
    /// Reads every gauge value out of `state`, one question per subsystem.
    pub(super) fn gather(state: &CoordinatorState) -> Self {
        Self {
            relays: relay_counts(state),
            lifecycle: state.lifecycle.metrics_census(),
            warm: warm_targets(state),
            backbone: backbone_rtts(state),
            beacon_backoff: beacon_backoff(state),
            flight_store_configured: state.flight_store.is_some(),
            tenants: tenant::metrics_census(state.setup.tenants()),
            dropped_notices: lifecycle::dropped_notice_count(),
        }
    }
}

/// Enrolled relays from the registry plus, from the ledger, the ones still
/// launching.
///
/// Launching relays live only in the ledger — they have not enrolled yet — so
/// they are counted per configured region there. Skipped on an unusable clock
/// (`u64::MAX`), the same guard the ledger's own expiry comparisons use: a
/// launching count derived from a bogus "now" would be worse than an absent one.
fn relay_counts(state: &CoordinatorState) -> BTreeMap<(String, String), u64> {
    let census = registry::metrics_census(state.setup.registry());
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (region, count) in census.live {
        counts.insert((region_label(region.as_ref()), "live".to_owned()), count);
    }
    for (region, count) in census.draining {
        counts.insert(
            (region_label(region.as_ref()), "draining".to_owned()),
            count,
        );
    }
    let now = unix_secs_fail_closed();
    if let Some(ledger) = &state.ledger
        && now != u64::MAX
    {
        for region in state.regions.regions() {
            if let Ok(count) = ledger.count_launching(Some(&region.id), now)
                && count > 0
            {
                counts.insert(
                    (region.id.as_ref().to_owned(), "launching".to_owned()),
                    count as u64,
                );
            }
        }
    }
    counts
}

/// The warm demand each configured region currently carries. Reported for every
/// configured region, including the cold ones (a zero is a value a dashboard
/// needs), so an unconfigured region never appears.
fn warm_targets(state: &CoordinatorState) -> Vec<(RegionId, u64)> {
    let warm = state.setup.provision().warm();
    state
        .regions
        .regions()
        .iter()
        .map(|region| (region.id.clone(), u64::from(warm.target(&region.id))))
        .collect()
}

/// The measured backbone round-trips, one series per direction.
fn backbone_rtts(state: &CoordinatorState) -> Vec<(String, String, u64)> {
    state
        .pair_rtts
        .metrics_census()
        .into_iter()
        .map(|(origin, target, rtt_ms)| (origin.0, target.0, u64::from(rtt_ms)))
        .collect()
}

/// Whether each configured region's coverage bootstrap is backing off. A region
/// the reconcile loop has never published a phase for (or a coordinator with no
/// loop at all) reads as not backing off.
fn beacon_backoff(state: &CoordinatorState) -> Vec<(RegionId, bool)> {
    let published = state.setup.provision().coverage().census();
    state
        .regions
        .regions()
        .iter()
        .map(|region| {
            (
                region.id.clone(),
                published.get(&region.id).copied().unwrap_or(false),
            )
        })
        .collect()
}
