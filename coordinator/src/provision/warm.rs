//! The warm-demand store: how many relays each region should be kept warm for,
//! and until when.
//!
//! Demand is a target count paired with a deadline. [`warm`](WarmTargets::warm)
//! (re-)sets a region's demand and pushes its deadline out by a TTL; once the
//! deadline passes the demand lapses on its own, so a caller keeps a region warm
//! by re-warming it before the TTL elapses and stops simply by going quiet. The
//! reconcile loop reads [`target`](WarmTargets::target) each tick to size a
//! region's relay count.
//!
//! The store is cheaply cloneable and shares one map behind an `Arc`, so an HTTP
//! endpoint that drives warm demand and the loop that reads it hold the same
//! state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rally_point_proto::control::RegionId;

/// The relay count a region demands while it is warm. Warm demand is binary
/// today — a region is warm or it is not — so warming a region asks for one relay;
/// the store keeps a count (not a flag) so raising it to N later is a policy
/// change here, not a rewrite of the loop, which already reconciles against a
/// count.
const WARM_TARGET: u32 = 1;

/// One region's warm demand: the relay count it asks for, valid until `deadline`.
#[derive(Debug, Clone, Copy)]
struct WarmDemand {
    /// The relay count demanded while warm.
    target: u32,
    /// The Unix-second instant past which the demand has lapsed.
    deadline: u64,
}

/// Per-region warm demand, keyed by region id. Cheaply cloneable; every clone
/// shares one map.
#[derive(Clone, Default)]
pub struct WarmTargets {
    demand: Arc<Mutex<HashMap<RegionId, WarmDemand>>>,
}

impl WarmTargets {
    /// An empty store — no region has any warm demand.
    pub fn new() -> Self {
        Self::default()
    }

    /// (Re-)warms `region`: sets its demand and extends its deadline to `ttl` from
    /// now. Called again before the TTL elapses to hold a region warm.
    pub fn warm(&self, region: RegionId, ttl: Duration) {
        self.warm_at(region, ttl, now_unix_secs());
    }

    /// [`warm`](Self::warm) with the current time supplied, so a test can pin the
    /// deadline deterministically.
    pub fn warm_at(&self, region: RegionId, ttl: Duration, now: u64) {
        let deadline = now.saturating_add(ttl.as_secs());
        self.demand.lock().insert(
            region,
            WarmDemand {
                target: WARM_TARGET,
                deadline,
            },
        );
    }

    /// The relay count `region` demands right now — its warm target while the
    /// demand is live, or `0` once the deadline has passed (or the region was
    /// never warmed).
    pub fn target(&self, region: &RegionId) -> u32 {
        self.target_at(region, now_unix_secs())
    }

    /// [`target`](Self::target) with the current time supplied, so a tick can be
    /// driven deterministically.
    pub fn target_at(&self, region: &RegionId, now: u64) -> u32 {
        match self.demand.lock().get(region) {
            Some(demand) if demand.deadline > now => demand.target,
            _ => 0,
        }
    }
}

/// The current Unix time in seconds — the store's clock for warm deadlines. A
/// pre-epoch or errored clock yields `0`, which makes every stored deadline read
/// as still in the future; warm demand erring toward *keeping* a relay is the
/// safe direction (it never strands players on a clock fault), and the reconcile
/// loop skips its tick outright on an unusable clock anyway.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str) -> RegionId {
        RegionId(name.to_owned())
    }

    #[test]
    fn an_unwarmed_region_targets_zero() {
        let targets = WarmTargets::new();
        assert_eq!(targets.target_at(&region("us-east"), 1_000), 0);
    }

    #[test]
    fn warming_targets_one_until_the_deadline_lapses() {
        let targets = WarmTargets::new();
        targets.warm_at(region("us-east"), Duration::from_secs(60), 1_000);

        // Live within the TTL.
        assert_eq!(targets.target_at(&region("us-east"), 1_030), 1);
        // At the deadline it is no longer in the future, so demand has lapsed.
        assert_eq!(targets.target_at(&region("us-east"), 1_060), 0);
        // And well past it.
        assert_eq!(targets.target_at(&region("us-east"), 5_000), 0);
    }

    #[test]
    fn re_warming_extends_the_deadline() {
        let targets = WarmTargets::new();
        targets.warm_at(region("us-east"), Duration::from_secs(60), 1_000);
        // A re-warm at 1_050 pushes the deadline to 1_110.
        targets.warm_at(region("us-east"), Duration::from_secs(60), 1_050);
        assert_eq!(
            targets.target_at(&region("us-east"), 1_100),
            1,
            "the re-warm kept the region live past the original deadline",
        );
    }

    #[test]
    fn demand_is_per_region() {
        let targets = WarmTargets::new();
        targets.warm_at(region("us-east"), Duration::from_secs(60), 1_000);
        assert_eq!(targets.target_at(&region("us-east"), 1_010), 1);
        assert_eq!(
            targets.target_at(&region("us-west"), 1_010),
            0,
            "warming one region leaves another cold",
        );
    }

    #[test]
    fn a_clone_shares_the_same_demand() {
        let targets = WarmTargets::new();
        let handle = targets.clone();
        handle.warm_at(region("us-east"), Duration::from_secs(60), 1_000);
        assert_eq!(
            targets.target_at(&region("us-east"), 1_010),
            1,
            "a clone writes through to the shared map",
        );
    }
}
