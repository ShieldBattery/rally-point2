//! The coverage bootstrap's published status: which regions the reconcile loop
//! is currently backing off.
//!
//! A region "needs bootstrap" while some configured backbone pair involving it
//! has no measurement, and the loop asks for a relay to run one. When an attempt
//! produces nothing inside its hold window the loop backs the region off for an
//! exponentially growing interval, so a dead beacon cannot relaunch-churn tasks.
//! The phase itself is loop-local — a restart resets it — but a scrape has to be
//! able to see it, so the loop publishes the one bit that matters here.
//!
//! Cheaply cloneable and sharing one map behind an `Arc`, the same way
//! [`WarmTargets`](super::WarmTargets) is: the loop that writes it and the
//! metrics scrape that reads it hold the same state.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::RegionId;

/// Which regions the coverage bootstrap is backing off right now. A region that
/// has never been published is not backing off.
#[derive(Clone, Default)]
pub struct CoverageStatus {
    backing_off: Arc<Mutex<HashMap<RegionId, bool>>>,
}

impl CoverageStatus {
    /// An empty status — no region has published a phase yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes whether the bootstrap is backing off `region`, called by the
    /// loop every tick it re-derives the region's coverage phase.
    pub fn publish(&self, region: &RegionId, backing_off: bool) {
        self.backing_off.lock().insert(region.clone(), backing_off);
    }

    /// A scrape-time census: whether each region that has published a phase is
    /// backing off. A region absent from it has published nothing and is not
    /// backing off.
    pub fn census(&self) -> HashMap<RegionId, bool> {
        self.backing_off.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_reads_as_backing_off_only_once_it_publishes_one() {
        let status = CoverageStatus::new();
        let region = RegionId("us-east".to_owned());
        assert!(
            !status.census().contains_key(&region),
            "an unpublished region has no entry at all, so a reader sees no backoff",
        );

        status.publish(&region, true);
        assert_eq!(status.census().get(&region), Some(&true));

        // Level-triggered: the loop republishes every tick, so clearing is just
        // the next publish.
        status.publish(&region, false);
        assert_eq!(status.census().get(&region), Some(&false));
    }

    #[test]
    fn every_clone_shares_one_map() {
        let status = CoverageStatus::new();
        let loop_side = status.clone();
        loop_side.publish(&RegionId("eu-west".to_owned()), true);
        assert_eq!(
            status.census().get(&RegionId("eu-west".to_owned())),
            Some(&true),
            "the scrape reads what the loop published through its own clone",
        );
    }
}
