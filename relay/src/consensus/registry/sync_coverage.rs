//! Read-only checksum-comparison coverage for flight-recorder samples.

use super::*;

impl DecisionMakers {
    /// Returns the current checksum-comparison coverage for `key`, when this
    /// relay still has a decision-maker for the session.
    pub fn sync_coverage(&self, key: &SessionKey) -> Option<SyncCoverage> {
        self.lock().get(key).map(|maker| maker.sync_coverage())
    }
}
