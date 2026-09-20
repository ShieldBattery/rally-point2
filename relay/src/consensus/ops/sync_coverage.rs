//! Read-only checksum-comparison coverage for flight-recorder samples.

use super::*;

/// Returns the current checksum-comparison coverage for `key`, when this
/// relay still has a decision-maker for the session.
pub fn sync_coverage(registry: &DecisionMakers, key: &SessionKey) -> Option<SyncCoverage> {
    registry.lock().get(key).map(|maker| maker.sync_coverage())
}
