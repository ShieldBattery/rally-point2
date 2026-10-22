//! Descriptor-backed admission across session configuration and retirement.

use super::SessionState;
use crate::consensus::EvidenceConfig;
use crate::key::SessionKey;

impl SessionState {
    /// Waits for a fully installed descriptor, or returns `None` on retirement.
    pub(crate) async fn wait_evidence_config(&self, key: &SessionKey) -> Option<EvidenceConfig> {
        loop {
            let changed = self.decision_makers.descriptor_changed();
            tokio::pin!(changed);
            // Retirement marks the gate before removing the maker and notifying.
            // Enable first so neither installation nor retirement can fall between
            // the state reads and the wait.
            changed.as_mut().enable();
            // Read without creating a gate: a timed-out dial owns no session
            // state. A retirement racing a ready config is checked again by
            // the admission and activation ingress gates.
            if self.gates.is_retired(key) {
                return None;
            }
            if let Some(config) = self.decision_makers.evidence_config(key) {
                return Some(config);
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests;
