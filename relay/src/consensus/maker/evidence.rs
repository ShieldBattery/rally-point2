//! Descriptor configuration and retained connection observations.

use super::*;

impl DecisionMaker {
    pub(in crate::consensus) fn evidence_assignment_current(
        &self,
        slot: SlotId,
        revision: u64,
    ) -> bool {
        self.admits_slot(slot)
            && self
                .evidence_config
                .assignments
                .get(&slot)
                .copied()
                .unwrap_or_default()
                == revision
    }

    pub(in crate::consensus) fn reconcile_evidence(&mut self, pushed: EvidenceConfig) {
        if self.evidence_config.keys != pushed.keys
            || self.evidence_config.required_slots != pushed.required_slots
        {
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                "descriptor re-push disagrees on evidence configuration; keeping the latched value"
            );
        }
        self.evidence_config.assignments = pushed.assignments;
    }
}

impl DecisionMaker {
    pub(in crate::consensus) fn record_evidence(
        &mut self,
        slot: SlotId,
        evidence: rally_point_proto::control::EvidenceObservation,
    ) {
        self.evidence.insert(slot, evidence);
    }

    pub(in crate::consensus) fn evidence_snapshot(
        &self,
    ) -> Vec<rally_point_proto::control::SlotEvidence> {
        let mut entries: Vec<_> = self
            .evidence
            .iter()
            .map(
                |(&slot, observation)| rally_point_proto::control::SlotEvidence {
                    slot,
                    observation: observation.clone(),
                },
            )
            .collect();
        entries.sort_by_key(|entry| entry.slot);
        entries
    }
}
