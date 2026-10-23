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
        self.evidence_config.periodic = pushed.periodic;
        self.periodic_evidence.retain(|slot, (observation, _)| {
            pushed.periodic
                && pushed.assignments.get(slot) == Some(&observation.assignment_revision)
        });
        self.evidence_config.assignments = pushed.assignments;
    }
}

impl DecisionMaker {
    pub(in crate::consensus) fn record_evidence(
        &mut self,
        slot: SlotId,
        evidence: rally_point_proto::control::EvidenceObservation,
    ) {
        self.periodic_evidence.remove(&slot);
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

impl DecisionMaker {
    pub(in crate::consensus) fn periodic_evidence_current(
        &self,
        slot: SlotId,
        epoch: u64,
        connection_id: &[u8; 32],
        revision: u64,
    ) -> bool {
        self.evidence_config.periodic
            && !self.evidence_config.keys.is_empty()
            && self.evidence_assignment_current(slot, revision)
            && self.connection_epoch_matches(slot, Some(epoch))
            && self.evidence.get(&slot).is_some_and(|admission| {
                admission.sample_id == 0
                    && &admission.connection_id == connection_id
                    && admission.assignment_revision == revision
            })
    }

    pub(in crate::consensus) fn record_periodic_evidence(
        &mut self,
        slot: SlotId,
        epoch: u64,
        mut observation: rally_point_proto::control::EvidenceObservation,
    ) -> bool {
        if observation.sample_id == 0
            || !self.periodic_evidence_current(
                slot,
                epoch,
                &observation.connection_id,
                observation.assignment_revision,
            )
            || self
                .periodic_evidence
                .get(&slot)
                .is_some_and(|(previous, _)| observation.sample_id <= previous.sample_id)
            || (!self.periodic_evidence.contains_key(&slot)
                && self.periodic_evidence.len()
                    >= rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS)
        {
            return false;
        }
        let Some(sequence) = super::super::next_evidence_sequence() else {
            return false;
        };
        observation.sequence = sequence;
        if observation.verdict != rally_point_proto::control::EvidenceVerdict::Valid {
            observation.body.clear();
        }
        self.periodic_evidence
            .insert(slot, (observation, rally_point_proto::time::unix_millis()));
        true
    }

    pub(in crate::consensus) fn periodic_evidence_slots(&self) -> Vec<SlotId> {
        if !self.evidence_config.periodic {
            return Vec::new();
        }
        self.periodic_evidence
            .iter()
            .filter_map(|(&slot, (sample, _))| {
                (self.evidence_assignment_current(slot, sample.assignment_revision)
                    && self.evidence.contains_key(&slot))
                .then_some(slot)
            })
            .collect()
    }

    pub(in crate::consensus) fn periodic_evidence_pair(
        &self,
        slot: SlotId,
        remaining: &mut usize,
    ) -> Option<(
        rally_point_proto::control::SlotEvidence,
        rally_point_proto::control::SlotEvidence,
    )> {
        let (sample, _) = self.periodic_evidence.get(&slot)?;
        if !self.evidence_config.periodic
            || !self.evidence_assignment_current(slot, sample.assignment_revision)
        {
            return None;
        }
        let admission = self.evidence.get(&slot)?;
        // Serialize borrowed values before cloning: even discarded candidates must
        // not copy every session's opaque bodies while holding the registry lock.
        let cost = serde_json::to_vec(&(admission, sample))
            .expect("observations serialize")
            .len()
            + 256;
        if cost > *remaining {
            return None;
        }
        *remaining -= cost;
        Some((
            rally_point_proto::control::SlotEvidence {
                slot,
                observation: admission.clone(),
            },
            rally_point_proto::control::SlotEvidence {
                slot,
                observation: sample.clone(),
            },
        ))
    }

    pub(in crate::consensus) fn periodic_evidence_notice(
        &self,
        slot: SlotId,
        sequence: u64,
    ) -> Option<(rally_point_proto::control::EvidenceObservation, u64)> {
        let (sample, time) = self.periodic_evidence.get(&slot)?;
        (self.evidence_config.periodic
            && self.evidence_assignment_current(slot, sample.assignment_revision)
            && sample.sequence == sequence)
            .then(|| (sample.clone(), *time))
    }

    pub(in crate::consensus) fn periodic_evidence_snapshot(
        &self,
    ) -> Vec<rally_point_proto::control::SlotEvidence> {
        if !self.evidence_config.periodic {
            return Vec::new();
        }
        let mut entries: Vec<_> = self
            .periodic_evidence
            .iter()
            .filter(|(slot, (observation, _))| {
                self.evidence_assignment_current(**slot, observation.assignment_revision)
            })
            .map(
                |(&slot, (observation, _))| rally_point_proto::control::SlotEvidence {
                    slot,
                    observation: observation.clone(),
                },
            )
            .collect();
        entries.sort_by_key(|entry| entry.slot);
        entries
    }
}
