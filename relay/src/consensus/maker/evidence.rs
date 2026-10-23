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
        self.evidence_history.retain(|slot, history| {
            pushed.assignments.get(slot) == Some(&history.sample.assignment_revision)
        });
        self.evidence_pending.retain(|slot, (_, sample)| {
            pushed.periodic && pushed.assignments.get(slot) == Some(&sample.assignment_revision)
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
        self.abandon_periodic_evidence(slot, None);
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
                (admission.verdict != rally_point_proto::control::EvidenceVerdict::Missing
                    || self.evidence_config.required_slots.contains(&slot))
                    && admission.sample_id == 0
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
        let sequence = if let Some((pending_epoch, pending)) = self.evidence_pending.get(&slot) {
            if *pending_epoch != epoch
                || pending.sample_id != observation.sample_id
                || pending.connection_id != observation.connection_id
            {
                return false;
            }
            let sequence = pending.sequence;
            self.evidence_pending.remove(&slot);
            sequence
        } else {
            return false;
        };
        observation.sequence = sequence;
        if observation.verdict != rally_point_proto::control::EvidenceVerdict::Valid {
            observation.body.clear();
        }
        let time = rally_point_proto::time::unix_millis();
        self.retain_failed_evidence(slot, &observation, time);
        self.periodic_evidence.insert(slot, (observation, time));
        true
    }

    pub(in crate::consensus) fn periodic_evidence_slots(&self) -> Vec<(SlotId, u64)> {
        if !self.evidence_config.periodic {
            return Vec::new();
        }
        let mut entries = Vec::new();
        for (&slot, (sample, _)) in &self.periodic_evidence {
            if self.evidence_assignment_current(slot, sample.assignment_revision) {
                entries.push((slot, sample.sequence));
            }
        }
        for (&slot, history) in &self.evidence_history {
            if self.evidence_assignment_current(slot, history.sample.assignment_revision)
                && !entries.contains(&(slot, history.sample.sequence))
            {
                entries.push((slot, history.sample.sequence));
            }
        }
        entries
    }

    pub(in crate::consensus) fn periodic_evidence_pair(
        &self,
        slot: SlotId,
        sequence: u64,
        remaining: &mut usize,
    ) -> Result<Option<PeriodicEvidencePair>, ()> {
        let Some((admission, sample, observed_at_ms, historical)) =
            self.reported_evidence(slot, sequence)
        else {
            return Ok(None);
        };
        let cost = serde_json::to_vec(&(admission, sample))
            .expect("observations serialize")
            .len()
            + 256;
        if cost > *remaining {
            return Err(());
        }
        *remaining -= cost;
        Ok(Some(PeriodicEvidencePair {
            admission: rally_point_proto::control::SlotEvidence {
                slot,
                observation: admission.clone(),
            },
            sample: rally_point_proto::control::SlotEvidence {
                slot,
                observation: sample.clone(),
            },
            observed_at_ms,
            historical,
        }))
    }

    fn reported_evidence(
        &self,
        slot: SlotId,
        sequence: u64,
    ) -> Option<(
        &rally_point_proto::control::EvidenceObservation,
        &rally_point_proto::control::EvidenceObservation,
        u64,
        bool,
    )> {
        if !self.evidence_config.periodic {
            return None;
        }
        if let Some(history) = self.evidence_history.get(&slot)
            && history.sample.sequence == sequence
            && self.evidence_assignment_current(slot, history.sample.assignment_revision)
        {
            return Some((
                &history.admission,
                &history.sample,
                history.observed_at_ms,
                true,
            ));
        }
        let (sample, time) = self.periodic_evidence.get(&slot)?;
        (sample.sequence == sequence
            && self.evidence_assignment_current(slot, sample.assignment_revision))
        .then(|| {
            (
                self.evidence
                    .get(&slot)
                    .expect("periodic sample has admission"),
                sample,
                *time,
                false,
            )
        })
    }

    pub(in crate::consensus) fn periodic_evidence_notice(
        &self,
        slot: SlotId,
        sequence: u64,
    ) -> Option<PeriodicEvidencePair> {
        let (admission, sample, observed_at_ms, historical) =
            self.reported_evidence(slot, sequence)?;
        Some(PeriodicEvidencePair {
            admission: rally_point_proto::control::SlotEvidence {
                slot,
                observation: admission.clone(),
            },
            sample: rally_point_proto::control::SlotEvidence {
                slot,
                observation: sample.clone(),
            },
            observed_at_ms,
            historical,
        })
    }

    pub(in crate::consensus) fn evidence_predecessor(
        &self,
        slot: SlotId,
    ) -> Option<Box<rally_point_proto::control::EvidenceHistory>> {
        self.evidence_history.get(&slot).cloned().map(Box::new)
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

impl DecisionMaker {
    pub(in crate::consensus) fn periodic_evidence_ready(&self, slot: SlotId) -> bool {
        self.is_started() && (self.has_started(slot) || self.forwarded_slots.contains(&slot))
    }

    pub(in crate::consensus) fn begin_periodic_evidence(
        &mut self,
        slot: SlotId,
        epoch: u64,
        mut observation: rally_point_proto::control::EvidenceObservation,
    ) -> bool {
        if observation.sample_id == 0
            || self.evidence_pending.contains_key(&slot)
            || self.evidence_pending.len()
                >= rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS
            || self
                .periodic_evidence
                .get(&slot)
                .is_some_and(|(previous, _)| {
                    previous.connection_id == observation.connection_id
                        && previous.sample_id >= observation.sample_id
                })
            || !self.periodic_evidence_current(
                slot,
                epoch,
                &observation.connection_id,
                observation.assignment_revision,
            )
        {
            return false;
        }
        let Some(sequence) = super::super::next_evidence_sequence() else {
            return false;
        };
        observation.sequence = sequence;
        observation.verdict = rally_point_proto::control::EvidenceVerdict::Missing;
        observation.key_id = None;
        observation.body.clear();
        self.evidence_pending.insert(slot, (epoch, observation));
        true
    }

    pub(in crate::consensus) fn abandon_periodic_evidence(
        &mut self,
        slot: SlotId,
        expected: Option<(u64, u64)>,
    ) -> bool {
        let Some((epoch, pending)) = self.evidence_pending.get(&slot) else {
            return false;
        };
        if expected.is_some_and(|(e, id)| e != *epoch || id != pending.sample_id) {
            return false;
        }
        let (_, sample) = self
            .evidence_pending
            .remove(&slot)
            .expect("pending entry checked");
        if !self.evidence_assignment_current(slot, sample.assignment_revision) {
            return false;
        }
        let time = rally_point_proto::time::unix_millis();
        self.retain_failed_evidence(slot, &sample, time);
        // Pending obligations and completed samples have separate bounds. Other
        // slots may have completed while this obligation was outstanding.
        if self.periodic_evidence.contains_key(&slot)
            || self.periodic_evidence.len()
                < rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS
        {
            self.periodic_evidence.insert(slot, (sample, time));
        }
        true
    }

    fn retain_failed_evidence(
        &mut self,
        slot: SlotId,
        sample: &rally_point_proto::control::EvidenceObservation,
        time: u64,
    ) {
        if sample.verdict == rally_point_proto::control::EvidenceVerdict::Valid
            || self.evidence_history.contains_key(&slot)
            || self.evidence_history.len()
                >= rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS
        {
            return;
        }
        let Some(admission) = self.evidence.get(&slot) else {
            return;
        };
        self.evidence_history.insert(
            slot,
            rally_point_proto::control::EvidenceHistory {
                admission: admission.clone(),
                sample: sample.clone(),
                observed_at_ms: time,
            },
        );
    }

    pub(in crate::consensus) fn evidence_history_snapshot(
        &self,
    ) -> Vec<rally_point_proto::control::SlotEvidenceHistory> {
        let mut entries: Vec<_> = self
            .evidence_history
            .iter()
            .map(
                |(&slot, history)| rally_point_proto::control::SlotEvidenceHistory {
                    slot,
                    history: history.clone(),
                },
            )
            .collect();
        entries.sort_by_key(|entry| entry.slot);
        entries
    }
}
