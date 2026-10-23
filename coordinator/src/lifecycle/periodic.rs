//! Periodic observations are scoped to a retained admission and never activate a slot.

use rally_point_proto::control::{
    CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceObservation, EvidenceVerdict, SlotEvidenceNotice,
    TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};

use super::{Lifecycle, evidence::StoredEvidence, notices::NoticeKey};
use crate::{notify, registry, session};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredPeriodic {
    pub(super) relay: RelayId,
    boot_id: u64,
    pub(super) observation: EvidenceObservation,
    notified_sample_id: Option<u64>,
}

impl StoredPeriodic {
    pub(super) fn matches_admission(&self, admission: &StoredEvidence) -> bool {
        self.relay == admission.relay
            && self.boot_id == admission.boot_id
            && self.observation.connection_id == admission.observation.connection_id
            && self.observation.assignment_revision == admission.observation.assignment_revision
            && self.observation.sequence > admission.observation.sequence
    }
}

impl Lifecycle {
    pub(super) fn ingest_periodic_notice(
        &self,
        relay: RelayId,
        generation: u64,
        mut notice: SlotEvidenceNotice,
    ) {
        let setup = &self.inner.setup;
        let _assignment = setup.lock_assignment();
        let epochs = self.inner.relay_epochs.lock();
        if !epochs
            .get(&relay)
            .is_some_and(|epoch| epoch.connected && epoch.generation == generation)
        {
            NoticeKey::Slot(notice.slot).warn_refused(
                relay,
                &notice.tenant,
                notice.session,
                "periodic notice from a superseded control connection; rejecting",
            );
            return;
        }
        let Some(boot_id) = registry::boot_id(setup.registry(), relay) else {
            return;
        };
        if notice.historical_admission.is_some() && notice.admission.is_some() {
            return;
        }
        let historical = notice.historical_admission.as_ref().map(|admission| {
            rally_point_proto::control::EvidenceHistory {
                admission: admission.clone(),
                sample: notice.evidence.clone(),
                observed_at_ms: notice.observed_at_ms,
            }
        });
        if historical.is_none()
            && let Some(admission) = &notice.admission
        {
            let sample = &notice.evidence;
            if admission.sample_id != 0
                || admission.sequence == 0
                || sample.sample_id == 0
                || sample.sequence <= admission.sequence
                || sample.connection_id != admission.connection_id
                || sample.assignment_revision != admission.assignment_revision
                || admission.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
                || sample.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            {
                return;
            }
            self.record_connection_evidence(
                (relay, boot_id),
                &notice.tenant,
                notice.session,
                notice.slot,
                admission,
                false,
            );
        }
        let accepted = if let Some(history) = &historical {
            self.record_evidence_history(
                (relay, boot_id),
                &notice.tenant,
                notice.session,
                notice.slot,
                history,
                true,
            )
        } else {
            self.record_periodic_evidence(
                (relay, boot_id),
                &notice.tenant,
                notice.session,
                notice.slot,
                &notice.evidence,
                true,
            )
        };
        if !accepted {
            NoticeKey::Slot(notice.slot).warn_refused(
                relay,
                &notice.tenant,
                notice.session,
                "periodic notice without current admission or advancing sample; rejecting",
            );
            return;
        }
        if notice.evidence.verdict != EvidenceVerdict::Valid {
            notice.evidence.body.clear();
        }
        notify::handle_slot_evidence(setup, notice);
    }

    // The caller holds assignment and control-epoch locks through the mutation.
    pub(super) fn record_periodic_evidence(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        observation: &EvidenceObservation,
        notify: bool,
    ) -> bool {
        let (relay, boot_id) = source;
        let setup = &self.inner.setup;
        if observation.sample_id == 0
            || observation.sequence == 0
            || observation.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            || setup.evidence_assignment(relay, tenant, session, slot)
                != Some(observation.assignment_revision)
            || !session::session_refs(setup, tenant, session)
                .is_some_and(|refs| refs.periodic_evidence)
            || !registry::entry(setup.registry(), relay).is_some_and(|entry| {
                entry
                    .capabilities
                    .iter()
                    .any(|cap| cap == CAPABILITY_PERIODIC_EVIDENCE_V1)
            })
        {
            return false;
        }
        let mut sanitized = observation.clone();
        if sanitized.verdict != EvidenceVerdict::Valid {
            sanitized.body.clear();
        }
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return false;
        };
        let Some(admission) = state.evidence.get(&slot) else {
            return false;
        };
        let candidate = StoredPeriodic {
            relay,
            boot_id,
            observation: sanitized,
            notified_sample_id: None,
        };
        if !candidate.matches_admission(admission) {
            return false;
        }
        let stored = state
            .periodic_evidence
            .entry(slot)
            .or_insert_with(|| candidate.clone());
        if !stored.matches_admission(admission) {
            *stored = candidate;
        } else if candidate.observation.sample_id > stored.observation.sample_id
            && candidate.observation.sequence > stored.observation.sequence
        {
            stored.observation = candidate.observation;
        } else if candidate.observation != stored.observation {
            return false;
        }
        if notify {
            if stored
                .notified_sample_id
                .is_some_and(|sample| sample >= observation.sample_id)
            {
                return false;
            }
            stored.notified_sample_id = Some(observation.sample_id);
        }
        true
    }
}

/// A first failure is an accumulated session fact, not a claim of current ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredHistory {
    relay: RelayId,
    boot_id: u64,
    pub(super) history: rally_point_proto::control::EvidenceHistory,
    notified: bool,
}

impl Lifecycle {
    // The caller holds assignment and control-epoch locks. Newly learned history
    // requires current ownership; accepted facts remain after ownership changes.
    pub(super) fn record_evidence_history(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        history: &rally_point_proto::control::EvidenceHistory,
        notify: bool,
    ) -> bool {
        let (relay, boot_id) = source;
        let setup = &self.inner.setup;
        let admission = &history.admission;
        let sample = &history.sample;
        if admission.sample_id != 0
            || admission.sequence == 0
            || sample.sample_id == 0
            || sample.sequence <= admission.sequence
            || sample.connection_id != admission.connection_id
            || sample.assignment_revision != admission.assignment_revision
            || sample.verdict == EvidenceVerdict::Valid
            || admission.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            || sample.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            || setup.evidence_assignment(relay, tenant, session, slot)
                != Some(sample.assignment_revision)
            || !session::session_refs(setup, tenant, session)
                .is_some_and(|refs| refs.periodic_evidence)
            || !registry::entry(setup.registry(), relay).is_some_and(|entry| {
                entry
                    .capabilities
                    .iter()
                    .any(|cap| cap == CAPABILITY_PERIODIC_EVIDENCE_V1)
            })
        {
            return false;
        }
        let mut history = history.clone();
        history.sample.body.clear();
        if history.admission.verdict != EvidenceVerdict::Valid {
            history.admission.body.clear();
        }
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return false;
        };
        if let Some(current) = state.evidence.get(&slot)
            && current.relay == relay
            && current.boot_id == boot_id
            && current.observation.assignment_revision == sample.assignment_revision
        {
            if current.observation.connection_id == admission.connection_id {
                if current.observation != history.admission {
                    return false;
                }
            } else if sample.sequence >= current.observation.sequence {
                return false;
            }
        }
        if !state.evidence_history.contains_key(&slot)
            && state.evidence_history.len()
                >= rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS
        {
            return false;
        }
        let stored = state
            .evidence_history
            .entry(slot)
            .or_insert_with(|| StoredHistory {
                relay,
                boot_id,
                history: history.clone(),
                notified: false,
            });
        if stored.relay != relay || stored.boot_id != boot_id || stored.history != history {
            return false;
        }
        if notify {
            if stored.notified {
                return false;
            }
            stored.notified = true;
        }
        true
    }
}
