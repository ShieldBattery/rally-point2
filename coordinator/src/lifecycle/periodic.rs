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
        if !self.record_periodic_evidence(
            (relay, boot_id),
            &notice.tenant,
            notice.session,
            notice.slot,
            &notice.evidence,
            true,
        ) {
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
