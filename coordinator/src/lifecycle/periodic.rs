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
    #[serde(default)]
    pub(super) observed_at_ms: Option<u64>,
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
                failures: 1,
                latest: None,

                admission: admission.clone(),
                sample: notice.evidence.clone(),
                observed_at_ms: notice.observed_at_ms,
            }
        });
        if historical.is_none()
            && let Some(admission) = &notice.admission
        {
            let sample = &notice.evidence;
            if !super::evidence::has_known_semantics(admission)
                || admission.sample_id != 0
                || admission.interruption.is_some()
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
                (&notice.evidence, Some(notice.observed_at_ms)),
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
        let failure_count = historical
            .as_ref()
            .and_then(|_| self.history_failure_count(&notice.tenant, notice.session, notice.slot));
        notify::handle_slot_evidence_summary(setup, notice, historical.is_some(), failure_count);
    }

    // The caller holds assignment and control-epoch locks through the mutation.
    pub(super) fn record_periodic_evidence(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        observation: (&EvidenceObservation, Option<u64>),
        notify: bool,
    ) -> bool {
        let (observation, observed_at_ms) = observation;
        let (relay, boot_id) = source;
        let setup = &self.inner.setup;
        if !super::evidence::has_known_semantics(observation)
            || observation.sample_id == 0
            || (observation.interruption.is_some()
                && observation.verdict != EvidenceVerdict::Missing)
            || matches!(
                observation.interruption,
                Some(
                    rally_point_proto::control::EvidenceInterruption::Revoked
                        | rally_point_proto::control::EvidenceInterruption::SessionRetired
                )
            )
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
            observed_at_ms,
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
            stored.observed_at_ms = candidate.observed_at_ms;
        } else if candidate.observation != stored.observation {
            return false;
        }
        if stored.observed_at_ms.is_none() {
            stored.observed_at_ms = observed_at_ms;
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
