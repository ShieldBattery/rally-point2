//! Historical reports carry no authority to activate a slot or change its admission.

use rally_point_proto::control::{
    CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceHistory, EvidenceReceipt, EvidenceReport,
    EvidenceVerdict, SlotEvidenceNotice, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};

use super::Lifecycle;
use crate::{notify, registry, session};

impl Lifecycle {
    /// Receipts confirm acceptance into memory. The normal background flush persists
    /// accumulated history; a receipt does not promise a completed durable write.
    pub(crate) fn ingest_evidence_report(
        &self,
        relay: RelayId,
        generation: u64,
        report: EvidenceReport,
    ) -> Option<EvidenceReceipt> {
        let setup = &self.inner.setup;
        let _assignment = setup.lock_assignment();
        let epochs = self.inner.relay_epochs.lock();
        if !epochs
            .get(&relay)
            .is_some_and(|epoch| epoch.connected && epoch.generation == generation)
        {
            return None;
        }
        let boot_id = registry::boot_id(setup.registry(), relay)?;
        if !self.record_history(
            (relay, boot_id),
            &report.tenant,
            report.session,
            report.slot,
            &report.history,
            HistoryDelivery {
                notify: false,
                retired: true,
            },
        ) {
            return None;
        }
        let receipt = report.receipt();
        // Receipt deduplication and webhook deduplication are distinct: a lost
        // receipt must be repeatable without repeating the notification.
        if self.record_history(
            (relay, boot_id),
            &report.tenant,
            report.session,
            report.slot,
            &report.history,
            HistoryDelivery {
                notify: true,
                retired: true,
            },
        ) {
            let mut evidence = report.history.sample;
            evidence.body.clear();
            notify::handle_slot_evidence(
                setup,
                SlotEvidenceNotice {
                    tenant: report.tenant,
                    session: report.session,
                    slot: report.slot,
                    external_id: None,
                    external_ref: None,
                    observed_at_ms: report.history.observed_at_ms,
                    admission: None,
                    historical_admission: None,
                    evidence,
                },
            );
        }
        Some(receipt)
    }

    // Live notices and heartbeat snapshots retain their current-assignment fence.
    pub(super) fn record_evidence_history(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        history: &EvidenceHistory,
        notify: bool,
    ) -> bool {
        self.record_history(
            source,
            tenant,
            session,
            slot,
            history,
            HistoryDelivery {
                notify,
                retired: false,
            },
        )
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

struct HistoryDelivery {
    notify: bool,
    retired: bool,
}

impl Lifecycle {
    // The caller holds assignment and control-epoch locks through the mutation.
    // Only explicit outbox reports may use a retired assignment's limited authority.
    fn record_history(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        history: &rally_point_proto::control::EvidenceHistory,
        delivery: HistoryDelivery,
    ) -> bool {
        let HistoryDelivery { notify, retired } = delivery;
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
            || !(if retired {
                setup.current_evidence_history_assignment(
                    relay,
                    boot_id,
                    tenant,
                    session,
                    slot,
                    sample.assignment_revision,
                ) || setup.evidence_history_assignment(
                    relay,
                    boot_id,
                    tenant,
                    session,
                    slot,
                    sample.assignment_revision,
                )
            } else {
                setup.evidence_assignment(relay, tenant, session, slot)
                    == Some(sample.assignment_revision)
            })
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
