//! Historical reports carry no authority to activate a slot or change its admission.

use rally_point_proto::control::{
    CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceFailure, EvidenceHistory, EvidenceInterruption,
    EvidenceObservation, EvidenceReceipt, EvidenceReceiptDisposition, EvidenceReport,
    EvidenceVerdict, SlotEvidenceNotice, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};

use super::Lifecycle;
use crate::{notify, registry, session};

/// Accumulated facts survive source retirement; source counters survive only while
/// that source is authorized to deliver another report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredHistory {
    relay: RelayId,
    boot_id: u64,
    pub(super) history: EvidenceHistory,
    notified: bool,
    #[serde(default)]
    sources: Vec<SourceCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SourceCounter {
    relay: RelayId,
    boot_id: u64,
    first: EvidenceFailure,
    failures: u32,
    latest_sequence: u64,
    notified_failures: u32,
    #[serde(default)]
    notified_sequence: u64,
}

struct HistoryDelivery {
    notify: bool,
    retired: bool,
}

struct HistoryResult {
    disposition: EvidenceReceiptDisposition,
    notify: bool,
    failures: u32,
}

fn first(history: &EvidenceHistory) -> EvidenceFailure {
    EvidenceFailure {
        admission: history.admission.clone(),
        sample: history.sample.clone(),
        observed_at_ms: history.observed_at_ms,
    }
}

fn valid_pair(admission: &EvidenceObservation, sample: &EvidenceObservation) -> bool {
    admission.sample_id == 0
        && admission.sequence > 0
        && admission.interruption.is_none()
        && sample.sample_id > 0
        && sample.sequence > admission.sequence
        && sample.connection_id == admission.connection_id
        && sample.assignment_revision == admission.assignment_revision
        && sample.verdict != EvidenceVerdict::Valid
        && (sample.interruption.is_none() || sample.verdict == EvidenceVerdict::Missing)
        && !matches!(
            sample.interruption,
            Some(EvidenceInterruption::Revoked | EvidenceInterruption::SessionRetired)
        )
        && admission.body.len() <= rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
        && sample.body.len() <= rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
}

fn sanitized(history: &EvidenceHistory) -> Option<EvidenceHistory> {
    if history.failures == 0 || !valid_pair(&history.admission, &history.sample) {
        return None;
    }
    match &history.latest {
        Some(latest)
            if history.failures > 1
                && valid_pair(&latest.admission, &latest.sample)
                && latest.sample.assignment_revision == history.sample.assignment_revision
                && latest.sample.sequence > history.sample.sequence => {}
        None if history.failures == 1 => {}
        _ => return None,
    }
    let mut history = history.clone();
    history.sample.body.clear();
    if history.admission.verdict != EvidenceVerdict::Valid {
        history.admission.body.clear();
    }
    if let Some(latest) = &mut history.latest {
        latest.sample.body.clear();
        if latest.admission.verdict != EvidenceVerdict::Valid {
            latest.admission.body.clear();
        }
    }
    Some(history)
}

impl Lifecycle {
    /// Receipts confirm terminal handling in memory, not a completed durable write.
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
        let history = sanitized(&report.history)?;
        let result = self.record_history(
            (relay, boot_id),
            &report.tenant,
            report.session,
            report.slot,
            &history,
            HistoryDelivery {
                notify: true,
                retired: true,
            },
        )?;
        let mut receipt = report.receipt();
        receipt.disposition = result.disposition;
        if result.notify {
            notify::handle_slot_evidence_summary(
                setup,
                SlotEvidenceNotice {
                    tenant: report.tenant,
                    session: report.session,
                    slot: report.slot,
                    external_id: None,
                    external_ref: None,
                    observed_at_ms: history.latest_observed_at_ms(),
                    admission: None,
                    historical_admission: None,
                    evidence: history.latest_sample().clone(),
                },
                true,
                Some(result.failures),
            );
        }
        Some(receipt)
    }

    pub(super) fn history_failure_count(
        &self,
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
    ) -> Option<u32> {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))?
            .evidence_history
            .get(&slot)
            .map(|stored| stored.history.failures)
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
        .is_some_and(|result| {
            if notify {
                result.notify
            } else {
                matches!(
                    result.disposition,
                    EvidenceReceiptDisposition::Accepted | EvidenceReceiptDisposition::Superseded
                )
            }
        })
    }

    // The caller holds assignment and control-epoch locks through the mutation.
    fn record_history(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        history: &EvidenceHistory,
        delivery: HistoryDelivery,
    ) -> Option<HistoryResult> {
        let (relay, boot_id) = source;
        let setup = &self.inner.setup;
        let history = sanitized(history)?;
        let revision = history.sample.assignment_revision;
        if !registry::entry(setup.registry(), relay).is_some_and(|entry| {
            entry
                .capabilities
                .iter()
                .any(|cap| cap == CAPABILITY_PERIODIC_EVIDENCE_V1)
        }) {
            return None;
        }
        if delivery.retired
            && setup
                .closed_evidence_history_assignment(relay, boot_id, tenant, session, slot, revision)
        {
            return Some(HistoryResult {
                disposition: EvidenceReceiptDisposition::SessionClosed,
                notify: false,
                failures: 0,
            });
        }
        let authorized = |relay, boot_id, revision| {
            setup.current_evidence_history_assignment(
                relay, boot_id, tenant, session, slot, revision,
            ) || setup.evidence_history_assignment(relay, boot_id, tenant, session, slot, revision)
        };
        if !(if delivery.retired {
            authorized(relay, boot_id, revision)
        } else {
            setup.current_evidence_history_assignment(
                relay, boot_id, tenant, session, slot, revision,
            )
        }) || !session::session_refs(setup, tenant, session)
            .is_some_and(|refs| refs.periodic_evidence)
        {
            return None;
        }
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            // Lifecycle retirement removes facts before session membership. Exact
            // live authority is still required throughout that narrow interval.
            return Some(HistoryResult {
                disposition: EvidenceReceiptDisposition::SessionClosed,
                notify: false,
                failures: 0,
            });
        };
        let admission = history.latest_admission();
        let sample = history.latest_sample();
        if let Some(current) = state.evidence.get(&slot)
            && current.relay == relay
            && current.boot_id == boot_id
            && current.observation.assignment_revision == revision
        {
            if current.observation.connection_id == admission.connection_id {
                if current.observation != *admission {
                    return None;
                }
            } else if sample.sequence >= current.observation.sequence {
                return None;
            }
        }
        if !state.evidence_history.contains_key(&slot)
            && state.evidence_history.len()
                >= rally_point_proto::control::MAX_PERIODIC_EVIDENCE_SLOTS
        {
            return Some(HistoryResult {
                disposition: EvidenceReceiptDisposition::Capacity,
                notify: false,
                failures: 0,
            });
        }
        let inserted = !state.evidence_history.contains_key(&slot);
        let stored = state
            .evidence_history
            .entry(slot)
            .or_insert_with(|| StoredHistory {
                relay,
                boot_id,
                history: history.clone(),
                notified: false,
                sources: Vec::new(),
            });
        // A persisted first-only record is also the highwater for its original
        // source. Seed it once before accepting another source or cumulative update.
        if stored.sources.is_empty() {
            stored.sources.push(SourceCounter {
                relay: stored.relay,
                boot_id: stored.boot_id,
                first: first(&stored.history),
                failures: stored.history.failures,
                latest_sequence: stored.history.latest_sample().sequence,
                notified_failures: if stored.notified {
                    stored.history.failures
                } else {
                    0
                },
                notified_sequence: if stored.notified {
                    stored.history.latest_sample().sequence
                } else {
                    0
                },
            });
        }
        stored.sources.retain(|counter| {
            setup.retained_evidence_history_assignment(
                counter.relay,
                counter.boot_id,
                tenant,
                session,
                slot,
                counter.first.sample.assignment_revision,
            )
        });
        let candidate_first = first(&history);
        let index = stored.sources.iter().position(|counter| {
            counter.relay == relay
                && counter.boot_id == boot_id
                && counter.first.sample.assignment_revision == revision
        });
        let mut advanced = inserted;
        let index = if let Some(index) = index {
            let counter = &mut stored.sources[index];
            if counter.first != candidate_first {
                return None;
            }
            if history.failures > counter.failures
                || (history.failures == u32::MAX && sample.sequence > counter.latest_sequence)
            {
                if sample.sequence <= counter.latest_sequence {
                    return None;
                }
                stored.history.failures = stored
                    .history
                    .failures
                    .saturating_add(history.failures - counter.failures);
                counter.failures = history.failures;
                counter.latest_sequence = sample.sequence;
                advanced = true;
            } else if (history.failures == counter.failures
                && history.failures != u32::MAX
                && sample.sequence != counter.latest_sequence)
                || (history.failures < counter.failures
                    && sample.sequence >= counter.latest_sequence)
            {
                return None;
            }
            index
        } else {
            // Authorization itself has one current and at most four retired
            // identities per slot. Never evict an authorized counter for room.
            if stored.sources.len() >= 5 {
                return Some(HistoryResult {
                    disposition: EvidenceReceiptDisposition::Capacity,
                    notify: false,
                    failures: stored.history.failures,
                });
            }
            stored.history.failures = stored.history.failures.saturating_add(history.failures);
            stored.sources.push(SourceCounter {
                relay,
                boot_id,
                first: candidate_first,
                failures: history.failures,
                latest_sequence: sample.sequence,
                notified_failures: 0,
                notified_sequence: 0,
            });
            advanced = true;
            stored.sources.len() - 1
        };
        if advanced && !inserted {
            stored.history.latest = Some(Box::new(EvidenceFailure {
                admission: admission.clone(),
                sample: sample.clone(),
                observed_at_ms: history.latest_observed_at_ms(),
            }));
        }
        let counter = &mut stored.sources[index];
        let notify = delivery.notify
            && history.failures == counter.failures
            && sample.sequence == counter.latest_sequence
            && (counter.notified_failures < counter.failures
                || counter.notified_sequence < counter.latest_sequence);
        if notify {
            counter.notified_failures = counter.failures;
            counter.notified_sequence = counter.latest_sequence;
            stored.notified = true;
        }
        Some(HistoryResult {
            disposition: if advanced || notify {
                EvidenceReceiptDisposition::Accepted
            } else {
                EvidenceReceiptDisposition::Superseded
            },
            notify,
            failures: stored.history.failures,
        })
    }
}
