//! Connection observations and their assignment, process, and activation fences.

use rally_point_proto::control::{
    EvidenceObservation, EvidenceVerdict, SessionPresence, SlotConnectedNotice, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};

use super::Lifecycle;
use super::notices::NoticeKey;
use crate::{notify, registry};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredEvidence {
    pub(super) relay: RelayId,
    pub(super) boot_id: u64,
    pub(super) observation: EvidenceObservation,
    notified_sequence: Option<u64>,
}

impl Lifecycle {
    /// Admission then latest periodic observations matching each current assignment.
    /// Each group is sorted by slot; earlier periodic samples are not retained.
    /// Unknown or retired sessions have no observations; this makes no completeness claim.
    pub fn connection_evidence(
        &self,
        tenant: &TenantId,
        session: SessionId,
    ) -> Vec<rally_point_proto::control::SlotEvidence> {
        let assignments = self.inner.setup.evidence_assignments(tenant, session);
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| current_evidence(state, &assignments))
            .unwrap_or_default()
    }

    /// Moves required sessions off an incapable relay, retiring only the affected
    /// session when no compatible replacement exists.
    pub(crate) fn evict_evidence_session(
        &self,
        tenant: &TenantId,
        session: SessionId,
        relay: RelayId,
    ) {
        let setup = &self.inner.setup;
        let outcome = crate::session::rehome_with_assignment_commit(
            setup,
            tenant,
            session,
            relay,
            || self.departed_slots(tenant, session),
            |replacement| self.on_rehome(tenant, session, relay, replacement),
        );
        if !matches!(outcome, crate::session::RehomeOutcome::Unavailable) {
            tracing::info!(
                relay_id = relay.0,
                tenant = tenant.as_ref(),
                session = session.0,
                ?outcome,
                "resolved session assignment after relay capability change"
            );
            return;
        }

        // A concurrent rehome or enrollment can resolve the mismatch between the
        // failed attempt and this lock. Retire only the still-unsupported assignment.
        let _assignment = setup.lock_assignment();
        if !setup.serving_relays(tenant, session).contains(&relay)
            || !crate::session::session_refs(setup, tenant, session)
                .is_some_and(|refs| !refs.required_evidence_slots.is_empty())
            || registry::entry(setup.registry(), relay).is_some_and(|entry| {
                entry.capabilities.iter().any(|capability| {
                    capability == rally_point_proto::control::CAPABILITY_EVIDENCE_V1
                })
            })
        {
            return;
        }
        let state = self
            .inner
            .sessions
            .lock()
            .remove(&(tenant.clone(), session))
            .unwrap_or_else(|| self.new_state(Vec::new()));
        self.close_and_retire(tenant.clone(), session, state);
        crate::metrics::session_closed(tenant);
        tracing::warn!(
            relay_id = relay.0,
            tenant = tenant.as_ref(),
            session = session.0,
            "retired session after relay capability loss: no compatible replacement"
        );
    }

    pub(super) fn ingest_evidence_notice(
        &self,
        relay: RelayId,
        generation: u64,
        mut notice: SlotConnectedNotice,
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
                "slot-connected notice from a superseded control connection; rejecting",
            );
            return;
        }
        let Some(observation) = &mut notice.evidence else {
            return;
        };
        if observation.sample_id != 0
            || observation.sequence == 0
            || observation.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            || !setup.relay_serves_session(relay, &notice.tenant, notice.session)
        {
            NoticeKey::Slot(notice.slot).warn_refused(
                relay,
                &notice.tenant,
                notice.session,
                "slot-connected notice with invalid evidence or unassigned reporter; rejecting",
            );
            return;
        }
        if observation.verdict != EvidenceVerdict::Valid {
            observation.body.clear();
        }
        let has_assignment = setup.has_session_refs(&notice.tenant, notice.session);
        if has_assignment
            && setup.evidence_assignment(relay, &notice.tenant, notice.session, notice.slot)
                != Some(observation.assignment_revision)
        {
            NoticeKey::Slot(notice.slot).warn_refused(
                relay,
                &notice.tenant,
                notice.session,
                "slot-connected notice from a relay not owning the assignment; rejecting",
            );
            return;
        }
        if let Some(boot_id) = registry::boot_id(setup.registry(), relay)
            && has_assignment
        {
            if !self.record_connection_evidence(
                (relay, boot_id),
                &notice.tenant,
                notice.session,
                notice.slot,
                observation,
                true,
            ) {
                return;
            }
        } else {
            // An arrival remains useful after lost assignment or process context, but
            // its connection observation cannot be attributed without both fences.
            notice.evidence = None;
        }
        self.on_slot_connected(notice.tenant.clone(), notice.session, notice.slot);
        notify::handle_slot_connected(setup, &self.inner.notices.slot_connects, self, notice);
    }

    /// Merges only current-assignment observations from the current control connection.
    /// Heartbeats and requested snapshots share this path and never emit webhooks.
    pub(crate) fn merge_connection_evidence(
        &self,
        relay: RelayId,
        generation: u64,
        sessions: &[SessionPresence],
    ) {
        let setup = &self.inner.setup;
        let _assignment = setup.lock_assignment();
        let epochs = self.inner.relay_epochs.lock();
        if !epochs
            .get(&relay)
            .is_some_and(|epoch| epoch.connected && epoch.generation == generation)
        {
            return;
        }
        let Some(boot_id) = registry::boot_id(setup.registry(), relay) else {
            return;
        };
        for session in sessions {
            let mut seen = std::collections::HashSet::new();
            for entry in &session.evidence {
                if !seen.insert(entry.slot) {
                    continue;
                }
                self.record_connection_evidence(
                    (relay, boot_id),
                    &session.tenant,
                    session.session,
                    entry.slot,
                    &entry.observation,
                    false,
                );
            }
            let mut seen = std::collections::HashSet::new();
            for entry in &session.periodic_evidence {
                if seen.insert(entry.slot) {
                    self.record_periodic_evidence(
                        (relay, boot_id),
                        &session.tenant,
                        session.session,
                        entry.slot,
                        &entry.observation,
                        false,
                    );
                }
            }
        }
    }

    // The caller holds assignment and relay-epoch locks through this mutation.
    fn record_connection_evidence(
        &self,
        source: (RelayId, u64),
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        observation: &EvidenceObservation,
        notify: bool,
    ) -> bool {
        let (relay, boot_id) = source;
        if observation.sample_id != 0
            || observation.sequence == 0
            || observation.body.len() > rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN
            || self
                .inner
                .setup
                .evidence_assignment(relay, tenant, session, slot)
                != Some(observation.assignment_revision)
        {
            return false;
        }
        // Only a verified body may become retained state or tenant payload.
        let mut sanitized = observation.clone();
        if sanitized.verdict != EvidenceVerdict::Valid {
            sanitized.body.clear();
        }
        let observation = &sanitized;
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        let stored = state
            .evidence
            .entry(slot)
            .or_insert_with(|| StoredEvidence {
                relay,
                boot_id,
                observation: observation.clone(),
                notified_sequence: None,
            });
        if stored.relay != relay
            || stored.boot_id != boot_id
            || stored.observation.assignment_revision != observation.assignment_revision
        {
            *stored = StoredEvidence {
                relay,
                boot_id,
                observation: observation.clone(),
                notified_sequence: None,
            };
        } else if observation.sequence > stored.observation.sequence {
            stored.observation = observation.clone();
        } else if observation.sequence == stored.observation.sequence
            && observation != &stored.observation
        {
            return false;
        }
        if state
            .periodic_evidence
            .get(&slot)
            .is_some_and(|periodic| !periodic.matches_admission(stored))
        {
            state.periodic_evidence.remove(&slot);
        }
        if notify {
            if stored
                .notified_sequence
                .is_some_and(|sequence| sequence >= observation.sequence)
            {
                return false;
            }
            stored.notified_sequence = Some(observation.sequence);
        }
        true
    }
}

/// Shared assignment filter for cached reads and load-state snapshots.
pub(super) fn current_evidence(
    state: &super::SessionState,
    assignments: &std::collections::BTreeMap<SlotId, (RelayId, u64)>,
) -> Vec<rally_point_proto::control::SlotEvidence> {
    state
        .evidence
        .iter()
        .filter(|(slot, stored)| {
            assignments.get(slot) == Some(&(stored.relay, stored.observation.assignment_revision))
        })
        .map(|(&slot, stored)| rally_point_proto::control::SlotEvidence {
            slot,
            observation: stored.observation.clone(),
        })
        .chain(
            state
                .periodic_evidence
                .iter()
                .filter(|(slot, stored)| {
                    assignments.get(slot)
                        == Some(&(stored.relay, stored.observation.assignment_revision))
                        && state
                            .evidence
                            .get(slot)
                            .is_some_and(|admission| stored.matches_admission(admission))
                })
                .map(|(&slot, stored)| rally_point_proto::control::SlotEvidence {
                    slot,
                    observation: stored.observation.clone(),
                }),
        )
        .collect()
}
