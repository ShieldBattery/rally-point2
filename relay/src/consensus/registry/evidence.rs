//! Descriptor evidence configuration and descriptor-ready notifications.

use super::*;
use rally_point_proto::control::EvidenceKey;

/// Descriptor-owned inputs to a connection's evidence check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceConfig {
    /// Enables bounded in-game observations for this session.
    pub periodic: bool,
    /// Public verification keys, fixed for the session's lifetime.
    pub keys: Vec<EvidenceKey>,
    /// Slots whose connections must supply valid evidence.
    pub required_slots: HashSet<SlotId>,
    /// Assignment revisions change when a slot moves to another home.
    pub assignments: HashMap<SlotId, u64>,
}

impl EvidenceConfig {
    pub(super) fn from_descriptor(descriptor: &SessionDescriptor) -> Self {
        Self {
            periodic: descriptor.periodic_evidence,
            keys: descriptor.evidence_keys.clone(),
            required_slots: descriptor.required_evidence_slots.iter().copied().collect(),
            assignments: descriptor
                .evidence_assignments
                .iter()
                .map(|entry| (entry.slot, entry.revision))
                .collect(),
        }
    }
}

impl DecisionMakers {
    /// Enables descriptor-backed admission on a coordinator-managed relay.
    pub fn require_descriptors(&self) {
        self.require_descriptors
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether admission must wait for the coordinator's session configuration.
    pub fn descriptors_required(&self) -> bool {
        self.require_descriptors
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Checks a captured assignment against the current descriptor under one lock.
    pub fn evidence_assignment_current(
        &self,
        key: &SessionKey,
        slot: SlotId,
        revision: u64,
    ) -> bool {
        self.lock()
            .get(key)
            .map(|maker| maker.evidence_assignment_current(slot, revision))
            .unwrap_or(!self.descriptors_required() && revision == 0)
    }

    /// Returns only a fully installed descriptor's evidence configuration.
    pub fn evidence_config(&self, key: &SessionKey) -> Option<EvidenceConfig> {
        self.lock()
            .get(key)
            .map(|maker| maker.evidence_config.clone())
    }

    /// A notification for descriptor installation or removal. Callers must enable
    /// the pinned waiter before reading configuration to avoid missing an update.
    pub(crate) fn descriptor_changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.descriptors_changed.notified()
    }
}

static EVIDENCE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn next_evidence_sequence() -> Option<u64> {
    let mut current = EVIDENCE_SEQUENCE.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match EVIDENCE_SEQUENCE.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(value) => return Some(value),
            Err(value) => current = value,
        }
    }
}

impl DecisionMakers {
    /// Returns a current connection's policy and whether its game loop has started.
    pub(crate) fn periodic_evidence_config(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        connection_id: &[u8; 32],
        revision: u64,
    ) -> Option<(EvidenceConfig, bool)> {
        if !self.descriptors_required() {
            return None;
        }
        let makers = self.lock();
        let maker = makers.get(key)?;
        if !maker.periodic_evidence_current(slot, epoch, connection_id, revision) {
            return None;
        }
        Some((
            maker.evidence_config.clone(),
            maker.is_started() && maker.has_started(slot),
        ))
    }

    /// Called with the session ingress and matching roster registration held stable.
    pub(crate) fn record_periodic_evidence(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        observation: rally_point_proto::control::EvidenceObservation,
    ) -> bool {
        self.lock()
            .get_mut(key)
            .is_some_and(|maker| maker.record_periodic_evidence(slot, epoch, observation))
    }

    /// Metadata only: no opaque bodies are copied before the heartbeat budget is known.
    pub(crate) fn periodic_evidence_candidates(&self) -> Vec<(SessionKey, SlotId)> {
        self.lock()
            .iter()
            .flat_map(|(key, maker)| {
                maker
                    .periodic_evidence_slots()
                    .into_iter()
                    .map(|slot| (key.clone(), slot))
            })
            .collect()
    }

    /// Copies at most one pair that fits the caller's remaining serialized-byte budget.
    pub(crate) fn periodic_evidence_pair(
        &self,
        key: &SessionKey,
        slot: SlotId,
        remaining: &mut usize,
    ) -> Option<(
        rally_point_proto::control::SlotEvidence,
        rally_point_proto::control::SlotEvidence,
    )> {
        self.lock()
            .get(key)?
            .periodic_evidence_pair(slot, remaining)
    }

    /// Rechecks one selected sample before the writer sends it; stale selections vanish.
    pub(crate) fn periodic_evidence_notice(
        &self,
        key: &SessionKey,
        slot: SlotId,
        sequence: u64,
    ) -> Option<rally_point_proto::control::SlotEvidenceNotice> {
        let (evidence, observed_at_ms) = self
            .lock()
            .get(key)?
            .periodic_evidence_notice(slot, sequence)?;
        let (external_id, external_ref) = self.session_refs(key).stamps(slot);
        Some(rally_point_proto::control::SlotEvidenceNotice {
            tenant: key.tenant.clone(),
            session: key.session,
            slot,
            external_id,
            external_ref,
            observed_at_ms,
            evidence,
        })
    }
}
