//! Descriptor evidence configuration and descriptor-ready notifications.

use super::*;
use rally_point_proto::control::EvidenceKey;

/// Descriptor-owned inputs to a connection's evidence check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceConfig {
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
