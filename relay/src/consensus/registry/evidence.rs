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
            maker.periodic_evidence_ready(slot),
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
        let recorded = self
            .lock()
            .get_mut(key)
            .is_some_and(|maker| maker.record_periodic_evidence(slot, epoch, observation));
        if recorded {
            self.notify_evidence_changed();
        }
        recorded
    }

    /// Metadata only: no opaque bodies are copied before the heartbeat budget is known.
    pub(crate) fn periodic_evidence_candidates(&self) -> Vec<(SessionKey, SlotId, u64)> {
        self.lock()
            .iter()
            .flat_map(|(key, maker)| {
                maker
                    .periodic_evidence_slots()
                    .into_iter()
                    .map(|(slot, sequence)| (key.clone(), slot, sequence))
            })
            .collect()
    }

    /// Copies only an exact retained observation that fits the byte budget.
    pub(crate) fn periodic_evidence_pair(
        &self,
        key: &SessionKey,
        slot: SlotId,
        sequence: u64,
        remaining: &mut usize,
    ) -> Result<Option<PeriodicEvidencePair>, ()> {
        let makers = self.lock();
        let Some(maker) = makers.get(key) else {
            return Ok(None);
        };
        maker.periodic_evidence_pair(slot, sequence, remaining)
    }

    /// Rechecks one selected sample before the writer sends it; stale selections vanish.
    pub(crate) fn periodic_evidence_notice(
        &self,
        key: &SessionKey,
        slot: SlotId,
        sequence: u64,
    ) -> Option<rally_point_proto::control::SlotEvidenceNotice> {
        let pair = self
            .lock()
            .get(key)?
            .periodic_evidence_notice(slot, sequence)?;
        let (external_id, external_ref) = self.session_refs(key).stamps(slot);
        let observed_at_ms = pair.observed_at_ms;
        let evidence = pair.sample.observation;
        let (admission, predecessor) = if pair.history.is_some() {
            (None, Some(pair.admission.observation))
        } else {
            (Some(pair.admission.observation), None)
        };
        Some(rally_point_proto::control::SlotEvidenceNotice {
            admission,
            historical_admission: predecessor,
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

/// A byte-budgeted current sample or cumulative historical failures.
pub(crate) struct PeriodicEvidencePair {
    pub admission: rally_point_proto::control::SlotEvidence,
    pub sample: rally_point_proto::control::SlotEvidence,
    pub history: Option<Box<rally_point_proto::control::EvidenceHistory>>,
    pub observed_at_ms: u64,
}

impl DecisionMakers {
    pub(crate) fn periodic_evidence_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.evidence_changes
            .get_or_init(|| tokio::sync::watch::channel(0).0)
            .subscribe()
    }

    pub(in crate::consensus) fn notify_evidence_changed(&self) {
        if let Some(changes) = self.evidence_changes.get() {
            changes.send_modify(|revision| *revision = revision.wrapping_add(1));
        }
    }

    pub(crate) fn begin_periodic_evidence(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        observation: rally_point_proto::control::EvidenceObservation,
    ) -> bool {
        self.lock()
            .get_mut(key)
            .is_some_and(|maker| maker.begin_periodic_evidence(slot, epoch, observation))
    }

    pub(crate) fn abandon_periodic_evidence(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        sample: u64,
        reason: rally_point_proto::control::EvidenceInterruption,
    ) {
        let _ = self.lock().get_mut(key).is_some_and(|maker| {
            maker.abandon_periodic_evidence(slot, Some((epoch, sample)), reason)
        });
        // Epoch replacement may already have settled this obligation synchronously.
        self.notify_evidence_changed();
    }
}

impl DecisionMakers {
    /// Settles a connection's pending check before teardown loses its cause.
    pub(crate) fn interrupt_periodic_evidence(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        reason: rally_point_proto::control::EvidenceInterruption,
    ) {
        let changed = self.lock().get_mut(key).is_some_and(|maker| {
            maker.connection_epoch_matches(slot, Some(epoch))
                && maker.abandon_periodic_evidence(slot, None, reason)
        });
        if changed {
            self.notify_evidence_changed();
        }
    }

    /// Selects a fair bounded retry batch without consulting live session makers.
    pub(crate) fn evidence_reports(
        &self,
        now: Instant,
        limit: usize,
    ) -> Vec<rally_point_proto::control::EvidenceReport> {
        self.evidence_outbox.reports(now, limit)
    }

    /// Rechecks a queued selection after higher-priority control work ran.
    pub(crate) fn evidence_report_pending(
        &self,
        receipt: &rally_point_proto::control::EvidenceReceipt,
        now: Instant,
    ) -> bool {
        self.evidence_outbox.contains(receipt, now)
    }

    /// Removes only the exact report named by a coordinator memory receipt.
    pub(crate) fn acknowledge_evidence(
        &self,
        receipt: &rally_point_proto::control::EvidenceReceipt,
    ) {
        self.evidence_outbox.acknowledge(receipt);
    }
}
