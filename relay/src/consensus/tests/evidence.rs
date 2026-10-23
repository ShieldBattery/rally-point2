use super::*;
use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict};

fn config(revision: u64) -> EvidenceConfig {
    EvidenceConfig {
        required_slots: [SlotId(0)].into_iter().collect(),
        assignments: [(SlotId(0), revision)].into_iter().collect(),
        ..Default::default()
    }
}

fn install(registry: &DecisionMakers, key: &SessionKey, evidence: EvidenceConfig) {
    let _ = registry.sync_maker(
        key,
        MakerSync {
            evidence,
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
}

#[test]
fn stale_assignment_cannot_activate_or_replace_retained_evidence() {
    let registry = new_decision_makers();
    let key = SessionKey {
        tenant: TenantId("tenant".into()),
        session: SessionId(1),
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    registry.set_notice_notifier(tx);
    registry.require_descriptors();
    install(&registry, &key, config(1));
    let observation = EvidenceObservation {
        sample_id: 0,
        connection_id: [1; 32],
        sequence: 1,
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![8],
    };
    assert!(registry.note_slot_connected(&key, SlotId(0), false, Some(observation.clone())));
    let first = registry.retained_load_state(&key).evidence;
    assert_eq!(first[0].observation, observation);
    assert!(
        matches!(rx.try_recv().unwrap(), RelayNotice::SlotConnected(notice) if notice.evidence == Some(observation.clone()))
    );
    install(&registry, &key, config(2));
    assert!(!registry.evidence_assignment_current(&key, SlotId(0), 1));
    assert!(!registry.note_slot_connected(&key, SlotId(0), true, Some(observation.clone())));
    assert_eq!(registry.retained_load_state(&key).evidence, first);
    assert!(rx.try_recv().is_err());
    let next = EvidenceObservation {
        connection_id: [2; 32],
        sequence: 2,
        assignment_revision: 2,
        ..observation
    };
    assert!(registry.note_slot_connected(&key, SlotId(0), true, Some(next.clone())));
    assert_eq!(
        registry.retained_load_state(&key).evidence[0].observation,
        next
    );
    registry.deregister_maker(&key);
    assert!(!registry.note_slot_connected(&key, SlotId(0), true, Some(next)));
}

#[test]
fn pending_obligations_and_failure_history_are_bounded_even_with_an_oversized_descriptor() {
    let registry = new_decision_makers();
    let key = SessionKey {
        tenant: TenantId("bounded".into()),
        session: SessionId(1),
    };
    let slots: HashSet<_> = (0..18).map(SlotId).collect();
    let _ = registry.sync_maker(
        &key,
        MakerSync {
            evidence: EvidenceConfig {
                periodic: true,
                keys: vec![rally_point_proto::control::EvidenceKey {
                    key_id: 7,
                    public_key: rally_point_proto::token::ClientPublicKey([7; 32]),
                }],
                assignments: slots.iter().map(|&slot| (slot, 1)).collect(),
                ..Default::default()
            },
            homed_slots: slots.clone(),
            expected_slots: slots,
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
    for slot in 0..18 {
        assert!(registry.activate_connection_epoch(&key, SlotId(slot), 1));
        let admission = EvidenceObservation {
            sample_id: 0,
            sequence: next_evidence_sequence().unwrap(),
            connection_id: [slot; 32],
            assignment_revision: 1,
            verdict: EvidenceVerdict::Valid,
            key_id: Some(7),
            body: vec![8],
        };
        assert!(registry.note_slot_connected(&key, SlotId(slot), false, Some(admission.clone())));
        let sample = EvidenceObservation {
            sample_id: 1,
            ..admission
        };
        assert_eq!(
            registry.begin_periodic_evidence(&key, SlotId(slot), 1, sample.clone()),
            slot < 17
        );
        if slot == 0 {
            // One completed sample coexists with sixteen other pending slots.
            assert!(registry.record_periodic_evidence(&key, SlotId(slot), 1, sample));
        }
    }
    for slot in 1..17 {
        registry.abandon_periodic_evidence(&key, SlotId(slot), 1, 1);
    }
    let state = registry.retained_load_state(&key);
    assert_eq!(state.evidence_history.len(), 16);
    assert_eq!(state.periodic_evidence.len(), 16);
    let mut presence: rally_point_proto::control::SessionPresence =
        serde_json::from_value(serde_json::json!({"tenant":"bounded", "session":1, "slots":[]}))
            .unwrap();
    presence.periodic_evidence = state.periodic_evidence.clone();
    presence.evidence_history = state.evidence_history.clone();
    assert!(serde_json::to_vec(&presence).is_ok());
    assert!(
        state
            .evidence_history
            .iter()
            .all(
                |entry| entry.history.sample.verdict == EvidenceVerdict::Missing
                    && entry.history.sample.body.is_empty()
            )
    );
}

fn pending_outbox_fixture() -> (DecisionMakers, SessionKey, EvidenceObservation) {
    let registry = new_decision_makers();
    let key = SessionKey {
        tenant: TenantId("outbox".into()),
        session: SessionId(4),
    };
    let _ = registry.sync_maker(
        &key,
        MakerSync {
            homed_slots: [SlotId(0)].into(),
            expected_slots: [SlotId(0)].into(),
            evidence: EvidenceConfig {
                periodic: true,
                keys: vec![rally_point_proto::control::EvidenceKey {
                    key_id: 7,
                    public_key: rally_point_proto::token::ClientPublicKey([7; 32]),
                }],
                ..config(1)
            },
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
    assert!(registry.activate_connection_epoch(&key, SlotId(0), 1));
    let admission = EvidenceObservation {
        sample_id: 0,
        sequence: next_evidence_sequence().unwrap(),
        connection_id: [5; 32],
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![6],
    };
    assert!(registry.note_slot_connected(&key, SlotId(0), false, Some(admission.clone())));
    let pending = EvidenceObservation {
        sample_id: 1,
        ..admission.clone()
    };
    assert!(registry.begin_periodic_evidence(&key, SlotId(0), 1, pending));
    (registry, key, admission)
}

#[test]
fn revocation_captures_pending_sample_before_homed_set_and_revision_change() {
    let (registry, key, admission) = pending_outbox_fixture();
    let mut changed = registry.evidence_config(&key).unwrap();
    changed.assignments.remove(&SlotId(0));
    changed.assignments.insert(SlotId(1), 2);
    let _ = registry.sync_maker(
        &key,
        MakerSync {
            homed_slots: [SlotId(1)].into(),
            evidence: changed,
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
    assert!(
        registry
            .retained_load_state(&key)
            .evidence_history
            .is_empty()
    );
    let reports = registry.evidence_reports(Instant::now(), 16);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].history.admission, admission);
    assert_eq!(reports[0].history.sample.verdict, EvidenceVerdict::Missing);
    assert_eq!(reports[0].history.sample.assignment_revision, 1);
    assert!(reports[0].history.sample.sequence > admission.sequence);
}

#[test]
fn removing_maker_retains_completed_and_pending_reports() {
    for completed in [false, true] {
        let (registry, key, admission) = pending_outbox_fixture();
        if completed {
            assert!(registry.record_periodic_evidence(
                &key,
                SlotId(0),
                1,
                EvidenceObservation {
                    sample_id: 1,
                    verdict: EvidenceVerdict::Invalid,
                    ..admission.clone()
                }
            ));
        }
        registry.deregister_maker(&key);
        assert!(!registry.maker_exists(&key));
        let reports = registry.evidence_reports(Instant::now(), 16);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].history.admission, admission);
        assert_eq!(
            reports[0].history.sample.verdict,
            if completed {
                EvidenceVerdict::Invalid
            } else {
                EvidenceVerdict::Missing
            }
        );
    }
}

#[test]
fn acknowledged_history_is_not_reenqueued_by_snapshots_reconnect_or_revocation() {
    let (registry, key, admission) = pending_outbox_fixture();
    registry.abandon_periodic_evidence(&key, SlotId(0), 1, 1);
    let now = Instant::now();
    let report = registry.evidence_reports(now, 16).pop().unwrap();
    registry.acknowledge_evidence(&report.receipt());
    assert_eq!(registry.retained_load_state(&key).evidence_history.len(), 1);
    assert!(registry.activate_connection_epoch(&key, SlotId(0), 2));
    assert!(registry.note_slot_connected(
        &key,
        SlotId(0),
        true,
        Some(EvidenceObservation {
            connection_id: [9; 32],
            sequence: next_evidence_sequence().unwrap(),
            ..admission
        })
    ));
    registry.deregister_maker(&key);
    assert!(
        registry
            .evidence_reports(now + Duration::from_secs(20), 16)
            .is_empty()
    );
}

#[test]
fn expired_history_is_not_reenqueued_by_later_failure_or_removal() {
    let (registry, key, admission) = pending_outbox_fixture();
    registry.abandon_periodic_evidence(&key, SlotId(0), 1, 1);
    let future = Instant::now() + Duration::from_secs(601);
    assert!(registry.evidence_reports(future, 16).is_empty());
    assert!(registry.begin_periodic_evidence(
        &key,
        SlotId(0),
        1,
        EvidenceObservation {
            sample_id: 2,
            ..admission
        }
    ));
    registry.abandon_periodic_evidence(&key, SlotId(0), 1, 2);
    registry.deregister_maker(&key);
    assert!(registry.evidence_reports(future, 16).is_empty());
}

#[test]
fn a_new_assignment_can_report_its_own_first_failure_after_prior_receipt() {
    let (registry, key, mut admission) = pending_outbox_fixture();
    registry.abandon_periodic_evidence(&key, SlotId(0), 1, 1);
    let first = registry.evidence_reports(Instant::now(), 16).pop().unwrap();
    registry.acknowledge_evidence(&first.receipt());
    let mut evidence = registry.evidence_config(&key).unwrap();
    evidence.assignments.insert(SlotId(0), 2);
    install(&registry, &key, evidence);
    assert!(registry.activate_connection_epoch(&key, SlotId(0), 2));
    admission.assignment_revision = 2;
    admission.connection_id = [8; 32];
    admission.sequence = next_evidence_sequence().unwrap();
    assert!(registry.note_slot_connected(&key, SlotId(0), true, Some(admission.clone())));
    assert!(registry.begin_periodic_evidence(
        &key,
        SlotId(0),
        2,
        EvidenceObservation {
            sample_id: 1,
            ..admission
        }
    ));
    registry.deregister_maker(&key);
    let next = registry.evidence_reports(Instant::now(), 16).pop().unwrap();
    assert_eq!(next.history.sample.assignment_revision, 2);
    assert_ne!(next.receipt(), first.receipt());
}
