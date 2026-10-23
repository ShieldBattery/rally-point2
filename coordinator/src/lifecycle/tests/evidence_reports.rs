use super::*;
use rally_point_proto::control::{
    EvidenceFailure, EvidenceHistory, EvidenceInterruption, EvidenceReceiptDisposition,
    EvidenceReport,
};

fn report(session: SessionId) -> EvidenceReport {
    EvidenceReport {
        tenant: tid(),
        session,
        slot: SlotId(0),
        history: EvidenceHistory {
            failures: 1,
            latest: None,

            admission: admission(1),
            sample: EvidenceObservation {
                verdict: EvidenceVerdict::Missing,
                body: vec![],
                ..sample(1, 1, 2)
            },
            observed_at_ms: 42,
        },
    }
}

#[tokio::test]
async fn receipts_repeat_without_repeating_webhook_or_activating_slot() {
    let _delivery = crate::test_support::PERIODIC_WEBHOOK_TEST_LOCK.lock().await;
    let (lc, session, generation) = setup(true);
    let (url, mut receiver) = WebhookReceiver::default().spawn().await;
    crate::tenant::set_notify(
        lc.inner.setup.tenants(),
        &tid(),
        Some(crate::tenant::NotifyConfig { url }),
    );
    let mut report = report(session);
    report.history.sample.body = vec![99];
    for disposition in [
        EvidenceReceiptDisposition::Accepted,
        EvidenceReceiptDisposition::Superseded,
    ] {
        let mut expected = report.receipt();
        expected.disposition = disposition;
        assert_eq!(
            lc.ingest_evidence_report(RelayId(1), generation, report.clone()),
            Some(expected)
        );
    }
    let webhook = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(webhook.body["evidence"]["verdict"], "missing");
    assert_eq!(lc.drain_webhooks(Duration::from_secs(2)).await, 0);
    assert!(receiver.try_recv().is_err());
    let states = lc.inner.sessions.lock();
    let state = states.get(&(tid(), session)).unwrap();
    assert!(state.evidence.is_empty());
    assert!(state.connected_slots.is_empty());
    assert!(!state.started);
    assert!(
        state.evidence_history[&SlotId(0)]
            .history
            .sample
            .body
            .is_empty()
    );
}

#[tokio::test]
async fn unreported_old_home_history_arrives_after_rehome_and_new_admission() {
    let (lc, session, old_generation) = setup(true);
    let replacement_generation = {
        let _assignment = lc.inner.setup.lock_assignment();
        let generation = lc
            .enroll_relay_epoch(RelayId(2), || {
                Ok::<_, ()>(registry::enroll(
                    lc.inner.setup.registry(),
                    hello(2, 14902)
                        .with_boot_id(8)
                        .with_capabilities(vec![CAPABILITY_PERIODIC_EVIDENCE_V1.into()]),
                ))
            })
            .unwrap();
        registry::note_boot_id(lc.inner.setup.registry(), RelayId(2), Some(8));
        generation
    };
    registry::remove(lc.inner.setup.registry(), RelayId(1));
    assert!(matches!(
        crate::session::rehome(&lc.inner.setup, &tid(), session, RelayId(1), vec![]),
        crate::session::RehomeOutcome::NewTarget(_)
    ));
    lc.on_rehome(&tid(), session, RelayId(1), RelayId(2));
    let mut current = admission(10);
    current.assignment_revision = 2;
    lc.merge_connection_evidence(
        RelayId(2),
        replacement_generation,
        &[snapshot(session, Some(current.clone()), None)],
    );
    let generation = enroll(&lc, 7, true);
    let report = report(session);
    assert!(
        lc.ingest_evidence_report(RelayId(1), old_generation, report.clone())
            .is_none()
    );
    lc.ingest_notice(RelayId(1), generation, history_notice(session, 1, 2));
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 1);
    assert_eq!(
        lc.ingest_evidence_report(RelayId(1), generation, report.clone()),
        Some(report.receipt())
    );
    let retained = lc.connection_evidence(&tid(), session);
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].observation, current);
    assert_eq!(retained[1].observation, report.history.sample);
    assert_eq!(
        lc.inner
            .setup
            .evidence_assignment(RelayId(1), &tid(), session, SlotId(0)),
        None
    );

    let mut replacement = report.clone();
    replacement.history.admission = current.clone();
    replacement.history.sample = EvidenceObservation {
        sample_id: 1,
        sequence: 11,
        verdict: EvidenceVerdict::Missing,
        body: Vec::new(),
        ..current.clone()
    };
    assert!(
        lc.ingest_evidence_report(RelayId(2), replacement_generation, replacement.clone())
            .is_some()
    );
    assert_eq!(
        lc.ingest_evidence_report(RelayId(2), replacement_generation, replacement)
            .unwrap()
            .disposition,
        EvidenceReceiptDisposition::Superseded
    );
    let retained = lc.connection_evidence(&tid(), session);
    assert_eq!(retained.len(), 3);
    assert_eq!(retained[0].observation, current);
    assert!(
        retained[1..]
            .iter()
            .all(|entry| entry.historical && entry.failure_count == Some(2))
    );

    let facts = lc.export_facts().remove(&(tid(), session)).unwrap();
    let facts = serde_json::from_slice(&serde_json::to_vec(&facts).unwrap()).unwrap();
    let restored = Lifecycle::new(lc.inner.setup.clone());
    restored.restore_session(
        tid(),
        session,
        vec![RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
        facts,
    );
    let generation = enroll(&restored, 7, true);
    assert_eq!(restored.connection_evidence(&tid(), session), retained);
    let mut expected = report.receipt();
    expected.disposition = EvidenceReceiptDisposition::Superseded;
    assert_eq!(
        restored.ingest_evidence_report(RelayId(1), generation, report.clone()),
        Some(expected)
    );
    restored.inner.setup.retire_session(&tid(), session);
    assert_eq!(
        restored
            .ingest_evidence_report(RelayId(1), generation, report)
            .unwrap()
            .disposition,
        EvidenceReceiptDisposition::SessionClosed
    );
}

#[tokio::test]
async fn report_rejects_wrong_pair_scope_process_and_control_generation() {
    let (lc, session, old_generation) = setup(true);
    let generation = enroll(&lc, 7, true);
    assert!(
        lc.ingest_evidence_report(RelayId(1), old_generation, report(session))
            .is_none()
    );
    for mode in 0..9 {
        let mut report = report(session);
        match mode {
            0 => report.tenant = TenantId("other".into()),
            1 => report.slot = SlotId(15),
            2 => report.history.sample.assignment_revision = 2,
            3 => report.history.admission.sample_id = 1,
            4 => report.history.sample.connection_id = [9; 32],
            5 => report.history.sample.sequence = 1,
            6 => report.history.sample.verdict = EvidenceVerdict::Valid,
            7 => {
                report.history.sample.body =
                    vec![1; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN + 1]
            }
            _ => report.history.sample.sample_id = 0,
        }
        assert!(
            lc.ingest_evidence_report(RelayId(1), generation, report)
                .is_none()
        );
    }
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    let generation = enroll(&lc, 8, true);
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, report(session))
            .is_none()
    );
    assert!(lc.connection_evidence(&tid(), session).is_empty());
}

#[tokio::test]
async fn receipt_does_not_claim_a_conflicting_first_failure_was_stored() {
    let (lc, session, generation) = setup(true);
    let report = report(session);
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, report.clone())
            .is_some()
    );
    let mut conflicting = report.clone();
    conflicting.history.sample.sequence += 1;
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, conflicting)
            .is_none()
    );
    assert_eq!(
        lc.connection_evidence(&tid(), session)[0].observation,
        report.history.sample
    );
}

fn cumulative(session: SessionId, failures: u32, connection: u64) -> EvidenceReport {
    let mut report = report(session);
    report.history.failures = failures;
    report.history.latest = Some(Box::new(EvidenceFailure {
        admission: admission(connection),
        sample: EvidenceObservation {
            verdict: EvidenceVerdict::Missing,
            interruption: Some(EvidenceInterruption::ConnectionReplaced),
            body: vec![],
            ..sample(connection, 1, connection + 1)
        },
        observed_at_ms: 50 + connection,
    }));
    report
}

#[tokio::test]
async fn cumulative_replacements_survive_reordering_and_restore() {
    let (lc, session, generation) = setup(true);
    let first = report(session);
    let second = cumulative(session, 2, 10);
    let third = cumulative(session, 3, 20);
    for item in [&first, &third, &second, &third, &first] {
        assert!(
            lc.ingest_evidence_report(RelayId(1), generation, item.clone())
                .is_some()
        );
    }
    let observations = lc.connection_evidence(&tid(), session);
    assert_eq!(observations.len(), 2);
    assert!(
        observations
            .iter()
            .all(|item| item.historical && item.failure_count == Some(3))
    );
    assert_eq!(observations[0].observation, first.history.sample);
    assert_eq!(observations[1].observation, *third.history.latest_sample());
    let facts = lc.export_facts().remove(&(tid(), session)).unwrap();
    let facts = serde_json::from_slice(&serde_json::to_vec(&facts).unwrap()).unwrap();
    let restored = Lifecycle::new(lc.inner.setup.clone());
    restored.restore_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
        facts,
    );
    let generation = enroll(&restored, 7, true);
    assert_eq!(
        restored
            .ingest_evidence_report(RelayId(1), generation, second)
            .unwrap()
            .disposition,
        EvidenceReceiptDisposition::Superseded
    );
    assert_eq!(restored.connection_evidence(&tid(), session), observations);
    assert!(
        restored.inner.sessions.lock()[&(tid(), session)]
            .evidence
            .is_empty()
    );
}

#[tokio::test]
async fn saturated_count_still_advances_latest_and_ack_identity() {
    let (lc, session, generation) = setup(true);
    let first = cumulative(session, u32::MAX, 10);
    let latest = cumulative(session, u32::MAX, 20);
    assert_ne!(first.receipt(), latest.receipt());
    for item in [&first, &latest, &first] {
        assert!(
            lc.ingest_evidence_report(RelayId(1), generation, item.clone())
                .is_some()
        );
    }
    let observations = lc.connection_evidence(&tid(), session);
    assert_eq!(observations[1].failure_count, Some(u32::MAX));
    assert_eq!(observations[1].observation, *latest.history.latest_sample());
}

#[tokio::test]
async fn lifecycle_cancellations_and_invalid_latest_pairs_are_not_counted() {
    let (lc, session, generation) = setup(true);
    for reason in [
        EvidenceInterruption::Revoked,
        EvidenceInterruption::SessionRetired,
    ] {
        let mut invalid = report(session);
        invalid.history.sample.interruption = Some(reason);
        assert!(
            lc.ingest_evidence_report(RelayId(1), generation, invalid)
                .is_none()
        );
    }
    let mut invalid = cumulative(session, 2, 10);
    invalid
        .history
        .latest
        .as_mut()
        .unwrap()
        .sample
        .connection_id = [99; 32];
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, invalid)
            .is_none()
    );
    let mut invalid = report(session);
    invalid.history.sample.verdict = EvidenceVerdict::Invalid;
    invalid.history.sample.interruption = Some(EvidenceInterruption::Timeout);
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, invalid)
            .is_none()
    );
    assert!(lc.connection_evidence(&tid(), session).is_empty());
}

#[tokio::test]
async fn closed_receipts_require_exact_known_authority() {
    let (lc, session, generation) = setup(true);
    lc.inner.setup.retire_session(&tid(), session);
    let good = report(session);
    assert_eq!(
        lc.ingest_evidence_report(RelayId(1), generation, good.clone())
            .unwrap()
            .disposition,
        EvidenceReceiptDisposition::SessionClosed
    );
    for mode in 0..4 {
        let mut invalid = good.clone();
        match mode {
            0 => invalid.session = SessionId(session.0 + 1),
            1 => invalid.tenant = TenantId("other".into()),
            2 => invalid.slot = SlotId(15),
            _ => {
                invalid.history.admission.assignment_revision = 99;
                invalid.history.sample.assignment_revision = 99;
            }
        }
        assert!(
            lc.ingest_evidence_report(RelayId(1), generation, invalid)
                .is_none()
        );
    }
    let generation = enroll(&lc, 8, true);
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, good)
            .is_none()
    );
}

#[tokio::test]
async fn legacy_history_restores_a_single_failure_highwater() {
    let (lc, session, generation) = setup(true);
    assert!(
        lc.ingest_evidence_report(RelayId(1), generation, report(session))
            .is_some()
    );
    let facts = lc.export_facts().remove(&(tid(), session)).unwrap();
    let mut encoded = serde_json::to_value(facts).unwrap();
    let stored = encoded["evidence_history"][0][1].as_object_mut().unwrap();
    stored.remove("sources");
    stored["history"]
        .as_object_mut()
        .unwrap()
        .remove("failures");
    stored["history"].as_object_mut().unwrap().remove("latest");
    let facts = serde_json::from_value(encoded).unwrap();
    let restored = Lifecycle::new(lc.inner.setup.clone());
    restored.restore_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
        facts,
    );
    let generation = enroll(&restored, 7, true);
    assert!(
        restored
            .ingest_evidence_report(RelayId(1), generation, report(session))
            .is_some()
    );
    assert!(
        restored
            .ingest_evidence_report(RelayId(1), generation, cumulative(session, 2, 10))
            .is_some()
    );
    assert!(
        restored
            .connection_evidence(&tid(), session)
            .iter()
            .all(|item| item.failure_count == Some(2))
    );
}

#[tokio::test]
async fn legacy_missing_pinned_boot_rejects_counts_instead_of_recounting() {
    let (lc, session, _) = setup(true);
    let mut records = {
        let guard = lc.inner.setup.lock_assignment();
        lc.inner.setup.export_records(&guard)
    };
    records
        .get_mut(&(tid(), session))
        .unwrap()
        .refs
        .as_mut()
        .unwrap()
        .evidence_home_boots
        .clear();
    let setup = bare_setup();
    setup.restore_records(records.into_iter().collect());
    let restored = Lifecycle::new(setup);
    restored.register_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    let generation = enroll(&restored, 7, true);
    for _ in 0..3 {
        assert!(
            restored
                .ingest_evidence_report(RelayId(1), generation, report(session))
                .is_none()
        );
        restored.ingest_notice(RelayId(1), generation, history_notice(session, 1, 2));
    }
    assert!(restored.connection_evidence(&tid(), session).is_empty());
}
