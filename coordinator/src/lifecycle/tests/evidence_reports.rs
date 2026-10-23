use super::*;
use rally_point_proto::control::{EvidenceHistory, EvidenceReport};

fn report(session: SessionId) -> EvidenceReport {
    EvidenceReport {
        tenant: tid(),
        session,
        slot: SlotId(0),
        history: EvidenceHistory {
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
    for _ in 0..2 {
        assert_eq!(
            lc.ingest_evidence_report(RelayId(1), generation, report.clone()),
            Some(report.receipt())
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
    assert_eq!(
        restored.ingest_evidence_report(RelayId(1), generation, report.clone()),
        Some(report.receipt())
    );
    restored.inner.setup.retire_session(&tid(), session);
    assert!(
        restored
            .ingest_evidence_report(RelayId(1), generation, report)
            .is_none()
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
