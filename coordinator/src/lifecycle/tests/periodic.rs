use super::*;
use rally_point_proto::control::{
    CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceKey, EvidenceObservation, EvidenceVerdict,
    SlotConnectedNotice, SlotEvidence, SlotEvidenceNotice,
};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};

fn enroll(lc: &Lifecycle, boot: u64, capable: bool) -> u64 {
    let setup = &lc.inner.setup;
    let _assignment = setup.lock_assignment();
    let generation = lc
        .enroll_relay_epoch(RelayId(1), || {
            Ok::<_, ()>(registry::enroll(
                setup.registry(),
                hello(1, 14901)
                    .with_boot_id(boot)
                    .with_capabilities(if capable {
                        vec![CAPABILITY_PERIODIC_EVIDENCE_V1.into()]
                    } else {
                        vec![]
                    }),
            ))
        })
        .unwrap();
    if registry::note_boot_id(setup.registry(), RelayId(1), Some(boot))
        == registry::BootLineage::Broken
    {
        lc.on_relay_lineage_break(RelayId(1));
    }
    generation
}

fn setup(periodic: bool) -> (Lifecycle, SessionId, u64) {
    let lc = Lifecycle::new(bare_setup());
    let generation = enroll(&lc, 7, true);
    let mut req = request(two_players());
    req.external_id = Some("game-1".into());
    req.periodic_evidence = periodic;
    req.evidence_keys = vec![EvidenceKey {
        key_id: 7,
        public_key: ClientPublicKey([4; 32]),
    }];
    let session = crate::session::create_session(&lc.inner.setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    lc.register_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    (lc, session, generation)
}

fn admission(sequence: u64) -> EvidenceObservation {
    EvidenceObservation {
        sample_id: 0,
        connection_id: [sequence as u8; 32],
        sequence,
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![1],
    }
}
fn sample(connection: u64, sample_id: u64, sequence: u64) -> EvidenceObservation {
    EvidenceObservation {
        sample_id,
        sequence,
        ..admission(connection)
    }
}
fn notice(session: SessionId, evidence: EvidenceObservation) -> SessionNotice {
    SessionNotice::SlotEvidence(SlotEvidenceNotice {
        tenant: tid(),
        session,
        slot: SlotId(0),
        external_id: Some("game-1".into()),
        external_ref: Some("user-1".into()),
        observed_at_ms: 42,
        evidence,
    })
}
fn snapshot(
    session: SessionId,
    admission: Option<EvidenceObservation>,
    periodic: Option<EvidenceObservation>,
) -> SessionPresence {
    SessionPresence {
        evidence: admission
            .into_iter()
            .map(|observation| SlotEvidence {
                slot: SlotId(0),
                observation,
            })
            .collect(),
        periodic_evidence: periodic
            .into_iter()
            .map(|observation| SlotEvidence {
                slot: SlotId(0),
                observation,
            })
            .collect(),
        ..presence_entry(&tid(), session, &[])
    }
}

#[tokio::test]
async fn periodic_notifications_are_separate_private_and_do_not_activate_slots() {
    let (lc, session, generation) = setup(true);
    let (url, mut receiver) = WebhookReceiver::default().spawn().await;
    crate::tenant::set_notify(
        lc.inner.setup.tenants(),
        &tid(),
        Some(crate::tenant::NotifyConfig { url }),
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 1, 2)));
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), None)],
    );
    let mut observation = sample(1, 1, 2);
    observation.verdict = EvidenceVerdict::Invalid;
    observation.body = b"unverified".to_vec();
    lc.ingest_notice(RelayId(1), generation, notice(session, observation.clone()));
    lc.ingest_notice(RelayId(1), generation, notice(session, observation));
    let webhook = timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(webhook.body["event"], "slotEvidence");
    assert_eq!(webhook.body["observedAtMs"], 42);
    assert_eq!(webhook.body["externalId"], "game-1");
    assert_eq!(webhook.body["externalRef"], "user-1");
    assert_eq!(webhook.body["evidence"]["sampleId"], 1);
    assert_eq!(webhook.body["evidence"]["body"], "");
    assert!(
        !lc.inner
            .sessions
            .lock()
            .get(&(tid(), session))
            .unwrap()
            .started
    );
    assert!(
        lc.load_state(&tid(), session)
            .unwrap()
            .connected_slots
            .is_empty()
    );
    assert!(lc.notice_dedup().slot_connects.lock().is_empty());
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 2);
    assert!(
        lc.connection_evidence(&tid(), session)[1]
            .observation
            .body
            .is_empty()
    );
    let facts = serde_json::to_value(lc.export_facts().remove(&(tid(), session)).unwrap()).unwrap();
    assert_eq!(facts["periodic_evidence"][0][1]["observation"]["body"], "");
    assert_eq!(lc.drain_webhooks(Duration::from_secs(2)).await, 0);
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn snapshots_merge_admission_first_and_late_arrival_does_not_drop_periodic() {
    let (lc, session, generation) = setup(true);
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 2, 3)))],
    );
    lc.ingest_notice(
        RelayId(1),
        generation,
        SessionNotice::SlotConnected(SlotConnectedNotice {
            tenant: tid(),
            session,
            slot: SlotId(0),
            external_id: None,
            external_ref: None,
            resumed: false,
            connected_at_ms: 0,
            evidence: Some(admission(1)),
        }),
    );
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 1, 2)))],
    );
    assert_eq!(
        lc.connection_evidence(&tid(), session)[1].observation,
        sample(1, 2, 3)
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 3, 2)));
    assert_eq!(
        lc.connection_evidence(&tid(), session)[1]
            .observation
            .sample_id,
        2
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 3, 4)));
    assert_eq!(
        lc.connection_evidence(&tid(), session)[1]
            .observation
            .sample_id,
        3
    );
    assert_eq!(
        lc.connection_evidence(&tid(), session),
        lc.load_state(&tid(), session).unwrap().evidence
    );
}

#[tokio::test]
async fn periodic_samples_cannot_cross_control_process_assignment_or_connection_fences() {
    let (lc, session, old_generation) = setup(true);
    lc.merge_connection_evidence(
        RelayId(1),
        old_generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 1, 2)))],
    );
    let generation = enroll(&lc, 7, true);
    lc.ingest_notice(RelayId(1), old_generation, notice(session, sample(1, 2, 3)));
    assert_eq!(
        lc.connection_evidence(&tid(), session)[1]
            .observation
            .sample_id,
        1
    );
    let mut wrong_revision = sample(1, 2, 3);
    wrong_revision.assignment_revision = 2;
    lc.ingest_notice(RelayId(1), generation, notice(session, wrong_revision));
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(2, 2, 999)));
    assert_eq!(
        lc.connection_evidence(&tid(), session)[1]
            .observation
            .sample_id,
        1
    );
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(3)), None)],
    );
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 1);
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 999, 999)));
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 1);
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(3, 1, 4)));
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 2);
    let generation = enroll(&lc, 8, true);
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(3, 2, 5)));
    assert!(lc.connection_evidence(&tid(), session).is_empty());
}

#[tokio::test]
async fn periodic_cache_survives_restart_and_is_removed_on_rehome_or_retirement() {
    let (lc, session, generation) = setup(true);
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 1, 2)))],
    );
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
        restored.connection_evidence(&tid(), session),
        lc.connection_evidence(&tid(), session)
    );
    restored.on_rehome(&tid(), session, RelayId(1), RelayId(1));
    assert_eq!(restored.connection_evidence(&tid(), session).len(), 1);
    assert!(
        restored
            .inner
            .sessions
            .lock()
            .get(&(tid(), session))
            .unwrap()
            .periodic_evidence
            .is_empty()
    );
    restored.ingest_notice(RelayId(1), generation, notice(session, sample(1, 2, 3)));
    restored.on_session_closed(tid(), session, RelayId(1), generation);
    assert!(restored.connection_evidence(&tid(), session).is_empty());
    restored.ingest_notice(RelayId(1), generation, notice(session, sample(1, 3, 4)));
    assert!(restored.load_state(&tid(), session).is_none());
}

#[tokio::test]
async fn periodic_policy_capability_and_sample_shape_gate_both_ingest_paths() {
    let (lc, session, generation) = setup(false);
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 1, 2)))],
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 1, 2)));
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 1);
    let (lc, session, generation) = setup(true);
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), None)],
    );
    for value in [sample(1, 0, 2), sample(1, 1, 1), sample(1, 1, 0)] {
        lc.ingest_notice(RelayId(1), generation, notice(session, value));
    }
    let generation = enroll(&lc, 7, false);
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, Some(admission(1)), Some(sample(1, 1, 2)))],
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, sample(1, 1, 2)));
    assert_eq!(lc.connection_evidence(&tid(), session).len(), 1);
}
