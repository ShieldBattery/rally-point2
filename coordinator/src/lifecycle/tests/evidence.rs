use super::*;
use rally_point_proto::control::{
    EvidenceObservation, EvidenceVerdict, SlotConnectedNotice, SlotEvidence,
};

fn enroll(lc: &Lifecycle, relay: u64, boot: u64) -> u64 {
    let setup = &lc.inner.setup;
    let _assignment = setup.lock_assignment();
    let generation = lc
        .enroll_relay_epoch(RelayId(relay), || {
            Ok::<_, ()>(registry::enroll(
                setup.registry(),
                hello(relay, 14900 + relay as u16).with_boot_id(boot),
            ))
        })
        .unwrap();
    if registry::note_boot_id(setup.registry(), RelayId(relay), Some(boot))
        == registry::BootLineage::Broken
    {
        lc.on_relay_lineage_break(RelayId(relay));
    }
    generation
}

fn setup_evidence() -> (Lifecycle, SessionId, u64) {
    let (setup, session) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup);
    let generation = enroll(&lc, 1, 7);
    lc.register_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    (lc, session, generation)
}

fn observation(sequence: u64, assignment_revision: u64) -> EvidenceObservation {
    EvidenceObservation {
        interruption: None,

        sample_id: 0,
        connection_id: [sequence as u8; 32],
        sequence,
        assignment_revision,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![sequence as u8],
    }
}

fn notice(session: SessionId, observation: EvidenceObservation) -> SessionNotice {
    SessionNotice::SlotConnected(SlotConnectedNotice {
        predecessor: None,
        tenant: tid(),
        session,
        slot: SlotId(0),
        external_id: Some("game-1".into()),
        external_ref: None,
        resumed: true,
        connected_at_ms: 1,
        evidence: Some(observation),
    })
}

fn snapshot(session: SessionId, observation: EvidenceObservation) -> SessionPresence {
    SessionPresence {
        evidence: vec![SlotEvidence {
            historical: false,
            failure_count: None,

            slot: SlotId(0),
            observation,
        }],
        ..presence_entry(&tid(), session, &[0])
    }
}

#[tokio::test]
async fn snapshots_cannot_regress_observations_or_swallow_notices() {
    let (lc, session, generation) = setup_evidence();
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    crate::tenant::set_notify(
        lc.inner.setup.tenants(),
        &tid(),
        Some(crate::tenant::NotifyConfig { url }),
    );
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(3, 1))],
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(2, 1)));
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(3, 1)));
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(3, 1)));
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(1, 1))],
    );
    assert_eq!(
        lc.load_state(&tid(), session).unwrap().evidence[0].observation,
        observation(3, 1)
    );
    for sequence in [2, 3] {
        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.body["evidence"]["sequence"], sequence);
    }
    assert!(lc.drain_webhooks(Duration::from_secs(2)).await == 0);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn current_home_generation_and_assignment_all_gate_evidence() {
    let (lc, session, old_generation) = setup_evidence();
    let generation = enroll(&lc, 1, 7);
    lc.ingest_notice(
        RelayId(1),
        old_generation,
        notice(session, observation(1, 1)),
    );
    lc.merge_connection_evidence(
        RelayId(1),
        old_generation,
        &[snapshot(session, observation(2, 1))],
    );
    let other = enroll(&lc, 2, 8);
    lc.ingest_notice(RelayId(2), other, notice(session, observation(3, 1)));
    lc.merge_connection_evidence(RelayId(2), other, &[snapshot(session, observation(4, 1))]);
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(5, 9)));
    assert!(lc.load_state(&tid(), session).unwrap().evidence.is_empty());
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(6, 1)));
    assert_eq!(
        lc.load_state(&tid(), session).unwrap().evidence[0]
            .observation
            .sequence,
        6
    );
}

#[tokio::test]
async fn a_return_to_the_same_home_does_not_revive_old_assignment_evidence() {
    let (lc, session, generation) = setup_evidence();
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(90, 1)));
    assert_eq!(
        lc.connection_evidence(&tid(), session),
        lc.load_state(&tid(), session).unwrap().evidence,
    );
    let setup = &lc.inner.setup;
    registry::remove(setup.registry(), RelayId(1));
    enroll(&lc, 2, 8);
    assert!(matches!(
        crate::session::rehome(setup, &tid(), session, RelayId(1), vec![]),
        crate::session::RehomeOutcome::NewTarget(_)
    ));
    assert!(lc.load_state(&tid(), session).unwrap().evidence.is_empty());
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    registry::remove(setup.registry(), RelayId(2));
    let generation = enroll(&lc, 1, 7);
    assert!(matches!(
        crate::session::rehome(setup, &tid(), session, RelayId(2), vec![]),
        crate::session::RehomeOutcome::NewTarget(_)
    ));
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(100, 1))],
    );
    assert!(lc.load_state(&tid(), session).unwrap().evidence.is_empty());
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(101, 3))],
    );
    assert_eq!(
        lc.load_state(&tid(), session).unwrap().evidence[0].observation,
        observation(101, 3)
    );
    assert_eq!(
        lc.connection_evidence(&tid(), session),
        lc.load_state(&tid(), session).unwrap().evidence,
    );
}

#[tokio::test]
async fn persisted_highwaters_survive_restart_and_new_relay_boots_reset_sequence_scope() {
    let (lc, session, generation) = setup_evidence();
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(90, 1)));
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
    let generation = enroll(&restored, 1, 7);
    restored.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(1, 1))],
    );
    assert_eq!(
        restored.load_state(&tid(), session).unwrap().evidence[0]
            .observation
            .sequence,
        90
    );
    let generation = enroll(&restored, 1, 8);
    assert!(
        restored
            .load_state(&tid(), session)
            .unwrap()
            .evidence
            .is_empty()
    );
    restored.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(1, 1))],
    );
    assert_eq!(
        restored.load_state(&tid(), session).unwrap().evidence[0]
            .observation
            .sequence,
        1
    );
}

#[tokio::test]
async fn malformed_shapes_and_unversioned_slots_do_not_record_evidence() {
    let (lc, session, generation) = setup_evidence();
    let mut oversized = observation(1, 1);
    oversized.body = vec![0; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN + 1];
    for value in [oversized, observation(0, 1), observation(1, 0)] {
        lc.ingest_notice(RelayId(1), generation, notice(session, value));
    }
    assert!(lc.load_state(&tid(), session).unwrap().evidence.is_empty());
}

#[tokio::test]
async fn duplicate_slot_entries_do_not_change_the_first_observation() {
    let (lc, session, generation) = setup_evidence();
    let mut values = snapshot(session, observation(1, 1));
    values.evidence.push(SlotEvidence {
        historical: false,
        failure_count: None,

        slot: SlotId(0),
        observation: observation(99, 1),
    });
    lc.merge_connection_evidence(RelayId(1), generation, &[values]);
    assert_eq!(
        lc.load_state(&tid(), session).unwrap().evidence[0]
            .observation
            .sequence,
        1
    );
}

#[test]
fn tenant_payload_uses_camel_case_and_base64() {
    let value =
        serde_json::to_value(crate::notify::EvidencePayload::from(observation(2, 1))).unwrap();
    assert_eq!(value["assignmentRevision"], 1);
    assert_eq!(value["keyId"], 7);
    assert_eq!(value["body"], "Ag==");
    assert_eq!(
        value["connectionId"],
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    );
    assert!(value.get("assignment_revision").is_none());
    assert!(value.get("key_id").is_none());
}

#[tokio::test]
async fn a_self_describing_orphan_arrival_keeps_ordinary_facts_without_evidence() {
    let (lc, _, generation) = setup_evidence();
    let orphan = SessionId(u64::MAX);
    lc.ingest_notice(RelayId(1), generation, notice(orphan, observation(1, 1)));
    let state = lc.load_state(&tid(), orphan).unwrap();
    assert_eq!(state.connected_slots, vec![SlotId(0)]);
    assert!(state.evidence.is_empty());
    assert!(
        lc.notice_dedup()
            .slot_connects
            .lock()
            .contains(&(tid(), orphan, SlotId(0)))
    );
    let stale = enroll(&lc, 1, 7);
    lc.ingest_notice(
        RelayId(1),
        generation,
        notice(SessionId(u64::MAX - 1), observation(2, 1)),
    );
    assert!(lc.load_state(&tid(), SessionId(u64::MAX - 1)).is_none());
    assert_ne!(generation, stale);
}

#[tokio::test]
async fn missing_boot_context_preserves_only_correctly_assigned_arrivals() {
    let (lc, session, generation) = setup_evidence();
    registry::note_boot_id(lc.inner.setup.registry(), RelayId(1), None);
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(1, 9)));
    let other = enroll(&lc, 2, 9);
    registry::note_boot_id(lc.inner.setup.registry(), RelayId(2), None);
    lc.ingest_notice(RelayId(2), other, notice(session, observation(2, 1)));
    assert!(
        lc.load_state(&tid(), session)
            .unwrap()
            .connected_slots
            .is_empty()
    );
    lc.ingest_notice(RelayId(1), generation, notice(session, observation(3, 1)));
    let state = lc.load_state(&tid(), session).unwrap();
    assert_eq!(state.connected_slots, vec![SlotId(0)]);
    assert!(state.evidence.is_empty());
}

#[tokio::test]
async fn restored_unversioned_assignments_accept_revision_zero() {
    let (original, session, _) = setup_evidence();
    let mut records = {
        let assignment = original.inner.setup.lock_assignment();
        original.inner.setup.export_records(&assignment)
    };
    let record = records.get_mut(&(tid(), session)).unwrap();
    record.refs.as_mut().unwrap().evidence_assignments.clear();
    for (_, descriptor) in &mut record.descriptors {
        descriptor.evidence_assignments.clear();
    }
    let setup = bare_setup();
    setup.restore_records(records.into_iter().collect());
    let restored = Lifecycle::new(setup);
    let generation = enroll(&restored, 1, 7);
    restored.ingest_notice(RelayId(1), generation, notice(session, observation(1, 0)));
    let state = restored.load_state(&tid(), session).unwrap();
    assert_eq!(state.connected_slots, vec![SlotId(0)]);
    assert_eq!(state.evidence[0].observation, observation(1, 0));
}

#[tokio::test]
async fn unverified_bodies_never_reach_retained_state_or_webhooks() {
    let (lc, session, generation) = setup_evidence();
    let (url, mut webhooks) = WebhookReceiver::default().spawn().await;
    crate::tenant::set_notify(
        lc.inner.setup.tenants(),
        &tid(),
        Some(crate::tenant::NotifyConfig { url }),
    );
    for (index, verdict) in [
        EvidenceVerdict::Missing,
        EvidenceVerdict::UnknownKey,
        EvidenceVerdict::Invalid,
    ]
    .into_iter()
    .enumerate()
    {
        let mut value = observation((index + 1) as u64, 1);
        value.verdict = verdict;
        lc.merge_connection_evidence(RelayId(1), generation, &[snapshot(session, value.clone())]);
        assert!(
            lc.load_state(&tid(), session).unwrap().evidence[0]
                .observation
                .body
                .is_empty()
        );
        lc.ingest_notice(RelayId(1), generation, notice(session, value));
        let webhook = timeout(Duration::from_secs(2), webhooks.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(webhook.body["evidence"]["body"], "");
        let persisted = serde_json::to_value(&lc.export_facts()[&(tid(), session)]).unwrap();
        assert_eq!(persisted["evidence"][0][1]["observation"]["body"], "");
    }
}

#[tokio::test]
async fn cached_evidence_is_tenant_scoped_and_removed_on_close() {
    let (lc, session, generation) = setup_evidence();
    let expected = vec![SlotEvidence {
        historical: false,
        failure_count: None,

        slot: SlotId(0),
        observation: observation(1, 1),
    }];
    lc.merge_connection_evidence(
        RelayId(1),
        generation,
        &[snapshot(session, observation(1, 1))],
    );
    assert_eq!(lc.connection_evidence(&tid(), session), expected);
    assert_eq!(
        lc.connection_evidence(&tid(), session),
        lc.load_state(&tid(), session).unwrap().evidence,
    );
    assert!(
        lc.connection_evidence(&TenantId("other".to_owned()), session)
            .is_empty()
    );

    lc.on_session_closed(tid(), session, RelayId(1), generation);
    assert!(lc.load_state(&tid(), session).is_none());
    assert!(lc.connection_evidence(&tid(), session).is_empty());
    assert!(
        lc.inner
            .setup
            .evidence_assignments(&tid(), session)
            .is_empty()
    );
}
