use super::*;
use rally_point_proto::control::{CAPABILITY_EVIDENCE_V1, EvidenceKey};

fn evidence_request() -> SessionRequest {
    let mut req = request(two_players());
    req.players[0].require_evidence = true;
    req.evidence_keys = vec![EvidenceKey {
        key_id: 7,
        public_key: ClientPublicKey([4; 32]),
    }];
    req.external_id = Some("evidence-session".into());
    req
}

fn enroll_evidence(setup: &SessionSetup, id: u64) {
    registry::enroll(
        setup.registry(),
        hello(id, 14900 + id as u16).with_capabilities(vec![CAPABILITY_EVIDENCE_V1.into()]),
    );
}

#[test]
fn enforcement_never_falls_back_to_an_unsupported_relay() {
    let setup = two_relay_fleet();
    assert!(matches!(
        create_session(&setup, evidence_request(), ExpiresAt(u64::MAX)),
        Err(SessionSetupError::NoRelaysAvailable)
    ));
    enroll_evidence(&setup, 3);
    let result = create_session(&setup, evidence_request(), ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(result.response.home_relay.relay_id, RelayId(3));
    let descriptor = &setup.descriptors().current_for(RelayId(3))[0];
    assert_eq!(descriptor.required_evidence_slots, vec![SlotId(0)]);
    assert_eq!(descriptor.evidence_keys, evidence_request().evidence_keys);
    assert!(
        descriptor
            .evidence_assignments
            .iter()
            .all(|a| a.revision == 1)
    );
    registry::remove(setup.registry(), RelayId(3));
    assert!(matches!(
        rehome(&setup, &tid(), result.response.session, RelayId(3), vec![]),
        RehomeOutcome::Unavailable
    ));
    enroll_evidence(&setup, 4);
    assert!(matches!(
        rehome(&setup, &tid(), result.response.session, RelayId(3), vec![]),
        RehomeOutcome::NewTarget(endpoint) if endpoint.relay_id == RelayId(4)
    ));
    let descriptor = &setup.descriptors().current_for(RelayId(4))[0];
    assert!(
        descriptor
            .evidence_assignments
            .iter()
            .all(|a| a.revision == 2)
    );
    // A capability downgrade cannot survive either the cached or the Stay path.
    registry::enroll(setup.registry(), hello(4, 14904));
    assert!(recorded_rehome(&setup, &tid(), result.response.session, RelayId(3)).is_none());
    assert!(matches!(
        rehome(&setup, &tid(), result.response.session, RelayId(4), vec![]),
        RehomeOutcome::Unavailable
    ));
}

#[test]
fn shadow_keys_keep_legacy_placement() {
    let setup = two_relay_fleet();
    let mut req = evidence_request();
    req.players[0].require_evidence = false;
    assert!(create_session(&setup, req, ExpiresAt(u64::MAX)).is_ok());
}

#[test]
fn invalid_key_sets_are_rejected_before_placement() {
    let setup = fleet(&[]).0;
    let base = evidence_request();
    let mut empty = base.clone();
    empty.evidence_keys.clear();
    let mut duplicate = base.clone();
    duplicate
        .evidence_keys
        .push(duplicate.evidence_keys[0].clone());
    let mut oversized = base;
    oversized.evidence_keys = (0..17)
        .map(|key_id| EvidenceKey {
            key_id,
            public_key: ClientPublicKey([4; 32]),
        })
        .collect();
    for req in [empty, duplicate, oversized] {
        assert!(matches!(
            create_session(&setup, req, ExpiresAt(u64::MAX)),
            Err(SessionSetupError::InvalidEvidenceKeys)
        ));
    }
}

#[test]
fn keys_and_requirements_join_the_persisted_create_fingerprint() {
    let setup = fleet(&[]).0;
    enroll_evidence(&setup, 1);
    let mut req = evidence_request();
    req.evidence_keys.push(EvidenceKey {
        key_id: 2,
        public_key: ClientPublicKey([6; 32]),
    });
    let first = create_session(&setup, req.clone(), ExpiresAt(u64::MAX)).unwrap();
    let records = {
        let guard = setup.lock_assignment();
        setup.export_records(&guard)
    };
    let restored = fleet(&[]).0;
    enroll_evidence(&restored, 1);
    restored.restore_records(
        records
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap(),
                )
            })
            .collect(),
    );
    req.evidence_keys.reverse();
    let replay = create_session(&restored, req.clone(), ExpiresAt(u64::MAX)).unwrap();
    assert!(replay.replayed);
    assert_eq!(first.response, replay.response);
    let mut changed = req.clone();
    changed.evidence_keys[0].public_key = ClientPublicKey([9; 32]);
    assert!(matches!(
        create_session(&restored, changed, ExpiresAt(u64::MAX)),
        Err(SessionSetupError::IdempotentCreateMismatch)
    ));
    req.players[0].require_evidence = false;
    assert!(matches!(
        create_session(&restored, req, ExpiresAt(u64::MAX)),
        Err(SessionSetupError::IdempotentCreateMismatch)
    ));
    assert_eq!(
        session_refs(&restored, &tid(), first.response.session)
            .unwrap()
            .evidence_assignments
            .get(&SlotId(0)),
        Some(&1)
    );
}

#[test]
fn assignment_revisions_survive_a_return_to_the_same_relay() {
    let setup = fleet(&[]).0;
    enroll_evidence(&setup, 1);
    let session = create_session(&setup, evidence_request(), ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    registry::remove(setup.registry(), RelayId(1));
    enroll_evidence(&setup, 2);
    assert!(matches!(
        rehome(&setup, &tid(), session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(_)
    ));
    registry::remove(setup.registry(), RelayId(2));
    enroll_evidence(&setup, 1);
    assert!(matches!(
        rehome(&setup, &tid(), session, RelayId(2), vec![]),
        RehomeOutcome::NewTarget(_)
    ));
    let refs = session_refs(&setup, &tid(), session).unwrap();
    assert_eq!(refs.homes.get(&SlotId(0)), Some(&RelayId(1)));
    assert_eq!(refs.evidence_assignments.get(&SlotId(0)), Some(&3));
}

#[test]
fn exhausted_assignment_revision_rejects_before_any_membership_mutation() {
    let setup = fleet(&[]).0;
    enroll_evidence(&setup, 1);
    let session = create_session(&setup, evidence_request(), ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    setup
        .session_refs
        .lock()
        .get_mut(&(tid(), session))
        .unwrap()
        .evidence_assignments
        .insert(SlotId(1), u64::MAX);
    let before = session_refs(&setup, &tid(), session).unwrap();
    let descriptors = setup.descriptors().current_for(RelayId(1));
    registry::remove(setup.registry(), RelayId(1));
    enroll_evidence(&setup, 2);
    assert!(matches!(
        rehome(&setup, &tid(), session, RelayId(1), vec![]),
        RehomeOutcome::Unavailable
    ));
    assert_eq!(setup.serving_relays(&tid(), session), vec![RelayId(1)]);
    assert_eq!(session_refs(&setup, &tid(), session).unwrap(), before);
    assert_eq!(setup.descriptors().current_for(RelayId(1)), descriptors);
    assert!(setup.descriptors().current_for(RelayId(2)).is_empty());
    assert!(recorded_rehome(&setup, &tid(), session, RelayId(1)).is_none());
}
