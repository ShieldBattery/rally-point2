use super::*;

#[test]
fn retired_assignment_is_exact_persisted_and_removed_on_close() {
    let setup = two_relay_fleet();
    registry::note_boot_id(setup.registry(), RelayId(1), Some(11));
    registry::note_boot_id(setup.registry(), RelayId(2), Some(22));
    let response = create_default_session(&setup);
    let session = response.session;
    assert!(!setup.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
    // The same relay id can restart before rehome. Retirement must retain the
    // assignment's original process, not whichever process most recently enrolled.
    registry::note_boot_id(setup.registry(), RelayId(1), Some(99));
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        rehome(&setup, &tid(), session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(_)
    ));
    assert!(setup.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
    for (relay, boot, slot, revision) in [
        (RelayId(2), 11, SlotId(0), 1),
        (RelayId(1), 99, SlotId(0), 1),
        (RelayId(1), 11, SlotId(9), 1),
        (RelayId(1), 11, SlotId(0), 2),
    ] {
        assert!(!setup.evidence_history_assignment(relay, boot, &tid(), session, slot, revision));
    }
    assert!(!setup.evidence_history_assignment(
        RelayId(1),
        11,
        &TenantId("other".into()),
        session,
        SlotId(0),
        1
    ));
    assert_eq!(
        setup.evidence_assignment(RelayId(1), &tid(), session, SlotId(0)),
        None
    );
    assert_eq!(
        setup.evidence_assignment(RelayId(2), &tid(), session, SlotId(0)),
        Some(2)
    );
    let records = {
        let guard = setup.lock_assignment();
        setup.export_records(&guard)
    };
    let restored = two_relay_fleet();
    restored.restore_records(
        records
            .into_iter()
            .map(|(key, record)| {
                (
                    key,
                    serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap(),
                )
            })
            .collect(),
    );
    assert!(restored.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
    assert_eq!(
        session_refs(&restored, &tid(), session)
            .unwrap()
            .evidence_home_boots
            .get(&SlotId(0)),
        Some(&22)
    );
    restored.retire_session(&tid(), session);
    assert!(!restored.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
}

#[test]
fn legacy_assignments_without_process_identity_cannot_authorize_history() {
    let setup = two_relay_fleet();
    let session = create_default_session(&setup).session;
    registry::note_boot_id(setup.registry(), RelayId(1), Some(11));
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        rehome(&setup, &tid(), session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(_)
    ));
    assert!(!setup.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
    let refs: SessionRefs = serde_json::from_str("{}").unwrap();
    assert!(refs.evidence_home_boots.is_empty());
    assert!(refs.retired_evidence_assignments.is_empty());
}

#[test]
fn authorization_checks_expiry_even_without_another_rehome() {
    let setup = two_relay_fleet();
    registry::note_boot_id(setup.registry(), RelayId(1), Some(11));
    let session = create_default_session(&setup).session;
    let mut refs = setup.session_refs.lock();
    refs.get_mut(&(tid(), session))
        .unwrap()
        .retire_evidence_assignments(RelayId(1), 0);
    drop(refs);
    assert!(!setup.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
}

#[test]
fn same_id_restart_cannot_borrow_either_current_or_retired_process_authority() {
    let setup = two_relay_fleet();
    registry::note_boot_id(setup.registry(), RelayId(1), Some(11));
    let session = create_default_session(&setup).session;
    assert!(setup.current_evidence_history_assignment(
        RelayId(1),
        11,
        &tid(),
        session,
        SlotId(0),
        1
    ));
    registry::enroll(setup.registry(), hello_with_cert(1, 14900, vec![0xEE; 4]));
    registry::note_boot_id(setup.registry(), RelayId(1), Some(99));
    assert!(!setup.current_evidence_history_assignment(
        RelayId(1),
        99,
        &tid(),
        session,
        SlotId(0),
        1
    ));
    assert!(
        matches!(rehome(&setup,&tid(),session,RelayId(1),vec![]),RehomeOutcome::NewTarget(endpoint) if endpoint.relay_id == RelayId(1))
    );
    assert!(setup.evidence_history_assignment(RelayId(1), 11, &tid(), session, SlotId(0), 1));
    assert!(!setup.evidence_history_assignment(RelayId(1), 99, &tid(), session, SlotId(0), 1));
    assert!(setup.current_evidence_history_assignment(
        RelayId(1),
        99,
        &tid(),
        session,
        SlotId(0),
        2
    ));
    assert!(!setup.current_evidence_history_assignment(
        RelayId(1),
        11,
        &tid(),
        session,
        SlotId(0),
        2
    ));
}
