//! Finalized-drop build classes: placement keeps a session inside one capability
//! cohort, the feature switch only decides whether the handshake turns on, and
//! neither a re-home nor an eviction may move a session across the boundary.

use super::*;

/// Placement is capability-homogeneous and prefers the capable cohort: a
/// mixed fleet places the session only on capability-advertising relays,
/// and the session's descriptors enable finalized drops.
#[test]
fn placement_prefers_the_capable_cohort_and_enables_finalized_drops() {
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900); // incapable
    enroll_capable_relay(&reg, 2, 14901);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);

    let resp = create_default_session(&setup);
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(2)],
        "the session lands wholly in the capable cohort, never mixed",
    );
    let staged = setup.descriptors().current_for(RelayId(2));
    assert_eq!(staged.len(), 1);
    assert!(
        staged[0].finalized_drops,
        "an all-capable session enables finalized drops",
    );
}

/// A fleet with no capable relay places normally with the feature off —
/// and the flag is immutable thereafter (rebuilds read the stored value).
#[test]
fn an_incapable_cohort_creates_the_session_with_finalized_drops_off() {
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    for relay_id in setup.serving_relays(&tid(), resp.session) {
        let staged = setup.descriptors().current_for(relay_id);
        assert!(!staged[0].finalized_drops);
    }
}

/// With the finalized-drops feature switch OFF, placement still keeps
/// build-class cohorts apart (a mixed session hands different clients
/// different leave schedules regardless of the feature), but the session
/// runs without the handshake — and a rehome still stays in-cohort,
/// keyed on the recorded build class rather than the feature flag.
#[test]
fn the_feature_switch_off_keeps_cohorts_but_disables_the_handshake() {
    let reg = registry::new_registry();
    enroll_capable_relay(&reg, 1, 14900);
    enroll_relay(&reg, 2, 14901);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants).with_finalized_drops(false);
    let resp = create_default_session(&setup);

    let staged = setup.descriptors().current_for(RelayId(1));
    assert_eq!(
        staged.len(),
        1,
        "the capable cohort is still preferred with the feature off",
    );
    assert!(
        !staged[0].finalized_drops,
        "the switched-off feature never enables the handshake",
    );

    // The capable home dies with only the incapable relay 2 live: the
    // rehome must NOT cross the build-class boundary even though the
    // session's finalized_drops flag is false.
    registry::remove(setup.registry(), RelayId(1));
    assert!(
        matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
        ),
        "the build-class cohort binds the rehome even with the feature off",
    );
    enroll_capable_relay(setup.registry(), 4, 14903);
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget once an in-cohort replacement exists");
    };
    assert_eq!(endpoint.relay_id, RelayId(4));
    assert!(!setup.descriptors().current_for(RelayId(4))[0].finalized_drops);
}

/// A rehome replacement must come from the session's own capability
/// cohort: a capable session with only incapable relays left is
/// Unavailable (the session ends) rather than silently mixed, and a
/// capable replacement is taken when one exists.
#[test]
fn a_rehome_stays_within_the_sessions_capability_cohort() {
    let reg = registry::new_registry();
    enroll_capable_relay(&reg, 1, 14900);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = create_default_session(&setup);
    assert!(
        setup.descriptors().current_for(RelayId(1))[0].finalized_drops,
        "a single capable relay creates a finalized-drops session",
    );

    // The capable home dies; the only live relay is incapable.
    registry::remove(setup.registry(), RelayId(1));
    enroll_relay(setup.registry(), 3, 14902);
    assert!(
        matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
        ),
        "no cross-cohort replacement: the session ends instead of mixing",
    );

    // A capable relay arrives: the rehome takes it.
    enroll_capable_relay(setup.registry(), 4, 14903);
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget once a capable replacement exists");
    };
    assert_eq!(endpoint.relay_id, RelayId(4));
    assert!(
        setup.descriptors().current_for(RelayId(4))[0].finalized_drops,
        "the resumed descriptor keeps the immutable flag",
    );
}

/// A relay downgraded mid-flight (re-enrolled without the capability,
/// same cert) is evicted from its finalized-drops sessions: the ordinary
/// rehome would answer Stay (it is alive and its cert still matches), so
/// the eviction path must not — and, with the evictee marked draining, it
/// must land on an in-cohort replacement.
#[test]
fn a_downgraded_relay_is_evicted_from_its_finalized_drops_sessions() {
    let reg = registry::new_registry();
    enroll_capable_relay(&reg, 1, 14900);
    enroll_capable_relay(&reg, 2, 14901);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = create_default_session(&setup);
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
    assert!(setup.descriptors().current_for(RelayId(1))[0].finalized_drops);

    // The downgrade: same id, same cert, no capability.
    let generation = registry::enroll(
        setup.registry(),
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            fake_cert(1),
        ),
    );
    assert!(
        matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Stay,
        ),
        "the ordinary rehome sees a live relay with a matching cert",
    );

    // The enroll-time eviction: draining first (so the pick can never
    // choose the evictee), then the stay-less rehome.
    assert!(registry::mark_draining(
        setup.registry(),
        RelayId(1),
        generation,
    ));
    let RehomeOutcome::NewTarget(endpoint) =
        rehome_evicting(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("the eviction moves the session");
    };
    assert_eq!(endpoint.relay_id, RelayId(2), "an in-cohort replacement");
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);
    assert!(
        setup.descriptors().current_for(RelayId(2))[0].finalized_drops,
        "the moved session keeps its immutable flag",
    );
}

#[test]
fn rehome_never_picks_a_serving_member_across_the_capability_boundary() {
    // The session was created without finalized drops on relays 1 and 2;
    // relay 2 then re-enrolled advertising the capability (an in-place
    // upgrade). When relay 1 dies, the already-serving relay 2 is the
    // preferred candidate by order — but it now sits on the wrong side of
    // the capability boundary, so the rehome must skip it and pick the
    // in-cohort idle relay 3 instead of mixing the classes placement kept
    // apart.
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    enroll_relay_in_region(&reg, 2, 14901, Some("region-b"));
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // Relay 2 upgrades in place; relay 3 is idle and still in-cohort.
    enroll_capable_relay(setup.registry(), 2, 14901);
    enroll_relay(setup.registry(), 3, 14902);
    registry::remove(setup.registry(), RelayId(1));

    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        endpoint.relay_id,
        RelayId(3),
        "the upgraded serving member is skipped for an in-cohort replacement",
    );
}
