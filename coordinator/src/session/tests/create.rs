//! Creating a session: relay assignment, token minting, the recorded serving
//! set, request validation, and session-id assignment.

use super::*;

#[test]
fn create_session_assigns_relays_and_mints_tokens() {
    let setup = setup_with_two_relays_and_tenant();
    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };

    let resp = create_session(&setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    // Home is the lowest-id relay, carrying the cert it reported at enrollment
    // so clients can pin it. With no player naming a region every slot falls
    // back there, so the response carries no per-slot overrides even with a
    // second relay enrolled.
    assert_eq!(resp.home_relay.relay_id, RelayId(1));
    assert_eq!(resp.home_relay.cert_der, fake_cert(1));
    assert!(
        resp.slot_homes.is_empty(),
        "a session with no per-slot regions homes every slot on the primary",
    );

    // One token per player.
    assert_eq!(resp.tokens.len(), 2);
    assert_eq!(resp.tokens[0].slot, SlotId(0));
    assert_eq!(resp.tokens[1].slot, SlotId(1));

    // Bounds come from the tenant's policy.
    assert_eq!(resp.bounds, BufferBounds::new(1, 6).unwrap());
}

#[test]
fn a_latency_estimate_change_is_a_create_mismatch_not_a_replay() {
    let setup = setup_with_two_relays_and_tenant();
    let request = |latency: Option<u32>| SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: latency,
    };

    create_session(&setup, request(Some(40)), ExpiresAt(u64::MAX)).unwrap();

    // Same roster + same estimate: an honest retry, replayed.
    let retry = create_session(&setup, request(Some(40)), ExpiresAt(u64::MAX)).unwrap();
    assert!(retry.replayed);

    // Same roster, different estimate: a different logical create — the
    // cached response would bind the wrong initial-buffer input to the
    // session, so it is refused rather than replayed.
    let err = create_session(&setup, request(Some(90)), ExpiresAt(u64::MAX)).unwrap_err();
    assert!(matches!(err, SessionSetupError::IdempotentCreateMismatch));
}

#[test]
fn the_session_ceiling_refuses_fresh_creates_and_frees_on_close() {
    let setup = setup_with_two_relays_and_tenant().with_session_ceiling(Some(1));
    let tenant = TenantId("sb-test".to_owned());
    let request = |external_id: &str| SessionRequest {
        tenant: tenant.clone(),
        players: two_players(),
        external_id: Some(external_id.to_owned()),
        latency_estimate_ms: None,
    };

    let first = create_session(&setup, request("game-1"), ExpiresAt(u64::MAX)).unwrap();

    // At the cap a fresh create is refused...
    let err = create_session(&setup, request("game-2"), ExpiresAt(u64::MAX)).unwrap_err();
    assert!(matches!(err, SessionSetupError::SessionCeilingReached));

    // ...but an idempotent retry of the live session still replays — it
    // mints nothing, so the cap must not fail an ordinary HTTP retry.
    let retry = create_session(&setup, request("game-1"), ExpiresAt(u64::MAX)).unwrap();
    assert!(retry.replayed);

    // Closing the live session frees the capacity.
    setup.forget_session_membership(&tenant, first.response.session);
    create_session(&setup, request("game-2"), ExpiresAt(u64::MAX)).unwrap();
}

#[test]
fn session_count_for_relay_counts_serving_memberships() {
    let setup = setup_with_two_relays_and_tenant();
    let tenant = TenantId("sb-test".to_owned());

    // No sessions yet: every relay serves zero.
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 0);
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 0);

    // Two single-relay sessions both home on relay 1 (the primary); relay 2
    // serves neither.
    let first = create_session(
        &setup,
        SessionRequest {
            tenant: tenant.clone(),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    let second = create_session(
        &setup,
        SessionRequest {
            tenant: tenant.clone(),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(
        setup.session_count_for_relay(RelayId(1)),
        2,
        "relay 1 homes both sessions",
    );
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 0);

    // Closing one session's membership drops relay 1's count.
    setup.take_session_membership(&tenant, first.session);
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 1);
    setup.take_session_membership(&tenant, second.session);
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 0);
}

#[test]
fn session_count_for_relay_counts_a_cross_relay_session_for_each_home() {
    // A session served by two relays counts once against each.
    let setup = setup_with_two_relays_region_b_and_tenant();
    create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 1);
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 1);
}

#[test]
fn region_override_preserves_each_slots_assigned_home() {
    // The slot naming region-b homes on the relay tagged for it, while the
    // other falls back to relay 1. Which equally populated relay is represented
    // as the primary rotates, but the per-slot assignment does not.
    let setup = setup_with_two_relays_region_b_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(1));
    assert_eq!(response_home_for_slot(&resp, SlotId(1)), RelayId(2));
    assert_eq!(resp.slot_homes.len(), 1, "one slot differs from primary");
    assert_eq!(
        response_endpoint_for_relay(&resp, RelayId(1)).cert_der,
        fake_cert(1),
    );
    assert_eq!(
        response_endpoint_for_relay(&resp, RelayId(2)).cert_der,
        fake_cert(2),
    );

    // The session serves exactly the distinct home relays of its slots.
    let serving = setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session);
    assert_eq!(
        serving
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([RelayId(1), RelayId(2)]),
    );
}

#[test]
fn serving_relays_are_the_distinct_homes_not_every_enrolled_relay() {
    // With no player naming a region (and even with a second relay enrolled)
    // the session serves only the primary home — a serving relay always homes
    // at least one slot, so an unused relay is never in the set.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(
        setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session),
        vec![RelayId(1)],
    );
}

#[test]
fn a_relay_with_no_assigned_slots_is_not_recorded_as_serving() {
    // Both slots name region-b, so relay 1 (untagged) wins none of them. It
    // must not be recorded as serving — a slotless serving relay would never
    // register a slot, never report `SessionClosed`, and the session's
    // lifecycle would never close.
    let setup = setup_with_two_relays_region_b_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: Some(RegionId("region-b".to_owned())),
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    region: Some(RegionId("region-b".to_owned())),
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // Both slots land on relay 2, so it is the home outright and no override
    // rides (every slot already homes on the home relay).
    assert_eq!(resp.home_relay.relay_id, RelayId(2));
    assert!(resp.slot_homes.is_empty());
    assert_eq!(
        setup.serving_relays(&TenantId("sb-test".to_owned()), resp.session),
        vec![RelayId(2)],
        "the slotless relay 1 is not recorded as serving",
    );

    // The descriptor built for the sole serving relay ranks only itself in the
    // authority order — the unused relay never appears.
    let desc = descriptor_for(
        &setup,
        &TenantId("sb-test".to_owned()),
        resp.session,
        RelayId(2),
    )
    .unwrap();
    assert_eq!(desc.authority_order, vec![RelayId(2)]);
    assert!(desc.peers.is_empty(), "the unused relay is not a mesh peer");
}

#[test]
fn issued_tokens_verify_on_the_relay() {
    let setup = setup_with_two_relays_and_tenant();
    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let resp = create_session(&setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    // Seed the relay registry with the tenant's verifying key.
    let (kid, pubkey) =
        tenant::verifying_key(&setup.tenants, &TenantId("sb-test".to_owned())).unwrap();
    let mut relay_registry = Registry::new();
    relay_registry.insert(kid, TenantId("sb-test".to_owned()), pubkey);

    // Each token the coordinator minted must verify on the relay.
    for player_token in &resp.tokens {
        let signed = SignedToken::decode(&player_token.token).unwrap();
        let authorized =
            rally_point_relay::auth::verify_token(&relay_registry, &signed, u64::MAX - 1).unwrap();
        assert_eq!(authorized.session, resp.session);
        assert_eq!(authorized.slot, player_token.slot);
    }
}

#[test]
fn no_relays_available_fails_without_consuming_the_session_id() {
    let setup = SessionSetup::new(registry::new_registry(), tenant::new_store());
    let request = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let candidate = candidate_session_id(&setup);
    let result = create_session(&setup, request.clone(), ExpiresAt(u64::MAX));
    assert_eq!(result.unwrap_err(), SessionSetupError::NoRelaysAvailable);
    assert_eq!(candidate_session_id(&setup), candidate);

    enroll_relay(setup.registry(), 1, 14900);
    tenant::enroll(
        setup.tenants(),
        KeyId("test-key-1".to_owned()),
        request.tenant.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let created = create_session(&setup, request, ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(
        created.response.session, candidate,
        "the next successful create receives the id the failed placement peeked",
    );
}

#[test]
fn unenrolled_tenant_fails() {
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    let setup = SessionSetup::new(reg, tenant::new_store());
    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("not-enrolled".to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(
        result.unwrap_err(),
        SessionSetupError::TenantNotFound(TenantId("not-enrolled".to_owned()))
    );
}

#[test]
fn empty_players_fails() {
    let setup = setup_with_two_relays_and_tenant();
    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(result.unwrap_err(), SessionSetupError::NoPlayers);
}

#[test]
fn slot_11_is_accepted_and_slot_12_is_rejected() {
    // BW supports 12 network participants (8 players + 4 observers), so
    // slots 0..=11 are valid and 12 is out of range.
    let setup = setup_with_two_relays_and_tenant();
    let player = |slot: u8| PlayerHandoff {
        slot: SlotId(slot),
        client_pubkey: ClientPublicKey([slot; 32]),
        external_ref: None,
        observer: false,
        region: None,
    };

    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: (0..=11).map(player).collect(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(resp.tokens.len(), 12);

    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![player(12)],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(result.unwrap_err(), SessionSetupError::SlotOutOfRange(12));
}

#[test]
fn two_players_naming_the_same_slot_is_rejected() {
    let setup = setup_with_two_relays_and_tenant();
    let player = |slot: u8| PlayerHandoff {
        slot: SlotId(slot),
        client_pubkey: ClientPublicKey([slot; 32]),
        external_ref: None,
        observer: false,
        region: None,
    };

    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![player(0), player(1), player(0)],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(result.unwrap_err(), SessionSetupError::DuplicateSlot(0));
}

#[test]
fn an_oversized_external_id_is_rejected() {
    let setup = setup_with_two_relays_and_tenant();
    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(result.unwrap_err(), SessionSetupError::ExternalIdTooLong);

    // Exactly at the cap is fine.
    let ok = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
            external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN)),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert!(ok.is_ok());
}

#[test]
fn an_oversized_external_ref_is_rejected() {
    let setup = setup_with_two_relays_and_tenant();
    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([1; 32]),
                    external_ref: Some("y".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
                    observer: false,
                    region: None,
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(
        result.unwrap_err(),
        SessionSetupError::ExternalRefTooLong(1)
    );
}

#[test]
fn session_ids_are_unique_per_session() {
    let setup = setup_with_two_relays_and_tenant();
    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let r1 = create_session(&setup, req.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let r2 = create_session(&setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_ne!(r1.session, r2.session);
}

#[test]
fn a_restarted_coordinator_does_not_reuse_session_ids() {
    // Relays keep per-session state through a coordinator outage, so ids
    // from different coordinator lifetimes must be disjoint. The counter
    // is seeded from the wall clock in microseconds: a restarted process
    // seeds later than any id the previous lifetime minted (a lifetime
    // would have to mint a session per microsecond of its whole runtime
    // to catch up to the next seed). Guard the seed's scale — a
    // regression to counting from 1 is the failure this test exists for.
    assert!(
        first_session_id() > 1_600_000_000_000_000,
        "the seed is wall-clock microseconds, not a small counter",
    );

    let before = setup_with_two_relays_and_tenant();
    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let old = create_session(&before, req.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    let after = setup_with_two_relays_and_tenant();
    let new = create_session(&after, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert!(
        new.session.0 >= old.session.0,
        "a fresh coordinator's ids never start below the old one's",
    );
}
