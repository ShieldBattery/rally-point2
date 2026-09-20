//! Creating a session: relay assignment, token minting, the recorded serving
//! set, request validation, and session-id assignment.

use super::*;

#[test]
fn create_session_assigns_relays_and_mints_tokens() {
    let setup = two_relay_fleet();
    let resp = create_session(&setup, request(two_players()), ExpiresAt(u64::MAX))
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
fn the_session_ceiling_refuses_fresh_creates_and_frees_on_close() {
    let setup = two_relay_fleet().with_session_ceiling(Some(1));
    let game = |external_id: &str| SessionRequest {
        external_id: Some(external_id.to_owned()),
        ..request(two_players())
    };

    let first = create_session(&setup, game("game-1"), ExpiresAt(u64::MAX)).unwrap();

    // At the cap a fresh create is refused...
    let err = create_session(&setup, game("game-2"), ExpiresAt(u64::MAX)).unwrap_err();
    assert!(matches!(err, SessionSetupError::SessionCeilingReached));

    // ...but an idempotent retry of the live session still replays — it
    // mints nothing, so the cap must not fail an ordinary HTTP retry.
    let retry = create_session(&setup, game("game-1"), ExpiresAt(u64::MAX)).unwrap();
    assert!(retry.replayed);

    // Closing the live session frees the capacity.
    setup.forget_session_membership(&tid(), first.response.session);
    create_session(&setup, game("game-2"), ExpiresAt(u64::MAX)).unwrap();
}

#[test]
fn session_count_for_relay_counts_serving_memberships() {
    // Relay 2 is tagged `region-b` so the third phase below can also produce a
    // cross-relay session, without changing how the first two phases behave —
    // an unnamed-region roster still falls back to relay 1 regardless of relay
    // 2's tag.
    let setup = region_b_fleet();

    // No sessions yet: every relay serves zero.
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 0);
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 0);

    // Two single-relay sessions both home on relay 1 (the primary); relay 2
    // serves neither.
    let first = create_session(&setup, request(two_players()), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let second = create_session(&setup, request(two_players()), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_eq!(
        setup.session_count_for_relay(RelayId(1)),
        2,
        "relay 1 homes both sessions",
    );
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 0);

    // Closing one session's membership drops relay 1's count.
    setup.take_session_membership(&tid(), first.session);
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 1);
    setup.take_session_membership(&tid(), second.session);
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 0);

    // A session served by two relays counts once against each home, not just
    // the primary.
    create_session(
        &setup,
        request(two_players_slot_1_in_region_b()),
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    assert_eq!(setup.session_count_for_relay(RelayId(1)), 1);
    assert_eq!(setup.session_count_for_relay(RelayId(2)), 1);
}

#[test]
fn serving_relays_are_the_distinct_homes_not_every_enrolled_relay() {
    // With no player naming a region (and even with a second relay enrolled)
    // the session serves only the primary home — a serving relay always homes
    // at least one slot, so an unused relay is never in the set.
    let setup = two_relay_fleet();
    let resp = create_default_session(&setup);
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
}

#[test]
fn a_relay_with_no_assigned_slots_is_not_recorded_as_serving() {
    // Both slots name region-b, so relay 1 (untagged) wins none of them. It
    // must not be recorded as serving — a slotless serving relay would never
    // register a slot, never report `SessionClosed`, and the session's
    // lifecycle would never close.
    let setup = region_b_fleet();
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-b")),
            player_in_region(1, Some("region-b")),
        ],
    );

    // Both slots land on relay 2, so it is the home outright and no override
    // rides (every slot already homes on the home relay).
    assert_eq!(resp.home_relay.relay_id, RelayId(2));
    assert!(resp.slot_homes.is_empty());
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(2)],
        "the slotless relay 1 is not recorded as serving",
    );

    // The descriptor built for the sole serving relay ranks only itself in the
    // authority order — the unused relay never appears.
    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(2)).unwrap();
    assert_eq!(desc.authority_order, vec![RelayId(2)]);
    assert!(desc.peers.is_empty(), "the unused relay is not a mesh peer");
}

#[test]
fn issued_tokens_verify_on_the_relay() {
    let setup = two_relay_fleet();
    let resp = create_session(&setup, request(two_players()), ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    // Seed the relay registry with the tenant's verifying key.
    let (kid, pubkey) = tenant::verifying_key(&setup.tenants, &tid()).unwrap();
    let mut relay_registry = Registry::new();
    relay_registry.insert(kid, tid(), pubkey);

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
    let setup = SessionSetup::new(registry::RelayRegistry::new(), tenant_store());
    let req = request(two_players());
    let candidate = candidate_session_id(&setup);
    let result = create_session(&setup, req.clone(), ExpiresAt(u64::MAX));
    assert_eq!(result.unwrap_err(), SessionSetupError::NoRelaysAvailable);
    assert_eq!(candidate_session_id(&setup), candidate);

    enroll_fleet(setup.registry(), &[(1, 14900, None, false)]);
    let created = create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap();
    assert_eq!(
        created.response.session, candidate,
        "the next successful create receives the id the failed placement peeked",
    );
}

#[test]
fn unenrolled_tenant_fails() {
    let setup = SessionSetup::new(registry::RelayRegistry::new(), tenant::TenantStore::new());
    enroll_fleet(setup.registry(), &[(1, 14900, None, false)]);
    let result = create_session(
        &setup,
        SessionRequest {
            tenant: TenantId("not-enrolled".to_owned()),
            ..request(two_players())
        },
        ExpiresAt(u64::MAX),
    );
    assert_eq!(
        result.unwrap_err(),
        SessionSetupError::TenantNotFound(TenantId("not-enrolled".to_owned()))
    );
}

#[test]
fn slot_11_is_accepted_and_slot_12_is_rejected() {
    // The survivor of a merge across every `validate_request` rejection: the
    // boundary that gives the test its name (BW supports 12 network
    // participants -- 8 players + 4 observers -- so slots 0..=11 are valid and
    // 12 is out of range), plus a table over every other way a request is
    // refused before placement ever runs.
    let setup = two_relay_fleet();
    let player = |slot: u8| PlayerHandoff {
        slot: SlotId(slot),
        client_pubkey: ClientPublicKey([slot; 32]),
        external_ref: None,
        observer: false,
        region: None,
    };

    let resp = create_session(
        &setup,
        request((0..=11).map(player).collect()),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(resp.tokens.len(), 12);
    assert_eq!(
        create_session(&setup, request(vec![player(12)]), ExpiresAt(u64::MAX)).unwrap_err(),
        SessionSetupError::SlotOutOfRange(12),
    );

    type ValidationCase = (&'static str, SessionRequest, SessionSetupError);
    let cases: Vec<ValidationCase> = vec![
        (
            "no players at all",
            request(vec![]),
            SessionSetupError::NoPlayers,
        ),
        (
            "two players naming the same slot",
            request(vec![player(0), player(1), player(0)]),
            SessionSetupError::DuplicateSlot(0),
        ),
        (
            "an external_id past the length cap",
            SessionRequest {
                external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
                ..request(two_players())
            },
            SessionSetupError::ExternalIdTooLong,
        ),
        (
            "a player's external_ref past the length cap",
            request(vec![
                player(0),
                PlayerHandoff {
                    external_ref: Some("y".repeat(MAX_EXTERNAL_STRING_LEN + 1)),
                    ..player(1)
                },
            ]),
            SessionSetupError::ExternalRefTooLong(1),
        ),
    ];
    for (label, req, expected) in cases {
        assert_eq!(
            create_session(&setup, req, ExpiresAt(u64::MAX)).unwrap_err(),
            expected,
            "{label} must be rejected",
        );
    }

    // Exactly at the external_id cap is fine -- only *past* it is rejected.
    assert!(
        create_session(
            &setup,
            SessionRequest {
                external_id: Some("x".repeat(MAX_EXTERNAL_STRING_LEN)),
                ..request(two_players())
            },
            ExpiresAt(u64::MAX),
        )
        .is_ok(),
        "exactly the cap is accepted",
    );
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

    let before = two_relay_fleet();
    let req = request(two_players());
    let old = create_session(&before, req.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    let after = two_relay_fleet();
    let new = create_session(&after, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert!(
        new.session.0 >= old.session.0,
        "a fresh coordinator's ids never start below the old one's",
    );
}
