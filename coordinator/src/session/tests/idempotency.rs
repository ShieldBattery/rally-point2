//! Create idempotency: replaying a duplicate create for a live `external_id`,
//! refusing one that reuses the id for a different roster, and every field a
//! roster can differ in that must be treated as that kind of conflict.

use super::*;

#[test]
fn a_duplicate_create_mints_no_new_session() {
    let setup = two_relay_fleet();
    let game = SessionRequest {
        external_id: Some("game-1".to_owned()),
        ..request(two_players())
    };
    let first = create_session(&setup, game.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let _ = create_session(&setup, game, ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    // An unrelated fresh create still gets the very next id in sequence --
    // proof the duplicate above never advanced the session-id counter, so
    // no session was actually minted for it.
    let unrelated = create_default_session(&setup);
    assert_eq!(
        unrelated.session.0,
        first.session.0 + 1,
        "the duplicate consumed no session id of its own",
    );
}

#[test]
fn no_external_id_is_never_idempotent() {
    // Neither "no external_id at all" nor "a different external_id" is a
    // replay: both mint a genuinely fresh session with fresh tokens.
    let setup = two_relay_fleet();
    let game = |external_id: Option<&str>| SessionRequest {
        external_id: external_id.map(|s| s.to_owned()),
        ..request(two_players())
    };
    for (first_id, second_id) in [(None, None), (Some("game-1"), Some("game-2"))] {
        let first = create_session(&setup, game(first_id), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        let second = create_session(&setup, game(second_id), ExpiresAt(u64::MAX))
            .unwrap()
            .response;
        assert_ne!(
            first.session, second.session,
            "external_id {first_id:?} -> {second_id:?} must not replay",
        );
        assert_ne!(first.tokens, second.tokens);
    }
}

#[test]
fn a_different_tenants_matching_external_id_is_not_a_duplicate() {
    // Tenant-scoped key: two tenants using the same external_id (plausible
    // if each mints its own game ids independently) must never collide.
    let setup = two_relay_fleet();
    let other_tenant = TenantId("sb-other".to_owned());
    tenant::enroll(
        setup.tenants(),
        KeyId("test-key-2".to_owned()),
        other_tenant.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();

    let game = |tenant: TenantId| SessionRequest {
        tenant,
        external_id: Some("shared-id".to_owned()),
        ..request(two_players())
    };
    let first = create_session(&setup, game(tid()), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let second = create_session(&setup, game(other_tenant), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_ne!(first.session, second.session);
}

#[test]
fn a_closed_sessions_external_id_can_be_reused() {
    let setup = two_relay_fleet();
    let game = SessionRequest {
        external_id: Some("game-1".to_owned()),
        ..request(two_players())
    };
    let first = create_session(&setup, game.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    // The same retirement path a full close uses: membership (and, with
    // it, the idempotency entry) is taken.
    setup.forget_session_membership(&tid(), first.session);
    assert!(
        !setup
            .create_idempotency
            .lock()
            .contains_key(&(tid(), "game-1".to_owned())),
        "retirement must remove the map entry outright, not just leave a stale one \
         that happens to fail the liveness check -- otherwise a tenant that never \
         reuses an external_id leaks one entry per closed session forever",
    );

    let second = create_session(&setup, game, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_ne!(
        second.session, first.session,
        "the external_id mints a genuinely new session once the old one is gone",
    );
    assert_ne!(second.tokens, first.tokens);

    // The rematch's own external_id is now the one an idempotent retry
    // would replay -- the entry was replaced, not just vacated.
    let retried = create_session(
        &setup,
        SessionRequest {
            external_id: Some("game-1".to_owned()),
            ..request(two_players())
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(retried, second);
}

#[test]
fn a_matching_replay_reports_replayed_while_the_first_create_does_not() {
    let setup = two_relay_fleet();
    let game = SessionRequest {
        external_id: Some("game-1".to_owned()),
        ..request(two_players())
    };
    let first = create_session(&setup, game.clone(), ExpiresAt(u64::MAX)).unwrap();
    assert!(
        !first.replayed,
        "the create that actually minted the session is a fresh mint, not a replay",
    );
    let second = create_session(&setup, game, ExpiresAt(u64::MAX)).unwrap();
    assert!(
        second.replayed,
        "a retry with the identical roster is served from the idempotency cache",
    );
    assert_eq!(
        first.response, second.response,
        "the replay hands back the exact original response",
    );
}

#[test]
fn a_replay_matches_regardless_of_player_order() {
    // The fingerprint sorts players by slot, so a retry that lists the same
    // roster in a different order is still an idempotent replay, not a
    // conflict -- request order carries no meaning.
    let setup = two_relay_fleet();
    let players = two_players();
    let mut reversed = players.clone();
    reversed.reverse();

    let first = create_session(
        &setup,
        SessionRequest {
            external_id: Some("game-1".to_owned()),
            ..request(players)
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    let second = create_session(
        &setup,
        SessionRequest {
            external_id: Some("game-1".to_owned()),
            ..request(reversed)
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    assert!(
        second.replayed,
        "the same roster in a different order is the same request, so it replays",
    );
    assert_eq!(first.response, second.response);
}

#[test]
fn a_conflicting_create_reusing_a_live_external_id_for_a_different_roster_is_refused() {
    let setup = two_relay_fleet();
    let original = SessionRequest {
        external_id: Some("game-1".to_owned()),
        ..request(two_players())
    };
    let first = create_session(&setup, original.clone(), ExpiresAt(u64::MAX)).unwrap();

    // The same external_id, still bound to the live session, but a different
    // roster: slot 1's client pubkey differs, so the tokens the first create
    // minted authorize different clients than this roster asks for. Handing
    // them back, or overwriting the live session's accounting, would both be
    // wrong -- so the create is refused.
    let mut conflicting = original.clone();
    conflicting.players[1].client_pubkey = ClientPublicKey([0xCC; 32]);
    let err = create_session(&setup, conflicting, ExpiresAt(u64::MAX)).unwrap_err();
    assert_eq!(err, SessionSetupError::IdempotentCreateMismatch);

    // The refused conflict minted nothing: an unrelated fresh create still
    // gets the very next id in sequence, so the conflict advanced no counter.
    let unrelated = create_default_session(&setup);
    assert_eq!(
        unrelated.session.0,
        first.response.session.0 + 1,
        "the refused conflict consumed no session id of its own",
    );

    // It also left the cached entry untouched: a retry with the ORIGINAL
    // roster still replays the first response.
    let replay = create_session(&setup, original, ExpiresAt(u64::MAX)).unwrap();
    assert!(
        replay.replayed,
        "the conflict must not have evicted or overwritten the original cache entry",
    );
    assert_eq!(replay.response, first.response);
}

#[test]
fn each_fingerprint_field_change_alone_is_refused_as_a_create_mismatch() {
    // Table-driven over every field `CreateFingerprint` folds in besides the
    // (tenant, external_id) key itself (gate.rs): flipping any one of them
    // alone must turn a would-be replay into an `IdempotentCreateMismatch`,
    // and must leave the cached entry serving the original roster's replays
    // untouched -- never evicted, overwritten, or silently accepted.
    let setup = two_relay_fleet();
    let base = || SessionRequest {
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: Some(40),
        ..request(vec![
            PlayerHandoff {
                external_ref: Some("ref-a".to_owned()),
                ..player(0)
            },
            player(1),
        ])
    };
    let original = create_session(&setup, base(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;

    type FingerprintCase = (&'static str, fn(&mut SessionRequest));
    let cases: Vec<FingerprintCase> = vec![
        // A differing client pubkey mints a non-interchangeable token for the
        // slot; handing back the cached one would authorize the wrong client.
        ("client pubkey", |r| {
            r.players[0].client_pubkey = ClientPublicKey([0xEE; 32]);
        }),
        // The observer flag shapes recorded state (the session's observer set
        // and its lifecycle player/observer split) even though it alters no
        // token.
        ("observer flag", |r| {
            r.players[1].observer = true;
        }),
        // Region selects a slot's home relay, so the same external_id
        // retried with a different per-slot region is a genuine roster
        // mismatch, not a replay.
        ("player region", |r| {
            r.players[1].region = Some(region("region-b"));
        }),
        // external_ref is stored per slot and echoed into departure/result
        // webhooks, so replaying the first roster's ref for a different
        // roster would mislabel the player.
        ("external_ref", |r| {
            r.players[0].external_ref = Some("ref-changed".to_owned());
        }),
        // latency_estimate_ms is recorded into the session's correlation
        // state and sizes the initial buffer at the authority relay, so
        // replaying a cached response for a different estimate would bind
        // the wrong depth input to the session.
        ("latency_estimate_ms", |r| {
            r.latency_estimate_ms = Some(90);
        }),
    ];

    for (label, mutate) in cases {
        let mut changed = base();
        mutate(&mut changed);
        assert_eq!(
            create_session(&setup, changed, ExpiresAt(u64::MAX)).unwrap_err(),
            SessionSetupError::IdempotentCreateMismatch,
            "{label} alone must be refused as a mismatch",
        );

        // The conflict must not have evicted or overwritten the cached
        // entry: the original roster still replays the exact first response.
        let replay = create_session(&setup, base(), ExpiresAt(u64::MAX)).unwrap();
        assert!(
            replay.replayed,
            "{label}: a conflict must leave the cache serving replays",
        );
        assert_eq!(replay.response, original);
    }
}
