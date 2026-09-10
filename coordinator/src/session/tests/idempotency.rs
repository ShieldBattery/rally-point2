//! Create idempotency: replaying a duplicate create for a live `external_id`,
//! and refusing one that reuses the id for a different roster.

use super::*;

#[test]
fn a_duplicate_create_within_the_window_replays_the_original_response() {
    let setup = setup_with_two_relays_and_tenant();
    let request = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let second = create_session(&setup, request, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_eq!(
        first, second,
        "a retried create for the same (tenant, external_id) gets the exact original response back",
    );
}

#[test]
fn a_duplicate_create_mints_no_new_session() {
    let setup = setup_with_two_relays_and_tenant();
    let request = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let _ = create_session(&setup, request, ExpiresAt(u64::MAX))
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
fn a_different_external_id_creates_a_genuinely_fresh_session() {
    let setup = setup_with_two_relays_and_tenant();
    let first = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    let second = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-2".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_ne!(first.session, second.session);
    assert_ne!(first.tokens, second.tokens);
}

#[test]
fn a_different_tenants_matching_external_id_is_not_a_duplicate() {
    // Tenant-scoped key: two tenants using the same external_id (plausible
    // if each mints its own game ids independently) must never collide.
    let setup = setup_with_two_relays_and_tenant();
    let other_tenant = TenantId("sb-other".to_owned());
    tenant::enroll(
        setup.tenants(),
        KeyId("test-key-2".to_owned()),
        other_tenant.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();

    let first = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("shared-id".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    let second = create_session(
        &setup,
        SessionRequest {
            tenant: other_tenant,
            players: two_players(),
            external_id: Some("shared-id".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_ne!(first.session, second.session);
}

#[test]
fn a_closed_sessions_external_id_can_be_reused() {
    let setup = setup_with_two_relays_and_tenant();
    let request = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
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

    let second = create_session(&setup, request, ExpiresAt(u64::MAX))
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
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(retried, second);
}

#[test]
fn no_external_id_is_never_idempotent() {
    let setup = setup_with_two_relays_and_tenant();
    let request = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    let second = create_session(&setup, request, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_ne!(
        first.session, second.session,
        "a request naming no external_id is never replayed, even back to back",
    );
}

#[test]
fn a_matching_replay_reports_replayed_while_the_first_create_does_not() {
    let setup = setup_with_two_relays_and_tenant();
    let request = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, request.clone(), ExpiresAt(u64::MAX)).unwrap();
    assert!(
        !first.replayed,
        "the create that actually minted the session is a fresh mint, not a replay",
    );
    let second = create_session(&setup, request, ExpiresAt(u64::MAX)).unwrap();
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
    let setup = setup_with_two_relays_and_tenant();
    let players = two_players();
    let mut reversed = players.clone();
    reversed.reverse();

    let first = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players,
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    let second = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: reversed,
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
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
    let setup = setup_with_two_relays_and_tenant();
    let original = SessionRequest {
        tenant: tid(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let first = create_session(&setup, original.clone(), ExpiresAt(u64::MAX)).unwrap();

    // The same external_id, still bound to the live session, but a different
    // roster: slot 1's client pubkey differs, so the tokens the first create
    // minted authorize different clients than this roster asks for. Handing
    // them back, or overwriting the live session's accounting, would both be
    // wrong -- so the create is refused.
    let conflicting = SessionRequest {
        tenant: tid(),
        players: vec![
            PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: None,
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xCC; 32]),
                external_ref: None,
                observer: false,
                region: None,
            },
        ],
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
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
fn a_conflicting_create_differing_only_in_the_observer_flag_is_refused() {
    // The observer flag shapes recorded state (the session's observer set and
    // its lifecycle player/observer split) even though it alters no token, so a
    // roster that flips it is a distinct request, not a retry.
    let setup = setup_with_two_relays_and_tenant();
    let players = two_players();
    let mut with_observer = players.clone();
    with_observer[1].observer = true;

    create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players,
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap();
    let err = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: with_observer,
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap_err();
    assert_eq!(err, SessionSetupError::IdempotentCreateMismatch);
}
