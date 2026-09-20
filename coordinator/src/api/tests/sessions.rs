//! `POST /session/create` and `POST /sessions/alive`: minting, idempotent
//! replay, request-signature refusals, token expiry, and the liveness probe.

use super::*;

#[tokio::test]
async fn create_session_endpoint_returns_tokens() {
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let session: SessionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(session.tokens.len(), 2);
    assert_eq!(session.home_relay.relay_id, RelayId(1));
}

#[tokio::test]
async fn create_session_endpoint_replays_a_duplicate_and_keeps_one_live_session() {
    let state = state_with_relay_and_tenant();
    let app = router(state.clone());

    let req = SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();

    let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let first: SessionResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let second: SessionResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        first, second,
        "a retry of the same create replays the exact original response",
    );
    assert!(
        state.lifecycle.is_alive(&tenant_id(), first.session),
        "the replayed create leaves the one original session live and undisturbed",
    );
}

#[tokio::test]
async fn create_session_endpoint_conflicts_on_a_reused_live_id_with_a_different_roster() {
    let state = state_with_relay_and_tenant();
    let app = router(state.clone());

    let original = SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&original).unwrap();
    let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let created: SessionResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();

    // The same external_id, still bound to the live session, but slot 1 now
    // carries a different client pubkey: a different game reusing a live id.
    // The coordinator maps this to 409 rather than minting a duplicate or
    // handing back the first game's tokens.
    let conflicting = SessionRequest {
        tenant: tenant_id(),
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
    let body = serde_json::to_vec(&conflicting).unwrap();
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    assert!(
        state.lifecycle.is_alive(&tenant_id(), created.session),
        "the refused conflict must leave the original session's accounting intact",
    );
}

#[tokio::test]
async fn create_session_refuses_every_bad_signature_shape_with_the_same_401() {
    // Verification is one shared gate, so the *shapes* of a bad signature are
    // proven once, here, against one endpoint: each fails closed and is
    // indistinguishable from the others, disclosing nothing about which check
    // tripped. A tenant with no enrolled key is one of the shapes — auth
    // precedes tenant lookup, so it 401s rather than reaching the session
    // logic's own unenrolled-tenant 400.
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let create_body = |tenant: &str| {
        serde_json::to_vec(&SessionRequest {
            tenant: TenantId(tenant.to_owned()),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        })
        .unwrap()
    };
    let enrolled = create_body(TEST_TENANT);

    let refusals = [
        (
            "no signature headers at all",
            unsigned_post(app.clone(), "/session/create", &enrolled).await,
        ),
        (
            "a signature from a key the tenant never enrolled",
            signed_post(app.clone(), "/session/create", &enrolled, &UNENROLLED_SEED).await,
        ),
        (
            "a correctly-keyed signature over a stale timestamp",
            stale_signed_post(app.clone(), "/session/create", &enrolled).await,
        ),
        (
            "a tenant with no enrolled request key",
            signed_post(
                app,
                "/session/create",
                &create_body("not-enrolled"),
                &TEST_CLIENT_SEED,
            )
            .await,
        ),
    ];
    for (shape, resp) in refusals {
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{shape} must be refused with the same bare 401",
        );
    }
}

#[tokio::test]
async fn sessions_alive_reports_live_and_omits_gone_or_unknown_and_caps() {
    let state = state_with_relay_and_tenant();
    enroll_other_tenant(&state);
    // A live session registered directly on the shared lifecycle, plus one
    // owned by a different tenant that this caller must never be told about.
    state.lifecycle.register_session(
        tenant_id(),
        SessionId(5),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    state.lifecycle.register_session(
        TenantId("sb-other".to_owned()),
        SessionId(7),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let app = router(state);

    // Probe a live id (5), an unknown id (6), and another tenant's live id (7).
    let req_body = serde_json::to_vec(&serde_json::json!({
        "tenant": TEST_TENANT,
        "sessions": [5, 6, 7],
    }))
    .unwrap();
    let resp = signed_post(app.clone(), "/sessions/alive", &req_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["alive"].as_array().unwrap(),
        &vec![serde_json::json!(5)],
        "only the caller's own live session id is returned; gone, unknown, and \
         another tenant's live session are all omitted",
    );

    // An over-cap probe list is rejected rather than scanned (the request is
    // still signed — the cap check is past the auth gate).
    let too_many: Vec<u64> = (0..=(MAX_LIVENESS_SESSIONS as u64)).collect();
    let big_body =
        serde_json::to_vec(&serde_json::json!({ "tenant": TEST_TENANT, "sessions": too_many }))
            .unwrap();
    let resp = signed_post(app, "/sessions/alive", &big_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn create_session_no_relays_returns_503() {
    // A tenant enrolled (with a client key, so the request authenticates) but
    // no relays registered — the 503 path is reached only past the auth gate.
    let setup = SessionFixture {
        relays: vec![],
        ..Default::default()
    }
    .setup_only();
    let app = router(state_over(setup));

    let req = SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn create_session_stamps_expiry_at_now_plus_configured_lifetime() {
    // The handler mints each token's expiry as (now + the configured
    // lifetime); decode a token out of the response and confirm it lands in
    // the window bracketing the call, offset by the lifetime.
    let state = state_with_relay_and_tenant();
    let lifetime_secs = state.player_token_lifetime.as_secs();
    let app = router(state);

    let req = SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();

    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let session_resp: SessionResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(!session_resp.tokens.is_empty(), "a session mints tokens");
    for player_token in &session_resp.tokens {
        let token = rally_point_proto::token::SignedToken::decode(&player_token.token).unwrap();
        let expires = token.claims.expires_at.0;
        assert!(
            expires >= before.saturating_add(lifetime_secs)
                && expires <= after.saturating_add(lifetime_secs),
            "expiry {expires} should be now + {lifetime_secs}s (call window {before}..={after})",
        );
    }
}
