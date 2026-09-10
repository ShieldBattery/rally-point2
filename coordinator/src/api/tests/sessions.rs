//! `POST /session/create` and `POST /sessions/alive`: minting, idempotent
//! replay, request-signature refusals, token expiry, and the liveness probe.

use super::*;

#[tokio::test]
async fn create_session_endpoint_returns_tokens() {
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
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
        tenant: TenantId("sb-test".to_owned()),
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
        state
            .lifecycle
            .is_alive(&TenantId("sb-test".to_owned()), first.session),
        "the replayed create leaves the one original session live and undisturbed",
    );
}

#[tokio::test]
async fn create_session_endpoint_conflicts_on_a_reused_live_id_with_a_different_roster() {
    let state = state_with_relay_and_tenant();
    let app = router(state.clone());

    let original = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
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
        tenant: TenantId("sb-test".to_owned()),
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
        state
            .lifecycle
            .is_alive(&TenantId("sb-test".to_owned()), created.session),
        "the refused conflict must leave the original session's accounting intact",
    );
}

#[tokio::test]
async fn create_session_rejects_an_unsigned_request() {
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    // No signature headers at all — fails closed.
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/session/create")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_session_rejects_a_wrong_key_signature() {
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    // Signed with a key whose public half is not the tenant's enrolled one.
    let resp = signed_post(app, "/session/create", &body, &[0x22; 32]).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_session_rejects_a_stale_timestamp() {
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();

    // A correctly-keyed signature, but over a timestamp far outside the
    // replay window — a captured request replayed long after the fact.
    let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_CLIENT_SEED).unwrap();
    let stale_ts = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - (REQUEST_TIMESTAMP_WINDOW_SECS + 60))
        .to_string();
    let message = build_request_message(&stale_ts, &Method::POST, "/session/create", &body);
    let sig = hex::encode(pair.sign(&message).as_ref());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/session/create")
                .header("content-type", "application/json")
                .header(REQUEST_TIMESTAMP_HEADER, stale_ts)
                .header(REQUEST_SIGNATURE_HEADER, sig)
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sessions_alive_reports_live_and_omits_gone_or_unknown_and_caps() {
    let state = state_with_relay_and_tenant();
    // A live session registered directly on the shared lifecycle.
    state.lifecycle.register_session(
        TenantId("sb-test".to_owned()),
        SessionId(5),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let app = router(state);

    // Probe a live id (5), an unknown id (6): only the live one is returned.
    let req_body = serde_json::to_vec(&serde_json::json!({
        "tenant": "sb-test",
        "sessions": [5, 6],
    }))
    .unwrap();
    let resp = signed_post(app.clone(), "/sessions/alive", &req_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["alive"].as_array().unwrap(),
        &vec![serde_json::json!(5)],
        "only the live session id is returned; gone/unknown are omitted",
    );

    // An over-cap probe list is rejected rather than scanned (the request is
    // still signed — the cap check is past the auth gate).
    let too_many: Vec<u64> = (0..=(MAX_LIVENESS_SESSIONS as u64)).collect();
    let big_body =
        serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "sessions": too_many }))
            .unwrap();
    let resp = signed_post(app, "/sessions/alive", &big_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn create_session_no_relays_returns_503() {
    // A tenant enrolled (with a client key, so the request authenticates) but
    // no relays registered — the 503 path is reached only past the auth gate.
    let tenants = crate::tenant::new_store();
    crate::tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let client_pubkey = crate::tenant::client_pubkey_from_seed(&TEST_CLIENT_SEED).unwrap();
    crate::tenant::set_client_pubkeys(
        &tenants,
        &TenantId("sb-test".to_owned()),
        vec![client_pubkey],
    );
    let setup = crate::session::SessionSetup::new(registry::new_registry(), tenants);
    let lifecycle = Lifecycle::new(setup.clone());
    let state = CoordinatorState {
        setup,
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: HELLO_TIMEOUT,
        liveness_timeout: LIVENESS_TIMEOUT,
        regions: RegionsConfig::default(),
        player_token_lifetime: TEST_TOKEN_LIFETIME,
        ledger: None,
        pair_rtts: pair_rtts::new_store(),
        flight_store: None,
    };
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("sb-test".to_owned()),
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
        tenant: TenantId("sb-test".to_owned()),
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

#[tokio::test]
async fn create_session_unenrolled_tenant_fails_auth() {
    // A tenant with no enrolled client key cannot produce a verifiable
    // signature, so auth fails closed (401) before the session logic's own
    // unenrolled-tenant 400 is ever reached — auth precedes tenant lookup.
    let state = state_with_relay_and_tenant();
    let app = router(state);

    let req = SessionRequest {
        tenant: TenantId("not-enrolled".to_owned()),
        players: two_players(),
        external_id: None,
        latency_estimate_ms: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    // Even a signature made by *some* valid key can't help: the tenant named
    // in the body has no enrolled client_pubkey to verify against.
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
