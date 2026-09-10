//! `POST /session/rehome`: the decision, the region label, the rate limit, and
//! the recorded-re-ask fast path.

use super::*;

#[tokio::test]
async fn rehome_endpoint_returns_a_new_target_when_the_home_died() {
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state);
    let session = create_rehome_session(&state);
    // The home relay (1) dies; the session should move to the live relay 2.
    registry::remove(state.setup.registry(), RelayId(1));

    let body = rehome_body("sb-test", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["decision"], "newTarget");
    // Response fields are snake_case, matching the rest of the tenant-facing API,
    // and `relay` is the same proto `RelayEndpoint` shape as `home_relay` —
    // `cert_der` rides as a JSON byte array, not hex.
    assert_eq!(json["relay"]["relay_id"], 2);
    assert!(json["relay"]["cert_der"].is_array());
    // Relay 2 enrolled with no region, so the response carries none either.
    assert!(json.get("relay_region").is_none());
}

#[tokio::test]
async fn rehome_endpoint_includes_the_replacement_relays_region_when_known() {
    let state = state_with_relay_and_tenant();
    registry::enroll(
        state.setup.registry(),
        RelayHello::new(
            RelayId(2),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            ProtocolVersion::CURRENT,
            vec![0xC2; 4],
        )
        .with_region(RegionId("us-east".to_owned())),
    );
    let session = create_rehome_session(&state);
    // The home relay (1) dies; the session should move to the live, tagged relay 2.
    registry::remove(state.setup.registry(), RelayId(1));

    let body = rehome_body("sb-test", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["decision"], "newTarget");
    assert_eq!(json["relay"]["relay_id"], 2);
    assert_eq!(json["relay_region"], "us-east");
}

#[tokio::test]
async fn rehome_endpoint_stays_when_the_relay_is_still_live() {
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    // Relay 1 is still enrolled: the coordinator overrules the caller's belief.
    let body = rehome_body("sb-test", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["decision"], "stay");
}

#[tokio::test]
async fn rehome_endpoint_rejects_a_wrong_key_signature() {
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state);
    let session = create_rehome_session(&state);
    registry::remove(state.setup.registry(), RelayId(1));

    // Signed by a key whose public half is not the tenant's enrolled request key.
    let body = rehome_body("sb-test", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &[0x99; 32]).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rehome_endpoint_rejects_a_stale_timestamp() {
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state);
    let session = create_rehome_session(&state);
    registry::remove(state.setup.registry(), RelayId(1));
    let app = router(state);

    // A correctly-keyed signature, but over a timestamp far outside the window.
    let body = rehome_body("sb-test", session, 1);
    let pair = Ed25519KeyPair::from_seed_unchecked(&TEST_CLIENT_SEED).unwrap();
    let stale_ts = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - (REQUEST_TIMESTAMP_WINDOW_SECS + 60))
        .to_string();
    let message = build_request_message(&stale_ts, &Method::POST, "/session/rehome", &body);
    let sig = hex::encode(pair.sign(&message).as_ref());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/session/rehome")
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
async fn rehome_endpoint_unavailable_for_a_cross_tenant_session() {
    // A different tenant (sb-other) names sb-test's session id in a validly
    // *self*-signed request. The session lookup is tenant-keyed, so sb-other
    // finds no serving set for that id and gets `unavailable` — no cross-tenant
    // state is touched or leaked, and (relay 1 removed so the stay-guard cannot
    // fire) the answer is unambiguously unavailable rather than stay.
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state);
    enroll_other_tenant(&state);
    let session = create_rehome_session(&state); // owned by sb-test
    registry::remove(state.setup.registry(), RelayId(1));

    let body = rehome_body("sb-other", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &OTHER_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["decision"], "unavailable");
    assert!(
        json.get("relay").is_none(),
        "no relay leaks to another tenant"
    );
}

#[tokio::test]
async fn rehome_endpoint_rate_limits_repeated_requests() {
    // Relay 1 stays live, so every ask resolves to `stay` — a non-recorded
    // outcome that spends a rate-limit token each time (the free recorded-rehome
    // fast path never applies, since a `stay` records no replacement). This is
    // the token-spending path the reorder must still rate-limit: the default
    // burst is 3, so the first three are admitted and the fourth is a 429.
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    let app = router(state);

    let body = rehome_body("sb-test", session, 1);
    for _ in 0..3 {
        let resp = signed_post(app.clone(), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = signed_post(app, "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_recorded_rehome_re_ask_does_not_consume_a_token() {
    // The idempotent recorded-rehome answer must be served without spending a
    // rate-limit token, so an already-answered straggler can never starve a real
    // survivor's ask. Prove it by exhausting the session's bucket, then showing a
    // recorded re-ask still succeeds while a fresh (non-recorded) ask is a 429.
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state);
    let session = create_rehome_session(&state);
    // The home relay (1) dies; the first ask records the move to the live relay
    // 2 (spending one token of the default burst of 3).
    registry::remove(state.setup.registry(), RelayId(1));
    let app = router(state);

    let recorded_body = rehome_body("sb-test", session, 1);
    let resp = signed_post(
        app.clone(),
        "/session/rehome",
        &recorded_body,
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Exhaust the remaining tokens with garbage dead-relay asks on the SAME
    // session (each unrecorded and unserving → `unavailable`, but token-spending).
    // Relay ids 77/88 drain the last two tokens; 99 then hits the empty bucket.
    for dead in [77u64, 88] {
        let resp = signed_post(
            app.clone(),
            "/session/rehome",
            &rehome_body("sb-test", session, dead),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = signed_post(
        app.clone(),
        "/session/rehome",
        &rehome_body("sb-test", session, 99),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a fresh, non-recorded ask is rate-limited once the bucket is empty",
    );

    // The straggler re-asks about the recorded dead relay 1. Even though the
    // bucket is exhausted, the recorded fast path answers `newTarget` (relay 2)
    // without charging a token.
    let resp = signed_post(app, "/session/rehome", &recorded_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["decision"], "newTarget");
    assert_eq!(
        json["relay"]["relay_id"], 2,
        "the recorded replacement is served despite the exhausted bucket",
    );
}
