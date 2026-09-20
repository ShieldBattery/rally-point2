//! `POST /session/rehome`: the decision, the region label, the rate limit, and
//! the recorded-re-ask fast path.

use super::*;

#[tokio::test]
async fn rehome_endpoint_returns_a_new_target_when_the_home_died() {
    // The replacement's region rides the answer when the coordinator knows it
    // and is omitted entirely when it does not — an untagged relay's answer
    // carries no `relay_region` key rather than a null one.
    for replacement_region in [None, Some("us-east")] {
        let state = state_with_relay_and_tenant();
        enroll_second_relay(&state, replacement_region);
        let session = create_rehome_session(&state);
        // The home relay (1) dies; the session should move to the live relay 2.
        registry::remove(state.setup.registry(), RelayId(1));

        let body = rehome_body(TEST_TENANT, session, 1);
        let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["decision"], "newTarget");
        // Response fields are snake_case, matching the rest of the tenant-facing
        // API, and `relay` is the same proto `RelayEndpoint` shape as
        // `home_relay` — `cert_der` rides as a JSON byte array, not hex.
        assert_eq!(json["relay"]["relay_id"], 2);
        assert!(json["relay"]["cert_der"].is_array());
        match replacement_region {
            Some(region) => assert_eq!(json["relay_region"], region),
            None => assert!(
                json.get("relay_region").is_none(),
                "an untagged replacement carries no region label at all",
            ),
        }
    }
}

#[tokio::test]
async fn rehome_endpoint_stays_when_the_relay_is_still_live() {
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    // Relay 1 is still enrolled: the coordinator overrules the caller's belief.
    let body = rehome_body(TEST_TENANT, session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["decision"], "stay");
}

#[tokio::test]
async fn rehome_endpoint_unavailable_for_a_cross_tenant_session() {
    // A different tenant (sb-other) names sb-test's session id in a validly
    // *self*-signed request. The session lookup is tenant-keyed, so sb-other
    // finds no serving set for that id and gets `unavailable` — no cross-tenant
    // state is touched or leaked, and (relay 1 removed so the stay-guard cannot
    // fire) the answer is unambiguously unavailable rather than stay.
    let state = state_with_relay_and_tenant();
    enroll_second_relay(&state, None);
    enroll_other_tenant(&state);
    let session = create_rehome_session(&state); // owned by sb-test
    registry::remove(state.setup.registry(), RelayId(1));

    let body = rehome_body("sb-other", session, 1);
    let resp = signed_post(router(state), "/session/rehome", &body, &OTHER_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
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

    let body = rehome_body(TEST_TENANT, session, 1);
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
    enroll_second_relay(&state, None);
    let session = create_rehome_session(&state);
    // The home relay (1) dies; the first ask records the move to the live relay
    // 2 (spending one token of the default burst of 3).
    registry::remove(state.setup.registry(), RelayId(1));
    let app = router(state);

    let recorded_body = rehome_body(TEST_TENANT, session, 1);
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
            &rehome_body(TEST_TENANT, session, dead),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = signed_post(
        app.clone(),
        "/session/rehome",
        &rehome_body(TEST_TENANT, session, 99),
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
    let json = body_json(resp).await;
    assert_eq!(json["decision"], "newTarget");
    assert_eq!(
        json["relay"]["relay_id"], 2,
        "the recorded replacement is served despite the exhausted bucket",
    );
}
