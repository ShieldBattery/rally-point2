//! Tenant key material and per-state enforcement: the pubkey endpoint,
//! multi-key request verification, the tenant-signature gate on every
//! tenant-facing route, and the suspended / revoked gates.

use super::*;

#[tokio::test]
async fn tenant_pubkey_endpoint_returns_the_enrolled_key_and_404s_for_an_unknown_tenant() {
    let reg = registry::new_registry();
    let tenants = crate::tenant::new_store();
    let expected_pubkey = crate::tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tenant_id(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = crate::session::SessionSetup::new(reg, tenants);
    let app = router(state_over(setup));

    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/tenant/sb-test/pubkey")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Exactly the two camelCase fields — nothing else on the shape.
    let map = json.as_object().unwrap();
    assert_eq!(
        map.keys().collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([&"kid".to_owned(), &"publicKey".to_owned()]),
        "the response is exactly {{kid, publicKey}}",
    );
    assert_eq!(json["kid"], "test-key-1");
    // Hex round-trips against what enroll returned: 64 lowercase hex chars
    // decoding back to the exact 32-byte verifying key.
    assert_eq!(json["publicKey"], hex::encode(expected_pubkey));
    assert_eq!(json["publicKey"].as_str().unwrap().len(), 64);

    // A tenant this coordinator never enrolled has no key to serve.
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/tenant/not-enrolled/pubkey")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- Multi-key inbound verification + per-state enforcement ---

/// The retired half of a request-key rotation: still listed, so a signature
/// from it must keep verifying until it is dropped.
const ROTATION_SEED_OLD: [u8; 32] = [0x55; 32];
/// The incoming half of a request-key rotation: listed alongside the old key,
/// so a signature from it verifies too.
const ROTATION_SEED_NEW: [u8; 32] = [0x66; 32];
/// A key that is not among the tenant's listed verification keys — its
/// signatures must be refused.
const UNLISTED_SEED: [u8; 32] = [0x77; 32];

/// A single-player create body anchored on `external_id`, so two otherwise
/// identical creates are independent sessions rather than an idempotent
/// replay.
fn create_body(external_id: &str) -> Vec<u8> {
    serde_json::to_vec(&SessionRequest {
        tenant: tenant_id(),
        players: two_players(),
        external_id: Some(external_id.to_owned()),
        latency_estimate_ms: None,
    })
    .unwrap()
}

/// Every tenant-authenticated route, each with a body its handler accepts —
/// the set a new endpoint has to join, so it cannot quietly skip the gate.
fn tenant_authed_routes(session: SessionId) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("/session/create", create_body("gate-probe")),
        ("/session/rehome", rehome_body(TEST_TENANT, session, 1)),
        (
            "/sessions/alive",
            serde_json::to_vec(
                &serde_json::json!({"tenant": TEST_TENANT, "sessions": [session.0]}),
            )
            .unwrap(),
        ),
        (
            "/session/load-state",
            serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "session": session.0}))
                .unwrap(),
        ),
        (
            "/presence/query",
            presence_body(TEST_TENANT, &["sb-user-7"]),
        ),
        (
            "/regions/warm",
            serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "regions": ["r"]}))
                .unwrap(),
        ),
        (
            "/flight/blobs",
            serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "session": session.0}))
                .unwrap(),
        ),
        (
            "/flight/blob",
            serde_json::to_vec(
                &serde_json::json!({"tenant": TEST_TENANT, "session": session.0, "relay_id": 1}),
            )
            .unwrap(),
        ),
    ]
}

#[tokio::test]
async fn every_tenant_authed_route_refuses_an_unsigned_request() {
    // The shapes a bad signature can take are proven once against one endpoint
    // (`create_session_refuses_every_bad_signature_shape_with_the_same_401`);
    // what each route has to prove is only that it is behind the gate at all.
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    let app = router(state);

    for (path, body) in tenant_authed_routes(session) {
        let resp = unsigned_post(app.clone(), path, &body).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must refuse an unsigned request",
        );
    }
}

#[tokio::test]
async fn verify_accepts_any_listed_client_key_and_refuses_an_unlisted_one() {
    // A request-key rotation in flight: the tenant lists both the old and the
    // new key at once. A signature from either verifies; one from an unlisted
    // key does not. This is what makes app-server key rotation zero-downtime.
    let state = state_with_relay_and_tenant();
    let old = crate::tenant::client_pubkey_from_seed(&ROTATION_SEED_OLD).unwrap();
    let new = crate::tenant::client_pubkey_from_seed(&ROTATION_SEED_NEW).unwrap();
    crate::tenant::set_client_pubkeys(state.setup.tenants(), &tenant_id(), vec![old, new]);
    let app = router(state);

    // The first (retiring) key verifies.
    let resp = signed_post(
        app.clone(),
        "/session/create",
        &create_body("rot-old"),
        &ROTATION_SEED_OLD,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The second (incoming) key verifies.
    let resp = signed_post(
        app.clone(),
        "/session/create",
        &create_body("rot-new"),
        &ROTATION_SEED_NEW,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A key absent from the list is refused, indistinguishably from any other
    // auth failure.
    let resp = signed_post(
        app,
        "/session/create",
        &create_body("rot-bad"),
        &UNLISTED_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Sends a `GET /tenant/sb-test/pubkey` and returns the status.
async fn get_pubkey_status(app: Router) -> StatusCode {
    app.oneshot(
        axum::http::Request::builder()
            .method("GET")
            .uri("/tenant/sb-test/pubkey")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn a_suspended_tenant_is_refused_create_but_still_serves_live_games() {
    let state = state_with_relay_and_tenant();
    // Live-game state the suspended tenant must keep serving: a session to
    // re-home (homed on the still-live relay 1), a liveness-probe target, and
    // a presence session.
    let rehome = create_rehome_session(&state);
    state.lifecycle.register_session(
        tenant_id(),
        SessionId(9001),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let presence_session = create_session_with_user(&state, "sb-user-7");
    presence::apply_heartbeat(
        state.setup.presence(),
        RelayId(1),
        1,
        &slot0_roster(presence_session),
        std::time::Instant::now(),
    );

    crate::tenant::set_state(
        state.setup.tenants(),
        &tenant_id(),
        crate::tenant::TenantState::Suspended,
    );
    let app = router(state);

    // Create is refused — but with 403 (state), a distinct status from the 401
    // an auth failure yields: the signature verified, the state did not permit.
    let resp = signed_post(
        app.clone(),
        "/session/create",
        &create_body("suspended-create"),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Re-home still works (relay 1 is alive, so the decision is "stay").
    let resp = signed_post(
        app.clone(),
        "/session/rehome",
        &rehome_body(TEST_TENANT, rehome, 1),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["decision"], "stay");

    // The liveness probe still works.
    let resp = signed_post(
        app.clone(),
        "/sessions/alive",
        &serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "sessions": [9001]}))
            .unwrap(),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["alive"], serde_json::json!([9001]));

    // The presence query still works.
    let resp = signed_post(
        app.clone(),
        "/presence/query",
        &presence_body(TEST_TENANT, &["sb-user-7"]),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["users"][0]["in_game"], true);

    // The verifying-key fetch still works (a suspended tenant's live games
    // keep signing webhooks the consumer validates against this key).
    assert_eq!(get_pubkey_status(app).await, StatusCode::OK);
}

#[tokio::test]
async fn a_revoked_tenant_is_refused_everywhere_and_its_pubkey_404s() {
    let state = state_with_relay_and_tenant();
    let rehome = create_rehome_session(&state);
    state.lifecycle.register_session(
        tenant_id(),
        SessionId(9001),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let _presence_session = create_session_with_user(&state, "sb-user-7");

    crate::tenant::set_state(
        state.setup.tenants(),
        &tenant_id(),
        crate::tenant::TenantState::Revoked,
    );
    let app = router(state);

    // Every tenant-authenticated endpoint refuses with 403 — the signature
    // still verifies (the key is unchanged), the state permits nothing.
    for (path, body) in [
        ("/session/create", create_body("revoked-create")),
        ("/session/rehome", rehome_body(TEST_TENANT, rehome, 1)),
        (
            "/sessions/alive",
            serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "sessions": [9001]}))
                .unwrap(),
        ),
        (
            "/presence/query",
            presence_body(TEST_TENANT, &["sb-user-7"]),
        ),
    ] {
        let resp = signed_post(app.clone(), path, &body, &TEST_CLIENT_SEED).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{path} must be refused with 403 for a revoked tenant",
        );
    }

    // The pubkey endpoint reports the revoked tenant as absent.
    assert_eq!(get_pubkey_status(app).await, StatusCode::NOT_FOUND);
}
