//! `POST /presence/query`: what a beating relay makes visible, and the
//! fail-open reads when it does not.

use super::*;

#[tokio::test]
async fn presence_query_reports_a_beating_user_in_game_and_an_unknown_one_not() {
    let state = state_with_relay_and_tenant();
    let session = create_session_with_user(&state, "sb-user-7");
    // Relay 1's heartbeat reports the slot connected.
    presence::apply_heartbeat(
        state.setup.presence(),
        RelayId(1),
        1,
        &slot0_roster(session),
        std::time::Instant::now(),
    );

    let body = presence_body("sb-test", &["sb-user-7", "sb-user-9"]);
    let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let users = json["users"].as_array().unwrap();
    assert_eq!(users.len(), 2, "one answer per queried user, in order");
    assert_eq!(users[0]["user"], "sb-user-7");
    assert_eq!(users[0]["in_game"], true);
    assert_eq!(
        users[0]["sessions"].as_array().unwrap(),
        &vec![serde_json::json!(session.0)],
        "the present user's session id rides along for observability",
    );
    assert_eq!(users[1]["user"], "sb-user-9");
    assert_eq!(users[1]["in_game"], false, "no evidence means not in game");
    assert!(users[1]["sessions"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn presence_query_reads_an_expired_entry_as_not_in_game() {
    // A beat older than the TTL no longer counts — fail-open: a silent relay's
    // players read as queueable rather than locked out.
    let state = state_with_relay_and_tenant();
    let session = create_session_with_user(&state, "sb-user-7");
    let stale = std::time::Instant::now()
        .checked_sub(presence::PRESENCE_TTL + Duration::from_secs(1))
        .expect("host uptime exceeds the presence TTL");
    presence::apply_heartbeat(
        state.setup.presence(),
        RelayId(1),
        1,
        &slot0_roster(session),
        stale,
    );

    let body = presence_body("sb-test", &["sb-user-7"]);
    let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["users"][0]["in_game"], false);
}

#[tokio::test]
async fn presence_query_reads_a_cleared_connection_as_not_in_game() {
    // The relay's control connection dropped: its presence was cleared
    // promptly, so its players read as queueable without waiting out the TTL.
    let state = state_with_relay_and_tenant();
    let session = create_session_with_user(&state, "sb-user-7");
    presence::apply_heartbeat(
        state.setup.presence(),
        RelayId(1),
        1,
        &slot0_roster(session),
        std::time::Instant::now(),
    );
    presence::clear_connection(state.setup.presence(), RelayId(1), 1);

    let body = presence_body("sb-test", &["sb-user-7"]);
    let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["users"][0]["in_game"], false);
}

#[tokio::test]
async fn presence_query_rejects_unsigned_and_wrong_key_requests_alike() {
    let state = state_with_relay_and_tenant();
    let app = router(state);
    let body = presence_body("sb-test", &["sb-user-7"]);

    // No signature headers at all — fails closed.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/presence/query")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Signed by a key that is not the tenant's enrolled request key — the
    // same indistinguishable 401.
    let resp = signed_post(app, "/presence/query", &body, &[0x99; 32]).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn presence_query_rejects_an_over_cap_user_list() {
    // An over-cap list is rejected rather than resolved, past the auth gate —
    // the same shape as the sessions-alive probe cap.
    let state = state_with_relay_and_tenant();
    let too_many: Vec<String> = (0..=MAX_PRESENCE_USERS)
        .map(|i| format!("sb-user-{i}"))
        .collect();
    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "users": too_many })).unwrap();
    let resp = signed_post(router(state), "/presence/query", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
