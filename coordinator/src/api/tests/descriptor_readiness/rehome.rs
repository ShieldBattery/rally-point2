//! A rehome waits for its replacement, independently of other homes' recovery.

use super::*;

#[tokio::test]
async fn correlated_home_failures_do_not_block_an_acknowledged_replacement() {
    rehome_with_unready_peer(true).await;
}

#[tokio::test]
async fn live_home_without_an_ack_does_not_block_an_acknowledged_replacement() {
    rehome_with_unready_peer(false).await;
}

async fn rehome_with_unready_peer(disconnect_peer: bool) {
    let relays = vec![
        RelaySpec {
            id: 1,
            region: Some("west"),
        },
        RelaySpec {
            id: 2,
            region: Some("east"),
        },
    ];
    let mut state = state_over(
        SessionFixture {
            relays: relays.clone(),
            ..Default::default()
        }
        .setup_only(),
    );
    state.descriptor_ack_timeout = Duration::from_secs(3600);
    let body = create_body(vec![
        player_in_region(0, Some("west")),
        player_in_region(1, Some("east")),
    ]);
    let app = router(state.clone());
    let original =
        created(signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await).await;
    let serving = state.setup.serving_relays(&tenant_id(), original.session);
    assert_eq!(serving.len(), 2);
    assert!(serving.contains(&RelayId(1)));
    assert!(serving.contains(&RelayId(2)));

    let peer_generation = capable(&state, relays[1]);
    let original_peer_ack = sent(&state, 2, peer_generation);
    acknowledge(&state, 2, peer_generation, original_peer_ack);
    registry::remove(state.setup.registry(), RelayId(1));
    if disconnect_peer {
        registry::remove(state.setup.registry(), RelayId(2));
    }
    let target_generation = capable(
        &state,
        RelaySpec {
            id: 3,
            region: Some("west"),
        },
    );
    let rehome_body = rehome_body(TEST_TENANT, original.session, 1);
    let fresh = signed_post(
        app.clone(),
        "/session/rehome",
        &rehome_body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(fresh);
    assert_pending(fresh.as_mut());
    assert_eq!(
        session::recorded_rehome(&state.setup, &tenant_id(), original.session, RelayId(1))
            .unwrap()
            .relay_id,
        RelayId(3)
    );
    let recorded = signed_post(
        app.clone(),
        "/session/rehome",
        &rehome_body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(recorded);
    assert_pending(recorded.as_mut());
    let create_retry = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED);
    tokio::pin!(create_retry);
    assert_pending(create_retry.as_mut());

    let target_ack = sent(&state, 3, target_generation);
    acknowledge(&state, 3, target_generation, target_ack);
    for response in [
        tokio::time::timeout(Duration::from_secs(1), fresh)
            .await
            .unwrap(),
        tokio::time::timeout(Duration::from_secs(1), recorded)
            .await
            .unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["decision"], "newTarget");
        assert_eq!(json["relay"]["relay_id"], 3);
    }
    assert!(
        state
            .setup
            .serving_relays(&tenant_id(), original.session)
            .contains(&RelayId(2))
    );
    assert_pending(create_retry.as_mut());

    let peer_generation = if disconnect_peer {
        capable(&state, relays[1])
    } else {
        peer_generation
    };
    assert_pending(create_retry.as_mut());
    let peer_ack = sent(&state, 2, peer_generation);
    acknowledge(&state, 2, peer_generation, peer_ack);
    let replay = created(
        tokio::time::timeout(Duration::from_secs(1), create_retry)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay.session, original.session);
    assert_eq!(replay.tokens, original.tokens);
    assert!(
        std::iter::once(replay.home_relay.relay_id)
            .chain(replay.slot_homes.iter().map(|home| home.relay.relay_id))
            .all(|relay| relay == RelayId(2) || relay == RelayId(3))
    );
}
