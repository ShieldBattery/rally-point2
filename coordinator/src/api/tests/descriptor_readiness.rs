//! Tenant responses wait for installation proofs only from capable relays.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

use rally_point_proto::control::CAPABILITY_DESCRIPTOR_ACK_V1;

use super::*;

mod rehome;

fn create_body(players: Vec<PlayerHandoff>) -> Vec<u8> {
    serde_json::to_vec(&SessionRequest {
        evidence_keys: Vec::new(),
        lobby_policy: None,
        rollback: false,
        tenant: tenant_id(),
        players,
        external_id: Some("ready-game".to_owned()),
        latency_estimate_ms: None,
    })
    .unwrap()
}

fn capable(state: &CoordinatorState, relay: RelaySpec) -> u64 {
    let generation = registry::enroll(
        state.setup.registry(),
        relay
            .hello()
            .with_capabilities(vec![CAPABILITY_DESCRIPTOR_ACK_V1.to_owned()]),
    );
    assert!(
        state
            .setup
            .descriptors()
            .delivery()
            .begin(RelayId(relay.id), generation)
    );
    generation
}

fn sent(state: &CoordinatorState, relay: u64, generation: u64) -> u64 {
    let descriptors = state.setup.descriptors();
    descriptors
        .delivery()
        .sent(
            RelayId(relay),
            generation,
            &descriptors.current_for(RelayId(relay)),
        )
        .unwrap()
}

fn acknowledge(state: &CoordinatorState, relay: u64, generation: u64, id: u64) {
    assert!(
        state
            .setup
            .descriptors()
            .delivery()
            .acknowledge(RelayId(relay), generation, id)
    );
}

fn assert_pending(future: Pin<&mut impl Future>) {
    assert!(
        future
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

async fn created(response: axum::http::Response<axum::body::Body>) -> SessionResponse {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_value(body_json(response).await).unwrap()
}

#[tokio::test]
async fn legacy_create_does_not_wait_for_an_installation_ack() {
    let mut state = state_with_relay_and_tenant();
    state.descriptor_ack_timeout = Duration::ZERO;
    let body = create_body(two_players());
    let response =
        created(signed_post(router(state), "/session/create", &body, &TEST_CLIENT_SEED).await)
            .await;
    assert_eq!(response.home_relay.relay_id, RelayId(1));
}

#[tokio::test]
async fn mixed_fleet_create_waits_for_every_capable_serving_relay() {
    let relays = vec![
        RelaySpec {
            id: 1,
            region: Some("west"),
        },
        RelaySpec {
            id: 2,
            region: Some("east"),
        },
        RelaySpec {
            id: 3,
            region: Some("north"),
        },
    ];
    let state = state_over(
        SessionFixture {
            relays: relays.clone(),
            ..Default::default()
        }
        .setup_only(),
    );
    let first_generation = capable(&state, relays[0]);
    let second_generation = capable(&state, relays[1]);
    let body = create_body(vec![
        player_in_region(0, Some("west")),
        player_in_region(1, Some("east")),
        player_in_region(2, Some("north")),
    ]);
    let request = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(request);
    assert_pending(request.as_mut());
    for relay in [1, 2, 3] {
        assert_eq!(
            state.setup.descriptors().current_for(RelayId(relay)).len(),
            1
        );
    }
    let first_id = sent(&state, 1, first_generation);
    acknowledge(&state, 1, first_generation, first_id);
    assert_pending(request.as_mut());
    let second_id = sent(&state, 2, second_generation);
    let delivery = state.setup.descriptors().delivery();
    assert!(!delivery.acknowledge(RelayId(2), second_generation, second_id + 1));
    assert!(!delivery.acknowledge(RelayId(2), second_generation - 1, second_id));
    assert_pending(request.as_mut());
    acknowledge(&state, 2, second_generation, second_id);
    let response = created(
        tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(response.tokens.len(), 3);
}

#[tokio::test]
async fn create_timeout_retry_reuses_the_committed_session_and_tokens() {
    let mut state = state_with_relay_and_tenant();
    state.descriptor_ack_timeout = Duration::ZERO;
    let generation = capable(
        &state,
        RelaySpec {
            id: 1,
            region: None,
        },
    );
    let body = create_body(two_players());
    let app = router(state.clone());
    let response = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let descriptors = state.setup.descriptors().current_for(RelayId(1));
    assert_eq!(descriptors.len(), 1);
    let session = descriptors[0].session;
    let id = sent(&state, 1, generation);
    acknowledge(&state, 1, generation, id);
    let first =
        created(signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await).await;
    let replay = created(signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await).await;
    assert_eq!(first.session, session);
    assert_eq!(first, replay);
    assert_eq!(state.setup.descriptors().current_for(RelayId(1)).len(), 1);
    assert!(state.lifecycle.is_alive(&tenant_id(), session));
}

#[tokio::test]
async fn fresh_and_recorded_rehome_answers_both_wait_for_installation() {
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    let generation = capable(
        &state,
        RelaySpec {
            id: 2,
            region: Some("east"),
        },
    );
    registry::remove(state.setup.registry(), RelayId(1));
    let body = rehome_body(TEST_TENANT, session, 1);
    let app = router(state.clone());
    let fresh = signed_post(app.clone(), "/session/rehome", &body, &TEST_CLIENT_SEED);
    tokio::pin!(fresh);
    assert_pending(fresh.as_mut());
    assert!(session::recorded_rehome(&state.setup, &tenant_id(), session, RelayId(1)).is_some());
    let recorded = signed_post(app, "/session/rehome", &body, &TEST_CLIENT_SEED);
    tokio::pin!(recorded);
    assert_pending(recorded.as_mut());
    let id = sent(&state, 2, generation);
    acknowledge(&state, 2, generation, id);
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
        assert_eq!(json["relay"]["relay_id"], 2);
        assert_eq!(json["relay_region"], "east");
    }
}

#[tokio::test]
async fn rehome_stay_does_not_need_an_installation_ack() {
    let mut state = state_with_relay_and_tenant();
    state.descriptor_ack_timeout = Duration::ZERO;
    capable(
        &state,
        RelaySpec {
            id: 1,
            region: None,
        },
    );
    let session = create_rehome_session(&state);
    let body = rehome_body(TEST_TENANT, session, 1);
    let response = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["decision"], "stay");
}

#[tokio::test]
async fn retirement_while_create_waits_refuses_the_response() {
    let state = state_with_relay_and_tenant();
    capable(
        &state,
        RelaySpec {
            id: 1,
            region: None,
        },
    );
    let body = create_body(two_players());
    let request = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(request);
    assert_pending(request.as_mut());
    let session = state.setup.descriptors().current_for(RelayId(1))[0].session;
    {
        let _assignment = state.setup.lock_assignment();
        state.setup.retire_session(&tenant_id(), session);
    }
    let response = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn create_answer_refreshes_assignment_after_rehome_during_wait() {
    let state = state_with_relay_and_tenant();
    let first_generation = capable(
        &state,
        RelaySpec {
            id: 1,
            region: None,
        },
    );
    let body = create_body(two_players());
    let request = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(request);
    assert_pending(request.as_mut());
    let session = state.setup.descriptors().current_for(RelayId(1))[0].session;
    let old_id = sent(&state, 1, first_generation);
    let replacement_generation = capable(
        &state,
        RelaySpec {
            id: 2,
            region: Some("east"),
        },
    );
    registry::remove(state.setup.registry(), RelayId(1));
    assert!(matches!(
        session::rehome(&state.setup, &tenant_id(), session, RelayId(1), Vec::new()),
        session::RehomeOutcome::NewTarget(_)
    ));
    acknowledge(&state, 1, first_generation, old_id);
    assert_pending(request.as_mut());
    let id = sent(&state, 2, replacement_generation);
    acknowledge(&state, 2, replacement_generation, id);
    let response = created(
        tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(response.session, session);
    assert_eq!(response.home_relay.relay_id, RelayId(2));
    assert_eq!(
        response.home_relay.cert_der,
        RelaySpec {
            id: 2,
            region: None
        }
        .hello()
        .cert_der
    );
    assert!(
        response
            .slot_homes
            .iter()
            .all(|home| home.relay.relay_id == RelayId(2))
    );
    assert_eq!(response.relay_regions.len(), 1);
    assert_eq!(
        response.relay_regions[0].region,
        RegionId("east".to_owned())
    );
}

#[tokio::test]
async fn control_reconnect_requires_a_new_installation_ack() {
    let state = state_with_relay_and_tenant();
    let relay = RelaySpec {
        id: 1,
        region: None,
    };
    let old_generation = capable(&state, relay);
    let body = create_body(two_players());
    let request = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(request);
    assert_pending(request.as_mut());
    let old_id = sent(&state, 1, old_generation);
    acknowledge(&state, 1, old_generation, old_id);
    // An installed descriptor on the old connection is not proof that its
    // replacement control connection has completed the authoritative resync.
    let generation = capable(&state, relay);
    assert!(generation > old_generation);
    assert_pending(request.as_mut());
    let id = sent(&state, 1, generation);
    assert!(
        !state
            .setup
            .descriptors()
            .delivery()
            .acknowledge(RelayId(1), old_generation, old_id)
    );
    assert_pending(request.as_mut());
    acknowledge(&state, 1, generation, id);
    let response = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn capability_only_downgrade_wakes_a_waiting_create() {
    let mut state = state_with_relay_and_tenant();
    state.descriptor_ack_timeout = Duration::from_secs(3600);
    let relay = RelaySpec {
        id: 1,
        region: None,
    };
    capable(&state, relay);
    let body = create_body(two_players());
    let request = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(request);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    assert!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    wakes.0.store(0, Ordering::SeqCst);
    let mesh = registry::subscribe_mesh_peers(state.setup.registry());
    registry::enroll(state.setup.registry(), relay.hello());
    // A capability-only change retains the same mesh identity. The request
    // must be scheduled by registry readiness, without a descriptor push.
    assert!(!mesh.has_changed().unwrap());
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    let response = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn recorded_rehome_answer_follows_a_second_move_while_waiting() {
    let state = state_with_relay_and_tenant();
    let session = create_rehome_session(&state);
    let second_generation = capable(
        &state,
        RelaySpec {
            id: 2,
            region: Some("east"),
        },
    );
    registry::remove(state.setup.registry(), RelayId(1));
    assert!(matches!(
        session::rehome(&state.setup, &tenant_id(), session, RelayId(1), Vec::new()),
        session::RehomeOutcome::NewTarget(_)
    ));
    let first_body = rehome_body(TEST_TENANT, session, 1);
    let app = router(state.clone());
    let recorded = signed_post(
        app.clone(),
        "/session/rehome",
        &first_body,
        &TEST_CLIENT_SEED,
    );
    tokio::pin!(recorded);
    assert_pending(recorded.as_mut());
    let old_id = sent(&state, 2, second_generation);
    let third_generation = capable(
        &state,
        RelaySpec {
            id: 3,
            region: Some("north"),
        },
    );
    registry::remove(state.setup.registry(), RelayId(2));
    let second_body = rehome_body(TEST_TENANT, session, 2);
    let fresh = signed_post(app, "/session/rehome", &second_body, &TEST_CLIENT_SEED);
    tokio::pin!(fresh);
    assert_pending(fresh.as_mut());
    acknowledge(&state, 2, second_generation, old_id);
    assert_pending(recorded.as_mut());
    assert_pending(fresh.as_mut());
    let id = sent(&state, 3, third_generation);
    acknowledge(&state, 3, third_generation, id);
    for response in [
        tokio::time::timeout(Duration::from_secs(1), recorded)
            .await
            .unwrap(),
        tokio::time::timeout(Duration::from_secs(1), fresh)
            .await
            .unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["decision"], "newTarget");
        assert_eq!(json["relay"]["relay_id"], 3);
        assert_eq!(json["relay_region"], "north");
    }
}
