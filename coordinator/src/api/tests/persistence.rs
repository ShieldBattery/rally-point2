//! Create and re-home refuse to answer until the session state behind the answer
//! is durable: a storage fault is a retryable `503`, and the retry — replayed
//! from the state the refused request already committed in memory — succeeds
//! and persists once storage does.

use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::ledger::RelayLedger;
use crate::persist::SessionStore;

/// The endpoint-test state with a session store over an in-memory ledger, plus
/// the ledger handle so a test can inject the storage fault.
fn state_with_store() -> (CoordinatorState, Arc<RelayLedger>) {
    let mut state = state_with_relay_and_tenant();
    let ledger = Arc::new(RelayLedger::open(Path::new(":memory:")).unwrap());
    let (store, _) =
        SessionStore::restore(ledger.clone(), state.setup.clone(), state.lifecycle.clone())
            .unwrap();
    state.session_store = Some(Arc::new(store));
    (state, ledger)
}

/// The sessions a coordinator restarted over `ledger` would hold, with their
/// serving relays.
fn restored_sessions(ledger: &Arc<RelayLedger>) -> Vec<(SessionId, Vec<RelayId>)> {
    let setup = SessionFixture::default().setup_only();
    let lifecycle = Lifecycle::new(setup.clone());
    SessionStore::restore(ledger.clone(), setup.clone(), lifecycle).unwrap();
    ledger
        .session_records()
        .unwrap()
        .into_iter()
        .map(|row| (row.session, setup.serving_relays(&tenant_id(), row.session)))
        .collect()
}

#[tokio::test]
async fn a_create_that_cannot_be_persisted_is_refused_and_its_retry_replays() {
    let (state, ledger) = state_with_store();
    let body = serde_json::to_vec(&SessionRequest {
        periodic_evidence: false,
        evidence_keys: Vec::new(),
        lobby_policy: None,
        rollback: false,
        tenant: tenant_id(),
        players: two_players(),
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    })
    .unwrap();

    ledger.set_session_writes_failing(true);
    let resp = signed_post(
        router(state.clone()),
        "/session/create",
        &body,
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no token leaves for a session a restart would forget",
    );

    assert_eq!(resp.headers()[RETRY_AFTER], "1");
    let committed = state.setup.descriptors().current_for(RelayId(1));
    assert_eq!(committed.len(), 1);

    // Storage recovers; the tenant's retry replays the session the refused
    // request committed, and only now answers — with it durable.
    ledger.set_session_writes_failing(false);
    let resp = signed_post(router(state), "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key(RETRY_AFTER));
    let created: SessionResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(created.session, committed[0].session);
    assert_eq!(
        restored_sessions(&ledger),
        vec![(created.session, vec![RelayId(1)])],
        "the replayed session is what a restart restores",
    );
}

#[tokio::test]
async fn a_rehome_that_cannot_be_persisted_is_refused_and_its_re_ask_persists_it() {
    let (state, ledger) = state_with_store();
    enroll_second_relay(&state, None);
    let session = create_rehome_session(&state);
    state.lifecycle.register_session(
        tenant_id(),
        session,
        state.setup.serving_relays(&tenant_id(), session),
        [SlotId(0)].into_iter().collect(),
        Default::default(),
    );
    state.session_store.as_ref().unwrap().flush().unwrap();
    registry::remove(state.setup.registry(), RelayId(1));
    let body = rehome_body(TEST_TENANT, session, 1);

    ledger.set_session_writes_failing(true);
    let resp = signed_post(
        router(state.clone()),
        "/session/rehome",
        &body,
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "no client is pointed at a move a restart would forget",
    );

    assert!(!resp.headers().contains_key(RETRY_AFTER));

    // The re-ask takes the recorded fast path for the move the refused ask
    // committed, and answers only once that move is durable.
    ledger.set_session_writes_failing(false);
    let resp = signed_post(router(state), "/session/rehome", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["decision"], "newTarget");
    assert_eq!(
        restored_sessions(&ledger),
        vec![(session, vec![RelayId(2)])]
    );
}
