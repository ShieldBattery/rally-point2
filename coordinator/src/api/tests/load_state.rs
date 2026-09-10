//! `POST /session/load-state`: the attestation exchange behind the
//! completeness claim, its rate limit, and the states that withhold the claim.

use super::*;

/// A roster/snapshot entry for `session` naming the slots that ever connected
/// and the slots that ever started.
fn load_snapshot(
    tenant: &TenantId,
    session: SessionId,
    ever_connected: &[u8],
    started: &[u8],
    started_at_ms: Option<u64>,
) -> rally_point_proto::control::SessionPresence {
    rally_point_proto::control::SessionPresence {
        tenant: tenant.clone(),
        session,
        slots: vec![],
        ever_connected: ever_connected.iter().map(|&s| SlotId(s)).collect(),
        started: started.iter().map(|&s| SlotId(s)).collect(),
        started_at_ms,
    }
}

/// Stands a relay's control connection in for the load-state exchange: drains
/// the questions addressed to `relay` and answers each with `snapshot`, through
/// the same inbound path a real connection's reader takes. The returned handle
/// is aborted by the test to model a relay going away.
fn spawn_attesting_relay(
    state: &CoordinatorState,
    relay: RelayId,
    snapshot: rally_point_proto::control::SessionPresence,
) -> tokio::task::JoinHandle<()> {
    spawn_relay_attesting_as(state, relay, snapshot, true)
}

/// [`spawn_attesting_relay`] with the fence verdict spelled out, so a test can
/// stand in a relay that answers but could not fence.
fn spawn_relay_attesting_as(
    state: &CoordinatorState,
    relay: RelayId,
    snapshot: rally_point_proto::control::SessionPresence,
    fenced: bool,
) -> tokio::task::JoinHandle<()> {
    let setup = state.setup.clone();
    let notices = state.notices.clone();
    let lifecycle = state.lifecycle.clone();
    let mut asks = setup.attest().subscribe(relay);
    tokio::spawn(async move {
        let regions = RegionsConfig::default();
        let store = pair_rtts::new_store();
        let rtt = idle_rtt_ingest(&regions, &store);
        while let Some(ask) = asks.recv().await {
            let frame = Message::Text(
                serde_json::to_string(&RelayToCoordinator::LoadStateSnapshot {
                    request_id: ask.request_id,
                    state: snapshot.clone(),
                    fenced,
                })
                .expect("a snapshot serializes")
                .into(),
            );
            note_inbound_frame(&setup, &notices, &lifecycle, relay, 0, &frame, &rtt);
        }
    })
}

/// Posts a signed load-state read for `session` and returns the raw body.
async fn read_load_state(app: axum::Router, session: u64) -> axum::body::Bytes {
    let body = serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "session": session }))
        .unwrap();
    let resp = signed_post(app, "/session/load-state", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
}

#[tokio::test]
async fn every_serving_relay_attesting_makes_the_answer_complete() {
    // The causal barrier: both serving relays snapshot after this read's own
    // request reached them, so the union of their answers covers everything
    // that had happened before the read was sent — and an absent slot may be
    // read as a player who never arrived.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1), RelayId(2)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    // Each relay knows only its own slot; the answer is their union. Recorded
    // out of slot order to prove the answer is sorted, not insertion-ordered.
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[1], &[1], Some(1_700_000_000_000)),
    );
    let _two = spawn_attesting_relay(
        &state,
        RelayId(2),
        load_snapshot(&tenant, SessionId(5), &[0], &[], None),
    );
    let app = router(state);

    let body = read_load_state(app, 5).await;
    // The exact wire shape the tenant parses: camelCase, absent optionals
    // omitted rather than sent as null, and no freshness stamp anywhere —
    // completeness is the exchange, not a clock.
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":true,"startedAtMs":1700000000000,"connectedSlots":[0,1],"startedSlots":[1]}"#,
    );
}

#[tokio::test]
async fn one_unfenced_relay_costs_the_claim_but_not_the_others_facts() {
    // A relay that answers promptly but could not fence one of its slots is not
    // silent — its facts merge and return like anyone's — but it cannot rule out
    // a report queued in that slot's client, so absence stops being proof.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1), RelayId(2)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[1], &[1], None),
    );
    let _two = spawn_relay_attesting_as(
        &state,
        RelayId(2),
        load_snapshot(&tenant, SessionId(5), &[0], &[], None),
        false,
    );
    let app = router(state);

    let body = read_load_state(app, 5).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[0,1],"startedSlots":[1]}"#,
        "both relays' positives stand; only the negative inference is withheld",
    );
}

/// Stands a relay's control connection in for the load-state exchange, holding
/// each answer until `gate` is notified and reporting every question it received
/// over the returned channel — the shape a test needs to observe how many rounds
/// of questions a burst of reads actually cost.
fn spawn_gated_attesting_relay(
    state: &CoordinatorState,
    relay: RelayId,
    snapshot: rally_point_proto::control::SessionPresence,
    gate: std::sync::Arc<tokio::sync::Notify>,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<u64>,
) {
    let setup = state.setup.clone();
    let notices = state.notices.clone();
    let lifecycle = state.lifecycle.clone();
    let mut asks = setup.attest().subscribe(relay);
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = tokio::spawn(async move {
        let regions = RegionsConfig::default();
        let store = pair_rtts::new_store();
        let rtt = idle_rtt_ingest(&regions, &store);
        while let Some(ask) = asks.recv().await {
            let _ = seen_tx.send(ask.request_id);
            gate.notified().await;
            let frame = Message::Text(
                serde_json::to_string(&RelayToCoordinator::LoadStateSnapshot {
                    request_id: ask.request_id,
                    state: snapshot.clone(),
                    fenced: true,
                })
                .expect("a snapshot serializes")
                .into(),
            );
            note_inbound_frame(&setup, &notices, &lifecycle, relay, 0, &frame, &rtt);
        }
    });
    (handle, seen_rx)
}

#[tokio::test]
async fn concurrent_reads_of_one_session_cost_fewer_rounds_than_reads() {
    // The fanout bound. Three overlapping reads of one session must not put
    // three rounds of questions to the fleet: the two that arrive while the
    // first round is running wait it out and then share a single round of their
    // own — one they can actually use, since it dispatches after they asked.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let (_relay, mut questions) = spawn_gated_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[0], &[0], None),
        std::sync::Arc::clone(&gate),
    );
    let app = router(state);

    // The first read leads a round and parks on the gated relay.
    let first = tokio::spawn(read_load_state(app.clone(), 5));
    questions
        .recv()
        .await
        .expect("the first read's question reaches the relay");

    // Two more arrive while that round is still open; give them time to join it
    // before anything is released.
    let second = tokio::spawn(read_load_state(app.clone(), 5));
    let third = tokio::spawn(read_load_state(app, 5));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Release everything: the first round completes, then the one round the
    // other two share.
    let releaser = tokio::spawn(async move {
        loop {
            gate.notify_waiters();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    for read in [first, second, third] {
        let body = read.await.expect("the read completes");
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"known":true,"connectedSlots":[0],"startedSlots":[0]}"#,
        );
    }
    releaser.abort();

    let mut rounds = 1;
    while questions.try_recv().is_ok() {
        rounds += 1;
    }
    assert_eq!(
        rounds, 2,
        "the two joiners shared one round rather than each running their own",
    );
}

#[tokio::test]
async fn a_tenant_reading_past_its_rate_limit_gets_a_429_with_a_retry_after() {
    // The read questions every relay serving the named session and holds a fence
    // open on each, so the limit is the tenant's rather than the session's: a
    // caller cannot buy a fresh burst by naming a different session.
    let state = state_with_relay_and_tenant();
    let state =
        CoordinatorState {
            setup: state.setup.clone().with_load_state_limiter(
                crate::rehome::LoadStateLimiter::new(1, Duration::from_secs(60)),
            ),
            ..state
        };
    let app = router(state);

    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "session": 5 })).unwrap();
    let resp = signed_post(app.clone(), "/session/load-state", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A different session, and therefore a request the per-session re-home limit
    // would have admitted: this one still spends the tenant's last token.
    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "session": 6 })).unwrap();
    let resp = signed_post(app, "/session/load-state", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get(RETRY_AFTER)
            .expect("a refused read says when to come back"),
        "60",
        "the header names the injected limiter's own refill interval",
    );
}

#[tokio::test]
async fn one_silent_relay_costs_the_claim_but_not_the_others_facts() {
    // The distinction the whole design turns on: a relay that does not answer
    // is not a relay answering "nothing". Its peer's positives are merged and
    // returned; only the right to read an absence as proof is withheld.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1), RelayId(2)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[1], &[1], None),
    );
    // Relay 2 holds a connection but never answers: subscribed, never drained.
    let _silent = state.setup.attest().subscribe(RelayId(2));
    let app = router(state);

    let body = tokio::time::timeout(LOAD_STATE_ATTEST_TIMEOUT * 2, read_load_state(app, 5))
        .await
        .expect("the read answers on its own deadline rather than hanging");
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[1],"startedSlots":[1]}"#,
    );
}

#[tokio::test]
async fn a_relay_with_no_control_connection_never_attests() {
    // Nothing to ask means nothing answered. The session's other facts stand;
    // the claim does not.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1), RelayId(2)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    state
        .lifecycle
        .on_slot_connected(tenant.clone(), SessionId(5), SlotId(0));
    // Only relay 1 is connected; relay 2 has never subscribed.
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[], &[], None),
    );
    let app = router(state);

    let body = read_load_state(app, 5).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[0],"startedSlots":[]}"#,
    );
}

#[tokio::test]
async fn a_broken_lineage_withholds_the_claim_even_when_every_relay_attests() {
    // The serving relay answers promptly and completely, but it came back as a
    // new process: whatever the old one saw and never restated is gone, and no
    // snapshot from this one can cover that interval.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    state.lifecycle.on_relay_lineage_break(RelayId(1));
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        load_snapshot(&tenant, SessionId(5), &[1], &[], None),
    );
    let app = router(state);

    let body = read_load_state(app, 5).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[1],"startedSlots":[]}"#,
        "the facts the snapshot carried still stand",
    );
}

#[tokio::test]
async fn a_session_the_coordinator_holds_nothing_for_answers_no_information() {
    // Never "nobody arrived": known false, empty sets, absent optionals omitted
    // rather than sent as null.
    let state = state_with_relay_and_tenant();
    let app = router(state);
    let body = read_load_state(app, 6).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[],"startedSlots":[]}"#,
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("startedAtMs").is_none(), "absent, never null");
}

#[tokio::test]
async fn a_session_this_coordinator_never_created_answers_its_facts_only() {
    // Restart amnesia, with a relay still reporting: the accumulated facts are
    // answered with, and no completeness claim is made — the sets start
    // wherever this process came up, so an absent slot says nothing.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    state
        .lifecycle
        .on_slot_connected(tenant.clone(), SessionId(7), SlotId(0));
    state
        .lifecycle
        .on_slot_started(tenant, SessionId(7), SlotId(0));
    let app = router(state);

    let body = read_load_state(app, 7).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[0],"startedSlots":[0]}"#,
        "the facts stand; only the read-absence-as-proof claim is withheld",
    );
}

#[tokio::test]
async fn a_snapshot_correlated_to_another_relays_request_is_discarded() {
    // A correlation id is a handle to one relay's answer. A relay answering
    // under an id that is not its own must not complete the set for the relay
    // that was actually asked — otherwise one relay could vouch for another's
    // silence, which is exactly the claim the exchange exists to prevent.
    let state = state_with_relay_and_tenant();
    let tenant = TenantId("sb-test".to_owned());
    let attest = state.setup.attest().clone();
    let mut asks_one = attest.subscribe(RelayId(1));
    let _asks_two = attest.subscribe(RelayId(2));
    let one = attest
        .request(RelayId(1), &tenant, SessionId(5))
        .expect("relay 1 is connected");
    let ask = asks_one.recv().await.expect("the question was queued");

    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let frame = Message::Text(
        serde_json::to_string(&RelayToCoordinator::LoadStateSnapshot {
            request_id: ask.request_id,
            state: load_snapshot(&tenant, SessionId(5), &[0], &[], None),
            fenced: true,
        })
        .unwrap()
        .into(),
    );
    note_inbound_frame(
        &state.setup,
        &state.notices,
        &state.lifecycle,
        RelayId(2),
        0,
        &frame,
        &rtt,
    );

    // Relay 2's positives are still merged — they are facts about the session
    // whoever reports them — but relay 1's request is untouched.
    assert_eq!(
        state
            .lifecycle
            .load_state(&tenant, SessionId(5))
            .expect("the merge created the state")
            .connected_slots,
        vec![SlotId(0)],
    );
    assert_eq!(
        attest.pending_count(),
        1,
        "relay 1 is still waiting to be answered",
    );
    drop(one);
}

#[tokio::test]
async fn session_load_state_rejects_an_unsigned_request() {
    // The read is past the same tenant-signature gate as every other
    // tenant-facing endpoint: an unsigned body never reaches the lifecycle.
    let state = state_with_relay_and_tenant();
    let app = router(state);
    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": "sb-test", "session": 5 })).unwrap();
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/session/load-state")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
