//! A retired session: the load facts the coordinator kept when its state was
//! retired are answered, with no relay asked and every completeness flag false.

use super::*;
use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict, SlotConnectedNotice};

#[tokio::test]
async fn a_closed_session_answers_its_facts_with_no_claim_and_asks_no_relay() {
    // The short game: both players connected, one reported its loop, and the
    // session closed before the tenant's load deadline. The read that deadline
    // triggers must still return those facts, and must vouch for nothing.
    let (setup, session) = SessionFixture {
        players: plain_players(&[0, 1]),
        ..Default::default()
    }
    .build();
    // An attestation deadline no test could wait out: a read that put a question
    // to any relay would hang on the silent subscriber below.
    let state = CoordinatorState {
        attest_timeout: Duration::from_secs(3600),
        ..state_over(setup)
    };
    let tenant = tenant_id();
    let serving = state.setup.serving_relays(&tenant, session);
    assert_eq!(serving, vec![RelayId(1)]);
    state.lifecycle.register_session(
        tenant.clone(),
        session,
        serving,
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    let generation = registry::enroll(
        state.setup.registry(),
        (RelaySpec {
            id: 1,
            region: None,
        })
        .hello(),
    );
    state.lifecycle.on_relay_enrolled(RelayId(1), generation);
    state
        .lifecycle
        .on_slot_connected(tenant.clone(), session, SlotId(1));
    state
        .lifecycle
        .on_slot_connected(tenant.clone(), session, SlotId(0));
    state
        .lifecycle
        .on_slot_started(tenant.clone(), session, SlotId(0));
    state
        .lifecycle
        .on_session_started(tenant.clone(), session, 1_700_000_000_000);

    let regions = RegionsConfig::default();
    let store = pair_rtts::PairRttStore::new();
    let rtt = idle_rtt_ingest(&regions, &store);
    let closed = Message::Text(
        serde_json::to_string(&RelayToCoordinator::SessionClosed {
            tenant: tenant.clone(),
            session,
        })
        .unwrap()
        .into(),
    );
    note_inbound_frame(
        &state.setup,
        &state.lifecycle,
        RelayId(1),
        generation,
        &closed,
        &rtt,
    );
    assert!(!state.lifecycle.is_alive(&tenant, session));
    assert!(state.setup.serving_relays(&tenant, session).is_empty());

    let mut questions = state.setup.attest().subscribe(RelayId(1));
    let app = router(state);
    let expected = r#"{"known":false,"turnsKnown":false,"closedKnown":false,"setupFinal":false,"startedAtMs":1700000000000,"connectedSlots":[0,1],"startedSlots":[0],"forwardedSlots":[],"lobbyViolationSlots":[],"closedSlots":[],"liveSlots":[]}"#;

    let body = tokio::time::timeout(
        Duration::from_secs(5),
        read_load_state(app.clone(), session.0),
    )
    .await
    .expect("a read with no relay to ask returns at once");
    assert_eq!(std::str::from_utf8(&body).unwrap(), expected);

    // Asking to settle the lobby changes nothing: there is no relay to settle,
    // and the answer still claims no finality.
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        settle_lobby_load_state(app, session.0),
    )
    .await
    .expect("a settling read with no relay to ask returns at once");
    assert_eq!(std::str::from_utf8(&body).unwrap(), expected);

    assert!(
        questions.try_recv().is_err(),
        "no question went to the relay that served the session",
    );
}

#[tokio::test]
async fn a_session_retired_during_the_exchange_still_answers_its_connection_observations() {
    let (setup, session) = SessionFixture::default().build();
    // The one serving relay is asked and never answers, so the exchange stays open
    // for this long: the window in which the test retires the session.
    let state = CoordinatorState {
        attest_timeout: Duration::from_millis(500),
        ..state_over(setup)
    };
    let relay = RelayId(1);
    let generation = state
        .lifecycle
        .enroll_relay_epoch(relay, || {
            Ok::<_, ()>(registry::enroll(
                state.setup.registry(),
                crate::test_support::hello(1, 14901).with_boot_id(7),
            ))
        })
        .unwrap();
    registry::note_boot_id(state.setup.registry(), relay, Some(7));
    state.lifecycle.register_session(
        tenant_id(),
        session,
        vec![relay],
        std::collections::HashSet::from([SlotId(0)]),
        Default::default(),
    );
    state.lifecycle.ingest_notice(
        relay,
        generation,
        crate::lifecycle::SessionNotice::SlotConnected(SlotConnectedNotice {
            predecessor: None,
            tenant: tenant_id(),
            session,
            slot: SlotId(0),
            external_id: None,
            external_ref: None,
            resumed: false,
            connected_at_ms: 1,
            evidence: Some(EvidenceObservation {
                interruption: None,
                sample_id: 0,
                connection_id: [9; 32],
                sequence: 1,
                assignment_revision: 1,
                verdict: EvidenceVerdict::Valid,
                key_id: Some(2),
                body: vec![1, 2, 3],
            }),
        }),
    );

    let setup = state.setup.clone();
    let lifecycle = state.lifecycle.clone();
    let mut questions = setup.attest().subscribe(relay);
    let read = tokio::spawn(read_load_state(router(state), session.0));
    // The question going out means the read has already taken its pre-exchange
    // facts, observations included.
    questions.recv().await.expect("the serving relay is asked");

    let regions = RegionsConfig::default();
    let store = pair_rtts::PairRttStore::new();
    let rtt = idle_rtt_ingest(&regions, &store);
    let closed = Message::Text(
        serde_json::to_string(&RelayToCoordinator::SessionClosed {
            tenant: tenant_id(),
            session,
        })
        .unwrap()
        .into(),
    );
    note_inbound_frame(&setup, &lifecycle, relay, generation, &closed, &rtt);
    assert!(!lifecycle.is_alive(&tenant_id(), session));

    let body = read.await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["known"], serde_json::json!(false));
    assert_eq!(response["connectedSlots"], serde_json::json!([0]));
    assert_eq!(response["evidence"][0]["slot"], serde_json::json!(0));
    assert_eq!(
        response["evidence"][0]["observation"]["body"],
        serde_json::json!("AQID"),
    );
}
