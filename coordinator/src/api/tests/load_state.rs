//! `POST /session/load-state`: the attestation exchange behind the
//! completeness claim, its rate limit, and the states that withhold the claim.

use rally_point_proto::control::SessionPresence;

use super::*;

/// How a stand-in relay answers the questions addressed to it.
struct AttestOptions {
    /// Whether its snapshot claims the session was fenced against its own
    /// clients — the difference between a relay that merely answered and one
    /// whose answer rules out a report still queued in a client.
    fenced: bool,
    /// When set, each answer is held until the test sends a release, so a test
    /// can keep a round open while other reads arrive.
    release: Option<tokio::sync::mpsc::Receiver<()>>,
    /// When set, every question's correlation id is reported here as it
    /// arrives — how a test counts the rounds a burst of reads actually cost.
    seen: Option<tokio::sync::mpsc::UnboundedSender<u64>>,
}

impl Default for AttestOptions {
    fn default() -> Self {
        Self {
            fenced: true,
            release: None,
            seen: None,
        }
    }
}

/// Stands a relay's control connection in for the load-state exchange: drains
/// the questions addressed to `relay` and answers each with `snapshot`, through
/// the same inbound path a real connection's reader takes. The returned handle
/// is aborted by the test to model a relay going away.
fn spawn_attesting_relay(
    state: &CoordinatorState,
    relay: RelayId,
    snapshot: SessionPresence,
    opts: AttestOptions,
) -> tokio::task::JoinHandle<()> {
    let setup = state.setup.clone();
    let notices = state.notices.clone();
    let lifecycle = state.lifecycle.clone();
    let mut asks = setup.attest().subscribe(relay);
    let AttestOptions {
        fenced,
        mut release,
        seen,
    } = opts;
    tokio::spawn(async move {
        let regions = RegionsConfig::default();
        let store = pair_rtts::new_store();
        let rtt = idle_rtt_ingest(&regions, &store);
        while let Some(ask) = asks.recv().await {
            if let Some(seen) = &seen {
                let _ = seen.send(ask.request_id);
            }
            if let Some(release) = release.as_mut() {
                release.recv().await;
            }
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
    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": TEST_TENANT, "session": session }))
            .unwrap();
    let resp = signed_post(app, "/session/load-state", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
}

/// Registers session 5 as served by `serving`, with slots 0 and 1 expected.
fn register_session_five(state: &CoordinatorState, serving: Vec<RelayId>) {
    state.lifecycle.register_session(
        tenant_id(),
        SessionId(5),
        serving,
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
}

#[tokio::test]
async fn every_serving_relay_attesting_makes_the_answer_complete() {
    // The causal barrier: both serving relays snapshot after this read's own
    // request reached them, so the union of their answers covers everything
    // that had happened before the read was sent — and an absent slot may be
    // read as a player who never arrived.
    let state = state_with_relay_and_tenant();
    let tenant = tenant_id();
    register_session_five(&state, vec![RelayId(1), RelayId(2)]);
    // Each relay knows only its own slot; the answer is their union. Recorded
    // out of slot order to prove the answer is sorted, not insertion-ordered.
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[1]),
            started: slots(&[1]),
            started_at_ms: Some(1_700_000_000_000),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions::default(),
    );
    let _two = spawn_attesting_relay(
        &state,
        RelayId(2),
        SessionPresence {
            ever_connected: slots(&[0]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions::default(),
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
    let tenant = tenant_id();
    register_session_five(&state, vec![RelayId(1), RelayId(2)]);
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[1]),
            started: slots(&[1]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions::default(),
    );
    let _two = spawn_attesting_relay(
        &state,
        RelayId(2),
        SessionPresence {
            ever_connected: slots(&[0]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions {
            fenced: false,
            ..Default::default()
        },
    );
    let app = router(state);

    let body = read_load_state(app, 5).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"connectedSlots":[0,1],"startedSlots":[1]}"#,
        "both relays' positives stand; only the negative inference is withheld",
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_reads_of_one_session_cost_fewer_rounds_than_reads() {
    // The fanout bound. Three overlapping reads of one session must not put
    // three rounds of questions to the fleet: the two that arrive while the
    // first round is running wait it out and then share a single round of their
    // own — one they can actually use, since it dispatches after they asked.
    let state = state_with_relay_and_tenant();
    let tenant = tenant_id();
    state.lifecycle.register_session(
        tenant.clone(),
        SessionId(5),
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let (release, release_rx) = tokio::sync::mpsc::channel(4);
    let (seen, mut questions) = tokio::sync::mpsc::unbounded_channel();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0]),
            started: slots(&[0]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions {
            release: Some(release_rx),
            seen: Some(seen),
            ..Default::default()
        },
    );
    let app = router(state);

    // The first read leads a round and parks on the held relay.
    let first = tokio::spawn(read_load_state(app.clone(), 5));
    questions
        .recv()
        .await
        .expect("the first read's question reaches the relay");

    // Two more arrive while that round is still open. Under the paused clock a
    // sleep only elapses once every other task has parked, so both joiners have
    // provably reached the round before anything below releases it.
    let second = tokio::spawn(read_load_state(app.clone(), 5));
    let third = tokio::spawn(read_load_state(app, 5));
    tokio::time::sleep(Duration::from_millis(1)).await;

    // Release the leader's answer; the two joiners then run exactly one round
    // between them, which this releases in turn.
    release.send(()).await.unwrap();
    questions
        .recv()
        .await
        .expect("the two joiners share one further round");
    release.send(()).await.unwrap();

    for read in [first, second, third] {
        let body = read.await.expect("the read completes");
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"known":true,"connectedSlots":[0],"startedSlots":[0]}"#,
        );
    }
    assert!(
        questions.try_recv().is_err(),
        "two rounds of questions served three reads: the joiners shared one \
         rather than each running their own",
    );
}

#[tokio::test]
async fn a_tenant_reading_past_its_rate_limit_gets_a_429_with_a_retry_after() {
    // The read questions every relay serving the named session and holds a fence
    // open on each, so the limit is the tenant's rather than the session's: a
    // caller cannot buy a fresh burst by naming a different session.
    let state = state_with_relay_and_tenant();
    let state = CoordinatorState {
        setup: state.setup.clone().with_load_state_limiter(
            crate::endpoint_limits::LoadStateLimiter::new(1, Duration::from_secs(60)),
        ),
        ..state
    };
    let app = router(state);

    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": TEST_TENANT, "session": 5 })).unwrap();
    let resp = signed_post(app.clone(), "/session/load-state", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // A different session, and therefore a request the per-session re-home limit
    // would have admitted: this one still spends the tenant's last token.
    let body =
        serde_json::to_vec(&serde_json::json!({ "tenant": TEST_TENANT, "session": 6 })).unwrap();
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

#[tokio::test(start_paused = true)]
async fn one_silent_relay_costs_the_claim_but_not_the_others_facts() {
    // The distinction the whole design turns on: a relay that does not answer
    // is not a relay answering "nothing". Its peer's positives are merged and
    // returned; only the right to read an absence as proof is withheld.
    //
    // The read's own attestation deadline is what ends it, so it is injected
    // short and the clock is paused: the deadline is then reached exactly, the
    // moment nothing else can make progress, rather than waited out.
    let state = CoordinatorState {
        attest_timeout: Duration::from_millis(50),
        ..state_with_relay_and_tenant()
    };
    let tenant = tenant_id();
    register_session_five(&state, vec![RelayId(1), RelayId(2)]);
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[1]),
            started: slots(&[1]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions::default(),
    );
    // Relay 2 holds a connection but never answers: subscribed, never drained.
    let _silent = state.setup.attest().subscribe(RelayId(2));
    let app = router(state);

    let body = read_load_state(app, 5).await;
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
    let tenant = tenant_id();
    register_session_five(&state, vec![RelayId(1), RelayId(2)]);
    state
        .lifecycle
        .on_slot_connected(tenant.clone(), SessionId(5), SlotId(0));
    // Only relay 1 is connected; relay 2 has never subscribed.
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        presence_entry(&tenant, SessionId(5), &[]),
        AttestOptions::default(),
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
    let tenant = tenant_id();
    register_session_five(&state, vec![RelayId(1)]);
    state.lifecycle.on_relay_lineage_break(RelayId(1));
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[1]),
            ..presence_entry(&tenant, SessionId(5), &[])
        },
        AttestOptions::default(),
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
    let tenant = tenant_id();
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
    let tenant = tenant_id();
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
            state: SessionPresence {
                ever_connected: slots(&[0]),
                ..presence_entry(&tenant, SessionId(5), &[])
            },
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
