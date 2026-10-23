use super::*;
use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict, SlotConnectedNotice};

#[tokio::test]
async fn cached_evidence_projects_retained_observations_without_asking_relays() {
    let (setup, session) = SessionFixture::default().build();
    let state = state_over(setup);
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
            tenant: tenant_id(),
            session,
            slot: SlotId(0),
            external_id: None,
            external_ref: None,
            resumed: false,
            connected_at_ms: 1,
            evidence: Some(EvidenceObservation {
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
    let mut asks = state.setup.attest().subscribe(relay);
    let before = state.lifecycle.load_state(&tenant_id(), session).unwrap();
    let response = read_evidence(router(state.clone()), session.0).await;
    assert!(
        asks.try_recv().is_err(),
        "a cached read sends no relay requests"
    );
    let after = state.lifecycle.load_state(&tenant_id(), session).unwrap();
    assert_eq!(before.evidence, after.evidence);
    assert_eq!(before.connected_slots, after.connected_slots);
    assert_eq!(response.as_object().unwrap().len(), 1);
    assert_eq!(
        response["evidence"],
        serde_json::json!([{
            "slot": 0,
            "observation": {
                "connectionId": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
                "sequence": 1,
                "assignmentRevision": 1,
                "verdict": "valid",
                "keyId": 2,
                "body": "AQID",
            }
        }])
    );
}

fn evidence_body(session: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "tenant": TEST_TENANT, "session": session })).unwrap()
}

async fn read_evidence(app: Router, session: u64) -> serde_json::Value {
    let response = signed_post(
        app,
        "/session/evidence",
        &evidence_body(session),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

#[tokio::test]
async fn unknown_session_returns_an_empty_list() {
    assert_eq!(
        read_evidence(router(state_with_relay_and_tenant()), 999).await,
        serde_json::json!({ "evidence": [] }),
    );
}

#[tokio::test]
async fn a_recovery_page_does_not_spend_load_state_tokens_or_vice_versa() {
    let state = state_with_relay_and_tenant();
    let state = CoordinatorState {
        setup: state.setup.clone().with_load_state_limiter(
            crate::endpoint_limits::LoadStateLimiter::new(1, Duration::from_secs(60)),
        ),
        ..state
    };
    let app = router(state);
    for session in 0..100 {
        read_evidence(app.clone(), session).await;
    }
    let response = signed_post(
        app.clone(),
        "/session/load-state",
        &evidence_body(999),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = signed_post(
        app.clone(),
        "/session/load-state",
        &evidence_body(998),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    read_evidence(app, 997).await;
}

#[tokio::test]
async fn evidence_reads_share_a_tenant_budget_and_refusals_supply_retry_after() {
    let state = state_with_relay_and_tenant();
    let state = CoordinatorState {
        setup: state.setup.clone().with_evidence_limiter(
            crate::endpoint_limits::EndpointLimiter::new(1, Duration::from_secs(60)),
        ),
        ..state
    };
    let app = router(state);
    read_evidence(app.clone(), 1).await;
    let response = signed_post(
        app,
        "/session/evidence",
        &evidence_body(2),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[RETRY_AFTER], "60");
}

#[tokio::test]
async fn cached_reads_require_the_named_tenants_signature_and_live_game_access() {
    let state = state_with_relay_and_tenant();
    let app = router(state.clone());
    let response = signed_post(
        app.clone(),
        "/session/evidence",
        &evidence_body(1),
        &UNENROLLED_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let other =
        serde_json::to_vec(&serde_json::json!({"tenant": "another-tenant", "session": 1})).unwrap();
    let response = signed_post(app.clone(), "/session/evidence", &other, &TEST_CLIENT_SEED).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    crate::tenant::set_state(
        state.setup.tenants(),
        &tenant_id(),
        crate::tenant::TenantState::Suspended,
    );
    read_evidence(app.clone(), 1).await;
    crate::tenant::set_state(
        state.setup.tenants(),
        &tenant_id(),
        crate::tenant::TenantState::Revoked,
    );
    let response = signed_post(
        app,
        "/session/evidence",
        &evidence_body(1),
        &TEST_CLIENT_SEED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn evidence_budget_sustains_recovery_pages_with_headroom() {
    let limiter = crate::endpoint_limits::EndpointLimiter::new(
        crate::endpoint_limits::EVIDENCE_BURST,
        crate::endpoint_limits::EVIDENCE_REFILL_INTERVAL,
    );
    let start = Instant::now();
    for page in 0..10 {
        for _ in 0..150 {
            assert!(limiter.check_at(&tenant_id(), start + Duration::from_secs(30 * page)));
        }
    }
}

#[tokio::test]
async fn cached_and_load_state_reads_include_admission_and_latest_periodic_sample() {
    use rally_point_proto::control::{
        CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceKey, SlotEvidence, SlotEvidenceNotice,
    };
    let setup = SessionFixture::default().setup_only();
    let mut request = crate::test_support::request(crate::test_support::two_players());
    request.periodic_evidence = true;
    request.evidence_keys = vec![EvidenceKey {
        key_id: 7,
        public_key: rally_point_proto::token::ClientPublicKey([4; 32]),
    }];
    let session = crate::session::create_session(
        &setup,
        request,
        rally_point_proto::token::ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
    .session;
    let mut state = state_over(setup);
    state.attest_timeout = Duration::from_millis(1);
    let relay = RelayId(1);
    let generation = state
        .lifecycle
        .enroll_relay_epoch(relay, || {
            Ok::<_, ()>(registry::enroll(
                state.setup.registry(),
                crate::test_support::hello(1, 14901)
                    .with_boot_id(7)
                    .with_capabilities(vec![CAPABILITY_PERIODIC_EVIDENCE_V1.into()]),
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
    let admission = EvidenceObservation {
        sample_id: 0,
        connection_id: [9; 32],
        sequence: 1,
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![1],
    };
    state.lifecycle.merge_connection_evidence(
        relay,
        generation,
        &[rally_point_proto::control::SessionPresence {
            evidence: vec![SlotEvidence {
                slot: SlotId(0),
                observation: admission.clone(),
            }],
            ..crate::test_support::presence_entry(&tenant_id(), session, &[])
        }],
    );
    state.lifecycle.ingest_notice(
        relay,
        generation,
        crate::lifecycle::SessionNotice::SlotEvidence(SlotEvidenceNotice {
            tenant: tenant_id(),
            session,
            slot: SlotId(0),
            external_id: None,
            external_ref: None,
            observed_at_ms: 1,
            evidence: EvidenceObservation {
                sample_id: 1,
                sequence: 2,
                ..admission
            },
        }),
    );
    for path in ["/session/evidence", "/session/load-state"] {
        let response = signed_post(
            router(state.clone()),
            path,
            &evidence_body(session.0),
            &TEST_CLIENT_SEED,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["evidence"].as_array().unwrap().len(), 2);
        assert!(json["evidence"][0]["observation"].get("sampleId").is_none());
        assert_eq!(json["evidence"][1]["observation"]["sampleId"], 1);
        assert_eq!(json["evidence"][1]["observation"]["sequence"], 2);
    }
}
