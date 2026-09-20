//! `GET /regions`, `POST /regions/warm`, and the hold-until-ready create that
//! answers `202` while a cold region warms.

use super::*;

async fn get_regions(app: Router) -> serde_json::Value {
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/regions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

#[tokio::test]
async fn regions_endpoint_returns_the_configured_list() {
    // The unauthenticated GET serves the config verbatim (snake_case), in file
    // order — the shape the SB server forwards to every client.
    let mut state = state_with_relay_and_tenant();
    state.regions = crate::regions::RegionsConfig::from_json(
            r#"{"regions": [
                {"id": "us-east", "display_name": "US East", "beacon": "e:20000", "fallback": "e:443"},
                {"id": "eu-west", "display_name": "EU West", "beacon": "w:20000", "fallback": "w:443"}
            ]}"#,
    )
    .unwrap();
    let json = get_regions(router(state)).await;

    let regions = json["regions"].as_array().unwrap();
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0]["id"], "us-east", "file order is preserved");
    assert_eq!(regions[0]["display_name"], "US East");
    assert_eq!(regions[0]["beacon"], "e:20000");
    assert_eq!(regions[0]["fallback"], "e:443");
    assert_eq!(regions[1]["id"], "eu-west");
    assert!(
        json.get("backbone_rtts").is_none(),
        "an empty pair table omits the backbone_rtts field entirely",
    );

    // No config at all is an empty list, not an error — the region-blind
    // posture, served in the same bare `{"regions": [...]}` shape.
    let json = get_regions(router(state_with_relay_and_tenant())).await;
    assert_eq!(json["regions"].as_array().unwrap().len(), 0);
    assert!(json.get("backbone_rtts").is_none());
}

#[tokio::test]
async fn regions_endpoint_serves_recorded_backbone_rtts() {
    // With pairs recorded, the endpoint serves them under backbone_rtts, canonical
    // (a <= b) and sorted, alongside the region list. A pair measured from both ends
    // serves the average of its two directions; a pair measured from one end serves
    // that direction as-is.
    let mut state = state_with_relay_and_tenant();
    state.regions = regions_config(&["us-east", "eu-west", "ap-south"]);
    let now = 1_752_555_555;
    // The eu-west|us-east link is measured from both ends (87 one way, 93 the
    // other), recorded in a non-sorted order — the serve path canonicalizes, sorts,
    // and averages.
    state.pair_rtts.record(
        &RegionId("us-east".to_owned()),
        &RegionId("eu-west".to_owned()),
        87,
        now,
    );
    state.pair_rtts.record(
        &RegionId("eu-west".to_owned()),
        &RegionId("us-east".to_owned()),
        93,
        now + 1,
    );
    // The ap-south|us-east link is measured from one end only.
    state.pair_rtts.record(
        &RegionId("ap-south".to_owned()),
        &RegionId("us-east".to_owned()),
        142,
        now,
    );

    let json = get_regions(router(state)).await;
    assert_eq!(json["regions"].as_array().unwrap().len(), 3);
    let rtts = json["backbone_rtts"].as_array().unwrap();
    assert_eq!(rtts.len(), 2);
    // Sorted by (a, b): ap-south|us-east precedes eu-west|us-east.
    assert_eq!(rtts[0]["a"], "ap-south");
    assert_eq!(rtts[0]["b"], "us-east");
    assert_eq!(
        rtts[0]["rtt_ms"].as_u64().unwrap(),
        142,
        "a single-direction pair serves that direction as-is",
    );
    assert_eq!(rtts[0]["measured_at"].as_u64().unwrap(), now);
    assert_eq!(rtts[1]["a"], "eu-west");
    assert_eq!(rtts[1]["b"], "us-east");
    assert_eq!(
        rtts[1]["rtt_ms"].as_u64().unwrap(),
        90,
        "a two-direction pair serves the average: (87 + 93) / 2 = 90",
    );
    assert_eq!(
        rtts[1]["measured_at"].as_u64().unwrap(),
        now + 1,
        "the served age is the newer of the two directions",
    );
}

/// A coordinator state with `region_ids` configured and relay 1 enrolled
/// untagged (the region-blind fallback). `provisioning` installs the gate so
/// the warm endpoint holds demand and a cold-region create returns `202`; the
/// dormant case still answers the warm endpoint but holds nothing.
fn provisioning_state(region_ids: &[&str], provisioning: bool) -> CoordinatorState {
    let mut setup = SessionFixture::default().setup_only();
    if provisioning {
        setup = setup.with_provision_gate(crate::session::ProvisionGate::provisioning(
            crate::provision::WarmTargets::new(),
            Duration::from_secs(600),
            Duration::from_secs(75),
        ));
    }
    CoordinatorState {
        regions: regions_config(region_ids),
        ..state_over(setup)
    }
}

/// A single-player create request naming `region` for its slot, anchored on
/// `external_id`.
fn region_create_body(region: &str, external_id: &str) -> Vec<u8> {
    let req = SessionRequest {
        tenant: tenant_id(),
        players: vec![PlayerHandoff {
            slot: SlotId(0),
            client_pubkey: ClientPublicKey([0xAA; 32]),
            external_ref: None,
            observer: false,
            region: Some(RegionId(region.to_owned())),
        }],
        external_id: Some(external_id.to_owned()),
        latency_estimate_ms: None,
    };
    serde_json::to_vec(&req).unwrap()
}

#[tokio::test]
async fn warm_endpoint_warms_known_regions_and_reports_unknown() {
    // Whether a provisioning loop is running or the gate is dormant, the
    // endpoint answers the same known/unknown split — only whether the demand
    // is actually recorded differs, so a caller sees one shape either way.
    for provisioning in [true, false] {
        let state = provisioning_state(&["region-a", "region-b"], provisioning);
        let warm = state.setup.provision().warm().clone();
        let app = router(state);

        let body = serde_json::to_vec(&serde_json::json!({
            "tenant": TEST_TENANT,
            "regions": ["region-a", "region-b", "atlantis"],
        }))
        .unwrap();
        let resp = signed_post(app, "/regions/warm", &body, &TEST_CLIENT_SEED).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(
            v["warmed"],
            serde_json::json!(["region-a", "region-b"]),
            "the configured regions are warmed",
        );
        assert_eq!(
            v["unknown"],
            serde_json::json!(["atlantis"]),
            "an unconfigured region is reported, not an error",
        );
        // Each warmed region reads target 1 and the unknown one never does.
        // A dormant coordinator writes the same demand into a store nothing
        // reconciles against, so the endpoint's answer never depends on
        // whether a provisioning loop happens to be running.
        assert_eq!(warm.target_at(&region("region-a"), 0), 1);
        assert_eq!(warm.target_at(&region("region-b"), 0), 1);
        assert_eq!(warm.target_at(&region("atlantis"), 0), 0);
    }
}

#[tokio::test]
async fn cold_region_create_returns_202_then_200_once_a_relay_enrolls() {
    let state = provisioning_state(&["region-a"], true);
    let app = router(state.clone());
    let body = region_create_body("region-a", "g1");

    // region-a has no relay: the create is held with a 202 provisioning body and
    // nothing is minted.
    let resp = signed_post(app.clone(), "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let v = body_json(resp).await;
    assert_eq!(v["status"], "provisioning");
    assert_eq!(v["regions"], serde_json::json!(["region-a"]));
    assert_eq!(v["retryAfterMs"], 2000);
    assert!(
        state.setup.descriptors().current_for(RelayId(1)).is_empty(),
        "a held create stages no descriptor and mints no session",
    );

    // A relay for region-a enrolls; the identical retry now places in-region.
    registry::enroll(
        state.setup.registry(),
        (RelaySpec {
            id: 2,
            region: Some("region-a"),
        })
        .hello(),
    );
    let resp = signed_post(app, "/session/create", &body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let session: SessionResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        session.home_relay.relay_id,
        RelayId(2),
        "the retry placed on the region's freshly enrolled relay",
    );
    assert_eq!(
        session.relay_regions,
        vec![rally_point_proto::control::RelayRegionLabel {
            relay_id: RelayId(2),
            region: RegionId("region-a".to_owned()),
        }],
        "the response labels its home relay with the region it enrolled in",
    );
}

fn region(name: &str) -> RegionId {
    RegionId(name.to_owned())
}
