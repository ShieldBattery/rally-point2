//! Signed HTTP creation waits for the real relay subscriber to install and
//! acknowledge its descriptor, and idempotent retries preserve the handoff.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioExecutor;
use rally_point_coordinator::tenant;
use rally_point_proto::control::{
    CAPABILITY_DESCRIPTOR_ACK_V1, PlayerHandoff, SessionRequest, SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SlotId};
use rally_point_proto::request_auth;
use rally_point_proto::token::ClientPublicKey;
use rally_point_relay::coordinator::client::{EnrollConfig, run_descriptor_subscriber_with};
use rally_point_relay::mesh::{MeshState, control::MeshControl};
use ring::signature::Ed25519KeyPair;

use crate::common::{CoordinatorBuilder, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn signed_create_waits_for_real_relay_installation_and_replays_the_handoff() {
    let served = CoordinatorBuilder::new().with_tenant().serve().await;
    let tenant = TenantId(TENANT.to_owned());
    let seed = [0x37; 32];
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    tenant::set_client_pubkeys(
        served.setup.tenants(),
        &tenant,
        vec![tenant::client_pubkey_from_seed(&seed).unwrap()],
    );

    let mesh = MeshState::default();
    let control = MeshControl::new(RelayId(1), &mesh, Default::default());
    let targets = apply_targets(control);
    let applied = targets.applied.clone();
    assert!(applied.is_empty());
    let mut hello = relay_hello(1, 14900);
    hello
        .capabilities
        .push(CAPABILITY_DESCRIPTOR_ACK_V1.to_owned());
    let subscriber = tokio::spawn(run_descriptor_subscriber_with(
        EnrollConfig {
            coordinator_url: served.base_url.clone(),
            bootstrap_secret: None,
            relay_hello: hello,
            identity_key: relay_key(1),
        },
        targets,
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));
    assert!(wait_for_enrollment(served.registry(), RelayId(1)).await);
    assert!(applied.is_empty(), "enrollment has no session to install");

    let body = serde_json::to_vec(&SessionRequest {
        periodic_evidence: false,
        tenant,
        players: (0..2)
            .map(|slot| PlayerHandoff {
                slot: SlotId(slot),
                client_pubkey: ClientPublicKey([slot + 1; 32]),
                external_ref: None,
                observer: false,
                region: None,
                require_evidence: false,
            })
            .collect(),
        external_id: Some("descriptor-installation-retry".to_owned()),
        latency_estimate_ms: None,
        rollback: false,
        lobby_policy: None,
        evidence_keys: vec![],
    })
    .unwrap();
    let http = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let mut original = None;
    for _ in 0..2 {
        let timestamp = rally_point_proto::time::unix_secs_fail_closed().to_string();
        let signature = pair.sign(&request_auth::request_message(
            &timestamp,
            "POST",
            "/session/create",
            &body,
        ));
        let request = Request::post(format!("{}/session/create", served.base_url))
            .header("content-type", "application/json")
            .header(request_auth::TIMESTAMP_HEADER, timestamp)
            .header(
                request_auth::SIGNATURE_HEADER,
                hex::encode(signature.as_ref()),
            )
            .body(Full::new(Bytes::copy_from_slice(&body)))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), http.request(request))
            .await
            .expect("HTTP creation completes after the descriptor acknowledgement")
            .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let response: SessionResponse =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        // No polling after HTTP success: the descriptor must already be installed
        // when the tenant is given the tokens and addresses its clients will use.
        assert!(!applied.is_empty());
        assert!(
            mesh.session
                .decision_makers
                .maker_exists(&session_key(response.session))
        );
        if let Some(original) = &original {
            assert_eq!(
                &response, original,
                "retry preserves session, tokens and assignment"
            );
        } else {
            original = Some(response);
        }
    }
    subscriber.abort();
}
