//! Tenant verifying-key distribution and the descriptor push's staging stamp: a
//! freshly enrolled connection is led by the tenant-key set (every configured
//! tenant's verifying key, so a relay can check client tokens before any
//! descriptor for it lands) before the descriptor re-sync, and each pushed
//! descriptor set carries the coordinator's wall-clock at the moment it left the
//! outbox.

use rally_point_coordinator::tenant;
use rally_point_proto::control::{CoordinatorToRelay, RelayToCoordinator, TenantId};
use rally_point_proto::token::KeyId;

use crate::common::{expect_tenant_keys, prove_identity, read_to_descriptors, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn the_tenant_key_set_is_pushed_before_the_first_descriptor() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with one enrolled tenant (sb-test / test-key-1) and a session
    // relay 1 serves. Relay 1 enrolls over a raw control socket so the test can
    // read the exact post-enroll frame order.
    let (base_url, _session, setup) = coordinator_with_session(None).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;

    // The first frame after enrollment is the tenant-key set — before any
    // descriptor — carrying every configured tenant, each with the verifying key
    // the coordinator holds for it.
    let pushed = expect_tenant_keys(&mut socket).await;
    let expected = tenant::all_verifying_keys(setup.tenants());
    assert_eq!(pushed.len(), expected.len());
    assert_eq!(
        pushed.len(),
        1,
        "the coordinator has exactly one tenant enrolled"
    );

    let (kid, verifying_key) = tenant::verifying_key(setup.tenants(), &TenantId(TENANT.to_owned()))
        .expect("the tenant is enrolled");
    assert_eq!(kid, KeyId("test-key-1".to_owned()));
    let entry = pushed
        .iter()
        .find(|k| k.kid == kid)
        .expect("the pushed set names the configured tenant");
    assert_eq!(entry.tenant, TenantId(TENANT.to_owned()));
    assert_eq!(
        entry.verifying_key,
        verifying_key.to_vec(),
        "the pushed verifying key matches the coordinator's signing key's public half",
    );

    // The descriptor re-sync follows the tenant-key lead on the same connection.
    let descriptors = read_to_descriptors(&mut socket).await;
    assert!(descriptors.contains("\"type\":\"descriptors\""));
}

#[tokio::test]
async fn the_pushed_descriptor_set_carries_a_recent_staging_stamp() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with a session relay 1 serves. Relay 1 enrolls over a raw
    // control socket so the test can read the descriptor frame and inspect its
    // staging stamp — the coordinator's wall-clock at the moment the set left its
    // outbox, which the relay differences against its own clock to measure apply lag.
    let (base_url, _session, _setup) = coordinator_with_session(None).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // The coordinator runs in this same process, so it stamps against this same
    // clock: the stamp must land in `[before, after]`, bracketing the whole exchange.
    let before = unix_ms_now();
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;

    let descriptors = read_to_descriptors(&mut socket).await;
    let after = unix_ms_now();

    let CoordinatorToRelay::Descriptors {
        staged_at_unix_ms, ..
    } = serde_json::from_str(&descriptors).unwrap()
    else {
        panic!("read_to_descriptors returns a descriptors frame");
    };
    let staged = staged_at_unix_ms.expect("a current coordinator stamps every descriptor push");
    assert!(
        (before..=after).contains(&staged),
        "the stamp is the coordinator's wall-clock when the set was pushed \
         (before={before}, staged={staged}, after={after})",
    );
}
