//! The liveness deadline: a relay that goes silent past it is deregistered and
//! its connection closed, while a relay that heartbeats inside the deadline stays
//! registered no matter how long the deadline has run.

use std::time::Duration;

use rally_point_coordinator::api;
use rally_point_coordinator::registry;
use rally_point_proto::ids::RelayId;
use rally_point_relay::coordinator;
use rally_point_relay::mesh::control::MeshControl;
use tokio::time::timeout;

use crate::common::{prove_identity, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn a_silent_relay_is_deregistered_after_the_liveness_deadline() {
    use futures_util::{SinkExt, StreamExt};
    use rally_point_proto::control::RelayToCoordinator;
    use tokio_tungstenite::tungstenite::Message;

    // A short liveness deadline so the test doesn't wait the production timeout.
    let (base_url, reg) =
        serve_bare_coordinator(api::HELLO_TIMEOUT, Duration::from_millis(300)).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll with a Hello and prove possession, then go silent — never send a
    // heartbeat.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(7, 15007))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(7)).await;
    assert!(
        wait_for_enrollment(&reg, RelayId(7)).await,
        "the relay enrolls from its Hello",
    );

    // Past the deadline with no heartbeat, the coordinator deregisters the relay
    // and closes the connection.
    assert!(
        wait_for_deregistration(&reg, RelayId(7)).await,
        "a silent relay is deregistered after the liveness deadline",
    );
    let closed = timeout(Duration::from_secs(2), async {
        while let Some(Ok(_)) = socket.next().await {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "the coordinator closes the timed-out connection",
    );
}

#[tokio::test]
async fn a_heartbeating_relay_stays_registered_past_the_liveness_deadline() {
    // The liveness deadline is short, but the relay heartbeats well inside it, so
    // the coordinator keeps resetting the deadline and never deregisters it. This
    // exercises the relay actually sending heartbeats over a live connection.
    let (base_url, reg) =
        serve_bare_coordinator(api::HELLO_TIMEOUT, Duration::from_millis(300)).await;
    let control = MeshControl::new(
        RelayId(7),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let _handle = tokio::spawn(coordinator::client::run_descriptor_subscriber_with(
        coordinator::client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(7, 15007),
            identity_key: relay_key(7),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_millis(100)), // heartbeat three times inside the 300ms deadline
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));
    assert!(
        wait_for_enrollment(&reg, RelayId(7)).await,
        "the relay enrolls from its Hello",
    );

    // Wait well past the liveness deadline; the heartbeats keep the relay alive.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        registry::peer(&reg, RelayId(7)).is_some(),
        "a heartbeating relay must not be deregistered",
    );
}
