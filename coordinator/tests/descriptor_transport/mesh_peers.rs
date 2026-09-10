//! Fleet mesh-peer distribution: every enrolled relay is pushed the fleet's
//! mesh-peer identity set on connect, and a membership change (another relay
//! enrolling or deregistering) pushes the updated set to every connection.

use rally_point_coordinator::api;
use rally_point_coordinator::registry;
use rally_point_proto::control::RelayToCoordinator;
use rally_point_proto::ids::RelayId;

use crate::common::{prove_identity, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn the_fleet_mesh_peer_set_is_pushed_and_tracks_membership() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (base_url, reg) = serve_bare_coordinator(api::HELLO_TIMEOUT, LIVENESS).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));

    // Relay 1 opens its control connection, proves possession, and enrolls.
    let (mut socket1, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let hello1 = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket1.send(Message::Text(hello1.into())).await.unwrap();
    prove_identity(&mut socket1, &relay_key(1)).await;
    assert!(wait_for_enrollment(&reg, RelayId(1)).await);

    // On connect it is pushed the fleet set — just itself so far — carrying the
    // fingerprint the coordinator recorded for it at enroll.
    let solo = read_mesh_peers_until(&mut socket1, 1).await;
    assert_eq!(solo, registry::mesh_peers(&reg));
    assert_eq!(solo[0].relay_id, RelayId(1));

    // Relay 2 enrolls over its own connection.
    let (mut socket2, _resp) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let hello2 = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(2, 14901))).unwrap();
    socket2.send(Message::Text(hello2.into())).await.unwrap();
    prove_identity(&mut socket2, &relay_key(2)).await;
    assert!(wait_for_enrollment(&reg, RelayId(2)).await);

    // The membership change pushes an updated set to BOTH connections, each naming
    // both relays with the coordinator's recorded fingerprints.
    let expected = registry::mesh_peers(&reg);
    assert_eq!(expected.len(), 2);
    let on_one = read_mesh_peers_until(&mut socket1, 2).await;
    assert_eq!(
        on_one, expected,
        "the earlier relay is pushed the grown set"
    );
    let on_two = read_mesh_peers_until(&mut socket2, 2).await;
    assert_eq!(
        on_two, expected,
        "the newly-connected relay receives the full set on connect",
    );
    // The two relays carry distinct fingerprints — they enrolled distinct certs.
    assert_ne!(on_one[0].cert_sha256, on_one[1].cert_sha256);

    // Relay 2 goes away: its deregistration shrinks the set pushed to relay 1.
    drop(socket2);
    assert!(wait_for_deregistration(&reg, RelayId(2)).await);
    let shrunk = read_mesh_peers_until(&mut socket1, 1).await;
    assert_eq!(shrunk, registry::mesh_peers(&reg));
    assert_eq!(shrunk[0].relay_id, RelayId(1));
}
