//! One-way mesh traffic still needs selective packet acknowledgements when its prefix is gapped.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_transport::MeshSessionKey;

use crate::helpers::*;

#[tokio::test]
async fn gapped_and_duplicate_payloads_are_acked_without_ack_only_ping_pong() -> Result<(), AnyError>
{
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(70),
    };
    let transport_key = MeshSessionKey::new(key.session, key.tenant.as_ref());
    let mesh = mesh::MeshState::default();
    let (local, mut peer, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    peer.open_session(transport_key.clone());
    let commands = spawn_mesh_link(local, Arc::default(), mesh.clone());
    commands.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_for_mesh_link(&mesh, &key).await;

    // Neither receipt reaches seq 0 or the receive-window collapse boundary.
    // The second packet is a duplicate at the receiver but needs its own ACK:
    // the sender can have lost the first ACK on an unreliable datagram path.
    for _ in 0..2 {
        peer.send(
            transport_key.clone(),
            Some(build_turn(0, 500, Some(500))),
            None,
        )?;
        assert_eq!(peer.payloads_in_flight(transport_key.clone()), 1);
        let receipt = tokio::time::timeout(Duration::from_secs(2), peer.recv()).await??;
        assert_eq!(receipt.session, key.session);
        assert!(!receipt.delivery.carried_payloads);
        assert_eq!(peer.payloads_in_flight(transport_key.clone()), 0);
        assert!(mesh::resume_cursor_snapshot(&mesh.seen, &key).is_empty());
        assert_eq!(
            mesh::slot_receipts(&mesh.seen, &key, SlotId(0)).ahead,
            vec![500]
        );
    }

    peer.send(transport_key, None, None)?;
    // An absence needs a real observation window. This spans several maintenance
    // flushes on loopback, so an ACK owed for an ACK-only packet would appear.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), peer.recv())
            .await
            .is_err()
    );
    Ok(())
}
