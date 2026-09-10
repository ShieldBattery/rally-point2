//! A turn crossing two relays over the production dial/accept halves — first
//! with the test joining the link by hand, then with a coordinator descriptor
//! driving the join over mesh control.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{BufferBounds, RelayPeer, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_relay::coordinator::client::FleetMeshPeers;
use rally_point_relay::mesh;
use rally_point_relay::mesh::control;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::rustls;

use crate::helpers::*;
use tokio::sync::mpsc;

/// Two relays mesh via the production connection half (`run_mesh_dial` +
/// `run_mesh_accept`); the test sends `Join` on the returned command senders;
/// a turn flows cross-relay.
#[tokio::test]
async fn cross_relay_turn_through_production_mesh_connection_half() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A is the lower id (1), so it dials. Relay B is the higher id (2),
    // so it accepts A's dial.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // A's mesh-dial identity: a real certificate, separate from A's client-edge
    // serving cert, whose fingerprint is seeded into B's fleet-peer map below —
    // so this test (unlike most of this file's) runs with peer-identity
    // enforcement ACTIVE, proving the happy path still works when the fleet map
    // is non-empty and the dialer's certificate actually matches it.
    let (dial_chain, dial_key, dial_ca) = self_signed();
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(1),
        cert_sha256: rally_point_transport::quic::cert_fingerprint(dial_ca.as_ref()),
    }]);

    // B's accept drain: spawns a `run_mesh_link` driver for each peer relay
    // that dials in, returning `(peer id, command sender)` on `links_b_rx`.
    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    // A dials B. The dial establishes the connection and spawns a
    // `run_mesh_link` driver, returning `(peer id, command sender)` on
    // `links_a_rx`.
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // Collect each side's link, labeled with the peer it reaches. A dialed B,
    // so A's link is labeled with B's id; B read the dialer's identity hello,
    // so B's link is labeled with A's id.
    let (peer_a, _generation_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    let (peer_b, _generation_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    assert_eq!(peer_a, RelayId(2), "A's link reaches B");
    assert_eq!(
        peer_b,
        RelayId(1),
        "B learned the dialer's id from the hello",
    );

    // Send Join on both sides — the test drives the command senders directly,
    // standing in for the coordinator-fed `MeshControl` Join source.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b.send(mesh::MeshCommand::Join(key.clone()))?;

    // Connect clients: slot 0 (sender) on relay A, slot 1 on relay B.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    // Let the mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A (slot 0) sends a turn.
    client_a.send(Some(turn(0, 0))).unwrap();

    // Client B (slot 1) receives exactly one copy via the mesh. This proves
    // the full production path: `run_mesh_dial` establishes the connection +
    // spawns the driver, `run_mesh_accept` accepts it + spawns the driver, the
    // returned command senders drive Join, and a turn flows cross-relay.
    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);

    // Consume relay_a: its mesh_accept_rx is unused (A dials, it doesn't
    // accept), so drop it to release the resources.
    drop(relay_a);
    Ok(())
}

/// The same cross-relay turn, but driven by [`mesh::control::MeshControl`]
/// applying a coordinator [`SessionDescriptor`] instead of a hand-sent `Join`.
///
/// Proves the production Join path end to end: each established link registers
/// in the relay's `MeshControl` keyed by the peer id the hello carried, a
/// descriptor names that peer, `apply_descriptor` emits the targeted `Join` on
/// the right link, and a turn flows cross-relay. This is exactly what the
/// coordinator's session-descriptor push will drive once its control transport
/// to the relay exists.
#[tokio::test]
async fn descriptor_drives_cross_relay_turn_via_mesh_control() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);

    // Relay A (id 1) dials; relay B (id 2) accepts.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // Each relay's Join source.
    let control_a = control::MeshControl::new(RelayId(1), Arc::default(), Arc::default());
    let control_b = control::MeshControl::new(RelayId(2), Arc::default(), Arc::default());

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // Register each established link in its relay's control, keyed by the peer
    // id the connection half labeled it with. Awaiting the link makes this
    // deterministic — no sleeping to hope the link came up.
    let (peer_a, generation_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    let _ = control_a.register_link(peer_a, generation_a, cmds_a);
    let (peer_b, generation_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    let _ = control_b.register_link(peer_b, generation_b, cmds_b);

    // The coordinator pushes each relay its descriptor: A's only peer is B, and
    // B's only peer is A. Applying it emits the targeted Join on the link the
    // peer id selects.
    control_a.apply_descriptor(&SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![RelayPeer {
            relay_id: RelayId(2),
            relay_addr: relay_b.addr,
            cert_der: relay_b.ca.to_vec(),
            relay_addrs: vec![],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    });
    control_b.apply_descriptor(&SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![RelayPeer {
            relay_id: RelayId(1),
            relay_addr: relay_a.addr,
            cert_der: relay_a.ca.to_vec(),
            relay_addrs: vec![],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    });

    // Connect clients: slot 0 (sender) on relay A, slot 1 on relay B.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    // Let the mesh drivers process the Join (open their sessions) before the turn.
    tokio::time::sleep(Duration::from_millis(50)).await;

    client_a.send(Some(turn(0, 0))).unwrap();

    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);

    drop(relay_a);
    Ok(())
}
