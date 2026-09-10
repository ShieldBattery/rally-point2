//! Cross-relay turn delivery: exactly-once fan-out to a remote peer, and the
//! oversize turn that diverts onto the mesh control stream.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::mesh;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::quic::{client_config, mesh_client_config};
use rally_point_transport::{Link, MeshLink, noq, rustls};

use crate::helpers::*;

/// `C–S===S–C`: a client on relay A sends a turn; a client on relay B receives
/// it across the mesh. Asserts exactly-once delivery.
#[tokio::test]
async fn cross_relay_turn_delivery_is_exactly_once() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mesh_ep = noq::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());
    cmds_a.send(mesh::MeshCommand::Join(key.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key.clone())).unwrap();

    // Connect clients: slot 0 (sender) on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant, session, SlotId(0), client_key_0.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_a.ca.clone()).unwrap();
    let client_cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_ep = noq::Endpoint::client(bind).unwrap();
    client_ep.set_default_client_config(client_cfg);

    let conn_slot0 = client_ep
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant, session, SlotId(1), client_key_1.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let client_ep_b = noq::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_slot1 = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let mut client_b = Link::new(conn_slot1);

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A (slot 0) sends a turn.
    client_a.send(Some(turn(0, 0))).unwrap();

    // Client B (slot 1) receives exactly one copy via the mesh.
    // This proves the full path: client A → relay A run_slot_link →
    // fan_out_to_mesh → mesh-link driver → MeshLink::send → relay B
    // MeshLink::recv → mesh-link driver → fan_out → client B.
    //
    // The client-side Dedup guarantees exactly-once delivery to each client
    // regardless of MeshSeen. MeshSeen is the relay's session-level gate for
    // reconnect/resume and re-home overlap, so this test proves direct
    // cross-relay delivery rather than that defensive duplicate path.
    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .expect("client B did not receive the turn within 2s")
        .expect("client B link error");
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);
    assert!(
        received_b.fresh[0].commands.is_empty(),
        "empty commands preserved"
    );

    Ok(())
}

/// `C-S===S-C` for a turn too large for any datagram: relay A's mesh forward
/// path diverts it onto the mesh control stream (no datagram could carry it),
/// relay B's dispatch folds it back into its normal turn path, and relay B's
/// slot link diverts it again onto the receiving client's own control stream.
/// Without the mesh divert this turn silently never reached B's clients — a
/// permanent lockstep stall in any cross-relay game whose turn outgrew the
/// datagram budget.
#[tokio::test]
async fn cross_relay_oversize_turn_diverts_over_the_mesh_control_stream() -> Result<(), AnyError> {
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mesh_ep = noq::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());
    cmds_a.send(mesh::MeshCommand::Join(key.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key.clone())).unwrap();

    // The receiving client on relay B (slot 1), reading its control stream —
    // that's where B's slot link delivers a turn too large for the client path.
    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant, session, SlotId(1), client_key_1.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let client_ep_b = noq::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_slot1 = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let client_b = Link::new(conn_slot1);
    let mut ctrl_b = spawn_control_reader(client_b.connection().clone());

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Relay A forwards slot 0's turn, as its slot-link task would after
    // validating it — but this one is far past any datagram budget, so A's
    // mesh-link driver must divert it onto the mesh control stream.
    let oversize = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0xAB; 5000].into(),
        game_frame_count: Some(12),
        ..Default::default()
    };
    mesh::forward_client_turn(
        &relay_a.sessions,
        &relay_a.mesh,
        &key,
        SlotId(0),
        oversize.clone(),
    );

    // Client B receives the turn on its control stream: two divert hops (mesh
    // control stream, then the client's own), one identical payload. Read past any
    // connectivity frame the client's own register fanned.
    let received = next_non_connectivity(&mut ctrl_b).await;
    let ControlInbound::OversizeTurn(delivered) = received else {
        panic!("expected an oversize turn, got {received:?}");
    };
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.seq, 0);
    assert_eq!(delivered.game_frame_count, Some(12));
    assert_eq!(
        delivered.commands, oversize.commands,
        "the command bytes cross both divert hops verbatim",
    );

    Ok(())
}
