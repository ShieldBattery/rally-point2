//! Session multiplexing on one mesh link: two sessions that must not cross-wire,
//! a session joined after the link is already running, and a colliding join from
//! another tenant.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::mesh;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::quic::{client_config, mesh_client_config};
use rally_point_transport::{Link, MeshLink, noq, rustls};

use crate::helpers::*;

/// `C-S===S-C` with two games on one relay-pair: a client in game 1 on relay A
/// sends a turn; the client in game 1 on relay B receives it. The client in
/// game 2 on relay B does *not* receive it — turns don't leak across sessions
/// on the shared mesh connection. This is the load-bearing proof for the
/// multi-session driver: one `MeshLink` dispatches to N per-session states, and
/// the `SessionId -> SessionState` demux keeps the two games independent.
#[tokio::test]
async fn two_sessions_on_one_mesh_link_do_not_cross_wire() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // Two games, same tenant, different session ids.
    let session_1 = SessionId(1);
    let session_2 = SessionId(2);
    let key_1 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_1,
    };
    let key_2 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_2,
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

    // One mesh-link driver per relay, serving both sessions on the shared
    // connection. Both sessions join up front here; the dynamic-join test
    // below exercises joining after the link is already running.
    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());
    for k in [&key_1, &key_2] {
        cmds_a.send(mesh::MeshCommand::Join(k.clone())).unwrap();
        cmds_b.send(mesh::MeshCommand::Join(k.clone())).unwrap();
    }

    // Game 1: slot 0 on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant, session_1, SlotId(0), client_key_0.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_ep_a = noq::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_slot0 = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a_game1 = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant, session_1, SlotId(1), client_key_1.public);
    let mut roots_b1 = rustls::RootCertStore::empty();
    roots_b1.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b1 = client_config(roots_b1).unwrap();
    let client_ep_b1 = noq::Endpoint::client(bind).unwrap();
    client_ep_b1.set_default_client_config(client_cfg_b1);
    let conn_slot1 = client_ep_b1
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let mut client_b_game1 = Link::new(conn_slot1);

    // Game 2: slot 0 on B (a different game with its own session id).
    let client_key_2 = keypair();
    let token_2 = mint_token(&tenant, session_2, SlotId(0), client_key_2.public);
    let mut roots_b2 = rustls::RootCertStore::empty();
    roots_b2.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b2 = client_config(roots_b2).unwrap();
    let client_ep_b2 = noq::Endpoint::client(bind).unwrap();
    client_ep_b2.set_default_client_config(client_cfg_b2);
    let conn_slot0_game2 = client_ep_b2
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0_game2, &token_2, &client_key_2).await?;
    let mut client_b_game2 = Link::new(conn_slot0_game2);

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A in game 1 sends a turn.
    client_a_game1.send(Some(turn(0, 0))).unwrap();

    // Client B in game 1 receives exactly one copy via the mesh.
    let received_b1 = tokio::time::timeout(Duration::from_secs(2), client_b_game1.recv())
        .await
        .expect("client B game 1 did not receive the turn within 2s")
        .expect("client B game 1 link error");
    assert_eq!(received_b1.fresh.len(), 1, "B game 1: exactly one payload");
    assert_eq!(received_b1.fresh[0].slot, 0);
    assert_eq!(received_b1.fresh[0].seq, 0);

    // Client B in game 2 does NOT receive game 1's turn. The multi-session
    // driver's SessionId demux keeps the two games independent on the shared
    // mesh connection.
    let leaked = tokio::time::timeout(Duration::from_millis(200), client_b_game2.recv()).await;
    assert!(
        leaked.is_err(),
        "game 2 client must not receive game 1's turn — sessions are isolated"
    );

    Ok(())
}

/// Dynamic session join on a running mesh link: one session starts joined and
/// delivers a turn, then a *second* session joins the already-running driver and
/// delivers its own turn. This proves the command-channel join path — the core
/// of the dynamic-join/leave API — not just the upfront-list path the other two
/// tests exercise.
#[tokio::test]
async fn a_session_joined_after_the_link_is_running_delivers() -> Result<(), AnyError> {
    let tenant = make_tenant();

    let session_1 = SessionId(1);
    let session_2 = SessionId(2);
    let key_1 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_1,
    };
    let key_2 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_2,
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

    // Spawn the drivers with no sessions joined yet — the links come up idle,
    // awaiting their first Join.
    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());

    // Session 1 joins first and exchanges a turn, proving the link is live.
    cmds_a.send(mesh::MeshCommand::Join(key_1.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_1.clone())).unwrap();

    let client_key_1a = keypair();
    let token_1a = mint_token(&tenant, session_1, SlotId(0), client_key_1a.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_ep_a = noq::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_s1_a = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s1_a, &token_1a, &client_key_1a).await?;
    let mut client_s1_a = Link::new(conn_s1_a);

    let client_key_1b = keypair();
    let token_1b = mint_token(&tenant, session_1, SlotId(1), client_key_1b.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let client_ep_b = noq::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_s1_b = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s1_b, &token_1b, &client_key_1b).await?;
    let mut client_s1_b = Link::new(conn_s1_b);

    tokio::time::sleep(Duration::from_millis(50)).await;
    client_s1_a.send(Some(turn(0, 0))).unwrap();
    let received_s1 = tokio::time::timeout(Duration::from_secs(2), client_s1_b.recv())
        .await
        .expect("session 1 turn did not arrive within 2s")
        .expect("session 1 link error");
    assert_eq!(received_s1.fresh.len(), 1, "session 1: exactly one payload");

    // Now session 2 joins the already-running link — the dynamic-join path.
    cmds_a.send(mesh::MeshCommand::Join(key_2.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_2.clone())).unwrap();

    let client_key_2a = keypair();
    let token_2a = mint_token(&tenant, session_2, SlotId(0), client_key_2a.public);
    let conn_s2_a = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s2_a, &token_2a, &client_key_2a).await?;
    let mut client_s2_a = Link::new(conn_s2_a);

    let client_key_2b = keypair();
    let token_2b = mint_token(&tenant, session_2, SlotId(1), client_key_2b.public);
    let conn_s2_b = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s2_b, &token_2b, &client_key_2b).await?;
    let mut client_s2_b = Link::new(conn_s2_b);

    tokio::time::sleep(Duration::from_millis(50)).await;
    client_s2_a.send(Some(turn(0, 0))).unwrap();
    let received_s2 = tokio::time::timeout(Duration::from_secs(2), client_s2_b.recv())
        .await
        .expect("session 2 turn did not arrive within 2s")
        .expect("session 2 link error");
    assert_eq!(received_s2.fresh.len(), 1, "session 2: exactly one payload");
    assert_eq!(received_s2.fresh[0].slot, 0);
    assert_eq!(received_s2.fresh[0].seq, 0);

    Ok(())
}

/// The per-Join collision guard on the live driver: two tenants that both
/// assigned session id 1 can't be told apart on the wire, so the second Join
/// is refused — not overwriting the first. The colliding tenant then *leaves*
/// the shared id; because the driver keys `joined` by the bare wire session id,
/// a Leave that matched on id alone would evict whatever holds it — tenant A.
/// A client in tenant A's session 1 still receives turns after both the
/// colliding Join and its Leave are attempted, proving the Leave matched the
/// full SessionKey and left the legitimate tenant's session intact.
#[tokio::test]
async fn a_colliding_join_across_tenants_is_refused_on_the_live_driver() -> Result<(), AnyError> {
    // tenant_b only needs to differ in name — the collision is on the mesh
    // driver's session-state map (bare session id can't disambiguate tenants),
    // not on the client edge, so no tenant_b client ever connects. Both relays
    // admit tenant_a's clients; tenant_b exists solely as a SessionKey.
    let tenant_a = make_tenant();
    let tenant_b_name = "sb-other".to_owned();

    let session = SessionId(1);
    let key_a = SessionKey {
        tenant: TenantId(tenant_a.name.clone()),
        session,
    };
    let key_b = SessionKey {
        tenant: TenantId(tenant_b_name),
        session,
    };

    let relay_a = Relay::start(&tenant_a);
    let mut relay_b = Relay::start(&tenant_a);

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

    // Tenant A joins session 1 first on both sides.
    cmds_a.send(mesh::MeshCommand::Join(key_a.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_a.clone())).unwrap();

    // Tenant B attempts to join the same session id — must be refused, not
    // overwriting tenant A's session. The command is accepted by the channel
    // (the driver logs and drops it); there's no ack, so we prove refusal by
    // showing tenant A's session still works afterward.
    cmds_b.send(mesh::MeshCommand::Join(key_b.clone())).unwrap();
    cmds_a.send(mesh::MeshCommand::Join(key_b.clone())).unwrap();

    // Tenant B then leaves the colliding id. The driver keys `joined` by the
    // bare wire session id, so a Leave matching on id alone would evict tenant
    // A's session 1. The Leave must match the full SessionKey and be ignored
    // here, leaving tenant A's session intact — proven by the delivery below.
    cmds_b
        .send(mesh::MeshCommand::Leave(key_b.clone()))
        .unwrap();
    cmds_a
        .send(mesh::MeshCommand::Leave(key_b.clone()))
        .unwrap();

    // Connect tenant A's clients: slot 0 on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant_a, session, SlotId(0), client_key_0.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_ep_a = noq::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_slot0 = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant_a, session, SlotId(1), client_key_1.public);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Tenant A's turn still delivers across the mesh after the colliding Join
    // and its Leave were attempted — proving tenant A's session survived, tenant
    // B never overwrote it, and B's Leave on the shared id did not evict it.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .expect("tenant A's turn did not arrive within 2s after colliding Join + Leave")
        .expect("client B link error");
    assert_eq!(received.fresh.len(), 1, "exactly one payload delivered");
    assert_eq!(received.fresh[0].slot, 0);
    assert_eq!(received.fresh[0].seq, 0);

    Ok(())
}
