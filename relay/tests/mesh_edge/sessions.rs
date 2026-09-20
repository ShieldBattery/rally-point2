//! Session multiplexing on one mesh link: two sessions that must not cross-wire,
//! a session joined after the link is already running, and a colliding join from
//! another tenant.

use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::mesh;
use rally_point_relay::routing::SessionKey;

use crate::helpers::*;

/// `C-S===S-C` with two games on one relay-pair: a client in game 1 on relay A
/// sends a turn; the client in game 1 on relay B receives it, exactly once. The
/// client in game 2 on relay B does *not* receive it — turns don't leak across
/// sessions on the shared mesh connection. This is the load-bearing proof for
/// the multi-session driver: one `MeshLink` dispatches to N per-session states,
/// and the `SessionId -> SessionState` demux keeps the two games independent.
#[tokio::test]
async fn two_sessions_on_one_mesh_link_do_not_cross_wire() -> Result<(), AnyError> {
    let tenant = make_default_tenant();

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

    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    // One mesh-link driver per relay, serving both sessions on the shared
    // connection. Game 1 joins with the link; game 2 joins on the same senders
    // (the dynamic-join test below covers joining a *running* link).
    let (cmds_a, cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key_1).await;
    cmds_a.send(mesh::MeshCommand::Join(key_2.clone()))?;
    cmds_b.send(mesh::MeshCommand::Join(key_2.clone()))?;

    // Game 1: slot 0 on A, slot 1 on B. Game 2: slot 0 on B — a different game
    // with its own session id.
    let mut client_a_game1 = connect_client(&relay_a, &tenant, session_1, SlotId(0)).await?;
    let mut client_b_game1 = connect_client(&relay_b, &tenant, session_1, SlotId(1)).await?;
    let mut client_b_game2 = connect_client(&relay_b, &tenant, session_2, SlotId(0)).await?;

    wait_for_mesh_link(&relay_a.mesh, &key_1).await;
    wait_for_mesh_link(&relay_b.mesh, &key_1).await;

    // Client A in game 1 sends a turn.
    client_a_game1.send(Some(turn(0, 0)))?;

    // Client B in game 1 receives exactly one copy via the mesh.
    let received_b1 = tokio::time::timeout(Duration::from_secs(2), client_b_game1.recv())
        .await
        .map_err(|_| "client B game 1 did not receive the turn within 2s")?
        .map_err(|e| format!("client B game 1 link error: {e}"))?;
    assert_eq!(received_b1.fresh.len(), 1, "B game 1: exactly one payload");
    assert_eq!(received_b1.fresh[0].slot, 0);
    assert_eq!(received_b1.fresh[0].seq, 0);

    // Client B in game 2 does NOT receive game 1's turn. The multi-session
    // driver's SessionId demux keeps the two games independent on the shared
    // mesh connection. Game 1's copy has already arrived by now, so a short
    // window that yields nothing is conclusive.
    let leaked = tokio::time::timeout(Duration::from_millis(100), client_b_game2.recv()).await;
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
    let tenant = make_default_tenant();

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

    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    // Session 1 joins with the link and exchanges a turn, proving it is live.
    let (cmds_a, cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key_1).await;
    let mut client_s1_a = connect_client(&relay_a, &tenant, session_1, SlotId(0)).await?;
    let mut client_s1_b = connect_client(&relay_b, &tenant, session_1, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key_1).await;
    wait_for_mesh_link(&relay_b.mesh, &key_1).await;

    client_s1_a.send(Some(turn(0, 0)))?;
    let received_s1 = tokio::time::timeout(Duration::from_secs(2), client_s1_b.recv())
        .await
        .map_err(|_| "session 1 turn did not arrive within 2s")?
        .map_err(|e| format!("session 1 link error: {e}"))?;
    assert_eq!(received_s1.fresh.len(), 1, "session 1: exactly one payload");

    // Now session 2 joins the already-running link — the dynamic-join path.
    cmds_a.send(mesh::MeshCommand::Join(key_2.clone()))?;
    cmds_b.send(mesh::MeshCommand::Join(key_2.clone()))?;
    let mut client_s2_a = connect_client(&relay_a, &tenant, session_2, SlotId(0)).await?;
    let mut client_s2_b = connect_client(&relay_b, &tenant, session_2, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key_2).await;
    wait_for_mesh_link(&relay_b.mesh, &key_2).await;

    client_s2_a.send(Some(turn(0, 0)))?;
    let received_s2 = tokio::time::timeout(Duration::from_secs(2), client_s2_b.recv())
        .await
        .map_err(|_| "session 2 turn did not arrive within 2s")?
        .map_err(|e| format!("session 2 link error: {e}"))?;
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
    // The colliding tenant only needs to differ in name — the collision is on
    // the mesh driver's session-state map (a bare session id can't disambiguate
    // tenants), not on the client edge, so no client of its own ever connects.
    let tenant_a = make_default_tenant();
    let session = SessionId(1);
    let key_a = SessionKey {
        tenant: TenantId(tenant_a.name.clone()),
        session,
    };
    let key_b = SessionKey {
        tenant: TenantId("sb-other".to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant_a, 1);
    let mut relay_b = Relay::start(&tenant_a, 2);

    // Tenant A joins session 1 first on both sides.
    let (cmds_a, cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key_a).await;

    // Tenant B attempts to join the same session id — must be refused, not
    // overwriting tenant A's session. The command is accepted by the channel
    // (the driver logs and drops it); there's no ack, so we prove refusal by
    // showing tenant A's session still works afterward.
    cmds_b.send(mesh::MeshCommand::Join(key_b.clone()))?;
    cmds_a.send(mesh::MeshCommand::Join(key_b.clone()))?;

    // Tenant B then leaves the colliding id. The driver keys `joined` by the
    // bare wire session id, so a Leave matching on id alone would evict tenant
    // A's session 1. The Leave must match the full SessionKey and be ignored
    // here, leaving tenant A's session intact — proven by the delivery below.
    cmds_b.send(mesh::MeshCommand::Leave(key_b.clone()))?;
    cmds_a.send(mesh::MeshCommand::Leave(key_b.clone()))?;

    // Connect tenant A's clients: slot 0 on A, slot 1 on B.
    let mut client_a = connect_client(&relay_a, &tenant_a, session, SlotId(0)).await?;
    let mut client_b = connect_client(&relay_b, &tenant_a, session, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key_a).await;
    wait_for_mesh_link(&relay_b.mesh, &key_a).await;

    // Tenant A's turn still delivers across the mesh after the colliding Join
    // and its Leave were attempted — proving tenant A's session survived, tenant
    // B never overwrote it, and B's Leave on the shared id did not evict it.
    client_a.send(Some(turn(0, 0)))?;
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "tenant A's turn did not arrive within 2s after colliding Join + Leave")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1, "exactly one payload delivered");
    assert_eq!(received.fresh[0].slot, 0);
    assert_eq!(received.fresh[0].seq, 0);

    Ok(())
}
