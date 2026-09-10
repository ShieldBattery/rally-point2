//! When a mesh link stands down and when it must not: the idle teardown after a
//! session ends, the never-joined link that outlives it, and the under-floor
//! attempt that must not displace a healthy link.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_relay::mesh;
use rally_point_relay::routing::{SessionKey, Sessions};

use crate::helpers::*;

/// An authenticated but under-floor connection must be refused BEFORE it can
/// claim the peer's mesh-link slot: claiming supersedes the healthy driver
/// currently serving the peer (advancing the generation and waking it to
/// exit), so a refusal that came after the claim would kill the healthy link
/// and then leave nothing in its place.
#[tokio::test]
async fn an_under_floor_mesh_attempt_never_supersedes_the_healthy_link() {
    let mesh = mesh::new_mesh_state();
    let peer = RelayId(3);
    let healthy_attempt = mesh::new_mesh_link_attempt();
    let healthy =
        mesh::claim_mesh_link(&mesh, peer, &healthy_attempt).expect("the healthy link claims");

    let (under_floor, _client_ep, _server_ep) = connection_with_peer_datagram_limit(800).await;
    let refused_attempt = mesh::new_mesh_link_attempt();
    match mesh::claim_verified_mesh_link(&mesh, peer, &refused_attempt, &under_floor) {
        mesh::MeshLinkAdmission::UnderFloor(_) => {}
        mesh::MeshLinkAdmission::Claimed(_) => {
            panic!("an under-floor peer must not be admitted")
        }
        mesh::MeshLinkAdmission::Superseded => {
            panic!("the refusal must come from the floor check, not the claim")
        }
    }
    assert!(
        healthy.is_current(),
        "a refused under-floor attempt must leave the healthy link current",
    );

    // A floor-clearing newer attempt still supersedes normally, proving the
    // verification gate refuses only what it should.
    let (good_link, _peer_link, _ep_a, _ep_b) = mesh_link_pair().await;
    let newer_attempt = mesh::new_mesh_link_attempt();
    match mesh::claim_verified_mesh_link(&mesh, peer, &newer_attempt, good_link.connection()) {
        mesh::MeshLinkAdmission::Claimed(_) => {}
        _ => panic!("a floor-clearing attempt claims normally"),
    }
    assert!(
        !healthy.is_current(),
        "the newer verified claim supersedes the old link",
    );
}

/// A link that served a session, went empty, and stayed empty past
/// `idle_timeout` tears down with [`mesh::MeshLinkExit::Idle`]. Joins a
/// session, leaves it, and waits past a short real-duration timeout — no
/// `tokio::time::pause`/`advance` (that would trip noq's own 10s idle
/// timeout before the 200ms app-level one, surfacing `ConnectionFailed`
/// instead of `Idle`).
#[tokio::test]
async fn idle_link_tears_down_after_timeout_post_session() -> Result<(), AnyError> {
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let (mesh_a, mesh_b, _ep_a, _ep_b) = mesh_link_pair().await;
    let sessions: Sessions = Arc::default();
    let mesh = mesh::new_mesh_state();
    let idle_timeout = Duration::from_millis(200);

    let (cmds_a, handle_a) =
        spawn_mesh_link_timed(mesh_a, Arc::clone(&sessions), mesh.clone(), idle_timeout);
    // Keep mesh_b alive so the QUIC connection doesn't close — dropping the
    // peer's Connection handle closes it from the other side, and A's driver
    // would exit `ConnectionFailed` instead of `Idle`. mesh_b isn't driven
    // (no recv loop); noq's endpoint processes keepalive ACKs internally.
    let _peer_alive = mesh_b;

    // Join, then leave — arming the idle timer on the transition to empty.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    cmds_a.send(mesh::MeshCommand::Leave(key))?;

    // Wait past the idle timeout (200ms) plus a margin.
    tokio::time::sleep(Duration::from_millis(350)).await;

    let exit = handle_a.await.expect("driver task panicked");
    assert_eq!(exit, mesh::MeshLinkExit::Idle, "should tear down idle");
    Ok(())
}

/// A never-joined link stays parked: the idle timer is not armed until a link
/// has served at least one session, so a link that got no `Join` survives
/// well past `idle_timeout`. This is the custody contract the binary relies
/// on (it holds the command sender so drivers stay ready for the future Join
/// source) — tearing never-joined links down would strand the pair.
#[tokio::test]
async fn never_joined_link_survives_past_idle_timeout() -> Result<(), AnyError> {
    let (mesh_a, mesh_b, _ep_a, _ep_b) = mesh_link_pair().await;
    let sessions: Sessions = Arc::default();
    let mesh = mesh::new_mesh_state();
    let idle_timeout = Duration::from_millis(150);

    let (_cmds_a, handle_a) =
        spawn_mesh_link_timed(mesh_a, Arc::clone(&sessions), mesh.clone(), idle_timeout);
    let _peer_alive = mesh_b;

    // Wait well past the idle timeout without ever sending a Join.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // The driver must still be running — never armed, never fired.
    assert!(
        !handle_a.is_finished(),
        "never-joined link should stay parked, not tear down"
    );
    // Cancel the task so the test doesn't leak it.
    handle_a.abort();
    Ok(())
}
