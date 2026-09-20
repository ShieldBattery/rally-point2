//! The dialer supervisor reconciling desired peer links against the fleet map:
//! establishing, retargeting a moved or unreachable address, falling back to the
//! next advertised candidate, and cleaning up a removed peer.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{RelayPeer, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_relay::mesh;
use rally_point_relay::mesh::dialer;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::rustls;

use crate::helpers::*;
use tokio::sync::{mpsc, watch};

/// The on-demand dialer establishes a mesh link to a peer the coordinator's
/// descriptors name, and re-establishes it after the link ends — the production
/// path that closes the "idle teardown then a new session leaves the pair
/// unmeshed" gap.
///
/// The dialer is fed a desired-peer set over a `watch` (standing in for the Join
/// source's `desired_peers()`), against a real accepting relay. Dropping the
/// surfaced command sender stands in for the link winding down; because the peer is
/// still desired, the dialer redials.
#[tokio::test]
async fn dialer_establishes_and_reestablishes_a_desired_peer_link() -> Result<(), AnyError> {
    let tenant = make_default_tenant();

    // A (id 1) dials; B (id 2) accepts via the production accept drain.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let _links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);

    // A's on-demand dialer, fed desired peers over a watch. Its configured
    // fallback roots are EMPTY: trust must come entirely from the pinned cert
    // the desired peer carries — the production two-relay shape, where each
    // relay self-signs at startup and only the coordinator-relayed cert links
    // them.
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let (peers_tx, peers_rx) = watch::channel(Vec::<RelayPeer>::new());
    let (dial_chain, dial_key, _) = self_signed();
    let config = dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots: rustls::RootCertStore::empty(),
        cert_chain: dial_chain,
        key: dial_key,
        sessions: Arc::clone(&relay_a.sessions),
        mesh: relay_a.mesh.clone(),
        links: links_a_tx,
        redial_delay: Duration::from_millis(50),
    };
    tokio::spawn(dialer::run_mesh_dialer(config, peers_rx));

    // The coordinator's descriptors name B as a peer, carrying B's enrolled
    // cert → the dialer pins it and dials.
    peers_tx.send(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }])?;
    let (peer1, _generation1, cmds1) =
        next_link(&mut links_a_rx, "the link to the desired peer").await?;
    assert_eq!(peer1, RelayId(2), "the dialed link reaches B");

    // The link winds down (its command sender is dropped). B is still desired, so
    // the dialer re-establishes the link.
    drop(cmds1);
    let (peer2, _generation2, _cmds2) =
        next_link(&mut links_a_rx, "the re-established link").await?;
    assert_eq!(peer2, RelayId(2), "the re-established link reaches B");

    drop(relay_a);
    Ok(())
}

/// A peer that moves to a new address (a restart, same id) is retargeted: the
/// dialer cancels the dial to the old address and dials the new one. Without that,
/// the one-per-peer dedup would leave a supervisor dialing the stale address forever
/// and the pair would never mesh.
#[tokio::test]
async fn dialer_retargets_a_link_when_a_peer_moves_to_a_new_address() -> Result<(), AnyError> {
    let tenant = make_default_tenant();

    // Peer id 2 exists first at relay B's address, then at relay C's (same id, new
    // address — a restart).
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let relay_c = Relay::start(&tenant, 2);
    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca, &relay_c.ca]);

    // Peer 2 at B's address: the dialer dials B. Waiting for the link before moving
    // the peer synchronizes on the dialer having applied the first address.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (peer1, _generation1, _cmds1) =
        next_link(&mut links_a_rx, "the link to the peer's first address").await?;
    assert_eq!(peer1, RelayId(2));

    // Peer 2 moves to C's address: the dialer retargets and a fresh link forms.
    peers_tx.send(vec![peer_at(2, relay_c.addr)])?;
    let (peer2, _generation2, _cmds2) = next_link(&mut links_a_rx, "the retargeted link").await?;
    assert_eq!(peer2, RelayId(2));

    drop(relay_a);
    Ok(())
}

/// A supervisor stuck retrying an unreachable address never stops on its own, so a
/// later address for the same peer must still get dialed: the dialer cancels the
/// stuck supervisor and dials the new address. This is the "removal while connects
/// are failing" case — otherwise the stuck retrier would hold the peer's slot and
/// the pair would never mesh once the peer became reachable.
#[tokio::test]
async fn dialer_retargets_away_from_an_unreachable_address() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // A free loopback port with nothing listening — a dial there never connects, so
    // the supervisor retries indefinitely and never reports a stop.
    let dead_addr = {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
    };

    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca]);

    // Peer 2 first at the unreachable address: the dialer spawns a supervisor that
    // fails to connect and keeps retrying. A connect to a dead loopback port is
    // refused at once, so a short window is enough to confirm no link forms.
    peers_tx.send(vec![peer_at(2, dead_addr)])?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        links_a_rx.try_recv().is_err(),
        "no link forms to an unreachable address",
    );

    // Peer 2 reappears at B's live address: the stuck supervisor must be cancelled
    // and a fresh dial started, or the dedup keeps it stuck on the dead address.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (peer, _generation, _cmds) = next_link(
        &mut links_a_rx,
        "the link after the peer moved off the dead address",
    )
    .await?;
    assert_eq!(peer, RelayId(2));

    drop(relay_a);
    Ok(())
}

/// Removing a peer while it is serving a session must clean up that session's mesh
/// forwarding state, even though the dialer cancels the link driver with a hard
/// abort. Otherwise `mesh.links` keeps a dead forward channel for the ended session
/// forever — session ids are never reused, so nothing later reclaims it.
#[tokio::test]
async fn removing_a_serving_peer_cleans_up_its_mesh_forwarding_state() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca]);

    // Dial B, then join a session on the established link (standing in for a
    // descriptor-driven Join); the join registers a mesh forward channel.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (_peer, _generation, cmds) = next_link(&mut links_a_rx, "the dialed link").await?;
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(1),
    };
    cmds.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_for_mesh_link(&relay_a.mesh, &key).await;

    // The peer is removed from the desired set: the dialer aborts the link driver.
    // The forward-channel registration must still be torn down despite the abort.
    peers_tx.send(vec![])?;
    wait_until(
        "the aborted link's mesh forwarding state was never cleaned up",
        || !relay_a.mesh.links.lock().contains_key(&key),
    )
    .await;

    drop(relay_a);
    Ok(())
}

/// A dual-stack peer's dial walks the candidate list: the first advertised
/// address is unusable (rejected at connect — port 0), and the link still
/// establishes on the second candidate within the same attempt, no redial
/// delay spent.
#[tokio::test]
async fn a_mesh_dial_falls_back_to_the_next_advertised_candidate() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);
    let unreachable: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut links_a = spawn_dial(
        &relay_a,
        edge::MeshDial {
            // The peer advertises an unusable candidate first; the walk must
            // fall through to the reachable one.
            peer_addrs: vec![unreachable, relay_b.addr],
            ..dial_to(&relay_b, 1, 2)
        },
    );

    // The link establishes on the second candidate — well within one attempt,
    // far sooner than a second attempt could even begin to matter.
    let (peer_a, _generation_a, _cmds_a) = next_link(&mut links_a, "the fallback link").await?;
    assert_eq!(peer_a, RelayId(2));
    let (peer_b, _generation_b, _cmds_b) =
        next_link(&mut links_b, "the acceptor's side of it").await?;
    assert_eq!(peer_b, RelayId(1));

    drop(relay_a);
    Ok(())
}
