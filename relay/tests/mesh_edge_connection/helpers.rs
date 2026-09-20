//! Fixtures only the mesh connection suite uses: the production dial and accept
//! halves wired up in one line each, and the polling waits the dial/redial tests
//! spin on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::RelayPeer;
use rally_point_proto::ids::RelayId;
use rally_point_relay::coordinator::client::{FleetMeshPeers, FleetMeshPeersReader};
use rally_point_relay::mesh;
use rally_point_relay::mesh::dialer;
use rally_point_relay::mesh::edge;
use rally_point_transport::rustls;
use rally_point_transport::rustls::pki_types::CertificateDer;

pub use crate::common::*;
use tokio::sync::{mpsc, watch};

/// An empty fleet mesh-peer read handle for the accept side: these tests exercise
/// the connection half, not the coordinator's peer-auth push, so the acceptor's
/// fleet map is empty (its writer is dropped immediately, leaving only the handle).
pub fn empty_fleet_peers() -> FleetMeshPeersReader {
    FleetMeshPeers::new().reader()
}

/// What an established mesh link surfaces on the `links` channel: the peer's id and
/// the command sender that drives `Join`/`Leave` on that link.
pub type LinkHandle = mesh::MeshLinkHandle;

/// Runs the production accept drain on `relay`, returning the channel each
/// established link surfaces on. `fleet` and `require_peer_auth` are the
/// peer-identity posture the acceptor enforces.
pub fn accept_on(
    relay: &mut Relay,
    fleet: FleetMeshPeersReader,
    require_peer_auth: bool,
) -> mpsc::Receiver<LinkHandle> {
    let accept_rx = relay.mesh_accept_rx();
    let (links_tx, links_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        accept_rx,
        Arc::clone(&relay.sessions),
        relay.mesh.clone(),
        links_tx,
        fleet,
        require_peer_auth,
    ));
    links_rx
}

/// A dial aimed at `peer`: trusting its serving cert, presenting a fresh
/// self-signed mesh identity, claiming `our_id` and expecting `peer_id`. A test
/// that needs a different identity, or a different candidate list, names those
/// fields with struct-update syntax over this.
pub fn dial_to(peer: &Relay, our_id: u64, peer_id: u64) -> edge::MeshDial {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(peer.ca.clone()).unwrap();
    let (cert_chain, key, _) = self_signed();
    edge::MeshDial {
        our_id: RelayId(our_id),
        peer_id: RelayId(peer_id),
        peer_addrs: vec![peer.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain,
        key,
    }
}

/// Supervises `dial` from `relay`, returning the channel its established links
/// surface on. The redial delay is short so a test that forces a link failure
/// doesn't wait the production interval.
pub fn spawn_dial(relay: &Relay, dial: edge::MeshDial) -> mpsc::Receiver<LinkHandle> {
    let (links_tx, links_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay.sessions),
        relay.mesh.clone(),
        links_tx,
        Duration::from_millis(50),
    ));
    links_rx
}

/// The ordinary pairing: relay A (id 1) dials relay B (id 2), which is the side
/// that accepts since the lower id always dials.
pub fn dial_a_to_b(relay_a: &Relay, relay_b: &Relay) -> mpsc::Receiver<LinkHandle> {
    spawn_dial(relay_a, dial_to(relay_b, 1, 2))
}

/// The next link to surface on `links`, failing the test rather than hanging if
/// none does. `what` names what was being waited on.
pub async fn next_link(
    links: &mut mpsc::Receiver<LinkHandle>,
    what: &str,
) -> Result<LinkHandle, AnyError> {
    tokio::time::timeout(Duration::from_secs(2), links.recv())
        .await
        .map_err(|_| format!("timed out waiting for {what}"))?
        .ok_or_else(|| format!("the links channel closed before {what}").into())
}

/// Polls `cond` until it holds, failing after a few seconds. Presence and
/// authority propagate on the mesh flush cadence (~150ms), so tests observe
/// them by polling, never by a single fixed sleep.
pub async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {what}").into())
}

/// A dialer config for relay A (id 1) with `roots` trusting the given peer certs,
/// plus the desired-peer watch sender and the links receiver, wired to a short
/// redial delay. Factors out the boilerplate the dialer lifecycle tests share.
pub fn dialer_for_a(
    relay_a: &Relay,
    peer_cas: &[&CertificateDer<'static>],
) -> (watch::Sender<Vec<RelayPeer>>, mpsc::Receiver<LinkHandle>) {
    let (links_a_tx, links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    for ca in peer_cas {
        roots.add((*ca).clone()).unwrap();
    }
    let (peers_tx, peers_rx) = watch::channel(Vec::<RelayPeer>::new());
    let (dial_chain, dial_key, _) = self_signed();
    let config = dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
        sessions: Arc::clone(&relay_a.sessions),
        mesh: relay_a.mesh.clone(),
        links: links_a_tx,
        redial_delay: Duration::from_millis(50),
    };
    tokio::spawn(dialer::run_mesh_dialer(config, peers_rx));
    (peers_tx, links_a_rx)
}

/// A desired peer carrying no pinned cert: the dial falls back to the
/// configured roots `dialer_for_a` was given (the old-coordinator shape). The
/// pinned-cert path is exercised by
/// `dialer_establishes_and_reestablishes_a_desired_peer_link`, which runs with
/// empty fallback roots.
pub fn peer_at(id: u64, addr: SocketAddr) -> RelayPeer {
    RelayPeer {
        relay_id: RelayId(id),
        relay_addr: addr,
        cert_der: Vec::new(),
        relay_addrs: Vec::new(),
    }
}
