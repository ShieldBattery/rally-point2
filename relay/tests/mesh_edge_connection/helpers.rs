//! Fixtures only the mesh connection suite uses: a relay that also hands back
//! its mesh-accept channel, and the polling waits the dial/redial tests spin on.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::RelayPeer;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::SignedToken;
use rally_point_relay::coordinator::client::{FleetMeshPeers, FleetMeshPeersReader};
use rally_point_relay::mesh;
use rally_point_relay::mesh::dialer;
use rally_point_relay::routing::Sessions;
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::CertificateDer;
use rally_point_transport::{Link, noq, rustls};

pub use crate::common::{
    AnyError, KID, Keypair, TENANT, Tenant, keypair, mint_token, self_signed, turn,
};
use tokio::sync::{mpsc, watch};

/// The one tenant these tests trust, named by the suite's fixed key id.
pub fn make_tenant() -> Tenant {
    crate::common::make_tenant(KID, TENANT)
}

/// A registry trusting `tenant` alone.
pub fn registry_for(tenant: &Tenant) -> rally_point_relay::auth::Registry {
    crate::common::registry_for(&[tenant])
}

/// Runs the client side of the handshake as a fresh dial, presenting no resume
/// cursors (an empty, zero-count frame) so the relay replays nothing.
pub async fn handshake(
    connection: &noq::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
) -> Result<(), AnyError> {
    crate::common::handshake(connection, token, signing_key, &[]).await
}

/// An empty fleet mesh-peer read handle for the accept side: these tests exercise
/// the connection half, not the coordinator's peer-auth push, so the acceptor's
/// fleet map is empty (its writer is dropped immediately, leaving only the handle).
pub fn empty_fleet_peers() -> FleetMeshPeersReader {
    FleetMeshPeers::new().reader()
}

/// What an established mesh link surfaces on the `links` channel: the peer's id and
/// the command sender that drives `Join`/`Leave` on that link.
pub type LinkHandle = mesh::MeshLinkHandle;

/// A relay with its client edge serving, plus the mesh-accept channel and
/// shared mesh state. Mirrors `mesh_edge`'s `Relay` but exposes
/// `mesh_accept_rx` for the production `run_mesh_accept` drain.
pub struct Relay {
    pub addr: SocketAddr,
    pub ca: CertificateDer<'static>,
    pub sessions: Sessions,
    pub mesh: mesh::MeshState,
    pub mesh_accept_rx: mpsc::Receiver<noq::Connection>,
}

impl Relay {
    pub fn start(tenant: &Tenant, relay_id: u64) -> Self {
        let (chain, key, ca) = self_signed();
        let cfg = server_config(chain, key).unwrap();
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = noq::Endpoint::server(cfg, bind).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let sessions: Sessions = Arc::default();
        let mesh = mesh::new_mesh_state();
        let (mesh_accept_tx, mesh_accept_rx) = mpsc::channel(8);

        tokio::spawn(server::serve(
            endpoint,
            Arc::new(registry_for(tenant)),
            Arc::clone(&sessions),
            mesh.clone(),
            Some(mesh_accept_tx),
        ));

        tracing::info!(relay_id, %addr, "relay started");
        Self {
            addr,
            ca,
            sessions,
            mesh,
            mesh_accept_rx,
        }
    }
}

/// Connects a client to `addr`, authorizes with a minted token, and returns
/// the `Link` for sending/receiving turns.
pub async fn connect_client(
    addr: SocketAddr,
    ca: &CertificateDer<'static>,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Result<Link, AnyError> {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let ep = noq::Endpoint::client(bind).unwrap();
    ep.set_default_client_config(cfg);
    let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&conn, &token, &client_key).await?;
    Ok(Link::new(conn))
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

/// Polls `cond` until it holds, up to a couple of seconds. Returns whether it
/// became true (for asserting async state settled without a fixed sleep).
pub async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}
