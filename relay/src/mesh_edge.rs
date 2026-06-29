//! The mesh-edge connection half: establish each relay↔relay QUIC connection
//! and spawn a [`mesh::run_mesh_link`] driver on it.
//!
//! This is the connection layer of the mesh — everything *below* the
//! [`MeshCommand`] Join/Leave stream that `run_mesh_link` consumes. It owns
//! the two ways a mesh link's QUIC connection comes into being:
//!
//! - **Accept** ([`run_mesh_accept`]): peer relays that dial this relay arrive
//!   on the `mesh_accept` channel the client-edge accept loop dispatches to
//!   (ALPN `rp2-mesh/N`). This task drains them, wraps each as a `MeshLink`,
//!   and spawns a driver. The higher-id side of a relay-pair ends up here.
//! - **Dial** ([`run_mesh_dial`]): this relay dials a peer relay when the
//!   [`should_dial_mesh`] tie-break says it is the lower id, wraps the
//!   connection, and spawns a driver. The lower-id side ends up here.
//!
//! Both halves are deliberately symmetric in what they *produce* — one
//! [`MeshCommand`] sender per established link — and differ only in which side
//! initiates the TCP/QUIC handshake. The tie-break (`lower id dials higher`)
//! guarantees exactly one side of a relay-pair dials, so exactly one QUIC
//! connection completes per pair and there is no redundant connection to tear
//! down. The peer's id must already be known (from configured topology) before
//! either side dials: a post-connect id exchange cannot decide the dial, since
//! the dial has already happened by the time it could run.
//!
//! # The Join source is pluggable
//!
//! Each established link returns its `MeshCommand` sender. Today the
//! integration test drives [`MeshCommand::Join`] on it directly (mirroring
//! `mesh_edge.rs`'s in-process harness). In production the coordinator's
//! session-descriptor push (Phase 3) sends `Join`/`Leave` on the sender for
//! the specific link serving a session — targeting the relay-pair that jointly
//! serves it, never broadcasting to links that don't. This module never sends
//! `Join` itself: it establishes the connection and owns the driver's lifetime,
//! not the session membership. Over-joining (telling a peer about a session it
//! doesn't serve) would just be logged-and-dropped by `run_mesh_link`, but it
//! would contradict the coordinator-targeted source, so the connection half
//! stays out of session membership entirely.
//!
//! # Auth today
//!
//! Real relay-to-relay authentication and tenant binding land with the
//! coordinator (Phase 3, open — see the build plan's open questions). Today the
//! dial trusts the peer's certificate against the same roots a client would,
//! so a dev/loopback pair with self-signed certs just works and a production
//! pair needs its relay certs in each other's trust store until the
//! coordinator issues a mesh-specific secret.

use std::net::SocketAddr;
use std::sync::Arc;

use rally_point_proto::ids::RelayId;
use rally_point_transport::quinn;
use rally_point_transport::rustls::RootCertStore;
use tokio::sync::mpsc;

use crate::mesh::{self, MeshState};
use crate::routing::Sessions;

/// The configuration for one mesh dial: who we are, who we dial, and how to
/// trust the peer's certificate. Bundling these keeps [`run_mesh_dial`] within
/// the argument-count the codebase holds elsewhere (no `#[allow(clippy::too_many_arguments)]`),
/// mirroring [`MeshState`].
pub struct MeshDial {
    /// This relay's id. The tie-break (`our_id < peer_id`) decides whether we
    /// dial or wait for the peer to dial us.
    pub our_id: RelayId,
    /// The peer relay's id.
    pub peer_id: RelayId,
    /// The peer relay's listen endpoint.
    pub peer_addr: SocketAddr,
    /// The TLS SNI / verified hostname for the peer's certificate (for
    /// self-signed dev certs this is `localhost`; for production it is the
    /// hostname on the relay's cert).
    pub server_name: String,
    /// Root certificates to trust the peer's cert chain against. Today the
    /// same roots a client would use; a mesh-specific secret lands with the
    /// coordinator (Phase 3).
    pub roots: RootCertStore,
}

/// Drives the accept side of the mesh edge.
///
/// For each peer-relay QUIC connection the client-edge accept loop dispatched to
/// `mesh_accept` (ALPN `rp2-mesh/N`), this wraps the connection as a
/// [`MeshLink`] and spawns a [`mesh::run_mesh_link`] driver on it, returning
/// the driver's `MeshCommand` sender over `links` — one per established link,
/// in arrival order. The senders are also the handles the test (today) or the
/// coordinator's session-descriptor push (Phase 3) uses to send
/// [`MeshCommand::Join`] for the specific link serving a session.
///
/// This is the *higher-id* side of a relay-pair: it stays in its accept loop and
/// lets the lower-id peer's dial arrive. The lower-id side runs
/// [`run_mesh_dial`] instead.
///
/// Ends when `mesh_accept` closes (the client-edge accept loop ended — the
/// relay is shutting down). Each link is independent: one peer link dropping
/// does not end the others.
pub async fn run_mesh_accept(
    mut mesh_accept: mpsc::Receiver<quinn::Connection>,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<mpsc::Sender<mesh::MeshCommand>>,
) {
    while let Some(connection) = mesh_accept.recv().await {
        let link = rally_point_transport::MeshLink::new(connection);
        let (tx, rx) = mpsc::channel(mesh::COMMAND_CAPACITY);
        let sessions = Arc::clone(&sessions);
        let mesh = mesh.clone();
        // The driver owns the link for its lifetime (both recv and send need
        // &mut self), so the MeshLink moves into the spawned task. The command
        // sender is handed back over `links` for the Join source to drive.
        tokio::spawn(async move {
            mesh::run_mesh_link(link, rx, sessions, mesh).await;
        });
        // A send failure here means the links collector has gone away (the relay
        // is tearing down); the driver keeps running on its connection until
        // that fails, which is fine — the collector dropping just means nobody
        // is enumerating new links, not that existing links should be torn down.
        let _ = links.send(tx).await;
    }
}

/// Dials a peer relay and spawns a [`mesh::run_mesh_link`] driver on the
/// established connection, returning its `MeshCommand` sender over `links`.
///
/// This is the *lower-id* side of a relay-pair: the [`should_dial_mesh`]
/// tie-break (`our_id < peer_id`) is checked before dialing, and if it returns
/// `false` this is a no-op (the peer will dial us — we stay in the accept loop).
/// Two relays with the same id is a misconfiguration: `should_dial_mesh`
/// returns `false` for equal ids, so neither dials rather than both.
///
/// A dial that fails (peer unreachable, TLS rejected) is logged and the
/// `links` channel receives nothing for it — one failed peer does not end the
/// relay. Production should retry with backoff; today this dials once.
pub async fn run_mesh_dial(
    dial: MeshDial,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<mpsc::Sender<mesh::MeshCommand>>,
) {
    let MeshDial {
        our_id,
        peer_id,
        peer_addr,
        server_name,
        roots,
    } = dial;

    // Pre-connect local decision: don't dial if we're the higher id. The peer
    // will dial us; we stay in the accept loop. Equal ids is a
    // misconfiguration — neither dials.
    if !rally_point_transport::should_dial_mesh(our_id, peer_id) {
        tracing::info!(
            our_id = our_id.0,
            peer_id = peer_id.0,
            "not dialing mesh peer (higher or equal id; peer dials if lower)",
        );
        return;
    }

    let mesh_cfg = match rally_point_transport::quic::mesh_client_config(roots) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::error!(%error, "building mesh client config; not dialing peer");
            return;
        }
    };
    let bind: SocketAddr = (std::net::Ipv6Addr::UNSPECIFIED, 0).into();
    let mut endpoint = match quinn::Endpoint::client(bind) {
        Ok(ep) => ep,
        Err(error) => {
            tracing::error!(%error, "binding mesh dial endpoint; not dialing peer");
            return;
        }
    };
    endpoint.set_default_client_config(mesh_cfg);

    tracing::info!(
        our_id = our_id.0,
        peer_id = peer_id.0,
        %peer_addr,
        server_name,
        "dialing mesh peer",
    );
    // `endpoint.connect` returns a `Connecting` that borrows the endpoint, so
    // `endpoint` must outlive the `.await`.
    let connecting = match endpoint.connect(peer_addr, &server_name) {
        Ok(c) => c,
        Err(error) => {
            tracing::error!(%error, "starting mesh dial connect; not dialing peer");
            return;
        }
    };
    let connection = match connecting.await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::info!(%error, "mesh dial to peer failed");
            return;
        }
    };

    tracing::info!(
        our_id = our_id.0,
        peer_id = peer_id.0,
        remote = %connection.remote_address(),
        "mesh link established (dial side)",
    );

    let link = rally_point_transport::MeshLink::new(connection);
    let (tx, rx) = mpsc::channel(mesh::COMMAND_CAPACITY);
    let sessions = Arc::clone(&sessions);
    let mesh = mesh.clone();
    // Move `endpoint` into the driver task: a quinn `Endpoint` closes its
    // connections when dropped, and the dialed connection would die the moment
    // this function returns if `endpoint` stayed local. The accept side needs
    // no such move — the *server* `Endpoint` that accepted the connection is
    // owned by `server::serve` and outlives the connections it accepts, but a
    // *client* `Endpoint::client` created here is not kept alive anywhere else.
    tokio::spawn(async move {
        let _endpoint = endpoint; // keep alive for the connection's lifetime
        mesh::run_mesh_link(link, rx, sessions, mesh).await;
    });
    let _ = links.send(tx).await;
}
