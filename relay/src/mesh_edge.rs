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
//! `(peer id, `[`MeshCommand`]` sender)` pair per established link — and differ
//! only in which side initiates the TCP/QUIC handshake. The tie-break
//! (`lower id dials higher`) guarantees exactly one side of a relay-pair dials,
//! so exactly one QUIC connection completes per pair and there is no redundant
//! connection to tear down. The peer's id must already be known (from configured
//! topology) before either side dials: a post-connect id exchange cannot decide
//! the dial, since the dial has already happened by the time it could run.
//!
//! # Knowing which peer a link reaches
//!
//! The dialer knows whom it dialed; the acceptor sees only an inbound connection
//! from an ephemeral source port. So right after connecting, the dialer sends a
//! [`MeshHello`](rally_point_proto::mesh::MeshHello) on a fresh unidirectional
//! stream announcing its id, and the acceptor reads it. Both halves then surface
//! the peer's id alongside the command sender, so the Join source can label each
//! link by which peer it reaches. This is *labeling*, not the dial tie-break —
//! it carries no authority (a claimed id is trusted only as far as the
//! connection's certificate is; relay-to-relay auth is a separate, later
//! concern) and does not influence which side dialed.
//!
//! # The Join source is pluggable
//!
//! Each established link surfaces `(peer id, `[`MeshCommand`]` sender)`. Today
//! the integration test drives [`MeshCommand::Join`] on the sender directly
//! (mirroring `mesh_edge.rs`'s in-process harness). In production the
//! [`MeshControl`](crate::mesh_control::MeshControl) Join source consumes the
//! coordinator's session descriptors and sends `Join`/`Leave` on the sender for
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
use std::time::Duration;

use rally_point_proto::ids::RelayId;
use rally_point_proto::mesh::{MESH_HELLO_LEN, MeshHello};
use rally_point_proto::version::ProtocolVersion;
use rally_point_transport::quinn;
use rally_point_transport::rustls::RootCertStore;
use tokio::sync::mpsc;

use crate::mesh::{self, MeshState};
use crate::routing::Sessions;

/// How long the accepting relay waits for the dialing relay's identity hello
/// before abandoning the connection. The dialer opens its hello stream the
/// moment it connects, so this completes sub-second in practice; the bound stops
/// a peer that connects and then stays silent from pinning an accept task open,
/// mirroring the client edge's authorization-handshake timeout.
const MESH_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the post-connect identity hello exchange failed. Logged, and the link is
/// abandoned — one peer that will not identify itself does not end the relay.
#[derive(Debug, thiserror::Error)]
enum MeshHelloError {
    /// Opening or accepting the hello stream failed (the connection dropped).
    #[error("mesh hello stream error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Writing the hello to the stream failed.
    #[error("mesh hello write error: {0}")]
    Write(#[from] quinn::WriteError),
    /// Reading the hello from the stream failed.
    #[error("mesh hello read error: {0}")]
    Read(#[from] quinn::ReadExactError),
    /// The peer connected but did not send its hello within the deadline.
    #[error("mesh hello not received within the deadline")]
    Timeout,
}

/// Announces our identity to the peer that accepted our dial, so it can label
/// the link with our id. Opens a fresh unidirectional stream, writes the fixed
/// hello frame, and closes the stream.
async fn send_mesh_hello(
    connection: &quinn::Connection,
    our_id: RelayId,
) -> Result<(), MeshHelloError> {
    let mut stream = connection.open_uni().await?;
    let hello = MeshHello::new(our_id, ProtocolVersion::CURRENT);
    stream.write_all(&hello.encode()).await?;
    // A failed finish only means the stream's clean-close frame was lost; the
    // hello bytes are already on the wire, so it does not fail the exchange.
    let _ = stream.finish();
    Ok(())
}

/// Reads the dialing peer's identity hello on the unidirectional stream it
/// opened right after connecting, bounded by [`MESH_HELLO_TIMEOUT`] so a peer
/// that connects but never identifies itself cannot pin this task open.
async fn recv_mesh_hello(connection: &quinn::Connection) -> Result<MeshHello, MeshHelloError> {
    let read = async {
        let mut stream = connection.accept_uni().await?;
        let mut frame = [0u8; MESH_HELLO_LEN];
        stream.read_exact(&mut frame).await?;
        Ok::<MeshHello, MeshHelloError>(MeshHello::decode(frame))
    };
    tokio::time::timeout(MESH_HELLO_TIMEOUT, read)
        .await
        .map_err(|_| MeshHelloError::Timeout)?
}

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
/// `mesh_accept` (ALPN `rp2-mesh/N`), this reads the dialer's identity hello,
/// wraps the connection as a [`MeshLink`], spawns a [`mesh::run_mesh_link`]
/// driver on it, and surfaces `(peer id, `[`MeshCommand`](mesh::MeshCommand)`
/// sender)` over `links` — one per established link. The peer id comes from the
/// hello (the acceptor cannot otherwise tell which relay dialed it); the sender
/// is the handle the test (today) or [`MeshControl`](crate::mesh_control::MeshControl)
/// (the coordinator's session descriptors) uses to send [`MeshCommand::Join`]
/// for the specific link serving a session.
///
/// This is the *higher-id* side of a relay-pair: it stays in its accept loop and
/// lets the lower-id peer's dial arrive. The lower-id side runs
/// [`run_mesh_dial`] instead.
///
/// Each connection is handled in its own task: reading the hello is a
/// peer-driven round trip, so doing it inline would let one slow or silent peer
/// stall every other inbound mesh connection. The accept loop stays free to take
/// the next connection immediately, and one peer link dropping does not end the
/// others.
///
/// Ends when `mesh_accept` closes (the client-edge accept loop ended — the
/// relay is shutting down).
pub async fn run_mesh_accept(
    mut mesh_accept: mpsc::Receiver<quinn::Connection>,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
) {
    while let Some(connection) = mesh_accept.recv().await {
        let sessions = Arc::clone(&sessions);
        let mesh = mesh.clone();
        let links = links.clone();
        tokio::spawn(async move {
            let peer_id = match recv_mesh_hello(&connection).await {
                Ok(hello) => {
                    if hello.protocol != ProtocolVersion::CURRENT {
                        tracing::warn!(
                            peer_id = hello.relay_id.0,
                            peer_protocol = %hello.protocol,
                            our_protocol = %ProtocolVersion::CURRENT,
                            "mesh peer protocol version differs from ours",
                        );
                    }
                    hello.relay_id
                }
                Err(error) => {
                    tracing::info!(%error, "mesh peer did not identify itself; dropping connection");
                    return;
                }
            };

            tracing::info!(
                peer_id = peer_id.0,
                remote = %connection.remote_address(),
                "mesh link established (accept side)",
            );

            // The driver owns the link for its lifetime (both recv and send need
            // &mut self), so the MeshLink moves into this task and the driver
            // runs here to completion. Hand the command sender — labeled with the
            // peer's id — to the Join source first. A send failure means the
            // links collector has gone away (the relay is tearing down); the
            // driver still runs on its connection until that fails, since the
            // collector dropping just means nobody is enumerating new links.
            let link = rally_point_transport::MeshLink::new(connection);
            let (tx, rx) = mesh::command_channel();
            let _ = links.send((peer_id, tx)).await;
            mesh::run_mesh_link(link, rx, sessions, mesh, mesh::IDLE_TIMEOUT).await;
        });
    }
}

/// Dials a peer relay and spawns a [`mesh::run_mesh_link`] driver on the
/// established connection, surfacing `(peer id, `[`MeshCommand`](mesh::MeshCommand)`
/// sender)` over `links`. The peer id is the configured `peer_id` — the dialer
/// already knows whom it dialed — and the dialer announces that id to the peer
/// (a [`MeshHello`](rally_point_proto::mesh::MeshHello)) so the accepting side
/// can label its own end of the link.
///
/// This is the *lower-id* side of a relay-pair: the [`should_dial_mesh`]
/// tie-break (`our_id < peer_id`) is checked before dialing, and if it returns
/// `false` this is a no-op (the peer will dial us — we stay in the accept loop).
/// Two relays with the same id is a misconfiguration: `should_dial_mesh`
/// returns `false` for equal ids, so neither dials rather than both.
///
/// A dial that fails (peer unreachable, TLS rejected, hello not sent) is logged
/// and the `links` channel receives nothing for it — one failed peer does not
/// end the relay. Production should retry with backoff; today this dials once.
pub async fn run_mesh_dial(
    dial: MeshDial,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
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

    // Announce our id so the accepting peer can label its end of the link. The
    // dial tie-break already decided this side connects; the hello is purely so
    // the higher-id acceptor learns which peer reached it.
    if let Err(error) = send_mesh_hello(&connection, our_id).await {
        tracing::info!(%error, peer_id = peer_id.0, "mesh hello send failed; abandoning dial");
        return;
    }

    let link = rally_point_transport::MeshLink::new(connection);
    let (tx, rx) = mesh::command_channel();
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
        mesh::run_mesh_link(link, rx, sessions, mesh, mesh::IDLE_TIMEOUT).await;
    });
    let _ = links.send((peer_id, tx)).await;
}
