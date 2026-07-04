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
use crate::presence;
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
/// the link with our id. Opens a fresh unidirectional stream and writes the
/// fixed hello frame — and returns the stream still open, because it stays in
/// service for the link's lifetime carrying this relay's presence frames (the
/// dialer's report channel; see [`presence`](crate::presence)).
async fn send_mesh_hello(
    connection: &quinn::Connection,
    our_id: RelayId,
) -> Result<quinn::SendStream, MeshHelloError> {
    let mut stream = connection.open_uni().await?;
    let hello = MeshHello::new(our_id, ProtocolVersion::CURRENT);
    stream.write_all(&hello.encode()).await?;
    Ok(stream)
}

/// Reads the dialing peer's identity hello on the unidirectional stream it
/// opened right after connecting, bounded by [`MESH_HELLO_TIMEOUT`] so a peer
/// that connects but never identifies itself cannot pin this task open.
/// Returns the stream alongside the hello: the dialer keeps writing to it —
/// its presence frames follow the hello — so the acceptor hands it to a
/// presence reader rather than dropping it.
async fn recv_mesh_hello(
    connection: &quinn::Connection,
) -> Result<(MeshHello, quinn::RecvStream), MeshHelloError> {
    let read = async {
        let mut stream = connection.accept_uni().await?;
        let mut frame = [0u8; MESH_HELLO_LEN];
        stream.read_exact(&mut frame).await?;
        Ok::<_, MeshHelloError>((MeshHello::decode(frame), stream))
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
            let (peer_id, hello_stream) = match recv_mesh_hello(&connection).await {
                Ok((hello, stream)) => {
                    if hello.protocol != ProtocolVersion::CURRENT {
                        tracing::warn!(
                            peer_id = hello.relay_id.0,
                            peer_protocol = %hello.protocol,
                            our_protocol = %ProtocolVersion::CURRENT,
                            "mesh peer protocol version differs from ours",
                        );
                    }
                    (hello.relay_id, stream)
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
            // Presence: the dialer's reports keep arriving on its hello
            // stream; ours go out on a uni-stream of our own — the only one an
            // acceptor ever opens, so the dialer can locate it unambiguously.
            let presence_rx = presence::spawn_presence_reader(hello_stream);
            let presence_tx = match connection.open_uni().await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::info!(%error, "mesh presence stream open failed; dropping connection");
                    return;
                }
            };

            // The bidirectional mesh control stream carries synced-leave
            // propagation. The dialer opens it right after its hello and writes an
            // establishing frame, so `accept_bi` completes promptly; bound it by
            // the same deadline as the hello so a peer that connects but never
            // opens it (e.g. one predating this ALPN version) can't pin the task —
            // failing to establish it drops the connection, like the hello.
            let (control_send, control_recv) =
                match tokio::time::timeout(MESH_HELLO_TIMEOUT, connection.accept_bi()).await {
                    Ok(Ok(halves)) => halves,
                    Ok(Err(error)) => {
                        tracing::info!(%error, "mesh control stream accept failed; dropping connection");
                        return;
                    }
                    Err(_) => {
                        tracing::info!("mesh control stream not established within the deadline; dropping connection");
                        return;
                    }
                };
            let peer_control_rx =
                rally_point_transport::mesh_control_stream::spawn_mesh_control_reader(control_recv);

            let link = rally_point_transport::MeshLink::new(connection);
            let (tx, rx) = mesh::command_channel();
            let _ = links.send((peer_id, tx)).await;
            let presence_io = presence::PresenceIo {
                peer_id,
                tx: presence_tx,
                rx: presence_rx,
            };
            let control_io = mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            };
            mesh::run_mesh_link(link, presence_io, control_io, rx, sessions, mesh, mesh::IDLE_TIMEOUT)
                .await;
        });
    }
}

/// The delay between mesh redial attempts, after a link's connection failed or a
/// dial attempt didn't connect. Mesh establishment is not latency-critical — a
/// running game rides already-established links, and a link returning a couple of
/// seconds later is fine — so a fixed short delay avoids hammering a peer that is
/// restarting or briefly unreachable, mirroring the coordinator control
/// connection's reconnect delay.
pub const MESH_REDIAL_DELAY: Duration = Duration::from_secs(2);

/// Dials a peer relay and *keeps a link to it established*, redialing after the
/// connection fails, surfacing `(peer id, `[`MeshCommand`](mesh::MeshCommand)`
/// sender)` over `links` on each (re)established link. The peer id is the
/// configured `peer_id` — the dialer already knows whom it dialed — and the dialer
/// announces that id to the peer (a [`MeshHello`](rally_point_proto::mesh::MeshHello))
/// so the accepting side can label its own end of the link.
///
/// This is the *lower-id* side of a relay-pair: the [`should_dial_mesh`]
/// tie-break (`our_id < peer_id`) is checked before dialing, and if it returns
/// `false` this is a no-op (the peer will dial us — we stay in the accept loop).
/// Two relays with the same id is a misconfiguration: `should_dial_mesh`
/// returns `false` for equal ids, so neither dials rather than both.
///
/// The dial is *supervised*: a dial that fails to connect, or an established
/// link's connection that later drops, is retried after [`MESH_REDIAL_DELAY`] —
/// one transient failure no longer strands the pair until the process restarts.
/// A fresh link re-registers under the same peer id, and the Join source re-syncs
/// the sessions it should serve onto it. An *intentional* wind-down is not
/// retried: an idle teardown (the link served its sessions and went empty) or the
/// relay dropping its command sender ends the supervisor.
pub async fn run_mesh_dial(
    dial: MeshDial,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
) {
    run_mesh_dial_with(dial, sessions, mesh, links, MESH_REDIAL_DELAY).await
}

/// [`run_mesh_dial`] with the redial delay injected, so a test need not wait the
/// production interval between attempts.
pub async fn run_mesh_dial_with(
    dial: MeshDial,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
    redial_delay: Duration,
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

    // Build the client config + endpoint once and reuse them across redials. Both
    // are terminal on failure — a bad TLS config or an unbindable client socket
    // won't fix itself by retrying, so there's nothing to supervise. The endpoint
    // outlives every connection dialed from it (a quinn `Endpoint` closes its
    // connections when dropped), so keeping it on this task's stack for the whole
    // supervisor loop keeps each attempt's connection alive while its driver runs.
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

    let target = DialTarget {
        our_id,
        peer_id,
        peer_addr,
        server_name,
    };

    // Supervisor loop: (re)establish the link, then decide from how it ended
    // whether to redial. Only a connection failure yields `Retry` — an intentional
    // wind-down yields `Stop`, which ends the `while let` and stops supervising.
    while let DialOutcome::Retry =
        dial_and_serve(&endpoint, &target, &sessions, &mesh, &links).await
    {
        tokio::time::sleep(redial_delay).await;
    }
}

/// The fixed target of a supervised dial, reused across redial attempts.
struct DialTarget {
    our_id: RelayId,
    peer_id: RelayId,
    peer_addr: SocketAddr,
    server_name: String,
}

/// What the supervisor should do after one dial attempt and the link's lifetime.
enum DialOutcome {
    /// The connection failed — a dial that didn't connect, or an established
    /// link's connection that dropped. Redial after the delay.
    Retry,
    /// The link wound down intentionally — an idle teardown, or the relay dropped
    /// its command sender. Stop supervising this peer.
    Stop,
}

/// One dial attempt: connect, announce our id, hand the link's command sender to
/// the Join source, and run the link driver to completion — returning whether the
/// supervisor should redial.
///
/// A connect or hello failure is [`Retry`](DialOutcome::Retry) (the peer may be
/// briefly unreachable). Once the link runs, the driver's [`MeshLinkExit`] decides:
/// a [`ConnectionFailed`](mesh::MeshLinkExit::ConnectionFailed) is retried, while
/// an [`Idle`](mesh::MeshLinkExit::Idle) teardown or a
/// [`CommandChannelClosed`](mesh::MeshLinkExit::CommandChannelClosed) shutdown is
/// intentional and stops the supervisor.
async fn dial_and_serve(
    endpoint: &quinn::Endpoint,
    target: &DialTarget,
    sessions: &Sessions,
    mesh: &MeshState,
    links: &mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
) -> DialOutcome {
    let DialTarget {
        our_id,
        peer_id,
        peer_addr,
        server_name,
    } = target;

    tracing::info!(
        our_id = our_id.0,
        peer_id = peer_id.0,
        %peer_addr,
        server_name,
        "dialing mesh peer",
    );
    let connecting = match endpoint.connect(*peer_addr, server_name) {
        Ok(c) => c,
        Err(error) => {
            tracing::info!(%error, peer_id = peer_id.0, "starting mesh dial connect failed; will retry");
            return DialOutcome::Retry;
        }
    };
    let connection = match connecting.await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::info!(%error, peer_id = peer_id.0, "mesh dial to peer failed; will retry");
            return DialOutcome::Retry;
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
    // the higher-id acceptor learns which peer reached it. The hello stream
    // stays open — our presence frames follow the hello on it.
    let presence_tx = match send_mesh_hello(&connection, *our_id).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::info!(%error, peer_id = peer_id.0, "mesh hello send failed; will retry");
            return DialOutcome::Retry;
        }
    };
    // The peer's presence arrives on the one uni-stream an acceptor opens;
    // the reader accepts it lazily so an establishment that races the peer's
    // open never stalls the dial.
    let presence_rx = presence::spawn_presence_reader_accepting(connection.clone());

    // Open the bidirectional mesh control stream and write an establishing frame
    // right away: QUIC does not surface an opened bidirectional stream to the peer
    // until its opener writes, so this is what makes the acceptor's bounded
    // `accept_bi` complete promptly on a link that may carry no leaves for a while.
    let (mut control_send, control_recv) = match connection.open_bi().await {
        Ok(halves) => halves,
        Err(error) => {
            tracing::info!(%error, peer_id = peer_id.0, "mesh control stream open failed; will retry");
            return DialOutcome::Retry;
        }
    };
    if let Err(error) =
        rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await
    {
        tracing::info!(%error, peer_id = peer_id.0, "mesh control stream establish failed; will retry");
        return DialOutcome::Retry;
    }
    let peer_control_rx =
        rally_point_transport::mesh_control_stream::spawn_mesh_control_reader(control_recv);

    let link = rally_point_transport::MeshLink::new(connection);
    let (tx, rx) = mesh::command_channel();
    // Hand the fresh command sender to the Join source. On a redial this
    // re-registers under the same peer id, which re-syncs the sessions the peer
    // should serve onto the new link (the old, dead sender is replaced).
    let _ = links.send((*peer_id, tx)).await;

    let presence_io = presence::PresenceIo {
        peer_id: *peer_id,
        tx: presence_tx,
        rx: presence_rx,
    };
    let control_io = mesh::MeshControlIo {
        tx: control_send,
        rx: peer_control_rx,
    };
    let exit = mesh::run_mesh_link(
        link,
        presence_io,
        control_io,
        rx,
        Arc::clone(sessions),
        mesh.clone(),
        mesh::IDLE_TIMEOUT,
    )
    .await;

    match exit {
        mesh::MeshLinkExit::ConnectionFailed => {
            tracing::info!(
                peer_id = peer_id.0,
                "mesh link connection failed; redialing"
            );
            DialOutcome::Retry
        }
        mesh::MeshLinkExit::Idle => {
            tracing::info!(
                peer_id = peer_id.0,
                "mesh link idle-torn-down; not redialing"
            );
            DialOutcome::Stop
        }
        mesh::MeshLinkExit::CommandChannelClosed => {
            tracing::info!(
                peer_id = peer_id.0,
                "mesh link command channel closed (relay wound it down); not redialing",
            );
            DialOutcome::Stop
        }
    }
}
