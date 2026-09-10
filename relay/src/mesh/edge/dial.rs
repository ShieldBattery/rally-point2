//! The dial side of the mesh edge: this relay dials a peer when the
//! lower-id-dials-higher tie-break says so, then supervises the link —
//! redialing on connection failure, stopping on an intentional wind-down.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::RelayId;
use rally_point_proto::version::MESH_CLOSE_PROTOCOL_MISMATCH;
use rally_point_transport::noq;
use tokio::sync::mpsc;

use crate::mesh::{self, MeshState};
use crate::routing::Sessions;
use crate::session::presence;

use super::{MESH_REDIAL_DELAY, MeshDial, send_mesh_hello};

/// Dials a peer relay and *keeps a link to it established*, redialing after the
/// connection fails, surfacing `(peer id, `[`MeshCommand`](mesh::MeshCommand)`
/// sender)` over `links` on each (re)established link. The peer id is the
/// configured `peer_id` — the dialer already knows whom it dialed — and the dialer
/// announces that id to the peer (a [`MeshHello`](rally_point_proto::mesh::MeshHello))
/// so the accepting side can label its own end of the link.
///
/// This is the *lower-id* side of a relay-pair: the
/// [`should_dial_mesh`](rally_point_transport::should_dial_mesh)
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
    links: mpsc::Sender<mesh::MeshLinkHandle>,
) {
    run_mesh_dial_with(dial, sessions, mesh, links, MESH_REDIAL_DELAY).await
}

/// [`run_mesh_dial`] with the redial delay injected, so a test need not wait the
/// production interval between attempts.
pub async fn run_mesh_dial_with(
    dial: MeshDial,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<mesh::MeshLinkHandle>,
    redial_delay: Duration,
) {
    let MeshDial {
        our_id,
        peer_id,
        peer_addrs,
        server_name,
        roots,
        cert_chain,
        key,
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
    // outlives every connection dialed from it (a noq `Endpoint` closes its
    // connections when dropped), so keeping it on this task's stack for the whole
    // supervisor loop keeps each attempt's connection alive while its driver runs.
    let mesh_cfg = match rally_point_transport::quic::mesh_client_config(roots, cert_chain, key) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::error!(%error, "building mesh client config; not dialing peer");
            return;
        }
    };
    let bind: SocketAddr = (std::net::Ipv6Addr::UNSPECIFIED, 0).into();
    let endpoint = match noq::Endpoint::client(bind) {
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
        peer_addrs,
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

/// Whether the peer application-closed the connection refusing our protocol
/// version ([`MESH_CLOSE_PROTOCOL_MISMATCH`]). Read from the connection's close
/// reason rather than any one operation's error: the acceptor closes right after
/// reading our hello, so the refusal surfaces as whichever stream operation
/// happened to fail next, and this names it regardless of which that was.
fn refused_for_protocol_mismatch(connection: &noq::Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(noq::ConnectionError::ApplicationClosed(close))
            if close.error_code == noq::VarInt::from_u32(MESH_CLOSE_PROTOCOL_MISMATCH)
    )
}

/// Logs one post-connect dial failure before the supervisor retries, naming a
/// peer's protocol-version refusal distinctly (at warn — a deploy fixes it, not a
/// redial) and falling back to the ordinary retry line otherwise.
fn log_dial_retry(
    connection: &noq::Connection,
    peer_id: RelayId,
    context: &str,
    error: &dyn std::fmt::Display,
) {
    if refused_for_protocol_mismatch(connection) {
        tracing::warn!(
            peer_id = peer_id.0,
            "mesh peer refused our protocol version; will retry",
        );
    } else {
        tracing::info!(error = %error, peer_id = peer_id.0, "{}; will retry", context);
    }
}

/// The fixed target of a supervised dial, reused across redial attempts.
struct DialTarget {
    our_id: RelayId,
    peer_id: RelayId,
    peer_addrs: Vec<SocketAddr>,
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
    endpoint: &noq::Endpoint,
    target: &DialTarget,
    sessions: &Sessions,
    mesh: &MeshState,
    links: &mpsc::Sender<mesh::MeshLinkHandle>,
) -> DialOutcome {
    // Mint before connect/handshake awaits so generation order reflects attempt
    // creation, not whichever connection happens to authenticate last.
    let attempt = mesh::new_mesh_link_attempt();
    let DialTarget {
        our_id,
        peer_id,
        peer_addrs,
        server_name,
    } = target;

    // Walk the peer's candidate addresses in its advertised order until one
    // connects — the dual-stack fallback. Sequential on purpose: mesh
    // establishment is not latency-critical (a running game rides
    // already-established links), so a plain fallback loop beats
    // happy-eyeballs machinery here. All candidates failing is one failed
    // attempt: the supervisor redials after its delay and walks again.
    let mut connection = None;
    for peer_addr in peer_addrs {
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
                tracing::info!(
                    %error,
                    peer_id = peer_id.0,
                    %peer_addr,
                    "mesh dial candidate rejected; trying the next",
                );
                continue;
            }
        };
        match connecting.await {
            Ok(conn) => {
                connection = Some(conn);
                break;
            }
            Err(error) => tracing::info!(
                %error,
                peer_id = peer_id.0,
                %peer_addr,
                "mesh dial candidate failed; trying the next",
            ),
        }
    }
    let Some(connection) = connection else {
        tracing::info!(
            peer_id = peer_id.0,
            "every mesh dial candidate failed; will retry",
        );
        return DialOutcome::Retry;
    };

    tracing::info!(
        our_id = our_id.0,
        peer_id = peer_id.0,
        remote = ?connection.path(noq::PathId::ZERO).and_then(|path| path.remote_address().ok()),
        "mesh link established (dial side)",
    );

    // Announce our id so the accepting peer can label its end of the link. The
    // dial tie-break already decided this side connects; the hello is purely so
    // the higher-id acceptor learns which peer reached it. The hello stream
    // stays open — our presence frames follow the hello on it.
    let presence_tx = match send_mesh_hello(&connection, *our_id).await {
        Ok(stream) => stream,
        Err(error) => {
            log_dial_retry(&connection, *peer_id, "mesh hello send failed", &error);
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
            log_dial_retry(
                &connection,
                *peer_id,
                "mesh control stream open failed",
                &error,
            );
            return DialOutcome::Retry;
        }
    };
    if let Err(error) =
        rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await
    {
        log_dial_retry(
            &connection,
            *peer_id,
            "mesh control stream establish failed",
            &error,
        );
        return DialOutcome::Retry;
    }
    let peer_control_rx =
        rally_point_transport::mesh_control_stream::spawn_mesh_control_reader(control_recv);

    // Verification precedes the claim inside `claim_verified_mesh_link`: an
    // under-floor peer is refused before it can supersede (and kill) whatever
    // healthy link currently serves this peer id. Retrying the same
    // misconfigured peer is pointless but harmless, so an under-floor refusal
    // surfaces as an ordinary failed attempt.
    let lease = match mesh::claim_verified_mesh_link(mesh, *peer_id, &attempt, &connection) {
        mesh::MeshLinkAdmission::Claimed(lease) => lease,
        mesh::MeshLinkAdmission::UnderFloor(error) => {
            tracing::warn!(peer = peer_id.0, %error, "refusing under-floor mesh peer");
            connection.close(0u32.into(), b"datagram budget under guaranteed floor");
            return DialOutcome::Retry;
        }
        mesh::MeshLinkAdmission::Superseded => {
            connection.close(0u32.into(), b"superseded mesh link");
            return DialOutcome::Stop;
        }
    };

    // A cheap handle kept past the link's move below, so a driver exit can still
    // read the connection's close reason (naming a protocol-version refusal).
    let connection_for_exit = connection.clone();
    let link = rally_point_transport::MeshLink::new(connection);
    let (tx, rx) = mesh::command_channel();
    // Hand the fresh command sender to the Join source. On a redial this
    // re-registers under the same peer id, which re-syncs the sessions the peer
    // should serve onto the new link (the old, dead sender is replaced).
    let _ = links.send((*peer_id, lease.generation(), tx)).await;

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
        mesh::MeshLinkIo {
            presence: presence_io,
            control: control_io,
            lease,
        },
        rx,
        Arc::clone(sessions),
        mesh.clone(),
        mesh::IDLE_TIMEOUT,
    )
    .await;

    match exit {
        mesh::MeshLinkExit::ConnectionFailed => {
            if refused_for_protocol_mismatch(&connection_for_exit) {
                tracing::warn!(
                    peer_id = peer_id.0,
                    "mesh link closed: peer refused our protocol version; redialing",
                );
            } else {
                tracing::info!(
                    peer_id = peer_id.0,
                    "mesh link connection failed; redialing"
                );
            }
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
        mesh::MeshLinkExit::Superseded => {
            tracing::info!(
                peer_id = peer_id.0,
                "mesh link superseded by a newer local generation; not redialing",
            );
            DialOutcome::Stop
        }
    }
}
