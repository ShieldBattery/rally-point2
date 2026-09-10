//! The accept side of the mesh edge: peer relays that dial this relay arrive
//! on the `mesh_accept` channel the client-edge accept loop dispatches to,
//! bounded by the dedicated [`MESH_ACCEPT_CONCURRENCY`] handshake-window
//! semaphore so an anonymous connection flood cannot pin unbounded tasks.

use std::sync::Arc;

use rally_point_proto::version::{self, MESH_CLOSE_PROTOCOL_MISMATCH};
use rally_point_transport::noq;
use tokio::sync::{Semaphore, mpsc};

use crate::coordinator::client::FleetMeshPeersReader;
use crate::mesh::{self, MeshState};
use crate::routing::Sessions;
use crate::session::presence;

use super::{MESH_HELLO_TIMEOUT, recv_mesh_hello, verify_mesh_peer_identity};

/// How many mesh accept-side handshakes ([`recv_mesh_hello`] through the
/// control-stream `accept_bi`) may be in flight at once, fleet-wide on this
/// relay.
///
/// A dedicated cap, not the client edge's `MAX_PENDING_HANDSHAKES` admission
/// semaphore (`server::serve_with_max_pending`): that one is sized for
/// thousands of *players*, dropped before this handshake even starts (mesh
/// connections are routed off the client edge's ALPN dispatch, which frees
/// its own permit immediately — mesh peers were never meant to compete for
/// client capacity). A relay fleet has few legitimate peers -- a handful of
/// other relays, not thousands of players -- so a small dedicated bound is
/// the right shape here: 8 is comfortably above any real fleet's concurrent
/// (re)connect burst while still bounding how many QUIC connections an
/// attacker speaking `MESH_ALPN` can hold open in a stalled, pre-link
/// handshake state at once. The fleet-peer identity check (see the module
/// docs) only runs *after* a connection sends its hello — a peer that never
/// does is by definition unidentified, no matter what this permit gates — so
/// this cap is still what bounds how many such silent connections can sit here
/// concurrently.
///
/// Held only across the handshake window this const is named for -- acquired
/// in the accept loop before the connection gets a task of its own, dropped
/// once the connection is ready to become a `MeshLink` and
/// [`mesh::run_mesh_link`] takes over its lifetime. Never held across the
/// established link's own lifetime, which can run for the life of the
/// relay-pair. Acquiring in the loop (not per-connection tasks racing on the
/// semaphore) is what makes the whole waiting room bounded: at most one
/// connection waits at the loop itself, the bounded hand-off channel from the
/// ALPN dispatch queues a few more, and the dispatch refuses
/// ([`MESH_CLOSE_AT_CAPACITY`](rally_point_proto::version::MESH_CLOSE_AT_CAPACITY))
/// past that -- so a flood of anonymous
/// `MESH_ALPN` dials can never accumulate an unbounded set of parked tasks
/// each pinning a live connection. A real fleet's concurrent (re)connect
/// burst is a handful of peers, resolved within the queue and the existing
/// hello/control timeouts below -- and every acquired permit is bounded to at
/// most those timeouts' worth of hold time, so a stalled or hostile
/// connection can only ever camp on one permit for a bounded window, never
/// indefinitely.
pub(super) const MESH_ACCEPT_CONCURRENCY: usize = 8;

/// The process-wide gate [`MESH_ACCEPT_CONCURRENCY`] enforces.
pub(super) static MESH_ACCEPT_PERMITS: Semaphore = Semaphore::const_new(MESH_ACCEPT_CONCURRENCY);
/// Drives the accept side of the mesh edge.
///
/// For each peer-relay QUIC connection the client-edge accept loop dispatched to
/// `mesh_accept` (ALPN `rp2-mesh/N`), this reads the dialer's identity hello,
/// wraps the connection as a [`MeshLink`](rally_point_transport::MeshLink), spawns a [`mesh::run_mesh_link`]
/// driver on it, and surfaces `(peer id, `[`MeshCommand`](mesh::MeshCommand)`
/// sender)` over `links` — one per established link. The peer id comes from the
/// hello (the acceptor cannot otherwise tell which relay dialed it); the sender
/// is the handle the test (today) or [`MeshControl`](crate::mesh::control::MeshControl)
/// (the coordinator's session descriptors) uses to send [`MeshCommand::Join`](mesh::MeshCommand::Join)
/// for the specific link serving a session.
///
/// This is the *higher-id* side of a relay-pair: it stays in its accept loop and
/// lets the lower-id peer's dial arrive. The lower-id side runs
/// [`run_mesh_dial`](super::run_mesh_dial) instead.
///
/// Each connection is handled in its own task: reading the hello is a
/// peer-driven round trip, so doing it inline would let one slow or silent peer
/// stall every other inbound mesh connection. The accept loop stays free to take
/// the next connection immediately, and one peer link dropping does not end the
/// others.
///
/// Ends when `mesh_accept` closes (the client-edge accept loop ended — the
/// relay is shutting down).
///
/// `fleet_peers` is the coordinator's enrolled-fleet mesh-peer fingerprint map
/// (see [`FleetMeshPeersReader`]): right after hello + version negotiation, this
/// pins the dialer's presented TLS client certificate against the fingerprint
/// the coordinator recorded for its claimed relay id. `require_peer_auth` (the relay's
/// `--require-mesh-peer-auth` flag) forces that check to run even while
/// `fleet_peers` is still empty — refusing every dial until the coordinator's
/// first push lands — rather than treating an empty map as unenforced, which is
/// the default (and how the dev/loopback static `--mesh-peer` path, which never
/// receives a fleet push, keeps working with no peer-identity checks at all).
pub async fn run_mesh_accept(
    mut mesh_accept: mpsc::Receiver<noq::Connection>,
    sessions: Sessions,
    mesh: MeshState,
    links: mpsc::Sender<mesh::MeshLinkHandle>,
    fleet_peers: FleetMeshPeersReader,
    require_peer_auth: bool,
) {
    while let Some(connection) = mesh_accept.recv().await {
        // Mint provenance at dequeue, before permit/handshake awaits can let a
        // slower older connection finish after its replacement.
        let attempt = mesh::new_mesh_link_attempt();
        // Gate the handshake window behind the dedicated mesh-accept cap
        // BEFORE the connection gets a task of its own: acquiring here makes
        // this loop stop taking connections off the channel while every slot
        // is busy — at most one connection waits right here, the channel's own
        // bound is the rest of the waiting room, and the ALPN dispatch sheds
        // on overflow past that — so a burst of anonymous dials can never
        // accumulate one parked permit-waiting task per connection, each
        // pinning a live `noq::Connection`. The permit moves into the task
        // and is dropped there before the link driver takes over, never held
        // across the established link's own lifetime.
        let accept_permit = MESH_ACCEPT_PERMITS
            .acquire()
            .await
            .expect("MESH_ACCEPT_PERMITS is never closed");
        let sessions = Arc::clone(&sessions);
        let mesh = mesh.clone();
        let links = links.clone();
        let fleet_peers = fleet_peers.clone();
        tokio::spawn(async move {
            let (peer_id, hello_stream) = match recv_mesh_hello(&connection).await {
                Ok((hello, stream)) => {
                    // The acceptor is the version-enforcement point for the pair:
                    // the hello is one-way (dialer→acceptor), and exactly one side
                    // of every relay-pair accepts. The fixed hello frame carries a
                    // single version, so it negotiates as a degenerate window. No
                    // overlap means the two relays cannot mesh at any version —
                    // close before the link driver ever spawns or the link
                    // surfaces, so an incompatible pair never half-establishes.
                    // The dial side's supervision redials on its ordinary delay;
                    // the coordinator's descriptors stop pairing the two once the
                    // fleet converges on one version.
                    if let Err(error) = version::negotiate(hello.protocol, hello.protocol) {
                        tracing::warn!(
                            peer_id = hello.relay_id.0,
                            %error,
                            "refusing mesh peer: no common protocol version",
                        );
                        connection.close(
                            noq::VarInt::from_u32(MESH_CLOSE_PROTOCOL_MISMATCH),
                            b"protocol version mismatch",
                        );
                        return;
                    }
                    (hello.relay_id, stream)
                }
                Err(error) => {
                    tracing::info!(%error, "mesh peer did not identify itself; dropping connection");
                    return;
                }
            };

            if let Err(refusal) =
                verify_mesh_peer_identity(&connection, peer_id, &fleet_peers, require_peer_auth)
            {
                tracing::warn!(
                    peer_id = peer_id.0,
                    remote = ?connection.path(noq::PathId::ZERO).and_then(|path| path.remote_address().ok()),
                    reason = %refusal,
                    "refusing mesh peer: identity check failed",
                );
                connection.close(
                    noq::VarInt::from_u32(refusal.close_code()),
                    refusal.reason_bytes(),
                );
                return;
            }

            tracing::info!(
                peer_id = peer_id.0,
                remote = ?connection.path(noq::PathId::ZERO).and_then(|path| path.remote_address().ok()),
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
            let (control_send, control_recv) = match tokio::time::timeout(
                MESH_HELLO_TIMEOUT,
                connection.accept_bi(),
            )
            .await
            {
                Ok(Ok(halves)) => halves,
                Ok(Err(error)) => {
                    tracing::info!(%error, "mesh control stream accept failed; dropping connection");
                    return;
                }
                Err(_) => {
                    tracing::info!(
                        "mesh control stream not established within the deadline; dropping connection"
                    );
                    return;
                }
            };
            let peer_control_rx =
                rally_point_transport::mesh_control_stream::spawn_mesh_control_reader(control_recv);

            // The handshake window this permit bounds is over: the connection
            // is about to become a `MeshLink` and hand off to the driver,
            // which owns its lifetime from here on (potentially the life of
            // the relay-pair) -- freeing the slot for the next handshake now,
            // not when this task itself eventually ends.
            drop(accept_permit);

            // Verification precedes the claim inside `claim_verified_mesh_link`:
            // an under-floor peer is refused before it can supersede (and kill)
            // whatever healthy link currently serves this peer id.
            let lease = match mesh::claim_verified_mesh_link(&mesh, peer_id, &attempt, &connection)
            {
                mesh::MeshLinkAdmission::Claimed(lease) => lease,
                mesh::MeshLinkAdmission::UnderFloor(error) => {
                    tracing::warn!(peer = peer_id.0, %error, "refusing under-floor mesh peer");
                    connection.close(0u32.into(), b"datagram budget under guaranteed floor");
                    return;
                }
                mesh::MeshLinkAdmission::Superseded => {
                    connection.close(0u32.into(), b"superseded mesh link");
                    return;
                }
            };

            let link = rally_point_transport::MeshLink::new(connection);
            let (tx, rx) = mesh::command_channel();
            let _ = links.send((peer_id, lease.generation(), tx)).await;
            let presence_io = presence::PresenceIo {
                peer_id,
                tx: presence_tx,
                rx: presence_rx,
            };
            let control_io = mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            };
            mesh::run_mesh_link(
                link,
                mesh::MeshLinkIo {
                    presence: presence_io,
                    control: control_io,
                    lease,
                },
                rx,
                sessions,
                mesh,
                mesh::IDLE_TIMEOUT,
            )
            .await;
        });
    }
}
