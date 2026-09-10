//! The mesh-edge connection half: establish each relay↔relay QUIC connection
//! and spawn a [`mesh::run_mesh_link`](crate::mesh::run_mesh_link) driver on it.
//!
//! This is the connection layer of the mesh — everything *below* the
//! [`MeshCommand`](crate::mesh::MeshCommand) Join/Leave stream that `run_mesh_link` consumes. It owns
//! the two ways a mesh link's QUIC connection comes into being:
//!
//! - **Accept** ([`run_mesh_accept`]): peer relays that dial this relay arrive
//!   on the `mesh_accept` channel the client-edge accept loop dispatches to
//!   (ALPN `rp2-mesh/N`). This task drains them, wraps each as a `MeshLink`,
//!   and spawns a driver. The higher-id side of a relay-pair ends up here.
//! - **Dial** ([`run_mesh_dial`]): this relay dials a peer relay when the
//!   [`should_dial_mesh`](rally_point_transport::should_dial_mesh) tie-break says it is the lower id, wraps the
//!   connection, and spawns a driver. The lower-id side ends up here.
//!
//! Both halves are deliberately symmetric in what they *produce* — one
//! `(peer id, `[`MeshCommand`](crate::mesh::MeshCommand)` sender)` pair per established link — and differ
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
//! [`MeshHello`] on a fresh unidirectional
//! stream announcing its id, and the acceptor reads it. Both halves then surface
//! the peer's id alongside the command sender, so the Join source can label each
//! link by which peer it reaches. This is *labeling*, not the dial tie-break —
//! it carries no authority (a claimed id is trusted only as far as the
//! connection's certificate is; relay-to-relay auth is a separate, later
//! concern) and does not influence which side dialed.
//!
//! # The Join source is pluggable
//!
//! Each established link surfaces `(peer id, `[`MeshCommand`](crate::mesh::MeshCommand)` sender)`. Today
//! the integration test drives [`MeshCommand::Join`](crate::mesh::MeshCommand::Join) on the sender directly
//! (mirroring `mesh_edge.rs`'s in-process harness). In production the
//! [`MeshControl`](crate::mesh::control::MeshControl) Join source consumes the
//! coordinator's session descriptors and sends `Join`/`Leave` on the sender for
//! the specific link serving a session — targeting the relay-pair that jointly
//! serves it, never broadcasting to links that don't. This module never sends
//! `Join` itself: it establishes the connection and owns the driver's lifetime,
//! not the session membership. Over-joining (telling a peer about a session it
//! doesn't serve) would just be logged-and-dropped by `run_mesh_link`, but it
//! would contradict the coordinator-targeted source, so the connection half
//! stays out of session membership entirely.
//!
//! # Peer identity
//!
//! Each side of a mesh connection presents its own self-signed certificate as
//! its TLS identity — a relay's client edge and mesh edge share one cert, so
//! the same certificate a game client pins from a session response is what a
//! peer relay presents when it dials the mesh edge. The **dial** side trusts
//! the peer it is dialing by pinning the exact certificate the coordinator's
//! descriptor carried for it (`mesh::dialer::dial_roots`; the static
//! dev/loopback `--mesh-peer` path pins the configured mesh roots instead, no
//! coordinator involved). The **accept** side cannot pin a descriptor-carried
//! cert before the connection exists, so it instead checks the dialer's
//! identity hello and presented certificate against the coordinator's
//! fleet-peer set — every enrolled relay's id and certificate fingerprint,
//! pushed down the control connection — right after hello and version
//! negotiation in [`run_mesh_accept`]. No shared certificate authority exists
//! or is needed: fingerprint pinning in both directions is the whole trust
//! model.

mod accept;
mod dial;
#[cfg(test)]
mod tests;

pub use accept::run_mesh_accept;
pub use dial::{run_mesh_dial, run_mesh_dial_with};

use std::net::SocketAddr;
use std::time::Duration;

use rally_point_proto::ids::RelayId;
use rally_point_proto::mesh::{MESH_HELLO_LEN, MeshHello};
use rally_point_proto::version::{
    MESH_CLOSE_CERT_MISMATCH, MESH_CLOSE_NO_CLIENT_CERT, MESH_CLOSE_UNKNOWN_PEER, ProtocolVersion,
};
use rally_point_transport::noq;
use rally_point_transport::quic::cert_fingerprint;
use rally_point_transport::rustls::RootCertStore;
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::coordinator::client::FleetMeshPeersReader;

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
    Connection(#[from] noq::ConnectionError),
    /// Writing the hello to the stream failed.
    #[error("mesh hello write error: {0}")]
    Write(#[from] noq::WriteError),
    /// Reading the hello from the stream failed.
    #[error("mesh hello read error: {0}")]
    Read(#[from] noq::ReadExactError),
    /// The peer connected but did not send its hello within the deadline.
    #[error("mesh hello not received within the deadline")]
    Timeout,
}

/// Announces our identity to the peer that accepted our dial, so it can label
/// the link with our id. Opens a fresh unidirectional stream and writes the
/// fixed hello frame — and returns the stream still open, because it stays in
/// service for the link's lifetime carrying this relay's presence frames (the
/// dialer's report channel; see [`presence`](crate::session::presence)).
async fn send_mesh_hello(
    connection: &noq::Connection,
    our_id: RelayId,
) -> Result<noq::SendStream, MeshHelloError> {
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
    connection: &noq::Connection,
) -> Result<(MeshHello, noq::RecvStream), MeshHelloError> {
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
/// mirroring [`MeshState`](crate::mesh::MeshState).
pub struct MeshDial {
    /// This relay's id. The tie-break (`our_id < peer_id`) decides whether we
    /// dial or wait for the peer to dial us.
    pub our_id: RelayId,
    /// The peer relay's id.
    pub peer_id: RelayId,
    /// The peer relay's candidate endpoints, in the peer's advertised
    /// preference order — each dial attempt walks them until one connects. A
    /// single-address peer (the static `--mesh-peer` path, or a descriptor
    /// carrying no set) is just a one-element list.
    pub peer_addrs: Vec<SocketAddr>,
    /// The TLS SNI / verified hostname for the peer's certificate (for
    /// self-signed dev certs this is `localhost`; for production it is the
    /// hostname on the relay's cert).
    pub server_name: String,
    /// Root certificates to trust the peer's cert chain against. On the
    /// descriptor-driven dial path this is the peer's own enrolled certificate,
    /// pinned (see `mesh::dialer::dial_roots`); the static dev/loopback dial
    /// passes the configured mesh roots.
    pub roots: RootCertStore,
    /// This relay's own certificate chain, presented as the TLS client
    /// identity on the mesh dial — the same chain it serves with. The peer's
    /// acceptor pins it against the coordinator's fleet-peer set.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// The private key matching `cert_chain`.
    pub key: PrivateKeyDer<'static>,
}
/// Why the mesh acceptor refused a dialing peer's identity, once hello and
/// version negotiation already succeeded. Each variant closes the connection
/// with its own code (see `rally_point_proto::version`) so a trace tells the
/// three failure shapes apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshPeerAuthRefusal {
    /// The dialer completed the TLS handshake without presenting a client
    /// certificate, so there is nothing to pin against the fleet map.
    NoClientCert,
    /// The claimed relay id names no relay in the coordinator's currently
    /// enrolled fleet set — including every claim when peer-identity
    /// enforcement is forced on ([`run_mesh_accept`]'s `require_peer_auth`)
    /// while the coordinator has not yet pushed its first fleet-peer set.
    UnknownPeer,
    /// A certificate was presented and the claimed id is enrolled, but its
    /// SHA-256 fingerprint does not match the one the coordinator recorded for
    /// that relay id at its enroll.
    CertMismatch,
}

impl MeshPeerAuthRefusal {
    /// The QUIC application close code naming this refusal.
    fn close_code(self) -> u32 {
        match self {
            Self::NoClientCert => MESH_CLOSE_NO_CLIENT_CERT,
            Self::UnknownPeer => MESH_CLOSE_UNKNOWN_PEER,
            Self::CertMismatch => MESH_CLOSE_CERT_MISMATCH,
        }
    }

    /// The close frame's reason bytes.
    fn reason_bytes(self) -> &'static [u8] {
        match self {
            Self::NoClientCert => b"no mesh client certificate presented",
            Self::UnknownPeer => b"claimed relay id not enrolled in the fleet",
            Self::CertMismatch => b"client certificate fingerprint mismatch",
        }
    }
}

impl std::fmt::Display for MeshPeerAuthRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoClientCert => "no client certificate presented",
            Self::UnknownPeer => "claimed relay id not in the fleet-peer set",
            Self::CertMismatch => "certificate fingerprint does not match the fleet-peer set",
        })
    }
}

/// Pins a dialing peer's TLS client certificate against the coordinator's
/// fleet-peer set, once hello + version negotiation have already succeeded.
///
/// Enforced whenever `fleet_peers` is non-empty (the coordinator has pushed at
/// least one relay's identity) **or** `require_peer_auth` is set. The latter
/// fails closed even before the coordinator's first push, so a relay started
/// with `--require-mesh-peer-auth` never serves an unauthenticated mesh accept
/// during its brief startup window — every claimed id trivially fails the
/// "enrolled in the fleet" check against an empty map, which is exactly the
/// refusal this function already produces for an unrecognized id, so no
/// separate case is needed for "map empty and required".
///
/// With neither condition true, this is a no-op — the dev/loopback static-mesh
/// path (`--mesh-peer`, no coordinator) never receives a fleet push and stays
/// exactly as unauthenticated as it was before peer-identity pinning existed.
fn verify_mesh_peer_identity(
    connection: &noq::Connection,
    peer_id: RelayId,
    fleet_peers: &FleetMeshPeersReader,
    require_peer_auth: bool,
) -> Result<(), MeshPeerAuthRefusal> {
    if fleet_peers.is_empty() && !require_peer_auth {
        return Ok(());
    }

    let leaf = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certs.into_iter().next());
    let Some(leaf) = leaf else {
        return Err(MeshPeerAuthRefusal::NoClientCert);
    };

    let Some(expected) = fleet_peers.fingerprint(peer_id) else {
        return Err(MeshPeerAuthRefusal::UnknownPeer);
    };

    if cert_fingerprint(&leaf) != expected {
        return Err(MeshPeerAuthRefusal::CertMismatch);
    }

    Ok(())
}
/// The delay between mesh redial attempts, after a link's connection failed or a
/// dial attempt didn't connect. Mesh establishment is not latency-critical — a
/// running game rides already-established links, and a link returning a couple of
/// seconds later is fine — so a fixed short delay avoids hammering a peer that is
/// restarting or briefly unreachable, mirroring the coordinator control
/// connection's reconnect delay.
pub const MESH_REDIAL_DELAY: Duration = Duration::from_secs(2);
