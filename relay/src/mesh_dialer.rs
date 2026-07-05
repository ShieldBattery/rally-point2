//! On-demand mesh dialing: keep a dial supervisor alive per higher-id peer the
//! coordinator's descriptors say this relay should currently mesh with.
//!
//! The connection half ([`mesh_edge`](crate::mesh_edge)) knows *how* to dial a
//! peer and keep that one link healthy ([`run_mesh_dial`](crate::mesh_edge::run_mesh_dial)),
//! but it is told *which* peer to dial once, at startup. In production the peer set
//! is not known at startup — relays churn under scale-to-zero and games pair
//! regions dynamically — so *which* peers to dial is driven at runtime by the
//! coordinator's session descriptors. This module is that driver for the dial
//! side.
//!
//! It subscribes to the Join source's declarative **desired-peer set**
//! ([`MeshControl::desired_peers`](crate::mesh_control::MeshControl::desired_peers))
//! — the union of every current session's mesh peers, with addresses — and keeps
//! exactly one dial supervisor alive per peer this relay should dial: the higher-id
//! peers, since the lower id dials (lower-id peers dial *us* and arrive on the
//! accept side). One supervisor per peer, deduplicated, so a re-pushed descriptor
//! never stacks dials.
//!
//! # Why this closes the idle-teardown gap
//!
//! A mesh link tears down when it has served its sessions and gone idle — a
//! deliberate wind-down that stops its supervisor (a *failed* connection is retried
//! inside the supervisor instead). That is correct as a resource optimization, but
//! it means a later session pairing the same two relays would find no link and,
//! with a once-at-startup dial, nothing to re-establish it. Here, when a new
//! descriptor names a peer whose link had wound down, the desired-peer set changes
//! and the dialer dials it afresh; and if a peer is still desired at the moment its
//! supervisor stops (a rare race with the idle timer), the dialer redials
//! immediately.
//!
//! # Supervisor lifecycle: removal, address changes, and cert changes
//!
//! A supervisor is tracked by peer id *and* the target it dials (address plus
//! pinned cert), with an abort handle. When a peer drops out of the desired set
//! — or reappears at a new address, or with a new certificate, after a restart
//! — its old supervisor is cancelled. This matters because a supervisor retries
//! a *failed* connection forever: without cancellation, a peer removed while
//! unreachable would leave a supervisor dialing a dead address for the relay's
//! whole life, and a peer that moved (or re-enrolled with a fresh self-signed
//! cert at the same address) would keep the old supervisor dialing the stale
//! target while the one-per-peer dedup blocked a dial to the corrected one —
//! leaving the pair unmeshed, the very failure this exists to prevent. A
//! cancelled supervisor reports no stop (it is aborted before it can); a
//! *naturally* stopped one reports its id and the target it was dialing, and the
//! dialer prunes it only if that target is still the current one — so a late
//! stop from a since-retargeted supervisor can't evict its replacement.
//!
//! # Trust: the descriptor-carried pin
//!
//! Each desired peer carries the certificate it enrolled with the coordinator
//! (`RelayPeer::cert_der`), and the dial trusts exactly that cert — mirroring
//! how a game client pins `RelayEndpoint::cert_der` for its relay dial — so two
//! independently self-signed relays mesh with no shared root or out-of-band cert
//! distribution. The configured [`DialerConfig::roots`] are the fallback for a
//! peer whose descriptor carried no cert (a coordinator that predates the
//! field); see [`dial_roots`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::RelayPeer;
use rally_point_proto::ids::RelayId;
use rally_point_transport::rustls::RootCertStore;
use rally_point_transport::rustls::pki_types::CertificateDer;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::mesh::{self, MeshState};
use crate::mesh_edge::{self, MeshDial};
use crate::routing::Sessions;

/// The fixed ingredients every on-demand dial shares — everything a
/// [`MeshDial`] needs except the per-peer id, address, and pinned cert, which
/// come from the desired-peer set. Held by the dialer and cloned into each
/// supervisor it spawns.
pub struct DialerConfig {
    /// This relay's id — the tie-break decides which peers we dial vs. accept.
    pub our_id: RelayId,
    /// The TLS SNI to verify on each peer's certificate.
    pub server_name: String,
    /// Fallback roots to trust a peer's certificate against, used only when the
    /// peer's descriptor carried no pinned cert (see [`dial_roots`]). A
    /// descriptor-carried pin wins over these.
    pub roots: RootCertStore,
    /// The relay's session routing state, shared into each link driver.
    pub sessions: Sessions,
    /// The relay's mesh state, shared into each link driver.
    pub mesh: MeshState,
    /// Where each established link surfaces its `(peer id, command sender)`, the
    /// same collector that registers links into the Join source.
    pub links: mpsc::Sender<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>,
    /// How long a supervisor waits before redialing after a failed connection.
    pub redial_delay: Duration,
}

/// How many supervisor-stop notifications may be in flight before the dialer
/// processes them. Stops are rare (only intentional teardowns), so a small buffer
/// is plenty; it exists only so a supervisor task never blocks reporting its exit.
const STOPPED_CHANNEL_DEPTH: usize = 16;

/// One desired peer's dial target: the address to dial and the certificate the
/// descriptor pinned for it (empty when the descriptor carried none — the dial
/// then falls back to the configured mesh roots). The cert is part of the dial
/// identity alongside the address: a relay that restarts re-enrolls with a fresh
/// self-signed cert, often at the same address, and a supervisor pinning the
/// stale cert would redial a doomed TLS config forever while the one-per-peer
/// dedup blocked the corrected dial — the same trap the address-change
/// cancellation exists to prevent.
#[derive(Clone, PartialEq, Eq)]
struct PeerTarget {
    addr: SocketAddr,
    cert_der: Vec<u8>,
}

impl PeerTarget {
    fn from_peer(peer: &RelayPeer) -> Self {
        Self {
            addr: peer.relay_addr,
            cert_der: peer.cert_der.clone(),
        }
    }
}

/// A live dial supervisor: the target it is dialing and a handle to cancel it.
/// The target distinguishes the current supervisor from a stale one — a retarget
/// installs a new target, and both a late stop notification and the next reconcile
/// check against it — so no separate generation token is needed.
struct ActiveDial {
    target: PeerTarget,
    abort: AbortHandle,
}

/// Drives on-demand dialing from the Join source's desired-peer set: subscribes to
/// `peers_rx` and keeps one [`run_mesh_dial`](mesh_edge::run_mesh_dial) supervisor
/// alive per higher-id desired peer, at that peer's current address. Ends when the
/// desired-peer channel closes (the Join source was dropped — the relay is shutting
/// down).
pub async fn run_mesh_dialer(config: DialerConfig, mut peers_rx: watch::Receiver<Vec<RelayPeer>>) {
    // The higher-id peers we should currently dial (with their addresses and
    // pinned certs), and the supervisor running for each (with the target it is
    // dialing).
    let mut desired: HashMap<RelayId, PeerTarget> = HashMap::new();
    let mut active: HashMap<RelayId, ActiveDial> = HashMap::new();
    // Supervisors report `(peer id, dialed target)` when they stop naturally — a
    // failed connection is retried inside the supervisor, so only an intentional
    // wind-down is reported, and a cancelled supervisor is aborted before it can.
    let (stopped_tx, mut stopped_rx) =
        mpsc::channel::<(RelayId, PeerTarget)>(STOPPED_CHANNEL_DEPTH);

    // Seed from the current set before waiting for changes (a dialer that connects
    // after descriptors were already applied still dials them).
    let initial = peers_rx.borrow_and_update().clone();
    apply_desired(&config, &initial, &mut desired, &mut active, &stopped_tx);

    loop {
        tokio::select! {
            changed = peers_rx.changed() => {
                if changed.is_err() {
                    break; // the Join source dropped: relay shutting down
                }
                let peers = peers_rx.borrow_and_update().clone();
                apply_desired(&config, &peers, &mut desired, &mut active, &stopped_tx);
            }
            Some((peer_id, target)) = stopped_rx.recv() => {
                // Act only if this stop is from the *current* supervisor for the
                // peer (same target). A retarget aborts the old supervisor and
                // installs a new one at a new target; a late stop carrying the old
                // target must not evict that replacement.
                if active.get(&peer_id).map(|d| &d.target) == Some(&target) {
                    active.remove(&peer_id);
                    // Re-establish only if the peer is still desired at this target
                    // — an idle teardown normally fires well after the session (and
                    // so the peer) left, so this is usually a no-op; it closes the
                    // narrow race where a peer's link winds down while still named.
                    if desired.get(&peer_id) == Some(&target) {
                        let abort = spawn_dial(&config, peer_id, target.clone(), &stopped_tx);
                        active.insert(peer_id, ActiveDial { target, abort });
                    }
                }
            }
        }
    }
}

/// Reconciles the running supervisors to the desired set. Replaces `desired` with
/// the higher-id peers from `peers` (the only ones this relay dials), cancels any
/// supervisor whose peer is no longer wanted *at the target it is dialing* — a
/// removed peer, one that moved to a new address, or one whose pinned cert
/// changed — and starts a supervisor for every desired peer not already being
/// dialed.
///
/// Cancelling on removal is what keeps a supervisor from dialing a dead or stale
/// target forever (it retries a failed connection indefinitely), and cancelling
/// on an address or cert change is what lets the corrected dial through the
/// one-per-peer dedup.
fn apply_desired(
    config: &DialerConfig,
    peers: &[RelayPeer],
    desired: &mut HashMap<RelayId, PeerTarget>,
    active: &mut HashMap<RelayId, ActiveDial>,
    stopped_tx: &mpsc::Sender<(RelayId, PeerTarget)>,
) {
    *desired = peers
        .iter()
        .filter(|p| rally_point_transport::should_dial_mesh(config.our_id, p.relay_id))
        .map(|p| (p.relay_id, PeerTarget::from_peer(p)))
        .collect();

    // Cancel supervisors no longer wanted at the target they are dialing. An
    // aborted supervisor sends no stop notification, so this can't race a redial.
    active.retain(|peer_id, dial| {
        let still_wanted = desired.get(peer_id) == Some(&dial.target);
        if !still_wanted {
            dial.abort.abort();
        }
        still_wanted
    });

    // Start a supervisor for every desired peer not already being dialed (a retarget
    // removed the stale one just above, so its fresh-target dial starts here).
    for (&peer_id, target) in desired.iter() {
        active.entry(peer_id).or_insert_with(|| {
            let abort = spawn_dial(config, peer_id, target.clone(), stopped_tx);
            ActiveDial {
                target: target.clone(),
                abort,
            }
        });
    }
}

/// Spawns one dial supervisor for `peer_id` at `target`, reporting `(peer_id,
/// target)` on `stopped_tx` when it ends naturally so the dialer can prune (and
/// possibly redial) it. Returns a handle to cancel it — the dialer aborts a
/// supervisor whose peer is removed or has retargeted. Only called for a peer not
/// already active, so at most one supervisor runs per peer.
fn spawn_dial(
    config: &DialerConfig,
    peer_id: RelayId,
    target: PeerTarget,
    stopped_tx: &mpsc::Sender<(RelayId, PeerTarget)>,
) -> AbortHandle {
    let dial = MeshDial {
        our_id: config.our_id,
        peer_id,
        peer_addr: target.addr,
        server_name: config.server_name.clone(),
        roots: dial_roots(peer_id, &target.cert_der, &config.roots),
    };
    let sessions = Arc::clone(&config.sessions);
    let mesh = config.mesh.clone();
    let links = config.links.clone();
    let redial_delay = config.redial_delay;
    let stopped_tx = stopped_tx.clone();
    tokio::spawn(async move {
        mesh_edge::run_mesh_dial_with(dial, sessions, mesh, links, redial_delay).await;
        // The supervisor only returns on an intentional wind-down (a failed
        // connection is retried inside it), so this reports a real stop; a cancelled
        // supervisor is aborted before it reaches here.
        let _ = stopped_tx.send((peer_id, target)).await;
    })
    .abort_handle()
}

/// The trust store for one mesh dial. A descriptor-carried pinned cert wins: the
/// store trusts exactly the peer's enrolled certificate — mirroring how a game
/// client pins `RelayEndpoint::cert_der` for its relay dial — so independently
/// self-signed relay certs mesh with no shared root or out-of-band distribution.
/// An empty pin (a coordinator that predates carrying peer certs) falls back to
/// the configured mesh roots; a pin rustls rejects falls back too, loudly —
/// dialing with the configured trust reproduces the pre-pin behavior and logs
/// the real problem, where refusing to dial would strand the pair silently.
fn dial_roots(peer_id: RelayId, cert_der: &[u8], fallback: &RootCertStore) -> RootCertStore {
    if cert_der.is_empty() {
        return fallback.clone();
    }
    let mut roots = RootCertStore::empty();
    match roots.add(CertificateDer::from(cert_der.to_vec())) {
        Ok(()) => roots,
        Err(error) => {
            tracing::error!(
                %error,
                peer_id = peer_id.0,
                "descriptor-pinned mesh peer cert did not parse; falling back to configured mesh roots",
            );
            fallback.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed_der() -> Vec<u8> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        cert.cert.der().to_vec()
    }

    fn fallback_with_one_root() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self_signed_der())).unwrap();
        roots
    }

    /// A descriptor-carried cert pins the dial's trust to exactly that cert —
    /// the fallback roots contribute nothing.
    #[test]
    fn a_pinned_cert_wins_over_the_fallback_roots() {
        let fallback = fallback_with_one_root();
        let pinned = self_signed_der();
        let roots = dial_roots(RelayId(2), &pinned, &fallback);
        assert_eq!(roots.len(), 1, "exactly the pinned cert is trusted");
        // Pinning the same cert against an empty fallback yields the same
        // trust anchors, proving the fallback contributed nothing.
        let from_empty = dial_roots(RelayId(2), &pinned, &RootCertStore::empty());
        assert_eq!(
            roots.roots, from_empty.roots,
            "the fallback contributed nothing"
        );
        assert_ne!(
            roots.roots, fallback.roots,
            "the pinned store is not the fallback's contents",
        );
    }

    /// No pinned cert (an old coordinator's descriptor): the configured mesh
    /// roots are used as-is.
    #[test]
    fn an_empty_pin_falls_back_to_the_configured_roots() {
        let fallback = fallback_with_one_root();
        let roots = dial_roots(RelayId(2), &[], &fallback);
        assert_eq!(roots.roots, fallback.roots);
    }

    /// A malformed pinned cert falls back to the configured roots (logged)
    /// rather than producing an empty store that could never trust anyone.
    #[test]
    fn a_malformed_pin_falls_back_to_the_configured_roots() {
        let fallback = fallback_with_one_root();
        let roots = dial_roots(RelayId(2), &[0xDE, 0xAD], &fallback);
        assert_eq!(roots.roots, fallback.roots);
    }
}
