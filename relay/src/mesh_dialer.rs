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
//! # Supervisor lifecycle: removal and address changes
//!
//! A supervisor is tracked by peer id *and* the address it dials, with an abort
//! handle. When a peer drops out of the desired set — or reappears at a new address
//! after a restart — its old supervisor is cancelled. This matters because a
//! supervisor retries a *failed* connection forever: without cancellation, a peer
//! removed while unreachable would leave a supervisor dialing a dead address for
//! the relay's whole life, and a peer that moved would keep the old supervisor
//! dialing the stale address while the one-per-peer dedup blocked a dial to the new
//! one — leaving the pair unmeshed, the very failure this exists to prevent. A
//! cancelled supervisor reports no stop (it is aborted before it can); a *naturally*
//! stopped one reports its id and the address it was dialing, and the dialer prunes
//! it only if that address is still the current one — so a late stop from a
//! since-retargeted supervisor can't evict its replacement.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::RelayPeer;
use rally_point_proto::ids::RelayId;
use rally_point_transport::rustls::RootCertStore;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::mesh::{self, MeshState};
use crate::mesh_edge::{self, MeshDial};
use crate::routing::Sessions;

/// The fixed ingredients every on-demand dial shares — everything a
/// [`MeshDial`] needs except the per-peer id and address, which come from the
/// desired-peer set. Held by the dialer and cloned into each supervisor it spawns.
pub struct DialerConfig {
    /// This relay's id — the tie-break decides which peers we dial vs. accept.
    pub our_id: RelayId,
    /// The TLS SNI to verify on each peer's certificate.
    pub server_name: String,
    /// The roots to trust peer certificates against.
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

/// A live dial supervisor: the address it is dialing and a handle to cancel it.
/// The address distinguishes the current supervisor from a stale one — a retarget
/// installs a new address, and both a late stop notification and the next reconcile
/// check against it — so no separate generation token is needed.
struct ActiveDial {
    addr: SocketAddr,
    abort: AbortHandle,
}

/// Drives on-demand dialing from the Join source's desired-peer set: subscribes to
/// `peers_rx` and keeps one [`run_mesh_dial`](mesh_edge::run_mesh_dial) supervisor
/// alive per higher-id desired peer, at that peer's current address. Ends when the
/// desired-peer channel closes (the Join source was dropped — the relay is shutting
/// down).
pub async fn run_mesh_dialer(config: DialerConfig, mut peers_rx: watch::Receiver<Vec<RelayPeer>>) {
    // The higher-id peers we should currently dial (with their addresses), and the
    // supervisor running for each (with the address it is dialing).
    let mut desired: HashMap<RelayId, SocketAddr> = HashMap::new();
    let mut active: HashMap<RelayId, ActiveDial> = HashMap::new();
    // Supervisors report `(peer id, dialed address)` when they stop naturally — a
    // failed connection is retried inside the supervisor, so only an intentional
    // wind-down is reported, and a cancelled supervisor is aborted before it can.
    let (stopped_tx, mut stopped_rx) =
        mpsc::channel::<(RelayId, SocketAddr)>(STOPPED_CHANNEL_DEPTH);

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
            Some((peer_id, addr)) = stopped_rx.recv() => {
                // Act only if this stop is from the *current* supervisor for the
                // peer (same address). A retarget aborts the old supervisor and
                // installs a new one at a new address; a late stop carrying the old
                // address must not evict that replacement.
                if active.get(&peer_id).map(|d| d.addr) == Some(addr) {
                    active.remove(&peer_id);
                    // Re-establish only if the peer is still desired at this address
                    // — an idle teardown normally fires well after the session (and
                    // so the peer) left, so this is usually a no-op; it closes the
                    // narrow race where a peer's link winds down while still named.
                    if desired.get(&peer_id) == Some(&addr) {
                        let abort = spawn_dial(&config, peer_id, addr, &stopped_tx);
                        active.insert(peer_id, ActiveDial { addr, abort });
                    }
                }
            }
        }
    }
}

/// Reconciles the running supervisors to the desired set. Replaces `desired` with
/// the higher-id peers from `peers` (the only ones this relay dials), cancels any
/// supervisor whose peer is no longer wanted *at the address it is dialing* — a
/// removed peer, or one that moved to a new address — and starts a supervisor for
/// every desired peer not already being dialed.
///
/// Cancelling on removal is what keeps a supervisor from dialing a dead or stale
/// address forever (it retries a failed connection indefinitely), and cancelling on
/// an address change is what lets the correct dial through the one-per-peer dedup.
fn apply_desired(
    config: &DialerConfig,
    peers: &[RelayPeer],
    desired: &mut HashMap<RelayId, SocketAddr>,
    active: &mut HashMap<RelayId, ActiveDial>,
    stopped_tx: &mpsc::Sender<(RelayId, SocketAddr)>,
) {
    *desired = peers
        .iter()
        .filter(|p| rally_point_transport::should_dial_mesh(config.our_id, p.relay_id))
        .map(|p| (p.relay_id, p.relay_addr))
        .collect();

    // Cancel supervisors no longer wanted at the address they are dialing. An
    // aborted supervisor sends no stop notification, so this can't race a redial.
    active.retain(|peer_id, dial| {
        let still_wanted = desired.get(peer_id) == Some(&dial.addr);
        if !still_wanted {
            dial.abort.abort();
        }
        still_wanted
    });

    // Start a supervisor for every desired peer not already being dialed (a retarget
    // removed the stale one just above, so its fresh-address dial starts here).
    for (&peer_id, &addr) in desired.iter() {
        active.entry(peer_id).or_insert_with(|| {
            let abort = spawn_dial(config, peer_id, addr, stopped_tx);
            ActiveDial { addr, abort }
        });
    }
}

/// Spawns one dial supervisor for `peer_id` at `peer_addr`, reporting `(peer_id,
/// peer_addr)` on `stopped_tx` when it ends naturally so the dialer can prune (and
/// possibly redial) it. Returns a handle to cancel it — the dialer aborts a
/// supervisor whose peer is removed or has moved. Only called for a peer not already
/// active, so at most one supervisor runs per peer.
fn spawn_dial(
    config: &DialerConfig,
    peer_id: RelayId,
    peer_addr: SocketAddr,
    stopped_tx: &mpsc::Sender<(RelayId, SocketAddr)>,
) -> AbortHandle {
    let dial = MeshDial {
        our_id: config.our_id,
        peer_id,
        peer_addr,
        server_name: config.server_name.clone(),
        roots: config.roots.clone(),
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
        let _ = stopped_tx.send((peer_id, peer_addr)).await;
    })
    .abort_handle()
}
