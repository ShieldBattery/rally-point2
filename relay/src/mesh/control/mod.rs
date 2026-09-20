//! The Join source: turn a coordinator session descriptor into per-link
//! `Join`/`Leave` commands on the right mesh links.
//!
//! The connection half ([`mesh::edge`](crate::mesh::edge)) establishes one QUIC
//! connection per relay-pair and surfaces a [`MeshCommand`] sender per link,
//! labeled with the peer relay's id. `MeshControl` is what *drives* those
//! senders: it holds the per-peer senders and, given a
//! [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor) the
//! coordinator pushed, sends [`Join`](MeshCommand::Join) on the link to each peer
//! the descriptor names — and [`Leave`](MeshCommand::Leave) on a link a later
//! descriptor drops. Because a descriptor names specific peers, a join reaches
//! only the links serving that session; it is never a broadcast.
//!
//! # Intent vs. delivered state, and reconciliation
//!
//! Two maps, deliberately kept distinct:
//!
//! - **`desired`** — the coordinator's intent: for each session, which peers
//!   should serve it. Set by descriptors; survives a link dying.
//! - **`joined`** — what each link has *actually* been told: for each peer, the
//!   sessions a `Join` was successfully enqueued for (and not yet `Leave`d).
//!
//! All sends go through a *reconcile* that drives a peer's link from its current
//! `joined` set toward its target (the sessions `desired` says it should serve),
//! sending only the difference. The two maps diverge exactly when a send fails
//! or a link has not established — and the next reconcile closes the gap. A
//! reconcile is triggered by a descriptor (intent changed), a link registering
//! (a new or reconnected link starts joined to nothing), or a session ending.
//! `joined` advances *only* on a successful enqueue, so a dropped command is not
//! mistaken for delivered: the next reconcile recomputes the same difference and
//! re-sends it. This is what makes membership eventually consistent rather than
//! permanently diverged after a single dropped command. `Join`/`Leave` are
//! idempotent on the driver, so a redundant re-send is harmless.
//!
//! The command channel is unbounded (see `command_channel` in the mesh
//! module), so a send to a live link
//! cannot fail under load — the command is enqueued for the driver and `joined`
//! advances. The only send failure is a *closed* channel (the driver exited):
//! that link is dropped from the registry, intent kept, so a reconnect under the
//! same peer id re-registers and reconciles from an empty `joined`, re-sending
//! every session it should serve. There is no silent drop to recover from — that
//! is the point of the unbounded channel.
//!
//! # Why a plain mutex
//!
//! A plain (non-async) mutex guards the state, and the send is a non-blocking,
//! await-free [`UnboundedSender::send`](tokio::sync::mpsc::UnboundedSender::send),
//! so it is safe to hold the lock across (the rule the codebase keeps is *never
//! across an await*, which this is not). Holding it across the send makes
//! compute-send-commit one atomic step, so `joined` tracks delivery exactly: a
//! successful send means the command is in the driver's own queue and will be
//! processed. The control plane is low-frequency, so lock-hold time is a
//! non-issue.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::RelayPeer;
use rally_point_proto::ids::RelayId;
use tokio::sync::{mpsc, watch};

use crate::consensus;
use crate::key::SessionKey;
use crate::mesh::{MeshCommand, MeshState};
use crate::routing::Sessions;
use crate::session::presence;

/// Drives the mesh links' `Join`/`Leave` commands from coordinator session
/// descriptors. Clone it cheaply (the state is behind one `Arc`) to hand a copy
/// to the link collector and to the descriptor source.
#[derive(Clone)]
pub struct MeshControl {
    /// This relay's own id, used to drop a self-reference defensively if a
    /// descriptor ever lists it (a relay never meshes with itself), and to
    /// resolve this relay's own place in each session's authority order.
    our_id: RelayId,
    /// The relay's turn-path state, shared (never a private copy): the
    /// decision-makers this creates on a descriptor and destroys on a
    /// retirement are the ones the slot-link and mesh-link tasks feed and
    /// stamp; the presence order recorded here is the one their live-player
    /// reports land on; the gates retired here are the boundary every ingress
    /// runs through; the drop holds read here are the ones a reconnect could
    /// still claim; and the provisional-turn pen drained here is the one the
    /// turn funnel deposits into. A control plane wired to anything else would
    /// silently drive state nothing reads.
    mesh: MeshState,
    /// The local roster, for the pushes a descriptor can trigger at this
    /// relay's own clients: a synced leave a demoted authority never
    /// delivered, a corrected region-label map, a coordinator reap.
    sessions: Sessions,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    /// The command sender for each established peer-relay link, keyed by peer id.
    links: HashMap<RelayId, mpsc::UnboundedSender<MeshCommand>>,
    /// Highest process-local physical-link generation ever accepted per peer.
    /// Kept after a dead sender is removed so a delayed older registration can
    /// never become current again.
    latest_generations: HashMap<RelayId, u64>,
    /// Coordinator intent: for each session, which peers should serve it.
    desired: HashMap<SessionKey, HashSet<RelayId>>,
    /// Delivered state: for each peer, the sessions its link has been
    /// successfully told to join (and not yet leave). Only entries for peers
    /// with a live link exist here.
    joined: HashMap<RelayId, HashSet<SessionKey>>,
    /// Latest contact details seen for each peer (from descriptors): the
    /// reachable address plus the enrolled certificate a dial pins, so the
    /// desired-peer set published for the dialer carries everything a dial
    /// needs, not just ids. Pruned to the currently-desired peers on each
    /// publish.
    peer_contacts: HashMap<RelayId, PeerContact>,
    /// Publishes the peers this relay currently needs mesh links to (id +
    /// address), so the on-demand dialer can (re)establish them. Declarative
    /// latest-wins state — like the coordinator's descriptor push, a level down:
    /// the coordinator says which peers a session needs, and this republishes the
    /// union across all sessions for the connection half to act on.
    desired_peers_tx: watch::Sender<Vec<RelayPeer>>,
}

/// One peer's dial ingredients as the latest descriptor reported them: where to
/// reach it and the certificate to pin (empty when the coordinator predates
/// carrying certs — the dialer then falls back to its configured mesh roots).
/// `addrs` is the peer's complete advertised set (empty for a single-address
/// peer), carried through so the dialer can walk every candidate.
struct PeerContact {
    addr: SocketAddr,
    addrs: Vec<SocketAddr>,
    cert_der: Vec<u8>,
}

mod apply;
#[cfg(test)]
mod tests;

impl MeshControl {
    /// Creates an empty `MeshControl` for a relay with no peer links and no
    /// sessions yet. `our_id` is this relay's id; `mesh` and `sessions` are the
    /// turn-path state this control plane drives — the same registries the
    /// slot-link and mesh-link tasks hold, cloned here (every field is a shared
    /// handle). A control plane with no turn path — a standalone descriptor
    /// driver, a test that only watches `Join`/`Leave` — passes a state of its
    /// own (`&MeshState::default()`, `Sessions::default()`): still real and
    /// self-consistent, just not shared with anything.
    pub fn new(our_id: RelayId, mesh: &MeshState, sessions: Sessions) -> Self {
        let (desired_peers_tx, _) = watch::channel(Vec::new());
        Self {
            our_id,
            mesh: mesh.clone(),
            sessions,
            inner: Arc::new(Mutex::new(Inner {
                links: HashMap::new(),
                latest_generations: HashMap::new(),
                desired: HashMap::new(),
                joined: HashMap::new(),
                peer_contacts: HashMap::new(),
                desired_peers_tx,
            })),
        }
    }

    /// Subscribes to the set of peers this relay currently needs mesh links to
    /// (id + address). The on-demand dialer watches this and keeps a dial
    /// supervisor alive per higher-id peer, so a link torn down while idle is
    /// re-established when a later session needs the peer again. The set is the
    /// union of every current session's mesh peers, republished on every change.
    pub fn desired_peers(&self) -> watch::Receiver<Vec<RelayPeer>> {
        self.inner.lock().desired_peers_tx.subscribe()
    }

    /// Registers the command sender for an established link to `peer_id`.
    ///
    /// A (re)established link starts joined to nothing, so reconciling it sends
    /// `Join` for every session the coordinator wants this peer to serve. A
    /// repeat registration for the same peer replaces the prior sender — the
    /// reconnect case — and resets its delivered state, re-sending its joins.
    #[must_use]
    pub fn register_link(
        &self,
        peer_id: RelayId,
        generation: u64,
        sender: mpsc::UnboundedSender<MeshCommand>,
    ) -> bool {
        let mut inner = self.inner.lock();
        if inner
            .latest_generations
            .get(&peer_id)
            .is_some_and(|current| *current >= generation)
        {
            return false;
        }
        inner.latest_generations.insert(peer_id, generation);
        inner.links.insert(peer_id, sender);
        // The link knows nothing yet; reconcile re-sends every desired join.
        inner.joined.insert(peer_id, HashSet::new());
        reconcile_peers(&mut inner, [peer_id]);
        true
    }

    /// Closes the named slots' links for a session — the coordinator's reap
    /// directive. Fires each slot's shutdown signal in the roster; a slot this
    /// relay does not currently hold is a no-op. The closed link then flows through
    /// the ordinary link-death path (a departure notice, a synced leave), which is
    /// what makes the reap self-resolving. A no-op against the empty default roster
    /// (a control plane with no turn path).
    pub fn close_slots(&self, key: &SessionKey, slots: &[rally_point_proto::ids::SlotId]) {
        crate::routing::close_slots(&self.sessions, key, slots);
    }

    /// Ends a session's mesh membership: destroys its decision-maker, forgets the
    /// desired set, and reconciles its peers, which leaves each link that was
    /// joined. Idempotent — ending an unknown session is a no-op.
    ///
    /// The decision-maker is dropped first, unconditionally: a single-relay
    /// session has a maker but no mesh peers to reconcile, so gating its teardown
    /// on the mesh state below would leak it.
    pub fn end_session(&self, key: &SessionKey) {
        // Close the session's ingress gate first, before any state is
        // destroyed. The write acquisition drains every in-flight ingress
        // critical section (mesh dispatch, the turn funnel, an admission), so
        // their mutations land wholly before the sweeps below; every ingress
        // that starts afterward observes the retirement and refuses. Without
        // this boundary a buffered mesh frame — still passing its link
        // driver's joined check until the queued Leave drains — would find no
        // maker, read a `SlotDeparted` as an undecided drop, and recreate a
        // drop hold (or report a second close, or re-create a flight
        // recording) for a session that no longer exists.
        self.mesh.session.gates.retire(key);
        consensus::deregister_maker(&self.mesh.session.decision_makers, key);
        presence::forget(&self.mesh.session.presence, key);
        // Discard any turns still penned for the session — with the maker
        // gone and the gate retired, no descriptor will ever drain them. The
        // replay ring and forward-once seen state fall with them: the
        // session-emptied close retains both while an undecided hold still
        // promises a reconnect (their receipts seed that resume's receive
        // window), and retirement is the terminal boundary that ends the
        // promise — with the descriptor gone there is no admission path left,
        // so nothing else would ever sweep a retained pair whose reconnect
        // never came. Idempotent when the emptied close already removed them.
        self.mesh.session.provisional_turns.discard(key);
        self.mesh.session.turn_ring.end_session(key);
        crate::mesh::deregister_seen(&self.mesh.seen, key);
        // Retirement is terminal for the session's drop bookkeeping: with the
        // descriptor gone there is no admission path left for a held slot's
        // reconnect and no decide path for its leave, so any armed abandon
        // timer and every remaining hold would otherwise leak forever — the
        // timer's expiry stands down on the forgotten presence (never deciding
        // or releasing), and nothing else ever sweeps the entries.
        self.mesh.session.drop_holds.cancel_abandon(key);
        self.mesh.session.drop_holds.end_session_terminal(key);
        {
            let mut inner = self.inner.lock();
            if let Some(peers) = inner.desired.remove(key) {
                reconcile_peers(&mut inner, peers);
                publish_desired_peers(&mut inner);
            }
        }
        // Cleared only here — and last, after the mesh Leave commands above are
        // queued — so the seal guards against straggling mesh events for as
        // much of the teardown as possible; a genuine later re-serve of this
        // key must be able to record again. An in-flight event a link driver
        // was already delivering can still slip past this ordering; the
        // repeat-store warn diagnoses that residual.
        self.mesh
            .session
            .decision_makers
            .flight_recorder()
            .clear_close_seal(key);
    }
}

/// Recomputes the peers this relay currently needs mesh links to — the union of
/// every session's desired peers, each paired with its latest known address and
/// pinned cert — and publishes it if it changed. The contact book is pruned to
/// just the desired peers so it can't grow without bound across a relay's
/// lifetime.
///
/// Publishing only on a real change keeps the dialer from re-evaluating on every
/// descriptor that leaves the peer set untouched. `send_if_modified` updates the
/// stored value even with no subscribers yet (a relay without a dialer), so a
/// dialer that subscribes later still sees the current set.
fn publish_desired_peers(inner: &mut Inner) {
    let desired_ids: HashSet<RelayId> = inner.desired.values().flatten().copied().collect();
    inner.peer_contacts.retain(|id, _| desired_ids.contains(id));

    let mut peers: Vec<RelayPeer> = desired_ids
        .iter()
        .filter_map(|id| {
            inner.peer_contacts.get(id).map(|contact| RelayPeer {
                relay_id: *id,
                relay_addr: contact.addr,
                cert_der: contact.cert_der.clone(),
                relay_addrs: contact.addrs.clone(),
            })
        })
        .collect();
    peers.sort_by_key(|p| p.relay_id.0);

    inner.desired_peers_tx.send_if_modified(|current| {
        if *current == peers {
            false
        } else {
            *current = peers;
            true
        }
    });
}

/// Drives each named peer's link from its delivered state toward what `desired`
/// now says it should serve, sending only the difference.
///
/// `joined` advances only on a successful enqueue. The command channel is
/// unbounded, so on a live link the send always succeeds and the command is
/// durably queued for the driver. A peer with no link is skipped (its joins fire
/// when the link registers). A send that fails means the channel has closed —
/// the driver exited — so the link is dropped along with its delivered state,
/// and a reconnect re-syncs from scratch.
fn reconcile_peers(inner: &mut Inner, peers: impl IntoIterator<Item = RelayId>) {
    let peers: HashSet<RelayId> = peers.into_iter().collect();
    let mut dead: Vec<RelayId> = Vec::new();

    for peer in peers {
        // What this peer should serve, from coordinator intent.
        let target: HashSet<SessionKey> = inner
            .desired
            .iter()
            .filter(|(_, members)| members.contains(&peer))
            .map(|(key, _)| key.clone())
            .collect();

        // No link yet: intent is recorded; the join fires when it registers.
        let Some(sender) = inner.links.get(&peer).cloned() else {
            continue;
        };

        let delivered = inner.joined.entry(peer).or_default();
        let to_join: Vec<SessionKey> = target.difference(delivered).cloned().collect();
        let to_leave: Vec<SessionKey> = delivered.difference(&target).cloned().collect();

        // A send fails only if the channel has closed — the driver exited.
        let mut closed = false;
        for key in to_join {
            if sender.send(MeshCommand::Join(key.clone())).is_ok() {
                delivered.insert(key);
            } else {
                closed = true;
                break;
            }
        }
        if !closed {
            for key in to_leave {
                if sender.send(MeshCommand::Leave(key.clone())).is_ok() {
                    delivered.remove(&key);
                } else {
                    closed = true;
                    break;
                }
            }
        }
        if closed {
            dead.push(peer);
        }
    }

    // Drop links whose drivers have exited. Intent (`desired`) is kept, so a
    // reconnect under the same id re-registers and reconciles from an empty
    // delivered set, re-sending every join.
    for peer in dead {
        inner.links.remove(&peer);
        inner.joined.remove(&peer);
    }
}
