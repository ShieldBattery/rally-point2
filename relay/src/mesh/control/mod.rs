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

use crate::consensus::{self, DecisionMakers};
use crate::mesh::{MeshCommand, MeshLinks};
use crate::routing::{SessionKey, Sessions};
use crate::session::drop_hold::DropHolds;
use crate::session::presence::{self, PresenceRegistry};

/// Drives the mesh links' `Join`/`Leave` commands from coordinator session
/// descriptors. Clone it cheaply (the state is behind one `Arc`) to hand a copy
/// to the link collector and to the descriptor source.
#[derive(Clone)]
pub struct MeshControl {
    /// This relay's own id, used to drop a self-reference defensively if a
    /// descriptor ever lists it (a relay never meshes with itself), and to
    /// resolve this relay's own place in each session's authority order.
    our_id: RelayId,
    /// Per-session decision-makers, created and destroyed here as descriptors
    /// arrive and sessions end. Shared with the turn path (via `MeshState`) so the
    /// slot-link and mesh-link tasks feed conditions in and stamp decisions out.
    decision_makers: Arc<DecisionMakers>,
    /// Per-session presence: each descriptor's authority order is recorded
    /// here, and the live-player reports the roster and mesh deliver combine
    /// with it into the authority verdict. Shared with the turn-path tasks
    /// (via `MeshState`) for the same reason as the decision-makers.
    presence: Arc<PresenceRegistry>,
    /// The turn-path handles a descriptor-driven authority promotion needs to
    /// re-broadcast any synced leave the demoted authority never delivered: local
    /// survivors via `sessions`, peer survivors via `mesh_links`. Empty registries
    /// by default (a control plane with no turn path — tests, a standalone
    /// descriptor driver); wired to the real ones with [`with_broadcast`](Self::with_broadcast).
    sessions: Sessions,
    mesh_links: MeshLinks,
    /// This relay's undecided drop holds, read on every `apply_descriptor` so a
    /// descriptor-driven promotion skips a slot whose drop a client could still
    /// return from — the same protection the presence-driven promotion
    /// ([`presence::recompute`]) already gets from its caller. A fresh,
    /// never-shared registry by default (a control plane with no turn path —
    /// tests, a standalone descriptor driver): it is always empty, so
    /// `apply_descriptor` degrades to treating every undecided departure as
    /// immediately decidable, exactly like the behavior this replaces. Wired to
    /// the real per-relay registry with [`with_drop_holds`](Self::with_drop_holds).
    drop_holds: DropHolds,
    /// The relay's provisional-admission registry, cleared here whenever a
    /// descriptor names a session -- a fresh, never-shared registry by
    /// default (a control plane with no turn path — tests, a standalone
    /// descriptor driver), where clearing is a harmless no-op against state
    /// nothing else ever marks. Wired to the real per-relay registry with
    /// [`with_provisional`](Self::with_provisional).
    provisional: crate::session::provisional::ProvisionalSessions,
    /// The per-session terminal ingress boundary. Descriptor application
    /// reopens a session's gate (a genuine re-serve) and retirement closes it
    /// before sweeping — see [`crate::session::gate`]. A fresh, never-shared
    /// registry by default (a control plane with no turn path); wired to the
    /// relay-wide one with [`with_gates`](Self::with_gates).
    gates: crate::session::gate::SessionGates,
    /// The relay's full turn-path state, wired with
    /// [`with_turn_path`](Self::with_turn_path) so descriptor application can
    /// drain the provisional-turn pen through the ordinary forward path the
    /// moment the maker exists (and the seeded decided-leave fence with it).
    /// `None` by default (a control plane with no turn path — tests, a
    /// standalone descriptor driver), where nothing ever pens a turn and
    /// there is nothing to drain.
    turn_path: Option<crate::mesh::MeshState>,
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
    /// sessions yet. `our_id` is this relay's id. `decision_makers` is the
    /// registry the relay's turn path holds (via `MeshState`), so a maker this
    /// creates on a descriptor is the one the slot-link and mesh-link tasks
    /// feed and stamp — a required argument, because a `MeshControl` minting
    /// its own registry would create makers the turn path silently never
    /// reads. `presence` is required for the same reason: the order recorded
    /// here must be the one the turn-path tasks' live-player reports land on,
    /// or the authority verdict would never move. A caller with no turn path
    /// (tests, a standalone control plane) passes `Arc::default()` for both.
    pub fn new(
        our_id: RelayId,
        decision_makers: Arc<DecisionMakers>,
        presence: Arc<PresenceRegistry>,
    ) -> Self {
        let (desired_peers_tx, _) = watch::channel(Vec::new());
        Self {
            our_id,
            decision_makers,
            presence,
            sessions: Sessions::default(),
            mesh_links: crate::mesh::new_mesh_links(),
            // A fresh, never-shared registry: nothing ever holds anything in
            // it, so `apply_descriptor` reads an always-empty held set unless
            // `with_drop_holds` wires the real one. Production values are used
            // even for this placeholder purely so its unlock/abandon timings
            // are never surprising if something did reach it unwired.
            drop_holds: DropHolds::new(
                crate::session::drop_hold::DROP_UNLOCK,
                crate::session::drop_hold::ABANDONED_SESSION_TIMEOUT,
            ),
            provisional: crate::session::provisional::ProvisionalSessions::new(
                crate::session::provisional::PROVISIONAL_WINDOW,
            ),
            gates: crate::session::gate::SessionGates::default(),
            turn_path: None,
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

    /// Wires the turn-path handles so a descriptor-driven authority *promotion*
    /// can re-broadcast a synced leave the demoted authority never delivered —
    /// pushing it to local survivors (`sessions`) and peer survivors
    /// (`mesh_links`) — and so a descriptor that changes an already-released
    /// region-label map can correct the local slots still holding the superseded
    /// one. The production relay calls this with the same registries the turn
    /// path holds; a control plane with no turn path leaves the empty defaults
    /// from [`new`](Self::new), where both pushes are harmless no-ops against
    /// empty registries.
    pub fn with_broadcast(mut self, sessions: Sessions, mesh_links: MeshLinks) -> Self {
        self.sessions = sessions;
        self.mesh_links = mesh_links;
        self
    }

    /// Wires the relay-wide session-gate registry, so the retire/reopen this
    /// control plane performs is the same boundary the turn path, client
    /// admission, and mesh dispatch run their ingress through. The production
    /// relay passes `MeshState::gates`; a control plane with no turn path
    /// keeps the default fresh registry, where gating is a harmless no-op.
    pub fn with_gates(mut self, gates: crate::session::gate::SessionGates) -> Self {
        self.gates = gates;
        self
    }

    /// Wires the real per-relay drop-hold registry, so a descriptor-driven
    /// authority promotion skips a slot whose drop is still held undecided —
    /// the same protection the presence-driven promotion already has. The
    /// production relay calls this with the same [`DropHolds`] the turn path
    /// holds (via `MeshState`); a control plane with no turn path leaves the
    /// harmless placeholder from [`new`](Self::new).
    pub fn with_drop_holds(mut self, drop_holds: DropHolds) -> Self {
        self.drop_holds = drop_holds;
        self
    }

    /// Wires the real per-relay provisional-admission registry, so
    /// `apply_descriptor` clears a session's provisional mark the moment a
    /// descriptor names it. The production relay calls this with the same
    /// [`crate::session::provisional::ProvisionalSessions`] the turn path holds (via
    /// `MeshState`); a control plane with no turn path leaves the harmless
    /// placeholder from [`new`](Self::new).
    pub fn with_provisional(
        mut self,
        provisional: crate::session::provisional::ProvisionalSessions,
    ) -> Self {
        self.provisional = provisional;
        self
    }

    /// Wires the relay's full turn-path state, so `apply_descriptor` can
    /// drain the provisional-turn pen through the ordinary forward path the
    /// moment a descriptor creates the session's maker — the freshly seeded
    /// decided-leave fence then sorts a departed slot's held turns (dropped)
    /// from a current slot's (forwarded). The production relay passes its
    /// `MeshState` clone; a control plane with no turn path has nothing
    /// penned and skips the drain.
    pub fn with_turn_path(mut self, turn_path: crate::mesh::MeshState) -> Self {
        self.turn_path = Some(turn_path);
        self
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
        self.gates.retire(key);
        consensus::deregister_maker(&self.decision_makers, key);
        presence::forget(&self.presence, key);
        // Discard any turns still penned for the session — with the maker
        // gone and the gate retired, no descriptor will ever drain them. The
        // replay ring and forward-once seen state fall with them: the
        // session-emptied close retains both while an undecided hold still
        // promises a reconnect (their receipts seed that resume's receive
        // window), and retirement is the terminal boundary that ends the
        // promise — with the descriptor gone there is no admission path left,
        // so nothing else would ever sweep a retained pair whose reconnect
        // never came. Idempotent when the emptied close already removed them.
        if let Some(turn_path) = &self.turn_path {
            turn_path.provisional_turns.discard(key);
            turn_path.turn_ring.end_session(key);
            crate::mesh::deregister_seen(&turn_path.seen, key);
        }
        // Retirement is terminal for the session's drop bookkeeping: with the
        // descriptor gone there is no admission path left for a held slot's
        // reconnect and no decide path for its leave, so any armed abandon
        // timer and every remaining hold would otherwise leak forever — the
        // timer's expiry stands down on the forgotten presence (never deciding
        // or releasing), and nothing else ever sweeps the entries.
        self.drop_holds.cancel_abandon(key);
        self.drop_holds.end_session_terminal(key);
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
        self.decision_makers.flight_recorder().clear_close_seal(key);
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
