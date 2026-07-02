//! The Join source: turn a coordinator session descriptor into per-link
//! `Join`/`Leave` commands on the right mesh links.
//!
//! The connection half ([`mesh_edge`](crate::mesh_edge)) establishes one QUIC
//! connection per relay-pair and surfaces a [`MeshCommand`] sender per link,
//! labeled with the peer relay's id. `MeshControl` is what *drives* those
//! senders: it holds the per-peer senders and, given a [`SessionDescriptor`] the
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
//! The command channel is unbounded (see
//! [`command_channel`](crate::mesh::command_channel)), so a send to a live link
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
use rally_point_proto::control::{RelayPeer, SessionDescriptor};
use rally_point_proto::ids::RelayId;
use tokio::sync::{mpsc, watch};

use crate::consensus::{self, Authority, DecisionMakers};
use crate::mesh::MeshCommand;
use crate::routing::SessionKey;

/// Drives the mesh links' `Join`/`Leave` commands from coordinator session
/// descriptors. Clone it cheaply (the state is behind one `Arc`) to hand a copy
/// to the link collector and to the descriptor source.
#[derive(Clone)]
pub struct MeshControl {
    /// This relay's own id, used to drop a self-reference defensively if a
    /// descriptor ever lists it (a relay never meshes with itself), and to decide
    /// buffer authority (the lowest relay id serving a session decides).
    our_id: RelayId,
    /// Per-session decision-makers, created and destroyed here as descriptors
    /// arrive and sessions end. Shared with the turn path (via `MeshState`) so the
    /// slot-link and mesh-link tasks feed conditions in and stamp decisions out.
    decision_makers: Arc<DecisionMakers>,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    /// The command sender for each established peer-relay link, keyed by peer id.
    links: HashMap<RelayId, mpsc::UnboundedSender<MeshCommand>>,
    /// Coordinator intent: for each session, which peers should serve it.
    desired: HashMap<SessionKey, HashSet<RelayId>>,
    /// Delivered state: for each peer, the sessions its link has been
    /// successfully told to join (and not yet leave). Only entries for peers
    /// with a live link exist here.
    joined: HashMap<RelayId, HashSet<SessionKey>>,
    /// Latest reachable address seen for each peer (from descriptors), so the
    /// desired-peer set published for the dialer carries addresses, not just ids.
    /// Pruned to the currently-desired peers on each publish.
    peer_addrs: HashMap<RelayId, SocketAddr>,
    /// Publishes the peers this relay currently needs mesh links to (id +
    /// address), so the on-demand dialer can (re)establish them. Declarative
    /// latest-wins state — like the coordinator's descriptor push, a level down:
    /// the coordinator says which peers a session needs, and this republishes the
    /// union across all sessions for the connection half to act on.
    desired_peers_tx: watch::Sender<Vec<RelayPeer>>,
}

impl MeshControl {
    /// Creates an empty `MeshControl` for a relay with no peer links and no
    /// sessions yet. `our_id` is this relay's id. `decision_makers` is the
    /// registry the relay's turn path holds (via `MeshState`), so a maker this
    /// creates on a descriptor is the one the slot-link and mesh-link tasks
    /// feed and stamp — a required argument, because a `MeshControl` minting
    /// its own registry would create makers the turn path silently never
    /// reads. A caller with no turn path (tests, a standalone control plane)
    /// passes `Arc::default()`.
    pub fn new(our_id: RelayId, decision_makers: Arc<DecisionMakers>) -> Self {
        let (desired_peers_tx, _) = watch::channel(Vec::new());
        Self {
            our_id,
            decision_makers,
            inner: Arc::new(Mutex::new(Inner {
                links: HashMap::new(),
                desired: HashMap::new(),
                joined: HashMap::new(),
                peer_addrs: HashMap::new(),
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
    pub fn register_link(&self, peer_id: RelayId, sender: mpsc::UnboundedSender<MeshCommand>) {
        let mut inner = self.inner.lock();
        inner.links.insert(peer_id, sender);
        // The link knows nothing yet; reconcile re-sends every desired join.
        inner.joined.insert(peer_id, HashSet::new());
        reconcile_peers(&mut inner, [peer_id]);
    }

    /// Applies a coordinator [`SessionDescriptor`]: the session's mesh peers
    /// become exactly the descriptor's peers.
    ///
    /// Declarative — peers newly named are joined (on whichever of their links
    /// have established), peers dropped since the last descriptor for this
    /// session are left, and peers unchanged are untouched. Re-applying the same
    /// descriptor is also how a previously dropped command recovers: it
    /// reconciles the affected peers against delivered state and re-sends
    /// whatever did not get through. A named peer with no established link yet is
    /// remembered, so the join fires when [`register_link`](Self::register_link)
    /// sees it.
    pub fn apply_descriptor(&self, descriptor: &SessionDescriptor) {
        let key = SessionKey {
            tenant: descriptor.tenant.clone(),
            session: descriptor.session,
        };
        let new_peers: HashSet<RelayId> = descriptor
            .peers
            .iter()
            .map(|p| p.relay_id)
            .filter(|id| *id != self.our_id)
            .collect();

        // Create or reconcile this session's decision-maker with the
        // coordinator's bounds and this relay's authority. Authority is decided
        // by relay-id order: the lowest id among the relays serving the session
        // is the decision-maker, so one relay decides and the rest forward its
        // stamped turns. A single-relay session (no peers) is trivially the
        // authority. Reconciling on every push — not just creating on the first
        // — is what keeps the verdict true as the relay set changes: a re-push
        // that adds a lower-id relay demotes this one, and one that removes the
        // lowest promotes the next. (Relays receive a re-push at slightly
        // different moments, so two can disagree briefly while it propagates;
        // the directive's decision seq keeps clients consistent through that
        // window.) This id-order rule is interim until the coordinator assigns
        // an explicit priority order and a presence signal drives handoff when
        // the authority's players leave; it takes no coordinator round-trip.
        let authority = if new_peers.iter().all(|id| self.our_id.0 < id.0) {
            Authority::SelfRelay
        } else {
            Authority::Peer
        };
        consensus::sync_maker(&self.decision_makers, &key, descriptor.bounds, authority);

        let mut inner = self.inner.lock();

        // Remember each named peer's reachable address, so the desired-peer set
        // published for the dialer can carry it (a relay never dials itself).
        for peer in &descriptor.peers {
            if peer.relay_id != self.our_id {
                inner.peer_addrs.insert(peer.relay_id, peer.relay_addr);
            }
        }

        let old_peers = inner.desired.get(&key).cloned().unwrap_or_default();

        // An empty peer set means a single-relay session (no mesh); forget the
        // entry entirely rather than leave an empty set lingering.
        if new_peers.is_empty() {
            inner.desired.remove(&key);
        } else {
            inner.desired.insert(key.clone(), new_peers.clone());
        }

        // Reconcile every peer whose membership in this session could have
        // changed: the union of the old and new peer sets.
        let affected: HashSet<RelayId> = old_peers.union(&new_peers).copied().collect();
        reconcile_peers(&mut inner, affected);
        publish_desired_peers(&mut inner);
    }

    /// Ends a session's mesh membership: destroys its decision-maker, forgets the
    /// desired set, and reconciles its peers, which leaves each link that was
    /// joined. Idempotent — ending an unknown session is a no-op.
    ///
    /// The decision-maker is dropped first, unconditionally: a single-relay
    /// session has a maker but no mesh peers to reconcile, so gating its teardown
    /// on the mesh state below would leak it.
    pub fn end_session(&self, key: &SessionKey) {
        consensus::deregister_maker(&self.decision_makers, key);
        let mut inner = self.inner.lock();
        let Some(peers) = inner.desired.remove(key) else {
            return;
        };
        reconcile_peers(&mut inner, peers);
        publish_desired_peers(&mut inner);
    }
}

/// Recomputes the peers this relay currently needs mesh links to — the union of
/// every session's desired peers, each paired with its latest known address — and
/// publishes it if it changed. The address book is pruned to just the desired
/// peers so it can't grow without bound across a relay's lifetime.
///
/// Publishing only on a real change keeps the dialer from re-evaluating on every
/// descriptor that leaves the peer set untouched. `send_if_modified` updates the
/// stored value even with no subscribers yet (a relay without a dialer), so a
/// dialer that subscribes later still sees the current set.
fn publish_desired_peers(inner: &mut Inner) {
    let desired_ids: HashSet<RelayId> = inner.desired.values().flatten().copied().collect();
    inner.peer_addrs.retain(|id, _| desired_ids.contains(id));

    let mut peers: Vec<RelayPeer> = desired_ids
        .iter()
        .filter_map(|id| {
            inner.peer_addrs.get(id).map(|&addr| RelayPeer {
                relay_id: *id,
                relay_addr: addr,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{BufferBounds, RelayPeer, TenantId};
    use rally_point_proto::ids::SessionId;

    const TENANT: &str = "sb-test";

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
        }
    }

    fn relay_peer(id: u64) -> RelayPeer {
        RelayPeer {
            relay_id: RelayId(id),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
        }
    }

    fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
            peers: peers.iter().map(|&id| relay_peer(id)).collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
        }
    }

    /// A registered link plus the receiver standing in for its driver's command
    /// stream, so a test can assert what the link was told.
    fn link() -> (
        mpsc::UnboundedSender<MeshCommand>,
        mpsc::UnboundedReceiver<MeshCommand>,
    ) {
        mpsc::unbounded_channel()
    }

    #[test]
    fn applies_join_to_each_registered_peer() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        control.register_link(RelayId(2), tx2);
        control.register_link(RelayId(3), tx3);

        control.apply_descriptor(&descriptor(1, &[2, 3]));

        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn joins_only_named_peers_never_broadcasts() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        control.register_link(RelayId(2), tx2);
        control.register_link(RelayId(3), tx3);

        // Session 1 names only peer 2 — peer 3 serves a different session.
        control.apply_descriptor(&descriptor(1, &[2]));

        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert!(
            rx3.try_recv().is_err(),
            "peer not in the descriptor must not be joined",
        );
    }

    #[test]
    fn descriptor_before_link_joins_when_the_link_registers() {
        let control = MeshControl::new(RelayId(1), Arc::default());

        // The descriptor names peer 2, but its link has not established yet.
        control.apply_descriptor(&descriptor(1, &[2]));

        // The link establishes — the deferred join fires now.
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn re_applied_descriptor_leaves_a_dropped_peer() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        control.register_link(RelayId(2), tx2);
        control.register_link(RelayId(3), tx3);

        control.apply_descriptor(&descriptor(1, &[2, 3]));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // Peer 3 churns out of the session; a re-pushed descriptor drops it.
        control.apply_descriptor(&descriptor(1, &[2]));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        // Peer 2 was already joined and is unchanged — no redundant re-join.
        assert!(
            rx2.try_recv().is_err(),
            "an unchanged peer must not be re-joined",
        );
    }

    #[test]
    fn end_session_leaves_all_peers_and_forgets_membership() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        control.register_link(RelayId(2), tx2);
        control.register_link(RelayId(3), tx3);

        control.apply_descriptor(&descriptor(1, &[2, 3]));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));

        control.end_session(&key(1));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Leave(key(1)));

        // Membership was forgotten: a fresh descriptor for the same session id
        // joins from scratch rather than treating peer 2 as already joined.
        control.apply_descriptor(&descriptor(1, &[2]));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn end_session_on_an_unknown_session_is_a_no_op() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);
        // Never applied a descriptor for session 9.
        control.end_session(&key(9));
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn reconnect_replaces_sender_and_rejoins_desired_sessions() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2_old, mut rx2_old) = link();
        control.register_link(RelayId(2), tx2_old);
        control.apply_descriptor(&descriptor(1, &[2]));
        assert_eq!(rx2_old.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // The link to peer 2 drops and reconnects: a new sender registers under
        // the same id, and the desired session re-joins on it.
        let (tx2_new, mut rx2_new) = link();
        control.register_link(RelayId(2), tx2_new);
        assert_eq!(rx2_new.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn drops_a_descriptor_self_reference() {
        // A descriptor that erroneously lists this relay among its own peers
        // must not produce a self-join — a relay never meshes with itself.
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx1, mut rx1) = link();
        // Even if a link were somehow registered under our own id, we don't join.
        control.register_link(RelayId(1), tx1);
        control.apply_descriptor(&descriptor(1, &[1, 2]));
        assert!(
            rx1.try_recv().is_err(),
            "a relay must not join a link to itself",
        );
    }

    #[test]
    fn a_join_burst_beyond_the_old_capacity_is_never_dropped() {
        // A burst of session starts on one relay-pair — more than the previous
        // bounded command-channel capacity — must not drop any join. The
        // unbounded channel absorbs the burst; the driver drains it in order.
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);

        const BURST: u64 = 64; // well beyond the previous 32-deep bound
        for s in 1..=BURST {
            control.apply_descriptor(&descriptor(s, &[2]));
        }

        for s in 1..=BURST {
            assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(s)));
        }
        assert!(rx2.try_recv().is_err(), "no extra commands");
    }

    #[test]
    fn a_terminal_leave_is_delivered_under_backlog() {
        // The exact gap finding #2 flagged: a session's final `Leave` — with no
        // later descriptor to re-push it — must not be lost behind a backlog of
        // undrained commands. With an unbounded channel it is durably queued.
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);

        // Build a backlog of joins (beyond the old bound), none drained yet.
        const BACKLOG: u64 = 40;
        for s in 1..=BACKLOG {
            control.apply_descriptor(&descriptor(s, &[2]));
        }
        // Session 1 ends — its `Leave` is the terminal event for that session,
        // queued behind the whole backlog.
        control.end_session(&key(1));

        // Drain: the backlogged joins, then session 1's `Leave` — present, not
        // dropped despite the backlog.
        for s in 1..=BACKLOG {
            assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(s)));
        }
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn a_closed_link_is_dropped_and_a_reconnect_re_syncs() {
        // When a link's driver has exited (its receiver dropped), the stale
        // sender is removed but intent is kept, so a reconnect re-joins from
        // scratch rather than the session being lost.
        let control = MeshControl::new(RelayId(1), Arc::default());
        let (tx2_dead, rx2_dead) = link();
        control.register_link(RelayId(2), tx2_dead);
        drop(rx2_dead); // the driver exited; the channel is now closed

        // Applying a descriptor tries to join over the dead link and fails; the
        // link is dropped, but the desired membership is kept.
        control.apply_descriptor(&descriptor(1, &[2]));

        // The peer reconnects: a fresh link registers and the kept intent
        // re-joins on it.
        let (tx2_new, mut rx2_new) = link();
        control.register_link(RelayId(2), tx2_new);
        assert_eq!(rx2_new.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn apply_descriptor_publishes_desired_peers_with_addresses() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let mut peers_rx = control.desired_peers();
        assert!(peers_rx.borrow_and_update().is_empty());

        control.apply_descriptor(&descriptor(1, &[2, 3]));

        assert!(peers_rx.has_changed().unwrap());
        let published = peers_rx.borrow_and_update().clone();
        assert_eq!(published.len(), 2);
        // Sorted by id, each carrying the address the descriptor named.
        assert_eq!(published[0].relay_id, RelayId(2));
        assert_eq!(
            published[0].relay_addr,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14902))
        );
        assert_eq!(published[1].relay_id, RelayId(3));
    }

    #[test]
    fn ending_a_session_republishes_the_shrunk_peer_set() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let mut peers_rx = control.desired_peers();
        control.apply_descriptor(&descriptor(1, &[2]));
        peers_rx.borrow_and_update();

        control.end_session(&key(1));
        assert!(peers_rx.has_changed().unwrap());
        assert!(peers_rx.borrow_and_update().is_empty());
    }

    #[test]
    fn a_self_reference_is_not_published_as_a_desired_peer() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let mut peers_rx = control.desired_peers();
        // The descriptor erroneously lists this relay (1) among its own peers.
        control.apply_descriptor(&descriptor(1, &[1, 2]));
        let published = peers_rx.borrow_and_update().clone();
        assert_eq!(published.len(), 1, "a relay never dials itself");
        assert_eq!(published[0].relay_id, RelayId(2));
    }

    #[test]
    fn an_unchanged_peer_set_does_not_republish() {
        let control = MeshControl::new(RelayId(1), Arc::default());
        let mut peers_rx = control.desired_peers();
        control.apply_descriptor(&descriptor(1, &[2]));
        peers_rx.borrow_and_update();

        // A second session naming the same peer leaves the desired-peer union
        // unchanged, so the dialer isn't needlessly re-woken.
        control.apply_descriptor(&descriptor(2, &[2]));
        assert!(
            !peers_rx.has_changed().unwrap(),
            "an unchanged peer set must not republish",
        );
    }

    // -- Decision-maker lifecycle --

    #[test]
    fn apply_descriptor_creates_a_self_authority_maker_for_a_single_relay_session() {
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone());

        // A descriptor with no peers is a single-relay session: the relay is its
        // own buffer authority.
        control.apply_descriptor(&descriptor(1, &[]));

        let registry = makers.lock();
        let maker = registry.get(&key(1)).expect("a maker was created");
        assert!(
            maker.is_authority(),
            "a single-relay session is its own authority",
        );
    }

    #[test]
    fn authority_is_the_lowest_relay_id_serving_the_session() {
        // our_id 1, peer 2: we're the lowest, so we decide.
        let low = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), low.clone());
        control.apply_descriptor(&descriptor(1, &[2]));
        assert!(
            low.lock().get(&key(1)).unwrap().is_authority(),
            "the lowest relay id is the authority",
        );

        // our_id 3, peer 2: the peer is lower, so it decides, not us.
        let high = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(3), high.clone());
        control.apply_descriptor(&descriptor(1, &[2]));
        assert!(
            !high.lock().get(&key(1)).unwrap().is_authority(),
            "a relay that isn't the lowest id defers to the peer that is",
        );
    }

    #[test]
    fn a_repushed_descriptor_moves_authority_with_the_relay_set() {
        // Relay 2 starts as the session's only relay: it is the authority.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(2), makers.clone());
        control.apply_descriptor(&descriptor(1, &[]));
        assert!(makers.lock().get(&key(1)).unwrap().is_authority());

        // A player homed on relay 1 joins: the re-pushed descriptor names a
        // lower id, so relay 2 is demoted — a frozen verdict here would leave
        // the session with two authorities stamping conflicting directives.
        control.apply_descriptor(&descriptor(1, &[1]));
        assert!(
            !makers.lock().get(&key(1)).unwrap().is_authority(),
            "a lower-id relay joining demotes this one",
        );

        // Relay 1's players leave: the re-push drops it, promoting relay 2
        // back — a frozen verdict here would leave the session with none.
        control.apply_descriptor(&descriptor(1, &[]));
        assert!(
            makers.lock().get(&key(1)).unwrap().is_authority(),
            "the lowest id leaving promotes the next",
        );
    }

    #[test]
    fn end_session_destroys_the_maker() {
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone());

        control.apply_descriptor(&descriptor(1, &[]));
        assert!(makers.lock().contains_key(&key(1)));

        control.end_session(&key(1));
        assert!(
            !makers.lock().contains_key(&key(1)),
            "ending the session drops its maker, even with no mesh peers",
        );
    }

    #[test]
    fn a_created_maker_ingests_conditions_and_queues_a_directive() {
        use rally_point_proto::ids::{GameFrameCount, SlotId};
        use rally_point_proto::messages::{LinkConditions, SlotConditions};

        // The whole relay-side path, end to end at the registry level: a descriptor
        // creates the maker, a validated turn's frame and a high-RTT sample fed
        // through the same helpers the turn path uses make it decide, and the
        // decision is available to stamp.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone());
        control.apply_descriptor(&descriptor(1, &[])); // bounds (1, 6), SelfRelay

        consensus::observe_frame(&makers, &key(1), SlotId(0), GameFrameCount(1));
        let conditions = LinkConditions {
            slots: vec![SlotConditions {
                slot: 0,
                rtt_us: 150_000,
                lost_packets: 0,
                sent_packets: 100,
            }],
        };
        let decision = consensus::ingest_local_conditions(&makers, &key(1), &conditions)
            .expect("a raise fires on the first high-RTT sample");
        assert_eq!(
            decision.buffer.0, 4,
            "150ms -> 4 turns, within bounds (1, 6)"
        );

        let directive =
            consensus::active_directive(&makers, &key(1)).expect("a directive is queued");
        assert_eq!(directive.buffer_turns, 4);
        assert_eq!(directive.apply_at_frame, decision.applied_frame.0);
    }
}
