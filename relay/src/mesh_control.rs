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
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::SessionDescriptor;
use rally_point_proto::ids::RelayId;
use tokio::sync::mpsc;

use crate::mesh::MeshCommand;
use crate::routing::SessionKey;

/// Drives the mesh links' `Join`/`Leave` commands from coordinator session
/// descriptors. Clone it cheaply (the state is behind one `Arc`) to hand a copy
/// to the link collector and to the descriptor source.
#[derive(Clone)]
pub struct MeshControl {
    /// This relay's own id, used to drop a self-reference defensively if a
    /// descriptor ever lists it (a relay never meshes with itself).
    our_id: RelayId,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// The command sender for each established peer-relay link, keyed by peer id.
    links: HashMap<RelayId, mpsc::UnboundedSender<MeshCommand>>,
    /// Coordinator intent: for each session, which peers should serve it.
    desired: HashMap<SessionKey, HashSet<RelayId>>,
    /// Delivered state: for each peer, the sessions its link has been
    /// successfully told to join (and not yet leave). Only entries for peers
    /// with a live link exist here.
    joined: HashMap<RelayId, HashSet<SessionKey>>,
}

impl MeshControl {
    /// Creates an empty `MeshControl` for a relay with no peer links and no
    /// sessions yet. `our_id` is this relay's id.
    pub fn new(our_id: RelayId) -> Self {
        Self {
            our_id,
            inner: Arc::new(Mutex::new(Inner::default())),
        }
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

        let mut inner = self.inner.lock();
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
    }

    /// Ends a session's mesh membership: forgets the desired set and reconciles
    /// its peers, which leaves each link that was joined. Idempotent — ending an
    /// unknown session is a no-op.
    pub fn end_session(&self, key: &SessionKey) {
        let mut inner = self.inner.lock();
        let Some(peers) = inner.desired.remove(key) else {
            return;
        };
        reconcile_peers(&mut inner, peers);
    }
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));

        // The descriptor names peer 2, but its link has not established yet.
        control.apply_descriptor(&descriptor(1, &[2]));

        // The link establishes — the deferred join fires now.
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn re_applied_descriptor_leaves_a_dropped_peer() {
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
        let (tx2, mut rx2) = link();
        control.register_link(RelayId(2), tx2);
        // Never applied a descriptor for session 9.
        control.end_session(&key(9));
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn reconnect_replaces_sender_and_rejoins_desired_sessions() {
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
}
