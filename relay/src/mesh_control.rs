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
use rally_point_proto::control::{RelayPeer, SessionDescriptor};
use rally_point_proto::ids::{RelayId, SlotId};
use rally_point_proto::messages::RegionLabel;
use tokio::sync::{mpsc, watch};

use crate::consensus::{self, Authority, DecisionMakers};
use crate::drop_hold::DropHolds;
use crate::mesh::{self, MeshCommand, MeshLinks};
use crate::presence::{self, Candidate, PresenceRegistry};
use crate::routing::{self, SessionKey, Sessions};

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
    provisional: crate::provisional::ProvisionalSessions,
    /// The per-session terminal ingress boundary. Descriptor application
    /// reopens a session's gate (a genuine re-serve) and retirement closes it
    /// before sweeping — see [`crate::session_gate`]. A fresh, never-shared
    /// registry by default (a control plane with no turn path); wired to the
    /// relay-wide one with [`with_gates`](Self::with_gates).
    gates: crate::session_gate::SessionGates,
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
                crate::drop_hold::DROP_UNLOCK,
                crate::drop_hold::ABANDONED_SESSION_TIMEOUT,
            ),
            provisional: crate::provisional::ProvisionalSessions::new(
                crate::provisional::PROVISIONAL_WINDOW,
            ),
            gates: crate::session_gate::SessionGates::default(),
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
    pub fn with_gates(mut self, gates: crate::session_gate::SessionGates) -> Self {
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
    /// [`crate::provisional::ProvisionalSessions`] the turn path holds (via
    /// `MeshState`); a control plane with no turn path leaves the harmless
    /// placeholder from [`new`](Self::new).
    pub fn with_provisional(
        mut self,
        provisional: crate::provisional::ProvisionalSessions,
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

        // Deliberately no close-seal clearing here: a descriptor push is
        // routinely an idempotent *replay* — a coordinator reconnect re-pushes
        // every current descriptor — and unsealing a closed-but-not-yet-retired
        // session would let a straggling mesh event conjure the empty
        // replacement recording the seal exists to prevent. A *genuine*
        // re-serve always passes through the session's retirement first (the
        // coordinator removes a descriptor before it would ever re-add one),
        // and `end_session` clears the seal there.

        // Stamp the tenant's correlation ids into the decision-maker registry
        // so a departure notice for this session can carry its own
        // `external_id`/`external_ref` without depending on the coordinator's
        // in-memory session-refs store (which a coordinator restart wipes —
        // this descriptor, once applied, does not). Always overwrites: a
        // changed re-applied descriptor's refs replace rather than accumulate
        // alongside a stale copy.
        self.decision_makers.set_session_refs(
            &key,
            descriptor.external_id.clone(),
            descriptor
                .slot_refs
                .iter()
                .map(|r| (r.slot, r.external_ref.clone()))
                .collect(),
        );

        let new_peers: HashSet<RelayId> = descriptor
            .peers
            .iter()
            .map(|p| p.relay_id)
            .filter(|id| *id != self.our_id)
            .collect();

        // Record this session's authority order and re-derive the verdict.
        // The order is the coordinator's ranking (home relay first); which of
        // those relays still serves live players is the presence the roster
        // and the mesh report between pushes. One relay decides and the rest
        // forward its stamped turns; when the deciding relay's players all
        // leave, the verdict falls to the next in the order with no
        // coordinator round-trip. A descriptor from a coordinator that
        // predates the order carries none — fall back to relay-id order over
        // the session's relay set, the interim rule the assigned order
        // replaces. Reconciling on every push — not just creating on the
        // first — keeps the verdict true as the relay set changes. (Relays
        // receive a re-push at slightly different moments, so two can
        // disagree briefly while it propagates; the directive's decision seq
        // keeps clients consistent through that window.)
        let ranked: Vec<RelayId> = if descriptor.authority_order.is_empty() {
            let mut ids: Vec<RelayId> = new_peers.iter().copied().collect();
            ids.push(self.our_id);
            ids.sort_by_key(|id| id.0);
            ids
        } else {
            descriptor.authority_order.clone()
        };
        let order: Vec<Candidate> = ranked
            .into_iter()
            .map(|id| {
                if id == self.our_id {
                    Candidate::SelfRelay
                } else {
                    Candidate::Peer(id)
                }
            })
            .collect();
        presence::set_order(&self.presence, &key, order);
        let authority = presence::verdict(&self.presence, &key).unwrap_or(Authority::Peer);
        // A verdict that promotes this relay (e.g. the coordinator dropped the
        // former authority from the order because it crashed — a case presence
        // alone can't catch, since a crashed relay sends no zero report) yields
        // the synced leaves it must re-broadcast so no leave is lost. The
        // descriptor's observer slots are seeded into the maker here — a maker
        // created by this push starts with them excluded from the desync
        // comparator, so a single-relay session (one push, before any client
        // dials) never loses its observer set; a re-push replaces the set.
        //
        // The current held-slot set is read from the drop-hold registry right
        // before syncing, so a promotion here skips a slot whose drop a client
        // could still return from — exactly like the presence-driven promotion
        // (`presence::recompute`), which gets the same set from its own caller.
        // A descriptor naming this session is a genuine (re-)serve: lift any
        // retirement gate so its ingress — clients, turns, mesh frames —
        // dispatches again. Before `sync_maker`, so no window exists where
        // the maker is visible but the gate still refuses.
        self.gates.reopen(&key);
        let held_slots = self.drop_holds.pending_slots(&key);
        // A rehome (resumed) descriptor's departed-slot seeds — and the
        // resumed latch that stops leaves decided from here on from carrying
        // exact final turn counts — install inside `sync_maker`'s registry
        // lock, atomically with the maker becoming visible: a provisionally
        // admitted client can clean-leave the instant the maker exists, and a
        // latch set by a follow-up call would lose that race and emit a count
        // the rehomed session's split forwarding history cannot support. The
        // returned batch already folds in any directive the seeding newly
        // decided, so the broadcast below also reaches local clients admitted
        // before this descriptor (whose one registration-time leave
        // reconciliation predates the seed).
        let leaves = consensus::sync_maker(
            &self.decision_makers,
            &key,
            descriptor.bounds,
            authority,
            descriptor.observer_slots.iter().copied().collect(),
            descriptor.expected_slots.iter().copied().collect(),
            descriptor.homed_slots.iter().copied().collect(),
            held_slots,
            descriptor
                .resumed
                .then_some(descriptor.departed_slots.as_slice()),
            descriptor.finalized_drops,
        );
        // A descriptor now names this session, so any provisional-admission
        // mark it carried is moot -- the bounded-admission sweep would
        // otherwise still reap it on the original deadline. A session that
        // was never provisional (a mesh Join, or a descriptor that beat every
        // client dial) has nothing here to clear.
        self.provisional.clear(&key);
        // Stamps this relay's own id onto the maker so a buffer directive it
        // queues as authority carries the deterministic decision_seq
        // tie-break (see `BufferDirective.authority_relay_id`). Idempotent;
        // run on every descriptor push, not just creation, since `sync_maker`
        // itself re-syncs an existing maker the same way.
        consensus::set_own_relay_id(&self.decision_makers, &key, self.our_id);
        // Feed the descriptor-derived inputs to the initial-depth computation: the
        // tenant's latency hint, and whether this is a single-relay session (no
        // mesh peers) — the latter decides both the fully-observed rule and the
        // multi-relay hop cushion. Set on create and every re-sync, like the
        // observer/expected/homed sets above.
        consensus::set_session_shape(
            &self.decision_makers,
            &key,
            descriptor.latency_estimate_ms,
            new_peers.is_empty(),
        );
        // Record the session's relay → region labels. They go no further until the
        // session's release gate opens on the turn path; the only thing that can
        // send from here is a *changed* map on a session whose gate is already
        // open (a re-home named a different relay), where the clients holding the
        // superseded map must be corrected.
        let relabelled = consensus::set_region_labels(
            &self.decision_makers,
            &key,
            descriptor
                .relay_regions
                .iter()
                .map(|label| RegionLabel {
                    relay_id: label.relay_id.0,
                    region: label.region.0.clone(),
                })
                .collect(),
        );
        if let Some(labels) = relabelled {
            routing::fan_out_region_labels(&self.sessions, &key, &labels);
        }
        mesh::broadcast_leaves(&self.sessions, &self.mesh_links, &key, leaves);
        if descriptor.resumed && !descriptor.departed_slots.is_empty() {
            // A seeded departed slot may still hold a live local link — a
            // provisionally admitted dial that raced the descriptor. Its
            // leave is decided, so the home-ingress turn fence already drops
            // everything it sends; close the link too rather than leaving a
            // zombie connection pumping fenced turns until it gives up on its
            // own. The subject deliberately receives no LeaveDirective of its
            // own, so the close is the only signal it gets.
            let departed: Vec<_> = descriptor.departed_slots.iter().map(|d| d.slot).collect();
            crate::routing::close_slots(&self.sessions, &key, &departed);
        }
        if descriptor.resumed {
            self.decision_makers.flight_recorder().record(
                &key,
                crate::flight_recorder::FlightEvent::ResumedDescriptorApplied {
                    departed_slots: descriptor.departed_slots.len() as u32,
                },
            );
        }
        // A maker now exists, so drain the ingress journaled while the
        // session had none (pre-descriptor provisional dials) back through
        // the ordinary paths, in arrival order. This runs AFTER the seeding
        // above, so a seeded-departed slot's journaled turns hit the
        // decided-leave fence and die instead of reaching co-admitted
        // survivors; every current slot's turns flow exactly as if they had
        // arrived a moment later. A journaled departure re-announces into
        // the maker — a clean leave's exact count is derived HERE, over
        // exactly the slot's own turns drained ahead of it (its link was
        // closed at the intent, so the journaled prefix is complete), never
        // from the deposit-time snapshot that was blind to them. The drain
        // itself is the journal's one-shot resolved transition
        // (`take_and_resolve`), so a deposit racing this is refused and
        // re-runs against the maker.
        if let Some(turn_path) = &self.turn_path {
            for entry in turn_path.provisional_turns.take_and_resolve(&key) {
                match entry {
                    crate::provisional_turns::PennedIngress::Turn(slot, payload) => {
                        mesh::forward_client_turn(&self.sessions, turn_path, &key, slot, payload);
                    }
                    crate::provisional_turns::PennedIngress::Departure {
                        slot,
                        reason,
                        connection_epoch,
                    } => {
                        let exact_count = (reason == consensus::LEAVE_REASON_LEFT)
                            .then(|| mesh::forwarded_count(&turn_path.seen, &key, slot))
                            .flatten();
                        let _ = turn_path.gates.with_ingress(&key, || {
                            routing::announce_departure(
                                &self.drop_holds,
                                &self.decision_makers,
                                &self.sessions,
                                &self.mesh_links,
                                &turn_path.provisional_turns,
                                &key,
                                slot,
                                reason,
                                exact_count,
                                connection_epoch,
                            )
                        });
                    }
                }
            }
        }
        // Reconcile the roster into the maker this descriptor just created or
        // updated. A slot that dialed and registered before this descriptor
        // arrived announced its presence when the session had no maker yet, so
        // the announce found nothing to record and the presence was dropped;
        // the maker is then created with the expected set seeded but no live
        // slots, and coverage can never be reached for a session whose every
        // dial raced ahead of its descriptor. Re-note every slot the roster
        // currently holds so the maker sees the presence that was lost.
        // `note_slot_present` inserts into a set, so re-noting a slot its own
        // live announce already recorded is idempotent — no double count.
        // Registration seats a slot in the roster before its link task
        // announces, so any slot whose announce found no maker is already
        // visible in this snapshot; a slot that registers after this rescan
        // reaches the maker through its own later announce, and none can fall
        // between the two. Snapshot the slot ids under the sessions lock and
        // drop it before touching the decision makers — these two locks are
        // only ever taken sessions-then-decision-makers, never nested the other
        // way.
        let registered_slots: Vec<SlotId> = {
            let roster = self.sessions.lock();
            roster
                .get(&key)
                .map(|slots| slots.keys().copied().collect())
                .unwrap_or_default()
        };
        // A re-note that completes the expected set latches the session started
        // inside the maker, so the `maybe_start_session` below would then see an
        // already-started session and deliver nothing. Drive delivery from the
        // note that completed coverage instead: fan the start directive to every
        // local slot and across the mesh, exactly as a live announce's
        // completion does. The `|=` keeps every remaining slot seeded into the
        // live set after coverage latches, since only the first covering note
        // returns true.
        let mut reconcile_started_session = false;
        for slot in registered_slots {
            reconcile_started_session |=
                consensus::note_slot_present(&self.decision_makers, &key, slot);
        }
        if reconcile_started_session {
            crate::routing::deliver_session_start(
                &self.sessions,
                &self.decision_makers,
                &self.mesh_links,
                &key,
            );
        }
        // A descriptor push that promotes this relay to authority (the
        // coordinator dropped the former authority from the order) may make this
        // relay the one to observe full slot presence — re-evaluate and fire the
        // session-start directive if the accumulated live slots already cover the
        // expected set.
        crate::routing::maybe_start_session(
            &self.sessions,
            &self.decision_makers,
            &self.mesh_links,
            &key,
        );

        let mut inner = self.inner.lock();

        // Remember each named peer's contact details — address plus the enrolled
        // cert a dial pins — so the desired-peer set published for the dialer can
        // carry them (a relay never dials itself).
        for peer in &descriptor.peers {
            if peer.relay_id != self.our_id {
                inner.peer_contacts.insert(
                    peer.relay_id,
                    PeerContact {
                        addr: peer.relay_addr,
                        addrs: peer.relay_addrs.clone(),
                        cert_der: peer.cert_der.clone(),
                    },
                );
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
        // gone and the gate retired, no descriptor will ever drain them.
        if let Some(turn_path) = &self.turn_path {
            turn_path.provisional_turns.discard(key);
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, DepartedSlot, DepartureKind, RelayPeer, SlotExternalRef, TenantId,
    };
    use rally_point_proto::ids::{SessionId, SlotId};

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
            cert_der: vec![id as u8; 4],
            relay_addrs: vec![],
        }
    }

    fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            finalized_drops: false,
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
            peers: peers.iter().map(|&id| relay_peer(id)).collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: None,
            relay_regions: Vec::new(),
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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        let _ = control.register_link(RelayId(3), 1, tx3);

        control.apply_descriptor(&descriptor(1, &[2, 3]));

        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn joins_only_named_peers_never_broadcasts() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        let _ = control.register_link(RelayId(3), 1, tx3);

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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());

        // The descriptor names peer 2, but its link has not established yet.
        control.apply_descriptor(&descriptor(1, &[2]));

        // The link establishes — the deferred join fires now.
        let (tx2, mut rx2) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn re_applied_descriptor_leaves_a_dropped_peer() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        let _ = control.register_link(RelayId(3), 1, tx3);

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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let (tx3, mut rx3) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        let _ = control.register_link(RelayId(3), 1, tx3);

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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);
        // Never applied a descriptor for session 9.
        control.end_session(&key(9));
        assert!(rx2.try_recv().is_err());
    }

    #[test]
    fn reconnect_replaces_sender_and_rejoins_desired_sessions() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2_old, mut rx2_old) = link();
        let _ = control.register_link(RelayId(2), 1, tx2_old);
        control.apply_descriptor(&descriptor(1, &[2]));
        assert_eq!(rx2_old.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // The link to peer 2 drops and reconnects: a new sender registers under
        // the same id, and the desired session re-joins on it.
        let (tx2_new, mut rx2_new) = link();
        let _ = control.register_link(RelayId(2), 2, tx2_new);
        assert_eq!(rx2_new.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn late_older_registration_cannot_replace_or_resurrect_after_the_new_link_dies() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        control.apply_descriptor(&descriptor(1, &[2]));

        let (old_tx, mut old_rx) = link();
        assert!(control.register_link(RelayId(2), 10, old_tx));
        assert_eq!(old_rx.try_recv().unwrap(), MeshCommand::Join(key(1)));

        let (new_tx, mut new_rx) = link();
        assert!(control.register_link(RelayId(2), 20, new_tx));
        assert_eq!(new_rx.try_recv().unwrap(), MeshCommand::Join(key(1)));

        let (late_tx, mut late_rx) = link();
        assert!(!control.register_link(RelayId(2), 10, late_tx));
        control.apply_descriptor(&descriptor(2, &[2]));
        assert_eq!(new_rx.try_recv().unwrap(), MeshCommand::Join(key(2)));
        assert!(late_rx.try_recv().is_err());

        // Make the current sender fail so reconcile removes it, then prove the
        // retained generation tombstone still rejects E1.
        drop(new_rx);
        control.apply_descriptor(&descriptor(3, &[2]));
        let (resurrect_tx, mut resurrect_rx) = link();
        assert!(!control.register_link(RelayId(2), 10, resurrect_tx));
        assert!(resurrect_rx.try_recv().is_err());
    }

    #[test]
    fn drops_a_descriptor_self_reference() {
        // A descriptor that erroneously lists this relay among its own peers
        // must not produce a self-join — a relay never meshes with itself.
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx1, mut rx1) = link();
        // Even if a link were somehow registered under our own id, we don't join.
        let _ = control.register_link(RelayId(1), 1, tx1);
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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);

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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2, mut rx2) = link();
        let _ = control.register_link(RelayId(2), 1, tx2);

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
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let (tx2_dead, rx2_dead) = link();
        let _ = control.register_link(RelayId(2), 1, tx2_dead);
        drop(rx2_dead); // the driver exited; the channel is now closed

        // Applying a descriptor tries to join over the dead link and fails; the
        // link is dropped, but the desired membership is kept.
        control.apply_descriptor(&descriptor(1, &[2]));

        // The peer reconnects: a fresh link registers and the kept intent
        // re-joins on it.
        let (tx2_new, mut rx2_new) = link();
        let _ = control.register_link(RelayId(2), 2, tx2_new);
        assert_eq!(rx2_new.try_recv().unwrap(), MeshCommand::Join(key(1)));
    }

    #[test]
    fn apply_descriptor_publishes_desired_peers_with_addresses() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let mut peers_rx = control.desired_peers();
        assert!(peers_rx.borrow_and_update().is_empty());

        control.apply_descriptor(&descriptor(1, &[2, 3]));

        assert!(peers_rx.has_changed().unwrap());
        let published = peers_rx.borrow_and_update().clone();
        assert_eq!(published.len(), 2);
        // Sorted by id, each carrying the address and pinned cert the
        // descriptor named — the cert is what the dialer's trust config pins.
        assert_eq!(published[0].relay_id, RelayId(2));
        assert_eq!(
            published[0].relay_addr,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14902))
        );
        assert_eq!(published[0].cert_der, vec![2u8; 4]);
        assert_eq!(published[1].relay_id, RelayId(3));
        assert_eq!(published[1].cert_der, vec![3u8; 4]);
    }

    #[test]
    fn ending_a_session_republishes_the_shrunk_peer_set() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let mut peers_rx = control.desired_peers();
        control.apply_descriptor(&descriptor(1, &[2]));
        peers_rx.borrow_and_update();

        control.end_session(&key(1));
        assert!(peers_rx.has_changed().unwrap());
        assert!(peers_rx.borrow_and_update().is_empty());
    }

    #[test]
    fn a_self_reference_is_not_published_as_a_desired_peer() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
        let mut peers_rx = control.desired_peers();
        // The descriptor erroneously lists this relay (1) among its own peers.
        control.apply_descriptor(&descriptor(1, &[1, 2]));
        let published = peers_rx.borrow_and_update().clone();
        assert_eq!(published.len(), 1, "a relay never dials itself");
        assert_eq!(published[0].relay_id, RelayId(2));
    }

    #[test]
    fn an_unchanged_peer_set_does_not_republish() {
        let control = MeshControl::new(RelayId(1), Arc::default(), Arc::default());
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
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

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
    fn apply_descriptor_stamps_correlation_ids_that_a_departure_notice_carries() {
        // End to end through the production apply path: a descriptor carrying
        // the tenant's correlation ids, applied, must leave the registry able
        // to stamp them into a departure notice -- without depending on the
        // coordinator's in-memory session-refs store surviving to notice time.
        let makers = Arc::new(consensus::new_decision_makers());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

        let mut descriptor = descriptor(1, &[]);
        descriptor.external_id = Some("game-42".to_owned());
        descriptor.slot_refs = vec![SlotExternalRef {
            slot: SlotId(0),
            external_ref: "sb-user-3".to_owned(),
        }];
        control.apply_descriptor(&descriptor);

        consensus::observe_frame(
            &makers,
            &key(1),
            SlotId(1),
            rally_point_proto::ids::GameFrameCount(10),
        );
        assert!(
            consensus::decide_leave(&makers, &key(1), SlotId(0), 0x4000_0006).is_some(),
            "single-relay session is its own authority, so decide_leave succeeds",
        );

        let consensus::RelayNotice::Departure(notice) =
            rx.try_recv().expect("one departure notice")
        else {
            panic!("a departure notice");
        };
        assert_eq!(notice.external_id, Some("game-42".to_owned()));
        assert_eq!(notice.external_ref, Some("sb-user-3".to_owned()));
    }

    #[test]
    fn apply_descriptor_replaces_correlation_ids_on_a_changed_reapply() {
        let makers = Arc::new(consensus::new_decision_makers());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

        let mut first = descriptor(1, &[]);
        first.external_id = Some("game-old".to_owned());
        control.apply_descriptor(&first);

        let mut second = descriptor(1, &[]);
        second.external_id = Some("game-new".to_owned());
        control.apply_descriptor(&second);

        consensus::observe_frame(
            &makers,
            &key(1),
            SlotId(1),
            rally_point_proto::ids::GameFrameCount(10),
        );
        assert!(consensus::decide_leave(&makers, &key(1), SlotId(0), 0x4000_0006).is_some());
        let consensus::RelayNotice::Departure(notice) =
            rx.try_recv().expect("one departure notice")
        else {
            panic!("a departure notice");
        };
        assert_eq!(
            notice.external_id,
            Some("game-new".to_owned()),
            "the re-applied descriptor's refs replace the stale ones",
        );
    }

    #[test]
    fn authority_is_the_lowest_relay_id_serving_the_session() {
        // our_id 1, peer 2: we're the lowest, so we decide.
        let low = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), low.clone(), Arc::default());
        control.apply_descriptor(&descriptor(1, &[2]));
        assert!(
            low.lock().get(&key(1)).unwrap().is_authority(),
            "the lowest relay id is the authority",
        );

        // our_id 3, peer 2: the peer is lower, so it decides, not us.
        let high = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(3), high.clone(), Arc::default());
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
        let control = MeshControl::new(RelayId(2), makers.clone(), Arc::default());
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

    /// A descriptor carrying an explicit authority order, as a coordinator
    /// that assigns one sends.
    fn descriptor_with_order(session: u64, peers: &[u64], order: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            authority_order: order.iter().map(|&id| RelayId(id)).collect(),
            ..descriptor(session, peers)
        }
    }

    #[test]
    fn a_coordinator_assigned_order_overrides_id_order() {
        // our_id 1, peer 2. Id order would make us the authority; the
        // coordinator ranked relay 2 first (it is the session's home relay),
        // so relay 2 decides.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
        assert!(
            !makers.lock().get(&key(1)).unwrap().is_authority(),
            "the assigned order outranks the id-order fallback",
        );

        // The same relay ranked first decides, whatever its id.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(3), makers.clone(), Arc::default());
        control.apply_descriptor(&descriptor_with_order(1, &[2], &[3, 2]));
        assert!(
            makers.lock().get(&key(1)).unwrap().is_authority(),
            "the first relay in the assigned order decides",
        );
    }

    #[test]
    fn presence_hands_authority_off_between_descriptor_pushes() {
        // The handoff path with no coordinator involved: relay 2 heads the
        // order and decides; its players all leave; the presence report the
        // mesh driver records flips the verdict to us — no re-push needed.
        let makers = Arc::new(consensus::new_decision_makers());
        let presence_registry = Arc::new(presence::new_presence_registry());
        let control = MeshControl::new(RelayId(1), makers.clone(), presence_registry.clone());
        control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
        assert!(!makers.lock().get(&key(1)).unwrap().is_authority());

        // What the mesh-link driver does when relay 2's presence frame says
        // it no longer serves players.
        assert!(presence::record_peer(
            &presence_registry,
            &key(1),
            RelayId(2),
            0
        ));
        let _ = presence::recompute(
            &presence_registry,
            &makers,
            &key(1),
            &std::collections::HashSet::new(),
        );
        assert!(
            makers.lock().get(&key(1)).unwrap().is_authority(),
            "the authority's players leaving promotes the next relay in order",
        );

        // A later descriptor re-push must not resurrect relay 2's authority:
        // the verdict is recomputed against the *kept* presence reports.
        control.apply_descriptor(&descriptor_with_order(1, &[2], &[2, 1]));
        assert!(
            makers.lock().get(&key(1)).unwrap().is_authority(),
            "a re-push recomputes against known presence, not from scratch",
        );
    }

    #[test]
    fn a_resumed_descriptor_latches_started_and_seeds_departures() {
        // A rehome descriptor: it resumes an already-running session onto this fresh
        // relay, expecting slots {0, 1} with slot 1 already departed. The relay must
        // latch the session started (never wait on the full expected set, which lists
        // the departed slot that will never dial) and record the departure as already
        // decided.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1), SlotId(2)];
        desc.resumed = true;
        desc.departed_slots = vec![
            DepartedSlot {
                finalized: false,
                slot: SlotId(1),
                kind: DepartureKind::Left,
                final_turn_count: Some(240),
            },
            DepartedSlot {
                finalized: false,
                slot: SlotId(2),
                kind: DepartureKind::Dropped,
                // A drop count reaching a descriptor means the carrier ran code
                // predating the clean-leaves-only rule; the seed strips it.
                final_turn_count: Some(99),
            },
        ];
        control.apply_descriptor(&desc);

        {
            let registry = makers.lock();
            let maker = registry.get(&key(1)).expect("a maker was created");
            assert!(
                maker.is_authority(),
                "a single-relay rehome session is its own authority",
            );
            assert!(
                maker.is_started(),
                "a resumed descriptor latches the session started",
            );
            assert!(
                !maker.has_undecided_departure(),
                "the seeded departures are recorded as already decided",
            );
        }
        let (_, directives) = consensus::leave_reconcile(&makers, &key(1));
        assert!(
            directives
                .iter()
                .any(|l| l.slot == 1 && l.final_turn_count == Some(240)),
            "the seeded clean-leave directive a reconnecting survivor replays \
             carries the coordinator-retained count",
        );
        assert!(
            directives
                .iter()
                .any(|l| l.slot == 2 && l.final_turn_count.is_none()),
            "the seeded dropped directive's unsound count is stripped at ingress",
        );

        // Because the session is already started, a slot registering does not fire a
        // fresh session-wide start (the authority never re-covers the expected set).
        assert!(
            !consensus::note_slot_present(&makers, &key(1), SlotId(0)),
            "an already-started session fires no fresh session-wide start directive",
        );
    }

    /// A client admitted before its session's descriptor (provisional
    /// admission) performs its one leave reconciliation at registration, when
    /// there is nothing to reconcile. The resumed descriptor's seeded
    /// departures must therefore be *pushed* to it when they are seeded —
    /// otherwise it plays on forever, stalled on the departed slot's turns
    /// that will never come.
    #[tokio::test]
    async fn a_resumed_descriptor_fans_seeded_leaves_to_already_connected_survivors() {
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_links.clone());

        // The survivor — and the departed subject itself — both admitted
        // before any descriptor arrived (provisional admission).
        let (_reg, mut inbox) = crate::routing::register(&sessions, &key(1), SlotId(0)).unwrap();
        let (_subject_reg, subject_inbox) =
            crate::routing::register(&sessions, &key(1), SlotId(1)).unwrap();
        let subject_shutdown = subject_inbox.shutdown_handle();

        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        desc.resumed = true;
        desc.departed_slots = vec![DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Left,
            final_turn_count: Some(64),
        }];
        control.apply_descriptor(&desc);

        let leave = inbox
            .try_recv_leave()
            .expect("the seeded leave is pushed to the already-connected survivor");
        assert_eq!(leave.slot, 1);
        assert_eq!(leave.final_turn_count, Some(64));
        // The subject's live provisional link is signaled closed: its leave is
        // decided, so nothing it sends is part of the game any more (and the
        // home-ingress turn fence drops whatever it manages to send first).
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            subject_shutdown.notified(),
        )
        .await
        .expect("the seeded departed subject's link is signaled to close");

        // The idempotent descriptor replay re-decides nothing, so nothing is
        // re-pushed either (the client would dedup it by slot regardless).
        control.apply_descriptor(&desc);
        assert_eq!(inbox.try_recv_leave(), None);
    }

    /// On a coordinator-managed relay (pen armed), a turn arriving before any
    /// descriptor names its session is held, not fanned out — and descriptor
    /// application drains it through the ordinary forward path, where a
    /// current slot's turn reaches the survivors exactly as if it had arrived
    /// a moment later.
    #[test]
    fn a_pre_descriptor_turn_is_held_and_drained_current_by_the_descriptor() {
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_state = crate::mesh::MeshState {
            decision_makers: makers.clone(),
            ..crate::mesh::new_mesh_state()
        };
        mesh_state.provisional_turns.arm();
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_state.links.clone())
            .with_turn_path(mesh_state.clone());

        let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0)).unwrap();
        crate::mesh::forward_client_turn(
            &sessions,
            &mesh_state,
            &key(1),
            SlotId(1),
            rally_point_proto::messages::Payload {
                seq: 0,
                slot: 1,
                commands: vec![0x05].into(),
                ..Default::default()
            },
        );
        assert!(
            survivor.try_recv_forward().is_none(),
            "a pre-descriptor turn is held, not fanned out",
        );
        assert_eq!(mesh_state.provisional_turns.held(&key(1)), 1);

        control.apply_descriptor(&descriptor(1, &[]));
        assert!(
            survivor.try_recv_forward().is_some(),
            "the descriptor drains the held turn to the survivor",
        );
        assert_eq!(mesh_state.provisional_turns.held(&key(1)), 0);
    }

    /// The drain runs AFTER a resumed descriptor's departure seeding, so a
    /// slot the descriptor reveals as already departed has its held turns die
    /// at the decided-leave fence instead of reaching co-admitted survivors —
    /// the exact post-count ingress the pen exists to close.
    #[test]
    fn a_seeded_departed_slots_held_turns_die_at_the_fence() {
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_state = crate::mesh::MeshState {
            decision_makers: makers.clone(),
            ..crate::mesh::new_mesh_state()
        };
        mesh_state.provisional_turns.arm();
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_state.links.clone())
            .with_turn_path(mesh_state.clone());

        let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0)).unwrap();
        // The departed subject dials provisionally and originates a turn past
        // its sealed count before the descriptor lands.
        crate::mesh::forward_client_turn(
            &sessions,
            &mesh_state,
            &key(1),
            SlotId(1),
            rally_point_proto::messages::Payload {
                seq: 64,
                slot: 1,
                commands: vec![0x05].into(),
                ..Default::default()
            },
        );
        assert!(survivor.try_recv_forward().is_none());

        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        desc.resumed = true;
        desc.departed_slots = vec![DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Left,
            final_turn_count: Some(64),
        }];
        control.apply_descriptor(&desc);

        assert!(
            survivor.try_recv_leave().is_some(),
            "the seeded leave reaches the survivor",
        );
        assert!(
            survivor.try_recv_forward().is_none(),
            "the departed slot's held turn dies at the fence, never fanned",
        );
        assert_eq!(mesh_state.provisional_turns.held(&key(1)), 0);
    }

    /// A clean leave that lands before the session's descriptor is journaled,
    /// not lost: the drain replays it into the freshly created maker, ordered
    /// after the slot's own journaled turns, and derives the exact final turn
    /// count over exactly those turns — so the departure is recorded, the
    /// leave decided, and survivors never stall on an expected-but-absent
    /// slot waiting for the coordinator's holdout reap.
    #[test]
    fn a_pre_descriptor_clean_leave_is_journaled_and_drained_with_its_count() {
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_state = crate::mesh::MeshState {
            decision_makers: makers.clone(),
            ..crate::mesh::new_mesh_state()
        };
        mesh_state.provisional_turns.arm();
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_state.links.clone())
            .with_turn_path(mesh_state.clone());

        let (_reg, mut survivor) = crate::routing::register(&sessions, &key(1), SlotId(0)).unwrap();
        // The leaver plays two framed turns and cleanly leaves, all before the
        // descriptor arrives — everything lands in the journal.
        for seq in 0..2 {
            crate::mesh::forward_client_turn(
                &sessions,
                &mesh_state,
                &key(1),
                SlotId(1),
                rally_point_proto::messages::Payload {
                    seq,
                    slot: 1,
                    game_frame_count: Some(40 + seq as u32),
                    commands: vec![0x05].into(),
                    ..Default::default()
                },
            );
        }
        let announced = mesh_state.gates.with_ingress(&key(1), || {
            crate::routing::announce_departure(
                &mesh_state.drop_holds,
                &makers,
                &sessions,
                &mesh_state.links,
                &mesh_state.provisional_turns,
                &key(1),
                SlotId(1),
                consensus::LEAVE_REASON_LEFT,
                // Deposit-time count: blind to the journaled turns; the drain
                // must recompute it, not trust this.
                None,
                Some(7),
            )
        });
        assert_eq!(
            announced,
            Some(true),
            "the pre-descriptor leave is journaled"
        );
        assert!(
            survivor.try_recv_forward().is_none(),
            "nothing fanned before the descriptor",
        );
        assert!(
            !consensus::slot_departed(&makers, &key(1), SlotId(1)),
            "nothing recorded before the descriptor",
        );

        control.apply_descriptor(&descriptor(1, &[]));

        assert!(survivor.try_recv_forward().is_some());
        assert!(
            survivor.try_recv_forward().is_some(),
            "both journaled turns reach the survivor",
        );
        let leave = survivor
            .try_recv_leave()
            .expect("the drained departure decides the leave");
        assert_eq!(leave.reason, consensus::LEAVE_REASON_LEFT);
        assert_eq!(
            leave.final_turn_count,
            Some(2),
            "the exact count is derived at the drain, over the drained turns",
        );
        assert!(consensus::slot_departed(&makers, &key(1), SlotId(1)));
    }

    /// A descriptor push is routinely an idempotent replay (a coordinator
    /// reconnect re-pushes every current descriptor), so it must NOT clear a
    /// close seal: a closed-but-not-yet-retired session's seal is exactly what
    /// keeps a straggling mesh event from conjuring an empty replacement
    /// recording that would displace the real stored one.
    #[test]
    fn a_descriptor_replay_does_not_unseal_a_closed_flight_recording() {
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        let desc = descriptor(1, &[]);
        control.apply_descriptor(&desc);

        let recorder = makers.flight_recorder();
        recorder.record(
            &key(1),
            crate::flight_recorder::FlightEvent::SlotConnected {
                slot: 0,
                resumed: false,
            },
        );
        // The session's close flush: removes the recording and seals the key
        // (outside a runtime the detached flush discards synchronously).
        recorder.flush_session_detached(&key(1), true);

        // The coordinator reconnects and replays the unchanged descriptor.
        control.apply_descriptor(&desc);

        // A straggling mesh event must still be dropped, not begin a
        // replacement recording.
        recorder.record(
            &key(1),
            crate::flight_recorder::FlightEvent::DropHeld { slot: 1 },
        );
        assert!(
            recorder.recorded_sessions().is_empty(),
            "the replayed descriptor left the close seal in place",
        );

        // Retirement is what clears it; a genuine re-serve records again.
        control.end_session(&key(1));
        recorder.record(
            &key(1),
            crate::flight_recorder::FlightEvent::SlotConnected {
                slot: 0,
                resumed: true,
            },
        );
        assert_eq!(recorder.recorded_sessions(), vec![key(1)]);
    }

    /// Descriptor retirement is terminal for the session's drop bookkeeping:
    /// held (undecided) drops and any armed abandon timer must be swept with
    /// it, or they leak forever — the timer's expiry stands down on the
    /// forgotten presence without releasing anything, and no owner remains to
    /// clean the hold entries.
    #[tokio::test]
    async fn end_session_sweeps_undecided_holds_and_the_abandon_timer() {
        let holds = DropHolds::new(
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(3600),
        );
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_drop_holds(holds.clone());
        control.apply_descriptor(&descriptor(1, &[]));

        holds.hold(key(1), SlotId(0));
        holds
            .arm_abandon(key(1), |_| {})
            .expect("the abandon timer arms");

        control.end_session(&key(1));

        assert!(
            !holds.is_pending(&key(1), SlotId(0)),
            "the undecided hold is swept by retirement",
        );
        assert!(
            !holds.abandon_armed(&key(1)),
            "the abandon timer is cancelled by retirement",
        );
    }

    #[test]
    fn a_non_resumed_descriptor_leaves_the_session_not_started() {
        // The ordinary (non-rehome) path: without `resumed`, the session is not
        // latched started, so the normal start-on-coverage flow still governs it.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        control.apply_descriptor(&desc);
        let registry = makers.lock();
        assert!(
            !registry.get(&key(1)).unwrap().is_started(),
            "a fresh descriptor does not latch the session started",
        );
    }

    #[test]
    fn a_descriptor_reconciles_dials_that_raced_it_and_starts_the_session() {
        // Both of a two-player single-relay session's clients dial and register
        // before the coordinator's descriptor applies. Each slot's link task
        // announces its presence while the session has no maker yet, so the
        // announce finds nothing to record and the presence is dropped. The
        // descriptor must reconcile the roster it already holds into the maker it
        // creates, reach coverage, and deliver the start directive to the
        // connected clients.
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_links = crate::mesh::new_mesh_links();

        // Seat slots {0, 1} in the roster, as registration does before a link
        // task runs — hold the guards and inboxes so the slots stay registered
        // and the delivered start directive can be observed.
        let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0))
            .expect("slot 0 registers into an empty roster");
        let (_reg1, mut inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1))
            .expect("slot 1 registers into an empty roster");

        // Each slot's announce raced ahead of the descriptor: with no maker yet,
        // `note_slot_present` takes its no-maker path and reports no start, so the
        // presence is dropped.
        assert!(
            !consensus::note_slot_present(&makers, &key(1), SlotId(0)),
            "an announce with no maker yet drops the presence and fires no start",
        );
        assert!(
            !consensus::note_slot_present(&makers, &key(1), SlotId(1)),
            "an announce with no maker yet drops the presence and fires no start",
        );

        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_links);
        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        control.apply_descriptor(&desc);

        assert!(
            makers.lock().get(&key(1)).unwrap().is_started(),
            "the descriptor reconciles the already-registered roster and covers the expected set",
        );
        // The start directive reached both connected clients, not merely the
        // maker's latch — the fix must fan the directive, not just flip the flag.
        assert!(
            inbox0.try_recv_start().is_some(),
            "slot 0's connected client receives the start directive",
        );
        assert!(
            inbox1.try_recv_start().is_some(),
            "slot 1's connected client receives the start directive",
        );
    }

    #[test]
    fn a_reconcile_over_a_partial_roster_waits_for_the_late_slot() {
        // Only slot 0 raced the descriptor; slot 1 has not dialed yet. The
        // reconcile must not start the session on the partial roster — the
        // session starts only once slot 1 later announces.
        let makers = Arc::new(consensus::new_decision_makers());
        let sessions = Sessions::default();
        let mesh_links = crate::mesh::new_mesh_links();

        let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0))
            .expect("slot 0 registers into an empty roster");
        assert!(
            !consensus::note_slot_present(&makers, &key(1), SlotId(0)),
            "slot 0's announce with no maker yet drops the presence",
        );

        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default())
            .with_broadcast(sessions.clone(), mesh_links);
        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        control.apply_descriptor(&desc);

        assert!(
            !makers.lock().get(&key(1)).unwrap().is_started(),
            "a reconcile over a partial roster does not start the session",
        );
        assert!(
            inbox0.try_recv_start().is_none(),
            "no start directive is delivered before the expected set is covered",
        );

        // Slot 1 dials and announces after the descriptor applied: this completes
        // the expected set and starts the session, exactly as the live announce
        // path does. No premature start came from the reconcile.
        let (_reg1, _inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1))
            .expect("slot 1 registers after the descriptor applied");
        assert!(
            consensus::note_slot_present(&makers, &key(1), SlotId(1)),
            "slot 1's announce completes the expected set and fires the start",
        );
        assert!(
            makers.lock().get(&key(1)).unwrap().is_started(),
            "the session is started once slot 1 arrives",
        );
    }

    #[test]
    fn a_leave_decision_lands_in_the_flight_recorder() {
        // The consensus-side flight tap, through the production decide path: a
        // decided synced leave records its event (slot, kind, apply coordinates)
        // into the session's recording.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        control.apply_descriptor(&descriptor(1, &[])); // single relay: self-authority

        consensus::observe_frame(
            &makers,
            &key(1),
            SlotId(1),
            rally_point_proto::ids::GameFrameCount(10),
        );
        assert!(consensus::decide_leave(&makers, &key(1), SlotId(0), 0x4000_0006).is_some());

        let events: Vec<_> = makers
            .flight_recorder()
            .events(&key(1))
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            events.iter().any(|e| matches!(
                e,
                crate::flight_recorder::FlightEvent::LeaveDecided {
                    slot: 0,
                    kind: DepartureKind::Dropped,
                    ..
                }
            )),
            "the decided leave is recorded: {events:?}",
        );
    }

    #[test]
    fn a_resumed_descriptor_apply_lands_in_the_flight_recorder() {
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        desc.resumed = true;
        desc.departed_slots = vec![DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Dropped,
            final_turn_count: None,
        }];
        control.apply_descriptor(&desc);

        let events: Vec<_> = makers
            .flight_recorder()
            .events(&key(1))
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            events.contains(
                &crate::flight_recorder::FlightEvent::ResumedDescriptorApplied {
                    departed_slots: 1
                }
            ),
            "the re-home landing is recorded: {events:?}",
        );
    }

    #[test]
    fn end_session_destroys_the_maker() {
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());

        control.apply_descriptor(&descriptor(1, &[]));
        assert!(makers.lock().contains_key(&key(1)));

        control.end_session(&key(1));
        assert!(
            !makers.lock().contains_key(&key(1)),
            "ending the session drops its maker, even with no mesh peers",
        );
    }

    #[test]
    fn e2e_delivery_inputs_add_at_most_the_capped_cushion_and_respect_bounds() {
        use crate::delivery::{DeliveryHome, E2E_LAG_CUSHION_CAP_TURNS, EXTRA_HOP_CUSHION_TURNS};
        use rally_point_proto::ids::GameFrameCount;
        use rally_point_proto::messages::{LinkConditions, SlotConditions};

        let conditions = LinkConditions {
            slots: vec![SlotConditions {
                slot: 0,
                rtt_us: 150_000,
                lost_packets: 0,
                sent_packets: 100,
                connection_epoch: None,
            }],
        };

        // Wide bounds so the cushion's own caps are what bounds the outcome.
        // The malicious case: a cross-relay destination understating its cursor
        // by miles. The law's 150ms baseline is 4 turns (see the sibling test);
        // the delivery inputs may add AT MOST one hop turn plus the capped lag
        // term — never more, however absurd the claimed lag.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        let mut desc = descriptor(1, &[]);
        desc.bounds = BufferBounds::new(1, 20).unwrap();
        control.apply_descriptor(&desc);

        consensus::observe_turn_frame(
            &makers,
            &key(1),
            SlotId(0),
            100_000, // the origin's newest seq, miles past the claimed cursor
            GameFrameCount(1),
            DeliveryHome::Local,
        );
        consensus::observe_delivery(
            &makers,
            &key(1),
            SlotId(1),
            SlotId(0),
            0, // the wildly understated claim
            DeliveryHome::Peer(RelayId(9)),
        );

        let decision = consensus::ingest_local_conditions(&makers, &key(1), &conditions)
            .expect("a raise fires on the first high-RTT sample");
        assert_eq!(
            decision.buffer.0,
            4 + EXTRA_HOP_CUSHION_TURNS + E2E_LAG_CUSHION_CAP_TURNS,
            "the cushion saturates at its caps, however large the claimed lag",
        );

        // The same inputs under tight bounds: the existing BufferBounds clamp
        // still has the last word.
        let makers = Arc::new(consensus::new_decision_makers());
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        control.apply_descriptor(&descriptor(1, &[])); // bounds (1, 6)
        consensus::observe_turn_frame(
            &makers,
            &key(1),
            SlotId(0),
            100_000,
            GameFrameCount(1),
            DeliveryHome::Local,
        );
        consensus::observe_delivery(
            &makers,
            &key(1),
            SlotId(1),
            SlotId(0),
            0,
            DeliveryHome::Peer(RelayId(9)),
        );
        let decision = consensus::ingest_local_conditions(&makers, &key(1), &conditions)
            .expect("a raise fires");
        assert_eq!(
            decision.buffer.0, 6,
            "the cushion never escapes the session's BufferBounds",
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
        let control = MeshControl::new(RelayId(1), makers.clone(), Arc::default());
        control.apply_descriptor(&descriptor(1, &[])); // bounds (1, 6), SelfRelay

        consensus::observe_frame(&makers, &key(1), SlotId(0), GameFrameCount(1));
        let conditions = LinkConditions {
            slots: vec![SlotConditions {
                slot: 0,
                rtt_us: 150_000,
                lost_packets: 0,
                sent_packets: 100,
                connection_epoch: None,
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
