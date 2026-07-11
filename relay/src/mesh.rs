//! The relay mesh: peer-relay links and session-level topological dedup.
//!
//! A relay's client edge ([`routing`]) fans each validated turn out to the
//! session's local slots. The mesh adds a second fan-out path: to connected peer
//! relays, so a turn one relay receives from a local client reaches every other
//! relay's local clients too. Each relay↔relay link is a [`MeshLink`] — one QUIC
//! connection shared across every game both relays jointly serve, with per-session
//! transport state.
//!
//! Because a turn can reach a relay by more than one mesh path (A→B directly, and
//! A→C→B), the relay dedups **topologically**: it forwards each turn to its local
//! clients exactly once, on whichever copy arrives first. [`MeshSeen`] is that
//! session-level dedup — distinct from the per-link [`Dedup`] on each mesh link,
//! which drops redundant copies *within* one link. The origin `(slot, seq)`
//! identity is stable across the mesh because no hop restamps it, so the two
//! dedup layers collapse duplicates at different granularities without conflict.
//!
//! Mesh-link establishment uses a lower-id-dials-higher tie-break
//! ([`should_dial_mesh`](rally_point_transport::should_dial_mesh)): each relay
//! compares its own id to the peer's configured id and dials only when it is the
//! lower, so exactly one side connects and there is no two-way race to resolve
//! on the wire. Authenticated relay tokens and tenant binding land with the
//! coordinator (Phase 3); this increment has no auth token.

use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rally_point_proto::control::ResultEcho;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{
    GameChat, LeaveDirective, LinkConditions, LobbyCommand, MeshControlFrame, Payload, RequestDrop,
    SessionStart, SlotConditions, SlotConnectivity, SlotDeparted, SlotPresent, mesh_control_frame,
};
use tokio::sync::mpsc;

use crate::routing::{self, SessionKey};

/// Session-level topological dedup: records which `(slot, seq)` turns have
/// already been forwarded to this session's local clients, so a turn arriving
/// via a second mesh path is dropped rather than delivered twice.
///
/// Mirrors the per-link `Dedup`'s structure (a contiguous delivered prefix plus
/// an `ahead` set per slot) but serves a different purpose: `Dedup` is
/// receive-side (it gates delivery to the link's consumer), while `MeshSeen` is
/// forward-gate-side (it gates fan-out to local clients). It has no receive
/// window — a turn far ahead of the prefix is simply new, not rejected — because
/// the mesh trusts its peer relays and the origin seqs are client-assigned.
///
/// The prefix-slide lets it forget old seqs without unbounded growth: a late
/// redundant copy of a retired seq is dropped as `<= delivered_through` rather
/// than re-checked against a growing set.
#[derive(Default)]
pub struct MeshSeen {
    /// Per-slot forward-gate state.
    slots: HashMap<SlotId, SlotSeen>,
}

/// One slot's topological-dedup state.
struct SlotSeen {
    /// Top of the contiguous forwarded prefix; `None` until seq 0 is forwarded.
    forwarded_through: Option<u64>,
    /// Forwarded seqs above the prefix, kept until the gaps below them fill.
    /// Mirrors `Dedup::SlotDedup::ahead` so out-of-order mesh arrival doesn't
    /// cause a false "new" on a seq that was already forwarded out of order.
    ahead: BTreeSet<u64>,
}

/// Whether a `(slot, seq)` has already been forwarded to local clients.
#[derive(Debug, PartialEq, Eq)]
pub enum Seen {
    /// First time this `(slot, seq)` has been forwarded — deliver it to locals.
    New,
    /// Already forwarded (at/below the contiguous prefix, or seen out of order).
    Duplicate,
}

impl MeshSeen {
    /// Creates an empty topological-dedup set for one session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `(slot, seq)` as forwarded and reports whether it's new or a
    /// duplicate. A duplicate is dropped silently — the turn already reached
    /// this relay's local clients via an earlier mesh path.
    pub fn mark_forwarded(&mut self, slot: SlotId, seq: u64) -> Seen {
        let state = self.slots.entry(slot).or_insert_with(|| SlotSeen {
            forwarded_through: None,
            ahead: BTreeSet::new(),
        });

        let base = state.forwarded_through.map_or(0, |t| t + 1);

        if seq < base {
            return Seen::Duplicate;
        }
        if !state.ahead.insert(seq) {
            return Seen::Duplicate;
        }

        // Absorb any now-contiguous run into the forwarded prefix, so old seqs
        // can be forgotten.
        let mut next = base;
        while state.ahead.remove(&next) {
            state.forwarded_through = Some(next);
            next += 1;
        }
        Seen::New
    }
}

/// Per-session topological-dedup registries: each `SessionKey` → the `MeshSeen`
/// for that session, shared across all slot links + mesh-link tasks so every
/// ingress — local client or mesh peer — marks before forwarding to locals.
///
/// This is the guard against echo loops: a turn relay A fanned out to relay B
/// comes back to A via the mesh, and without a shared `MeshSeen` A would deliver
/// it to its local clients a second time — a duplicate turn into a lockstep slot,
/// a desync. With the registry, A's `run_slot_link` marked the turn when it
/// validated it, so the mesh echo is caught as `Duplicate` and dropped.
pub type SeenRegistries = Arc<Mutex<HashMap<SessionKey, MeshSeen>>>;

/// Creates an empty seen-registry for a relay with no sessions yet.
pub fn new_seen_registries() -> SeenRegistries {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Marks `(slot, seq)` as forwarded for `key`'s session, returning whether it's
/// new or a duplicate. Used by both `run_slot_link` (local-client ingress) and
/// `run_mesh_link` (mesh-peer ingress) before fanning out to local clients.
pub fn mark_seen(registries: &SeenRegistries, key: &SessionKey, slot: SlotId, seq: u64) -> Seen {
    let mut roster = registries.lock();
    roster
        .entry(key.clone())
        .or_default()
        .mark_forwarded(slot, seq)
}

/// Removes a session's seen registry (the session has ended). Idempotent.
pub fn deregister_seen(registries: &SeenRegistries, key: &SessionKey) {
    let mut roster = registries.lock();
    roster.remove(key);
}

/// Live mesh links for every session on this relay: each `SessionKey` → the
/// channels that reach each connected peer-relay's mesh-link task for that
/// session. A turn fanned out to the mesh goes to every peer relay serving that
/// session — including the one it arrived from, which is why the sender marks
/// `MeshSeen` before forwarding to locals: the echo is caught and dropped there.
///
/// Each link registers a [`MeshLinkTx`] bundling two senders into the same driver:
/// the bounded per-turn forward channel and the unbounded control-frame channel
/// (synced-leave propagation). Bundling them means a session's registration —
/// created on `Join`, torn down on `Leave` or driver exit — governs both together.
///
/// Shared across all connection + mesh-link tasks. A plain (non-async) mutex is
/// deliberate: every critical section is a short, await-free roster edit —
/// senders are cloned out before any send — so the lock is never held across a
/// turn's delivery, mirroring [`routing::Sessions`].
pub type MeshLinks = Arc<Mutex<HashMap<SessionKey, Vec<MeshLinkTx>>>>;

/// Creates an empty mesh-link registry for a relay with no peer-relay links yet.
/// Used by the server edge and tests to obtain a `MeshLinks` without referencing
/// the private `MeshForwardTx` type.
pub fn new_mesh_links() -> MeshLinks {
    Arc::new(Mutex::new(HashMap::new()))
}
/// Per-session, per-slot network conditions a relay's home-client links
/// observe, gathered for the latency-buffer decision-maker. Each
/// `run_slot_link` task publishes its own client's quinn path stats here;
/// `run_mesh_link` snapshots the session's slots to build the outgoing
/// [`LinkConditions`] sidecar on each forwarded datagram.
///
/// Outgoing-only: the relay reports its *own* home clients' conditions. It does
/// not store conditions received from peer relays — those ride the peer's own
/// origin datagrams to the decision-maker, and storing them here would add a
/// stale-conditions correctness surface for a consumer (the decision-maker) that
/// is not yet built. The mesh-link driver traces incoming conditions
/// for observability but does not persist them.
///
/// A plain (non-async) mutex mirrors [`MeshLinks`] and [`routing::Sessions`]:
/// every critical section is a short, await-free slot edit or a snapshot clone,
/// so the lock is never held across a turn's delivery.
pub type ConditionsRegistry = Arc<Mutex<HashMap<SessionKey, HashMap<SlotId, SlotConditions>>>>;

/// Creates an empty conditions registry for a relay with no sessions yet.
pub fn new_conditions_registry() -> ConditionsRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}
/// Publishes `conditions` for `key`'s `slot`, replacing any prior sample for
/// that slot. Called by `run_slot_link` after sampling its client's quinn path
/// stats. Idempotent in the sense that a re-publish overwrites the stale
/// sample — conditions are per-moment, and the latest is always what the
/// mesh attaches.
pub fn publish_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
    slot: SlotId,
    conditions: SlotConditions,
) {
    let mut roster = registry.lock();
    roster
        .entry(key.clone())
        .or_default()
        .insert(slot, conditions);
}

/// Removes `slot` from `key`'s conditions (the client disconnected). Idempotent.
/// Called by `run_slot_link` on exit so a departing client's stale stats don't
/// outlive its connection.
pub fn unpublish_conditions(registry: &ConditionsRegistry, key: &SessionKey, slot: SlotId) {
    let mut roster = registry.lock();
    if let Some(slots) = roster.get_mut(key) {
        slots.remove(&slot);
        if slots.is_empty() {
            roster.remove(key);
        }
    }
}

/// Snapshots all slot conditions published for `key`, as the [`LinkConditions`]
/// sidecar the mesh attaches to an outgoing datagram. Returns `None` when the
/// session has no published conditions (no local clients, or none have sampled
/// yet) — so an ack-only flush or a session with no local clients attaches no
/// sidecar, preserving the redundancy budget.
pub fn snapshot_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
) -> Option<LinkConditions> {
    let roster = registry.lock();
    roster.get(key).map(|slots| {
        let mut slots: Vec<SlotConditions> = slots.values().cloned().collect();
        // Stable order by slot so the sidecar is deterministic across samples
        // (the decision-maker diffs consecutive samples; a stable order makes
        // the diff unambiguous).
        slots.sort_by_key(|s| s.slot);
        LinkConditions { slots }
    })
}

/// The three mesh-related registries a relay thread needs: the live mesh links
/// (fan-out to peer relays), the session-level topological dedup (echo guard),
/// and the per-client conditions the mesh attaches to outgoing datagrams.
///
/// These are always created together, passed together, and used together, so
/// bundling them keeps the `serve` and `run_slot_link` signatures within the
/// argument-count the codebase holds elsewhere — no `#[allow(clippy::too_many_arguments)]`
/// needed. Clone the struct cheaply (each field is an `Arc`) to hand a copy to a
/// spawned task.
#[derive(Clone)]
pub struct MeshState {
    /// Channels to peer-relay mesh-link tasks, keyed by session.
    pub links: MeshLinks,
    /// Session-level topological dedup (echo guard).
    pub seen: SeenRegistries,
    /// Per-slot link conditions the mesh attaches to outgoing datagrams.
    pub conditions: ConditionsRegistry,
    /// Per-session latency-buffer decision-makers. The slot-link and mesh-link
    /// tasks feed conditions in (home-client stats directly, peer-relay stats off
    /// the mesh sidecar) and stamp the authority's buffer changes onto the turns
    /// they forward. `MeshControl` creates and destroys the makers as descriptors
    /// arrive and sessions end; sharing the registry here is what lets the turn
    /// path reach them. Bundled with the mesh registries because it has the same
    /// per-session lifecycle and is threaded through the same tasks.
    pub decision_makers: Arc<crate::consensus::DecisionMakers>,
    /// Per-session presence (the authority order plus who still serves live
    /// players), driving the buffer-authority verdict. The slot-link tasks
    /// report the local roster into it, the mesh-link drivers deliver peers'
    /// reports, and `MeshControl` sets the order from each descriptor. Same
    /// per-session lifecycle and task-threading as the registries above.
    pub presence: Arc<crate::presence::PresenceRegistry>,
    /// Per-session lobby-command fan-out and its ordered replay log. The
    /// slot-link tasks deliver their clients' lobby commands into it (and register
    /// each member for replay), and the mesh-link drivers deliver peers' lobby
    /// commands into it. Bundled here, not because it is a mesh concern, but
    /// because it has the same per-session lifecycle and is threaded through the
    /// same two tasks as the registries above. See [`crate::lobby`].
    pub lobby: crate::lobby::LobbyRegistry,
    /// Per-session game-chat fan-out. The mid-game counterpart to `lobby`: the
    /// slot-link tasks deliver their clients' chat messages into it (and
    /// register each member to receive others'), and the mesh-link drivers
    /// deliver peers' messages into it. No replay log — chat is ephemeral —
    /// but the same per-session lifecycle and task-threading as `lobby`. See
    /// [`crate::chat`].
    pub chat: crate::chat::ChatRegistry,
    /// Per-relay holds on dropped slots' synced-leave decisions, plus the
    /// per-requester rate cap on the manual drop requests that resolve them. A slot
    /// that dropped (its link died) has its departure recorded and announced
    /// immediately, but the decision to remove it from lockstep is held here
    /// indefinitely — made only when a surviving member's `RequestDrop` is honored
    /// past the unlock floor, never on a timer; a clean leave bypasses the hold.
    /// Local and ephemeral — not replicated — so it lives beside the other
    /// registries only because it shares their per-session task-threading, not
    /// because it is a mesh concern. See [`crate::drop_hold`].
    pub drop_holds: crate::drop_hold::DropHolds,
    /// Per-session bounded record of the turns this relay has forwarded, so a
    /// client that dropped and re-dialed while its drop was undecided can be replayed
    /// the turns it missed and catch its sim up. Local and ephemeral like `drop_holds`, and
    /// threaded through the same per-session tasks (the turn forward path records
    /// into it; a re-register reads from it). See [`crate::turn_ring`].
    pub turn_ring: crate::turn_ring::TurnRing,
}

/// Creates a `MeshState` with empty registries for a relay that has no peer-relay
/// links, no sessions, and no local clients yet.
pub fn new_mesh_state() -> MeshState {
    new_mesh_state_with_timings(
        crate::drop_hold::DROP_UNLOCK,
        crate::drop_hold::ABANDONED_SESSION_TIMEOUT,
    )
}

/// [`new_mesh_state`] with an explicit drop-unlock floor, so a test can inject a
/// tiny floor and drive the honor-a-drop-request path without waiting out the
/// production 30-second window. The abandoned-session window keeps its production
/// value.
pub fn new_mesh_state_with_drop_unlock(unlock: std::time::Duration) -> MeshState {
    new_mesh_state_with_timings(unlock, crate::drop_hold::ABANDONED_SESSION_TIMEOUT)
}

/// [`new_mesh_state`] with both drop-decision windows injected — the manual-drop
/// unlock floor and the fully-abandoned-session timeout — so a test can drive
/// either auto-decision path on a tiny window rather than the production waits.
/// Production builds it through [`new_mesh_state`] with the real constants.
pub fn new_mesh_state_with_timings(
    unlock: std::time::Duration,
    abandon_timeout: std::time::Duration,
) -> MeshState {
    MeshState {
        links: new_mesh_links(),
        seen: new_seen_registries(),
        conditions: new_conditions_registry(),
        decision_makers: Arc::new(crate::consensus::new_decision_makers()),
        presence: Arc::new(crate::presence::new_presence_registry()),
        lobby: crate::lobby::new_lobby_registry(),
        chat: crate::chat::new_chat_registry(),
        drop_holds: crate::drop_hold::DropHolds::new(unlock, abandon_timeout),
        turn_ring: crate::turn_ring::TurnRing::new(),
    }
}
/// The channel that pushes a turn to a peer-relay's mesh-link task. Tagged with
/// the session id so one merged receiver per link can demux to the right
/// session's transport state — every game on a relay-pair shares one QUIC
/// connection, so a single driver task drains all sessions' outbound turns from
/// one channel.
type MeshForwardTx = mpsc::Sender<(SessionId, Payload)>;

/// The channel that pushes an outbound `MeshControlFrame` to a peer-relay's
/// mesh-link task, which writes it on the shared bidirectional control stream.
///
/// **Unbounded**, unlike the per-turn forward channel — for the same reason the
/// `MeshCommand` channel is: control frames are rare (a handful per game, on a
/// departure), and every one must arrive. A dropped `SlotDeparted` could strand a
/// leave the authority never learns to author; a dropped `LeaveDirective` could
/// leave a peer relay's survivor stalled forever. Backpressure is the wrong tool
/// where every message must be delivered; the only send failure is the driver
/// having exited (closed channel), which the fan-out tolerates because the link is
/// gone and a redialed one re-syncs via the Join-time reconcile.
type MeshControlTx = mpsc::UnboundedSender<MeshControlFrame>;

/// The pair of senders one session registers into [`MeshLinks`] for one link: the
/// bounded per-turn forward channel and the unbounded control-frame channel, both
/// draining into the same link driver. Held together so a session's registration
/// governs both. Public only because it appears in the [`MeshLinks`] alias; its
/// fields are private, so the registry is built and read solely through this module.
pub struct MeshLinkTx {
    /// Distinguishes this entry from every other peer relay's entry in the same
    /// session's fan-out vec, so a driver deregisters only its own on teardown.
    id: u64,
    /// Bounded per-turn forward channel (turns, redundancy re-carried on drop).
    forward: MeshForwardTx,
    /// Unbounded control-frame channel (synced-leave propagation, never dropped).
    control: MeshControlTx,
}

/// Hands out a process-unique id for each mesh-link registration. A session's
/// [`MeshLinks`] entry is a vec with one element per connected peer relay; the id
/// tags each element so its owning driver can remove exactly that element when it
/// winds down, without disturbing the other peers still serving the session.
fn next_mesh_link_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
/// Creates the command channel for one mesh-link driver — the `Join`/`Leave`
/// stream the test (today) or the coordinator's session-descriptor push drives.
///
/// Unbounded by design. These are rare control messages (a handful per game, not
/// the turn stream) that the driver's select loop drains promptly, so the queue
/// does not grow in practice. Making it unbounded means a burst of session
/// starts on one relay-pair can never *drop* a `Join`/`Leave`: a dropped command
/// would silently desync mesh membership — most insidiously a dropped `Leave`,
/// which would leave the driver forwarding a session the coordinator has
/// removed, with no later event to correct it. Backpressure is the wrong tool
/// for a control channel where every message must arrive; the only delivery
/// failure is the receiver going away (the driver exited), which the Join source
/// ([`mesh_control`](crate::mesh_control)) treats as a dead link to re-sync on
/// reconnect.
///
/// This is distinct from the per-turn forward channel (`FORWARD_CAPACITY`),
/// which is deliberately bounded: there, dropping a redundant copy under load is
/// correct (the transport re-carries it), so backpressure is the right tool.
pub(crate) fn command_channel() -> (
    mpsc::UnboundedSender<MeshCommand>,
    mpsc::UnboundedReceiver<MeshCommand>,
) {
    mpsc::unbounded_channel()
}

/// How long a mesh link stays up after its last session leaves before the
/// driver tears it down. Production passes this as the `idle_timeout` arg to
/// [`run_mesh_link`]; tests pass a shorter real duration so the teardown is
/// observable without waiting a full minute.
///
/// This is *app-level* idle teardown, distinct from the QUIC idle timeout
/// (`transport::quic::MAX_IDLE_TIMEOUT`, 10s) that fires when the *connection*
/// goes dead (keepalive PINGs stop round-tripping). A live but session-less
/// link stays up at the QUIC layer (keepalive keeps it healthy); this timer
/// tears down a link nobody is using anymore so a churned-out relay-pair's
/// connection doesn't linger forever.
///
/// Armed only after a link has served at least one session (had a `Join`, then
/// went empty again) — a never-joined link stays parked, ready for the
/// coordinator's `Join` source (the binary holds its command sender for exactly
/// this). Tearing a never-joined link down would strand the pair: the dial-side
/// reconnect supervisor redials a *failed* connection but treats an idle teardown
/// as an intentional wind-down and stops, so a parked link torn down for idling
/// would not come back.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Why a mesh-link driver exited. The dial-side reconnect supervisor uses this to
/// distinguish intentional teardown from a dropped connection: only the
/// latter is worth retrying, since `Idle` means a deliberate wind-down and
/// `CommandChannelClosed` means the relay itself is shutting the link down.
///
/// `ConnectionFailed` covers every transport-level exit — a QUIC idle
/// timeout, a read/send error, a keepalive that stopped round-tripping, or the
/// peer's control-stream reader ending while the rest of the connection was
/// still alive (a one-sided reset, an over-cap frame, a decode failure). Those
/// all surface the same from the driver's perspective (the link is gone); the
/// reconnect supervisor treats them all as retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLinkExit {
    /// The link had at least one session, went empty, and stayed empty past
    /// [`IDLE_TIMEOUT`]. An intentional wind-down, not a failure.
    Idle,
    /// The connection failed: a recv/send error, QUIC idle timeout, or a dead
    /// control-stream reader. The peer is unreachable, dead, or the link is no
    /// longer trustworthy for correctness-critical traffic.
    ConnectionFailed,
    /// The command channel closed (the relay is tearing the link down — its
    /// `MeshCommand` sender was dropped). An intentional shutdown.
    CommandChannelClosed,
}

/// Registers one peer-relay link's `(forward, control)` senders for `key`,
/// appending them as a new element in that session's fan-out vec, and returns the
/// RAII guard that removes *only this* element when dropped. Each session's entry
/// holds one element per connected peer relay, so registering must never clobber
/// the peers already serving the session.
fn register_mesh_link(
    links: &MeshLinks,
    key: SessionKey,
    forward: MeshForwardTx,
    control: MeshControlTx,
) -> MeshLinkRegistration {
    let id = next_mesh_link_id();
    links
        .lock()
        .entry(key.clone())
        .or_default()
        .push(MeshLinkTx {
            id,
            forward,
            control,
        });
    MeshLinkRegistration {
        links: links.clone(),
        key,
        id,
    }
}

/// Removes the single mesh forward channel `id` registered for `key` (that one
/// peer-relay link has closed), leaving every other peer's channel for the
/// session in place. The whole `key` is dropped only once its last channel is
/// gone. Idempotent: an id already removed (or a key already empty) is a no-op.
fn deregister_mesh_link(links: &MeshLinks, key: &SessionKey, id: u64) {
    let mut roster = links.lock();
    if let Some(mesh_txs) = roster.get_mut(key) {
        mesh_txs.retain(|tx| tx.id != id);
        if mesh_txs.is_empty() {
            roster.remove(key);
        }
    }
}

/// Delivers `payload` to every peer-relay mesh link serving `key`, without ever
/// blocking on a slow peer. Mirrors [`routing::fan_out`] but for mesh links
/// instead of local slots.
///
/// Fans out to **all** mesh links for the session — including the one a turn
/// arrived on. The echo is caught not by excluding the ingress link (there's no
/// link id in the registry to exclude) but by `MeshSeen`: every ingress — local
/// client or mesh peer — marks `(slot, seq)` before forwarding to locals, so the
/// echo arrives, is seen as `Duplicate`, and is dropped before it reaches local
/// clients. This is why the flood-with-dedup model requires marking on *every*
/// forward-to-local, not just mesh ingress.
pub fn fan_out_to_mesh(links: &MeshLinks, key: &SessionKey, payload: Payload) {
    let targets: Vec<MeshForwardTx> = {
        let roster = links.lock();
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs.iter().map(|tx| tx.forward.clone()).collect(),
            None => Vec::new(),
        }
    };
    for tx in targets {
        // Tag with the session id so the driver's merged receiver can demux.
        // A full mesh forward queue is a slow peer relay — signal it later, for
        // now just drop (the per-link transport re-carries what was already sent).
        let _ = tx.try_send((key.session, payload.clone()));
    }
}

/// Delivers `frame` to every peer-relay mesh link serving `key` over each link's
/// reliable control stream. The control-channel twin of [`fan_out_to_mesh`], but
/// unbounded and drop-free: a control frame propagates a synced player-leave, so —
/// unlike a redundantly-re-carried turn — it must never be dropped. The frame's
/// `session` is stamped to `key` so every link on the pair reads it under the
/// right tenant-scoped session, exactly as its bare `MeshPacket` session resolves.
///
/// Senders are cloned under the lock and the lock dropped before delivery, as in
/// [`fan_out_to_mesh`]. The only send failure is a closed channel (the driver
/// exited); that is tolerated — the link is gone, and a redialed one re-syncs its
/// state via the Join-time reconcile.
pub(crate) fn fan_out_control(links: &MeshLinks, key: &SessionKey, mut frame: MeshControlFrame) {
    frame.session = key.session.0;
    let targets: Vec<MeshControlTx> = {
        let roster = links.lock();
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs.iter().map(|tx| tx.control.clone()).collect(),
            None => Vec::new(),
        }
    };
    for tx in targets {
        let _ = tx.send(frame.clone());
    }
}

/// Ships one destination client's complete delivered-through cursor map to every
/// peer relay serving `key` — the home relay re-sharing the beacon cursors it
/// already reads, so the session's authority (wherever it is) can fold final
/// delivery. Declarative per frame (the complete map), throttled at the caller
/// by [`crate::delivery::CursorShare`]; the receiver folds it and never
/// re-broadcasts (the no-echo rule every mesh control kind follows).
pub(crate) fn fan_out_delivery_cursors(
    links: &MeshLinks,
    key: &SessionKey,
    dest: SlotId,
    cursors: &[(SlotId, u64)],
) {
    fan_out_control(
        links,
        key,
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::DeliveryCursors(
                rally_point_proto::messages::DeliveryCursors {
                    dest_slot: u32::from(dest.0),
                    cursors: cursors
                        .iter()
                        .map(|&(origin, seq)| rally_point_proto::messages::DeliveryCursor {
                            origin_slot: u32::from(origin.0),
                            delivered_seq: seq,
                        })
                        .collect(),
                },
            )),
        },
    );
}

/// Announces a departed slot to every peer relay serving `key`: the home relay
/// tells its peers one of its clients left, so the session's authority can author
/// the synced leave and every relay records the departure for handoff robustness.
pub(crate) fn fan_out_slot_departed(
    links: &MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    last_frame: Option<u32>,
    reachable_frame: Option<u32>,
    result: Option<ResultEcho>,
    reason: u32,
) {
    fan_out_control(
        links,
        key,
        slot_departed_frame(
            key.session,
            slot,
            last_frame,
            reachable_frame,
            result,
            reason,
        ),
    );
}

/// Propagates a synced leave the authority decided to every peer relay serving
/// `key`, so each pushes it down its own local survivors. A relay that receives
/// this caches and locally fans it out but does not re-broadcast it — no echo.
pub(crate) fn fan_out_leave_directive(links: &MeshLinks, key: &SessionKey, leave: LeaveDirective) {
    fan_out_control(links, key, leave_directive_frame(key.session, leave));
}

/// Propagates a member's lobby command to every peer relay serving `key`, so each
/// fans it out to its own local members and appends it to its own replay log. The
/// origin relay stamps the authoring slot onto `command` before this call, so a
/// peer copy already carries the authoritative author. A relay that receives this
/// delivers it locally but does not re-broadcast it — no echo — mirroring the
/// oversize-turn divert.
pub(crate) fn fan_out_lobby_command(links: &MeshLinks, key: &SessionKey, command: LobbyCommand) {
    fan_out_control(links, key, lobby_command_frame(key.session, command));
}

/// Propagates one member's game-chat message to every peer relay serving `key`,
/// so each fans it out to its own local members. The origin relay stamps the
/// authoring slot onto `chat` before this call, so a peer copy already carries
/// the authoritative author. A relay that receives this delivers it locally but
/// does not re-broadcast it — no echo — mirroring [`fan_out_lobby_command`]
/// minus the replay-log side effect (chat keeps none).
pub(crate) fn fan_out_chat(links: &MeshLinks, key: &SessionKey, chat: GameChat) {
    fan_out_control(links, key, chat_frame(key.session, chat));
}

/// Announces a freshly registered slot to every peer relay serving `key`, so
/// each accumulates it into the session's live-slot set and the authority can
/// decide when every expected slot has connected. A duplicate (a re-announce) is
/// idempotent — the accumulated set is a set.
pub(crate) fn fan_out_slot_present(links: &MeshLinks, key: &SessionKey, slot: SlotId) {
    fan_out_control(links, key, slot_present_frame(key.session, slot));
}

/// Broadcasts the session-start directive the authority decided to every peer
/// relay serving `key`, so each fans it down its own local slots. A relay that
/// receives this latches the session started and fans it locally but does not
/// re-broadcast it — the authority already sent it to every relay — so there is
/// no echo.
pub(crate) fn fan_out_session_start(links: &MeshLinks, key: &SessionKey) {
    fan_out_control(links, key, session_start_frame(key.session));
}

/// Broadcasts a slot-connectivity change to every peer relay serving `key`, so
/// each fans it down its own local slots. Sent the moment the origin relay's
/// home client's link dies (`connected` false) or (re)registers (`connected`
/// true). A relay that receives this delivers it to its local slots but does not
/// re-broadcast it — the origin already sent a copy to every peer, so re-flooding
/// would only echo (mirroring the chat/oversize-turn divert). Best-effort and
/// informational; it rides the reliable mesh control stream but carries no
/// delivery guarantee of its own.
pub(crate) fn fan_out_slot_connectivity(
    links: &MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    connected: bool,
) {
    fan_out_control(
        links,
        key,
        slot_connectivity_frame(key.session, slot, connected),
    );
}

/// Broadcasts a manual drop request to every peer relay serving `key`, so the
/// session's authority relay — which may be a peer, not this one — can honor it.
/// `requester` is the authenticated slot that authored the request, stamped here
/// for logging and abuse attribution; `target` is the disconnected slot it wants
/// dropped. A relay that receives this honors it only if it is the authority and
/// the target's drop is past the unlock floor, and does not re-broadcast it — the
/// origin already sent a copy to every peer, so re-flooding would only echo.
pub(crate) fn fan_out_request_drop(
    links: &MeshLinks,
    key: &SessionKey,
    target: SlotId,
    requester: SlotId,
) {
    fan_out_control(
        links,
        key,
        request_drop_frame(key.session, target, requester),
    );
}

/// Builds a `RequestDrop` mesh control frame for `session`, carrying the target
/// slot and the relay-stamped requester.
fn request_drop_frame(session: SessionId, target: SlotId, requester: SlotId) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
            slot: u32::from(target.0),
            requester: u32::from(requester.0),
        })),
    }
}

/// Builds a `SlotPresent` mesh control frame for `session`.
fn slot_present_frame(session: SessionId, slot: SlotId) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotPresent(SlotPresent {
            slot: u32::from(slot.0),
        })),
    }
}

/// Builds a `SessionStart` mesh control frame for `session`.
fn session_start_frame(session: SessionId) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SessionStart(SessionStart {})),
    }
}

/// Builds a `SlotConnectivity` mesh control frame for `session`.
fn slot_connectivity_frame(session: SessionId, slot: SlotId, connected: bool) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: u32::from(slot.0),
                connected,
            },
        )),
    }
}

/// Broadcasts a batch of synced leaves — the ones a fresh authority promotion
/// must (re)deliver — to both local survivors ([`routing::fan_out_leave`]) and
/// every peer relay ([`fan_out_leave_directive`]). All are idempotent: clients
/// dedup by slot, and a peer relay caches by slot. A no-op on an empty batch (the
/// overwhelmingly common case — most authority changes carry no pending leave).
pub(crate) fn broadcast_leaves(
    sessions: &routing::Sessions,
    mesh_links: &MeshLinks,
    key: &SessionKey,
    leaves: Vec<LeaveDirective>,
) {
    for leave in leaves {
        let slot = SlotId(leave.slot as u8);
        routing::fan_out_leave(sessions, key, slot, leave);
        fan_out_leave_directive(mesh_links, key, leave);
    }
}

/// Builds a `SlotDeparted` mesh control frame for `session`.
///
/// `result` is the departing slot's home-authored end-of-game result echo, if it
/// reported one before departing: its fields ride the frame so every peer folds
/// the identical result into its departure record (an empty payload — no result —
/// leaves the echo fields at their defaults, which peers read as "no result").
fn slot_departed_frame(
    session: SessionId,
    slot: SlotId,
    last_frame: Option<u32>,
    reachable_frame: Option<u32>,
    result: Option<ResultEcho>,
    reason: u32,
) -> MeshControlFrame {
    let (result_payload, result_arrival_ms, result_session_frame, result_slot_frame) = match result
    {
        Some(echo) => (
            echo.payload.into(),
            echo.arrival_ms,
            echo.session_frame,
            echo.slot_frame,
        ),
        None => (Vec::new().into(), 0, None, None),
    };
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            slot: u32::from(slot.0),
            last_frame,
            reachable_frame,
            reason,
            result_payload,
            result_arrival_ms,
            result_session_frame,
            result_slot_frame,
        })),
    }
}

/// Builds a `LeaveDirective` mesh control frame for `session`.
fn leave_directive_frame(session: SessionId, leave: LeaveDirective) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(leave)),
    }
}

/// Builds a `LobbyCommand` mesh control frame for `session`.
fn lobby_command_frame(session: SessionId, command: LobbyCommand) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::LobbyCommand(command)),
    }
}

/// Builds a `GameChat` mesh control frame for `session`.
fn chat_frame(session: SessionId, chat: GameChat) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::GameChat(chat)),
    }
}

/// Forwards one turn: topological dedup, buffer-directive stamping, then
/// fan-out to local slots and peer relays. The single forward step shared by
/// the client-edge path (`run_slot_link`) and the mesh path (`run_mesh_link`),
/// so every path a turn can take treats the stamp identically.
///
/// Marking `(slot, seq)` in the session's seen-set before fanning out is what
/// catches the mesh echo: the mesh floods to all peers (no link-id exclusion),
/// so the turn comes back via the mesh, is seen as `Duplicate`, and is dropped
/// before it reaches local clients a second time — a duplicate turn into a
/// lockstep slot is a desync.
///
/// Stamping is stamp-or-preserve: when this relay's decision-maker has an
/// active directive (it is the session's authority), the directive is set on
/// the outgoing payload; when it has none — every non-authority relay, always
/// — a stamp already on the turn is left untouched, so the authority's
/// broadcast survives the hop across relays that merely forward it.
// `turn_ring` is the 8th argument (the replay record, alongside the mesh flood's
// existing registries); bundling into a struct would touch every call site
// (production and test) for one more reference, so this follows the same
// escape hatch already used elsewhere in the crate (`SyncTracker::record` in
// `consensus.rs`, `connect_and_stream` in `coordinator_client.rs`) rather than
// that churn.
#[allow(clippy::too_many_arguments)]
pub fn forward_turn(
    sessions: &routing::Sessions,
    mesh_links: &MeshLinks,
    seen: &SeenRegistries,
    decision_makers: &crate::consensus::DecisionMakers,
    turn_ring: &crate::turn_ring::TurnRing,
    key: &SessionKey,
    slot: SlotId,
    payload: Payload,
) {
    if let Some(payload) = deliver_turn_to_locals(
        sessions,
        seen,
        decision_makers,
        turn_ring,
        key,
        slot,
        payload,
    ) {
        fan_out_to_mesh(mesh_links, key, payload);
    }
}

/// The local half of [`forward_turn`]: topological dedup, buffer-directive
/// stamping, and fan-out to this relay's local slots — everything except the
/// mesh flood. Returns the (possibly stamped) payload when it was fresh, so
/// [`forward_turn`] can flood it onward, or `None` for a topological duplicate
/// already delivered via an earlier path.
///
/// Also the whole receive step for an oversize turn arriving over the mesh
/// control stream: the origin relay diverted a copy to *every* link serving the
/// session itself, so the receiver delivers locally and deliberately does not
/// re-flood — re-broadcasting would only produce the echo the dedup exists to
/// drop (harmless, but pure waste on a reliable stream).
fn deliver_turn_to_locals(
    sessions: &routing::Sessions,
    seen: &SeenRegistries,
    decision_makers: &crate::consensus::DecisionMakers,
    turn_ring: &crate::turn_ring::TurnRing,
    key: &SessionKey,
    slot: SlotId,
    mut payload: Payload,
) -> Option<Payload> {
    if mark_seen(seen, key, slot, payload.seq) == Seen::Duplicate {
        // Only the duplicate (mesh-echo) branch touches the recorder's maps —
        // the fresh-turn common path stays lock-free for the recorder.
        decision_makers.flight_recorder().note_dedup_drop(key, slot);
        return None;
    }
    // The desync comparator's one and only feed point. Every turn-delivery
    // path — client edge (datagram and oversize-control), mesh datagram, and
    // mesh oversize-control — funnels through here, and this is placed right
    // after the `mark_seen` dedup above: the mesh legitimately delivers the
    // same turn to the authority via more than one path (that's exactly what
    // `mark_seen` exists to catch), and the comparator's per-slot ordinal
    // count is not idempotent the way `observe_frame`'s monotone max is — a
    // duplicate walked twice would silently drift the count and misalign
    // every later comparison. A no-op unless this relay is the session
    // authority.
    crate::consensus::observe_sync(
        decision_makers,
        key,
        slot,
        payload.game_frame_count,
        &payload.commands,
    );
    match crate::consensus::active_directive(decision_makers, key) {
        Some(directive) => payload.buffer_directive = Some(directive),
        // Preserving an upstream stamp also records its seq and buffer: every
        // directive floods through every relay serving the session, so if this
        // relay is later promoted to authority, its own decisions number above
        // what clients already hold and baseline against the committed buffer
        // instead of restarting below it.
        None => {
            if let Some(incoming) = &payload.buffer_directive {
                crate::consensus::observe_directive(decision_makers, key, incoming);
            }
        }
    }
    // NOTE: player-leaves are NOT stamped here. A leave is delivered over the
    // reliable control stream (the relay pushes it to each surviving client), not
    // the turn envelope — a drop stops the turn stream, so an envelope stamp would
    // never reach the survivors it must unstall. See `routing`'s leave trigger.
    routing::fan_out(sessions, key, slot, payload.clone());
    // Record the fanned turn into the session's replay ring so a client that drops
    // and re-dials while its drop is undecided can be replayed what it missed. This is the one
    // choke point every turn-delivery path funnels through, placed right after the
    // `mark_seen` dedup, so each distinct `(slot, seq)` is recorded exactly once
    // even when the mesh delivers it by more than one path. Buffered only once the
    // session has started: pre-start lobby traffic has its own ordered replay log
    // and must not be double-buffered here.
    if crate::consensus::session_started(decision_makers, key) {
        turn_ring.record(key, &payload);
    }
    Some(payload)
}

/// A command to a mesh-link driver, telling it to start or stop serving one
/// session on its shared relay-pair connection.
///
/// The driver discovers sessions over time — a relay learns which games its
/// peer also serves as clients connect and games start — so it takes a stream
/// of these commands rather than an upfront list. Join opens the session's
/// transport state on the link and registers its forward channel; Leave
/// closes and deregisters it. Today the test harness drives the channel
/// directly; the coordinator's session-descriptor push (Phase 3) will be the
/// production source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshCommand {
    /// Start serving `key`'s session on this link. Opens per-session transport
    /// state and registers a forward channel so turns fanned out to the mesh
    /// reach this link. Idempotent: joining an already-joined session is a
    /// no-op (a re-announce after a transient drop is harmless).
    Join(SessionKey),
    /// Stop serving `key`'s session on this link. Closes its per-session
    /// transport state and deregisters its forward channel. Idempotent: leaving
    /// an absent session is a no-op.
    Leave(SessionKey),
}
/// The mesh control stream's I/O for one established link, handed to the link
/// driver: the send half this relay writes its outbound `MeshControlFrame`s on,
/// and the channel the peer's frames arrive over (fed by a
/// [`spawn_mesh_control_reader`](rally_point_transport::mesh_control_stream::spawn_mesh_control_reader)
/// task). Bundled so the driver's signature stays within the argument count the
/// codebase holds elsewhere, mirroring [`PresenceIo`](crate::presence::PresenceIo).
pub struct MeshControlIo {
    /// The send half of the bidirectional control stream — outbound frames.
    pub tx: rally_point_transport::quinn::SendStream,
    /// The peer's control frames, assembled off its recv half by a reader task.
    pub rx: mpsc::Receiver<MeshControlFrame>,
}

/// Drives a shared [`MeshLink`] for every session both relays jointly serve on
/// a relay-pair's single QUIC connection.
///
/// A near-twin of [`routing::run_slot_link`] but for the mesh edge:
///
/// - **Receives** turns from the peer relay via `MeshLink::recv()`, which
///   demultiplexes by session. Each datagram is routed to the session it names
///   — a session not currently joined is logged and dropped, not a crash. The
///   join may simply be in flight on the command channel.
/// - **No `validate_turn`** — the mesh trusts its peer relay. Validation
///   happened at the ingress client edge and is never repeated at a mesh hop.
/// - **Marks `MeshSeen`** before fanning out to local clients, so an echo (the
///   turn re-arriving via the mesh after being fanned out) is caught as
///   `Duplicate` and dropped.
/// - **Fans out** to both local slots and other mesh links, so a turn from a
///   peer relay reaches this relay's local clients and any *other* connected
///   peer relays.
///
/// One task owns the link: both `MeshLink::recv` and `send` need `&mut self`,
/// so N sessions are multiplexed over one driver loop rather than N tasks
/// racing on the connection's single `read_datagram` consumer. A merged
/// forward channel carries `(SessionId, Payload)` so one `select!` branch
/// drains all sessions' outbound turns without polling N receivers.
///
/// Sessions join and leave over `commands` as the relay discovers which games
/// its peer also serves. One `Join` opens the session's transport state and
/// registers its forward channel; one `Leave` closes and deregisters it. The
/// driver ends — returning a [`MeshLinkExit`] — when the link goes idle past
/// `idle_timeout` (after having served at least one session), the command
/// channel closes, or the connection fails.
///
/// # Idle teardown
///
/// `idle_timeout` is how long the driver keeps the link up after its last
/// session leaves, *once the link has served at least one session*. The timer
/// is armed only on the transition from "has sessions" to "no sessions" — a
/// never-joined link stays parked indefinitely, ready for the coordinator's
/// future `Join` source (the binary holds its command sender for exactly
/// this). Re-`Join`ing before the timer fires cancels it. Production passes
/// [`IDLE_TIMEOUT`]; tests pass a shorter real duration. This is distinct from
/// QUIC's own idle timeout (see [`IDLE_TIMEOUT`]).
///
/// # Tenant scoping
///
/// The wire carries a bare `session: u64` with no tenant (see `MeshPacket`).
/// Session ids are unique only *within* a tenant, so the driver keys its
/// per-session state by `SessionKey` (tenant + session) — never the bare id —
/// and a `SessionId -> SessionState` map demultiplexes a received datagram to
/// the right session. The collision guard runs on every `Join`: a caller that
/// skips [`join_sessions`] still can't silently cross-wire two tenants
/// sharing a session id — the second is logged and dropped, never overwrites
/// the first. This is fail-closed, not fail-open.
pub async fn run_mesh_link(
    mut link: rally_point_transport::MeshLink,
    presence_io: crate::presence::PresenceIo,
    mesh_control_io: MeshControlIo,
    mut commands: mpsc::UnboundedReceiver<MeshCommand>,
    sessions: routing::Sessions,
    mesh: MeshState,
    idle_timeout: std::time::Duration,
) -> MeshLinkExit {
    // Cloned (cheap — every field is an `Arc`) before the destructure below
    // pulls `mesh` apart, so `dispatch_mesh_control` can take the whole bundle
    // as one argument rather than a growing list of its individual registries
    // (mirroring `run_slot_link`'s `mesh_for_teardown`). `lobby` and `chat` are
    // used only inside that dispatch, via the clone, so this destructure omits
    // them (`..`) rather than binding two names this function never reads.
    let mesh_for_dispatch = mesh.clone();
    let MeshState {
        links: mesh_links,
        seen: seen_registries,
        conditions,
        decision_makers,
        presence,
        drop_holds,
        ..
    } = mesh;
    let crate::presence::PresenceIo {
        peer_id,
        tx: mut presence_tx,
        rx: mut presence_rx,
    } = presence_io;
    let MeshControlIo {
        tx: mut control_send,
        rx: mut peer_control_rx,
    } = mesh_control_io;
    // One merged outbound control channel for every session on this link:
    // `fan_out_control` pushes a `MeshControlFrame` (self-describing via its
    // session field) here, and the driver writes it on the shared control stream.
    // One sender is cloned into the mesh-links registry per session (alongside the
    // forward sender); the driver owns the receiver and holds the original sender
    // for the loop's life, so `recv()` returns `None` only on a genuine shutdown.
    let (control_forward_tx, mut control_forward_rx) =
        mpsc::unbounded_channel::<MeshControlFrame>();

    // The live-player count last pushed to the peer, per session — presence is
    // pushed on change (reconciled against the local slot roster on every
    // flush tick and on each Join), so a stable roster sends nothing.
    let mut presence_sent: HashMap<rally_point_proto::ids::SessionId, u32> = HashMap::new();
    // Whether the peer's presence reader task is still feeding reports. Once
    // it ends (the peer's stream closed or errored), `recv()` returns `None`
    // on every poll — an always-ready future that would spin the loop —
    // so the branch is disabled on the first `None`, exactly like the client
    // driver's beacon branch. A dead presence stream is not itself a link
    // failure; that surfaces through the datagram path.
    let mut presence_alive = true;

    // One merged forward channel for every session on this link: fan_out_to_mesh
    // pushes (SessionId, Payload) tagged with the session id, so a single
    // select! branch drains all sessions' outbound turns without polling N
    // per-session receivers. One sender is cloned into the mesh-links registry
    // for each session; the driver task owns the receiver.
    let (forward_tx, mut forward_rx) =
        mpsc::channel::<(rally_point_proto::ids::SessionId, Payload)>(routing::FORWARD_CAPACITY);

    // Per-session driver state, keyed by the wire's bare session id. Each entry
    // carries its full SessionKey so fan-out/conditions stay tenant-correct.
    // The collision guard runs on Join: if two tenants share a session id, the
    // wire can't tell them apart, so the second is logged and skipped — never
    // overwrites the first.
    let mut joined: HashMap<rally_point_proto::ids::SessionId, SessionState> = HashMap::new();

    // Idle teardown state. `idle_since` is the instant the last session left
    // (None while sessions are joined, or before the first Join); the driver
    // tears down when `idle_since + idle_timeout` passes without a re-Join.
    //
    // This alone encodes "has served traffic": it is only set to `Some` after a
    // `joined.remove()` that emptied `joined`, which can only follow a prior
    // successful Join. A never-joined link keeps `idle_since = None` and stays
    // parked indefinitely, ready for the coordinator's future Join source (the
    // binary holds its command sender for exactly this).
    let mut idle_since: Option<tokio::time::Instant> = None;

    // Each break carries its `MeshLinkExit` inline, so a reconnect supervisor
    // can tell an intentional wind-down (Idle, CommandChannelClosed) from a
    // dropped connection (ConnectionFailed). Non-exit paths `continue` the
    // loop; the value a `break` carries becomes the function's return.
    let exit = loop {
        // The earliest per-session flush deadline. `sleep` is cancel-safe, so
        // the loop recomputes it on every wake. With a handful of games per
        // relay-pair the O(N) scan is trivial; when no sessions are joined yet
        // (the link is up, awaiting its first Join) it parks on a long sleep
        // so the loop doesn't spin.
        let next_flush = joined
            .values()
            .map(|s| s.flush_deadline)
            .min()
            .unwrap_or(tokio::time::Instant::now() + routing::FLUSH_INTERVAL);

        // The idle-teardown deadline. Only armed once the link has served at
        // least one session and is now empty (`idle_since` is Some); otherwise
        // the fallback (a day out) keeps the branch dormant. Cancel-safe like
        // the flush timer.
        let idle_deadline = idle_since
            .map(|t| t + idle_timeout)
            .unwrap_or(tokio::time::Instant::now() + std::time::Duration::from_secs(86_400));

        tokio::select! {
            received = link.recv() => {
                match received {
                    Ok(mesh_received) => {
                        let Some(state) = joined.get(&mesh_received.session) else {
                            tracing::warn!(
                                session = mesh_received.session.0,
                                "mesh datagram for unjoined session; dropping",
                            );
                            continue;
                        };
                        let key = state.key.clone();
                        // Feed the peer relay's home-client conditions into this
                        // session's decision-maker. The mesh hop is a property of
                        // the relay-pair, sampled from this link's QUIC RTT, so a
                        // remote slot's effective path includes the trip across
                        // the backbone.
                        if let Some(peer_conditions) = &mesh_received.conditions {
                            tracing::trace!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slots = peer_conditions.slots.len(),
                                "received peer-relay link conditions",
                            );
                            let mesh_rtt_us = link_rtt_us(link.connection());
                            // Any decision it fires is logged by the helper and
                            // broadcast later, at fan-out.
                            let _ = crate::consensus::ingest_remote_conditions(
                                &decision_makers,
                                &key,
                                peer_conditions,
                                mesh_rtt_us,
                            );
                        }
                        for payload in mesh_received.delivery.fresh {
                            let slot = SlotId(payload.slot as u8);
                            // A remote slot's frame observation, validated by its
                            // home relay. Lobby turns carry no frame and don't
                            // move the consensus coordinate.
                            if let Some(frame) = payload.game_frame_count {
                                crate::consensus::observe_turn_frame(
                                    &decision_makers,
                                    &key,
                                    slot,
                                    payload.seq,
                                    rally_point_proto::ids::GameFrameCount(frame),
                                    crate::delivery::DeliveryHome::Peer(peer_id),
                                );
                            }
                            // NOTE: no desync-comparator call here. This relay
                            // may also reach the same turn via a different
                            // mesh path (or the client edge, if it's local),
                            // so counting it here — before dedup — would
                            // double-count it. `forward_turn` below funnels
                            // into `deliver_turn_to_locals`, which feeds the
                            // comparator exactly once, right after its
                            // mark_seen check.
                            forward_turn(
                                &sessions,
                                &mesh_links,
                                &seen_registries,
                                &decision_makers,
                                &mesh_for_dispatch.turn_ring,
                                &key,
                                slot,
                                payload,
                            );
                        }
                        continue;
                    }
                    Err(rally_point_transport::MeshLinkError::UnknownSession(session)) => {
                        tracing::warn!(
                            session = session.0,
                            "mesh packet for unknown session; ignoring",
                        );
                        continue;
                    }
                    Err(error) => {
                        tracing::info!(%error, "mesh link closed");
                        break MeshLinkExit::ConnectionFailed;
                    }
                }
            }
            // An outbound control frame (a `SlotDeparted` or `LeaveDirective` a
            // slot-link task or a handoff fanned out to this link): write it on
            // the shared reliable control stream. A write failure is a dead
            // connection — like a datagram send failure, it closes the link. The
            // frame is self-describing (its session field), so no demux is needed.
            outbound = control_forward_rx.recv() => {
                match outbound {
                    Some(frame) => {
                        if let Err(error) =
                            rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                                &mut control_send,
                                &frame,
                            )
                            .await
                        {
                            tracing::info!(%error, "mesh control send failed; closing link");
                            break MeshLinkExit::ConnectionFailed;
                        }
                        continue;
                    }
                    None => break MeshLinkExit::CommandChannelClosed,
                }
            }
            // A control frame from the peer relay: a departure it observed, a
            // synced leave its authority authored, or an oversize turn its
            // datagram path could not carry. The reader task assembled the
            // complete frame off a cancel-safe path; `recv` is cancel-safe.
            received = peer_control_rx.recv() => {
                match received {
                    Some(frame) => dispatch_mesh_control(
                        frame,
                        peer_id,
                        &joined,
                        &sessions,
                        &mesh_for_dispatch,
                    ),
                    // The reader task ended: a one-sided stream reset, an
                    // over-cap frame, a decode failure, or a clean EOF. This
                    // stream is the only channel `SlotDeparted`,
                    // `LeaveDirective`, an oversize-turn divert, and delivery
                    // cursors ever arrive on from this peer, so losing it is a
                    // link failure like any other here, not a degradation to
                    // limp on through -- ending the driver lets the dial
                    // supervisor (`dial_and_serve`) redial a fresh connection
                    // and every stream comes up new. Harmless if the
                    // connection was already dying for the same reason this
                    // reader ended.
                    None => {
                        tracing::info!("mesh control stream reader ended; closing link");
                        break MeshLinkExit::ConnectionFailed;
                    }
                }
            }
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some((session_id, payload)) => {
                        let Some(state) = joined.get(&session_id) else {
                            continue;
                        };
                        let key = state.key.clone();
                        let outgoing = snapshot_conditions(&conditions, &key);
                        // Too large for any mesh datagram on this path: divert to
                        // the reliable control stream, whose QUIC reliability
                        // replaces redundancy for this turn — the mesh twin of the
                        // client edge's divert. Written directly on the stream
                        // rather than through the merged outbound channel: this
                        // driver owns the send half, select! runs one branch to
                        // completion at a time so frames never interleave, and
                        // queueing behind pending control frames would only delay
                        // a turn the datagram path (which this replaces) imposes
                        // no such ordering on. A write failure closes the link —
                        // nothing re-carries a diverted turn.
                        let fits = match link.payload_fits(&payload, outgoing.as_ref()) {
                            Ok(fits) => fits,
                            Err(error) => {
                                tracing::info!(%error, "mesh send failed; closing link");
                                break MeshLinkExit::ConnectionFailed;
                            }
                        };
                        if !fits {
                            tracing::debug!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = payload.slot,
                                seq = payload.seq,
                                "diverting oversize turn to the mesh control stream",
                            );
                            let frame = MeshControlFrame {
                                session: session_id.0,
                                kind: Some(mesh_control_frame::Kind::OversizeTurn(payload)),
                            };
                            if let Err(error) =
                                rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                                    &mut control_send,
                                    &frame,
                                )
                                .await
                            {
                                tracing::info!(%error, "mesh control send failed; closing link");
                                break MeshLinkExit::ConnectionFailed;
                            }
                            continue;
                        }
                        match link.send(session_id, Some(payload), outgoing) {
                            Ok(_) => {}
                            // The pre-check above diverts anything that can never
                            // ride a datagram, so this arm is reachable only if
                            // the path budget moved between the check and the send
                            // (no await separates them, so in practice it isn't).
                            // The payload was consumed by the failed send; log it
                            // loudly rather than pretend it was delivered.
                            Err(rally_point_transport::MeshLinkError::PayloadTooLarge {
                                needed,
                                budget,
                            }) => {
                                tracing::warn!(
                                    tenant = key.tenant.as_ref(),
                                    session = key.session.0,
                                    needed,
                                    budget,
                                    "oversize turn slipped past the divert pre-check; dropped",
                                );
                            }
                            Err(error) => {
                                tracing::info!(%error, "mesh send failed; closing link");
                                break MeshLinkExit::ConnectionFailed;
                            }
                        }
                        continue;
                    }
                    None => break MeshLinkExit::CommandChannelClosed,
                }
            }
            _ = tokio::time::sleep_until(next_flush) => {
                let now = tokio::time::Instant::now();
                let mut failed = None;
                for (&session_id, state) in joined.iter_mut() {
                    if state.flush_deadline > now {
                        continue;
                    }
                    if link.payloads_in_flight(session_id) > 0
                        && let Err(error) = link.send(session_id, None, None)
                    {
                        failed = Some(error);
                        break;
                    }
                    state.flush_deadline = now + routing::FLUSH_INTERVAL;
                }
                if let Some(error) = failed {
                    tracing::info!(%error, "mesh flush failed; closing link");
                    break MeshLinkExit::ConnectionFailed;
                }
                // Reconcile presence on the same cadence: push each joined
                // session's live-player count when it differs from what the
                // peer last heard. Riding the tick (rather than hooking every
                // roster change into this task) keeps the roster paths free of
                // mesh plumbing; the ≤150ms of staleness is nothing against
                // the seconds-scale dwell of the buffer decisions presence
                // feeds. This reliable push is also why a relay whose players
                // have all left — and which therefore sends no datagrams at
                // all — still gets its "I'm out" to the peer.
                if reconcile_presence(&mut presence_tx, &mut presence_sent, &sessions, &joined)
                    .await
                    .is_err()
                {
                    tracing::info!("mesh presence push failed; closing link");
                    break MeshLinkExit::ConnectionFailed;
                }
                continue;
            }
            // A presence report from the peer: how many live home clients it
            // serves for one session. Record it and re-derive the session's
            // buffer-authority verdict — this is the handoff path when the
            // authority relay's players all leave. The reader task assembled
            // the complete frame off a cancel-safe path; `recv` is cancel-safe.
            received = presence_rx.recv(), if presence_alive => {
                match received {
                    Some(report) => {
                        // Tenant-scope the bare wire session id through the
                        // joined map, like a datagram; a report for an
                        // unjoined session has no key to record under.
                        let Some(state) = joined.get(&report.session) else {
                            continue;
                        };
                        if crate::presence::record_peer(
                            &presence,
                            &state.key,
                            peer_id,
                            report.live_players,
                        ) {
                            // A promotion here (the peer's players all left, and
                            // this relay is next in the order) yields any synced
                            // leave the departed authority never delivered; push
                            // each to local survivors and across the mesh.
                            // Skip slots whose drop is still held on this relay: a
                            // promotion here must not decide a departure a
                            // reconnecting client could still return from, and a held
                            // drop is only ever decided by a manual request.
                            let held = drop_holds.pending_slots(&state.key);
                            let leaves = crate::presence::recompute(
                                &presence,
                                &decision_makers,
                                &state.key,
                                &held,
                            );
                            broadcast_leaves(&sessions, &mesh_links, &state.key, leaves);
                            // A promotion here may also make this relay the one to
                            // observe full slot presence: re-evaluate and fire the
                            // session-start directive if it now covers the expected
                            // set (idempotent for already-started sessions).
                            routing::maybe_start_session(
                                &sessions,
                                &decision_makers,
                                &mesh_links,
                                &state.key,
                            );
                            // The peer's report may have emptied the session
                            // session-wide (the last live relay reporting zero),
                            // arming the abandoned-session timer — or refilled it,
                            // cancelling it.
                            routing::reconcile_abandon(
                                &drop_holds,
                                &decision_makers,
                                &sessions,
                                &mesh_links,
                                &presence,
                                &state.key,
                            );
                        }
                    }
                    None => presence_alive = false,
                }
            }
            // Idle teardown: the link served at least one session, went empty,
            // and stayed empty past `idle_timeout`. An intentional wind-down —
            // not a failure to retry. The `if` guard keeps this branch dormant
            // until `idle_since` is Some (armed after the first Join→empty
            // transition); `idle_deadline`'s day-out fallback makes the guard
            // the sole gate.
            _ = tokio::time::sleep_until(idle_deadline), if idle_since.is_some() => {
                tracing::info!("mesh link idle; closing");
                break MeshLinkExit::Idle;
            }
            command = commands.recv() => {
                match command {
                    Some(MeshCommand::Join(key)) => {
                        let session_id = key.session;
                        if let Some(existing) = joined.get(&session_id)
                            && existing.key.tenant != key.tenant
                        {
                            tracing::error!(
                                session = session_id.0,
                                existing_tenant = existing.key.tenant.as_ref(),
                                new_tenant = key.tenant.as_ref(),
                                "session id collision across tenants; refusing second tenant",
                            );
                            continue;
                        }
                        // Already joined (same tenant): a re-announce is harmless.
                        if joined.contains_key(&session_id) {
                            continue;
                        }
                        link.open_session(session_id);
                        let registration = register_mesh_link(
                            &mesh_links,
                            key.clone(),
                            forward_tx.clone(),
                            control_forward_tx.clone(),
                        );
                        // Re-send this relay's known leave state for the session
                        // down the fresh registration, so a link that died and
                        // redialed (its `joined` empty again) reconverges. All of
                        // these are idempotent (dedup by slot everywhere).
                        reconcile_leaves_on_join(&decision_makers, &control_forward_tx, &key);
                        joined.insert(
                            session_id,
                            SessionState {
                                key,
                                flush_deadline: tokio::time::Instant::now() + routing::FLUSH_INTERVAL,
                                _registration: registration,
                            },
                        );
                        idle_since = None;
                        // Announce this session's presence right away rather
                        // than waiting a flush tick: a fresh join (or a
                        // rejoin on a redialed link, whose `presence_sent`
                        // starts empty) is exactly when the peer knows
                        // nothing yet.
                        if reconcile_presence(
                            &mut presence_tx,
                            &mut presence_sent,
                            &sessions,
                            &joined,
                        )
                        .await
                        .is_err()
                        {
                            tracing::info!("mesh presence push failed; closing link");
                            break MeshLinkExit::ConnectionFailed;
                        }
                        continue;
                    }
                    Some(MeshCommand::Leave(key)) => {
                        let session_id = key.session;
                        // Match the full SessionKey, not just the wire's bare
                        // session id. A colliding cross-tenant Join (same id,
                        // different tenant) was refused at Join time and never
                        // entered `joined`, so a later Leave carrying that
                        // refused key must not evict the tenant that
                        // legitimately holds the id — that would close the wrong
                        // tenant's session and cross-wire the two.
                        if joined.get(&session_id).is_some_and(|state| state.key == key) {
                            // Dropping the removed `SessionState` deregisters this
                            // session's mesh forward channel (its RAII guard).
                            joined.remove(&session_id);
                            link.close_session(session_id);
                            presence_sent.remove(&session_id);
                            // Arm the idle timer when the last session leaves,
                            // so the driver tears the link down after
                            // `idle_timeout` of no further Joins.
                            if joined.is_empty() {
                                idle_since = Some(tokio::time::Instant::now());
                            }
                        }
                        continue;
                    }
                    // The command channel closed: the sender (the relay's
                    // mesh-link manager, or the test) dropped it, signaling
                    // the link should wind down.
                    None => break MeshLinkExit::CommandChannelClosed,
                }
            }
        }
    };

    // No explicit teardown here: each joined session's `SessionState` deregisters
    // its own forward channel when dropped, and `joined` is dropped as this
    // function returns — or when the driver task is cancelled — so the cleanup runs
    // on every exit path.
    exit
}

/// Handles one control frame received from the peer relay over the mesh control
/// stream. Resolves the frame's bare session id to a tenant-scoped key through
/// the same per-link `joined` state the datagram path uses (the collision guard
/// makes that mapping unambiguous), then:
///
/// - **`SlotDeparted`**: records the departure — max-merging the carried last
///   frame with this relay's own observation of the slot (the fuller view wins)
///   and retiring the slot's live state — and, if this relay is the authority,
///   decides the one synced leave, pushing it to local survivors and
///   broadcasting it to every peer (including the origin, harmlessly: it dedups
///   by slot, and may have its own survivors). A non-authority relay records but
///   decides nothing.
/// - **`LeaveDirective`**: caches it (dedup by slot) and fans it out to local
///   survivors. It is **not** re-broadcast across the mesh — the authority already
///   sent it to every relay — so there is no echo.
/// - **`OversizeTurn`**: a turn too large for the peer's datagram path, folded
///   back into the normal turn path exactly as a datagram delivery would be —
///   frame observation, topological dedup, buffer-directive stamping, local
///   fan-out — trusting it like any mesh-carried turn (validated at the origin's
///   client edge, never re-validated at a mesh hop). It too is not re-broadcast
///   to other mesh links: the origin diverted a copy to every link serving the
///   session itself.
/// - **`LobbyCommand`**: a lobby command a peer relay's member authored, already
///   slot-stamped by the origin. Delivered to this relay's local members and
///   appended to this relay's replay log — so a late-dialing local member still
///   gets it — but, like the oversize turn, not re-broadcast across the mesh:
///   the origin already sent a copy to every link serving the session.
/// - **`GameChat`**: a chat message a peer relay's member authored, already
///   slot-stamped by the origin. Delivered to this relay's local members — no
///   log to append to, chat is ephemeral — and, like the lobby command, not
///   re-broadcast across the mesh.
/// - **`RequestDrop`**: a manual drop request a peer relay's member authored,
///   already `requester`-stamped by the origin. Honored only if this relay is the
///   session authority and the target slot's drop has stood past the unlock floor;
///   a non-authority ignores it (the authority is among the broadcast's
///   receivers). Not re-broadcast across the mesh — no echo, like the arms above.
///
/// Kept defensive like the datagram path: a zero session id is malformed and a
/// session this link has not joined has no key to act under; both are logged at
/// debug and skipped (a race with `Join`/`Leave` is possible and benign given the
/// Join-time reconcile).
///
/// Takes the whole `mesh` bundle rather than its individual registries so this
/// signature doesn't grow a new parameter every time a control-frame kind needs
/// another per-session registry (`seen`, `lobby`, and `chat` all live inside it
/// already); `sessions` stays separate because it is not part of `MeshState`.
fn dispatch_mesh_control(
    frame: MeshControlFrame,
    peer_id: RelayId,
    joined: &HashMap<SessionId, SessionState>,
    sessions: &routing::Sessions,
    mesh: &MeshState,
) {
    if frame.session == 0 {
        tracing::debug!("mesh control frame with zero session id; dropping");
        return;
    }
    let session_id = SessionId(frame.session);
    let Some(state) = joined.get(&session_id) else {
        tracing::debug!(
            session = session_id.0,
            "mesh control frame for unjoined session; dropping",
        );
        return;
    };
    let key = state.key.clone();

    match frame.kind {
        Some(mesh_control_frame::Kind::SlotDeparted(departed)) => {
            let Ok(slot) = u8::try_from(departed.slot).map(SlotId) else {
                // A slot id past `u8` range names no real slot; a silent
                // truncation would alias it onto a valid one. Drop the frame
                // (defensive — wire values are validated upstream).
                tracing::warn!(
                    session = session_id.0,
                    slot = departed.slot,
                    "mesh SlotDeparted names a slot id out of range; dropping",
                );
                return;
            };
            // The departure record max-merges the carried last frame with this
            // relay's own observation of the slot, so the fuller view drives the
            // apply frame — and recording retires the slot's live state, letting
            // the session frame follow the survivors. A non-empty result payload
            // means the home relay embedded the slot's end-of-game result; fold it
            // into the record (first non-`None` wins) so this relay's own
            // departure notice can carry it too.
            let result = (!departed.result_payload.is_empty()).then(|| ResultEcho {
                payload: departed.result_payload.to_vec(),
                arrival_ms: departed.result_arrival_ms,
                session_frame: departed.result_session_frame,
                slot_frame: departed.result_slot_frame,
            });
            crate::consensus::record_departure(
                &mesh.decision_makers,
                &key,
                slot,
                departed
                    .last_frame
                    .map(rally_point_proto::ids::GameFrameCount),
                departed.reachable_frame,
                result,
                departed.reason,
            );
            // Turn the departure into the one synced leave — marking a *drop* as an
            // undecided hold (decided later only by an honored `RequestDrop`, or
            // never) and deciding a *clean* leave at once (which also releases any
            // hold this slot's earlier drop marked, the clean-intent-during-hold
            // ordering). A drop decides nothing here; a clean leave is a no-op on a
            // non-authority (`decide_leave` returns `None` there) and for an
            // already-decided slot. The departure is recorded above regardless, so a
            // promotion can still re-derive it.
            routing::hold_or_decide_leave(
                &mesh.drop_holds,
                &mesh.decision_makers,
                sessions,
                &mesh.links,
                &key,
                slot,
                departed.reason,
            );
        }
        Some(mesh_control_frame::Kind::LeaveDirective(leave)) => {
            crate::consensus::observe_leave(&mesh.decision_makers, &key, &leave);
            let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
                // Out of `u8` range: `observe_leave` above already ignored it
                // (its own checked conversion); nothing to fan out either.
                tracing::warn!(
                    session = session_id.0,
                    slot = leave.slot,
                    "mesh LeaveDirective names a slot id out of range; dropping",
                );
                return;
            };
            routing::fan_out_leave(sessions, &key, slot, leave);
        }
        Some(mesh_control_frame::Kind::OversizeTurn(payload)) => {
            let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = payload.slot,
                    "mesh OversizeTurn names a slot id out of range; dropping",
                );
                return;
            };
            // The same receive step a datagram-delivered mesh turn runs: a
            // validated remote slot's frame observation, then the shared local
            // delivery (dedup, stamp, local fan-out). Delivery below the fan-out
            // needs nothing new — a slot link whose client's path can't take the
            // turn diverts it onto that client's own control stream.
            if let Some(frame) = payload.game_frame_count {
                crate::consensus::observe_turn_frame(
                    &mesh.decision_makers,
                    &key,
                    slot,
                    payload.seq,
                    rally_point_proto::ids::GameFrameCount(frame),
                    crate::delivery::DeliveryHome::Peer(peer_id),
                );
            }
            // NOTE: no desync-comparator call here — `deliver_turn_to_locals`
            // below feeds it, after its own mark_seen dedup, so a redundant
            // control-stream copy (or an echo also seen via a datagram path)
            // isn't double-counted.
            let _ = deliver_turn_to_locals(
                sessions,
                &mesh.seen,
                &mesh.decision_makers,
                &mesh.turn_ring,
                &key,
                slot,
                payload,
            );
        }
        Some(mesh_control_frame::Kind::LobbyCommand(command)) => {
            // A lobby command a peer relay's member authored, already slot-stamped
            // by the origin. Fold it into this relay's local delivery (append to
            // the replay log, fan out to local members — the remote author is not
            // one of them, so every local member receives it). Deliberately NOT
            // re-broadcast across the mesh: the origin already sent a copy to every
            // link serving the session, exactly as with the oversize turn above.
            crate::lobby::deliver(&mesh.lobby, &key, command);
        }
        Some(mesh_control_frame::Kind::GameChat(chat_msg)) => {
            // A chat message a peer relay's member authored, already
            // slot-stamped by the origin — its size and rate caps already
            // applied there, so a mesh copy is trusted, not re-checked (mirrors
            // how a mesh-received lobby command's bytes are not re-validated).
            // No log to append to; deliberately NOT re-broadcast across the
            // mesh, exactly as the lobby command and oversize turn above.
            crate::chat::deliver(&mesh.chat, &key, chat_msg);
        }
        Some(mesh_control_frame::Kind::SlotPresent(present)) => {
            let Ok(slot) = u8::try_from(present.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = present.slot,
                    "mesh SlotPresent names a slot id out of range; dropping",
                );
                return;
            };
            // Accumulate the reported slot into this session's live-slot set. On
            // the authority, full coverage of the expected set fires the one
            // `SessionStart` — fanned to this relay's local slots and broadcast to
            // every peer (including the origin, harmlessly: it latches started and
            // fans to its own locals, but the frame is idempotent). A non-authority
            // relay just records it, for a later promotion.
            if crate::consensus::note_slot_present(&mesh.decision_makers, &key, slot) {
                routing::fan_out_session_start(sessions, &key);
                fan_out_session_start(&mesh.links, &key);
            }
        }
        Some(mesh_control_frame::Kind::SessionStart(_)) => {
            // The authority's session-start directive. Latch the session started —
            // so this relay's own late-registering local slots still get a re-push
            // — and fan it down every current local slot. Deliberately NOT
            // re-broadcast across the mesh: the authority already sent a copy to
            // every link serving the session, so re-flooding would only echo.
            crate::consensus::mark_session_started(&mesh.decision_makers, &key);
            routing::fan_out_session_start(sessions, &key);
        }
        Some(mesh_control_frame::Kind::SlotConnectivity(change)) => {
            let Ok(slot) = u8::try_from(change.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = change.slot,
                    "mesh SlotConnectivity names a slot id out of range; dropping",
                );
                return;
            };
            // A peer relay's home client's link changed. Fan it down this relay's
            // local slots so their connectivity displays reflect it. Deliberately
            // NOT re-broadcast across the mesh: the origin already sent a copy to
            // every peer, so re-flooding would only echo (mirroring chat above).
            routing::fan_out_connectivity(sessions, &key, slot, change.connected);
            // A `connected` of true is a slot coming *back* — a client that
            // re-registered on the origin relay while its drop was still undecided.
            // This relay marked its own hold on the slot's earlier `SlotDeparted`, so
            // claim it: the symmetric "it's back" signal that reaches a peer-homed
            // authority (or any peer holding a marker) so the drop can never later be
            // honored. A no-op when no hold is pending — a fresh connect, or a slot
            // this relay never held.
            //
            // Claims and reinstates atomically (`take_if_pending`), mirroring the
            // home relay's own re-register (`server.rs`), rather than the separate
            // release-then-reinstate this used to be: this relay may itself be the
            // session's authority, in which case a concurrent `RequestDrop` (or the
            // abandoned-session force-decide) for the same slot races this exactly
            // the way it races a re-register, and the hold's removal must be the
            // one linearization point both sides claim against so only one of them
            // ever acts. The claim's own success/failure needs no further handling
            // here — this relay isn't making an admission decision, only mirroring
            // the origin's; `reinstate_slot`'s effect (or lack of one, if a
            // concurrent decide already won) is what matters.
            if change.connected {
                let _ = mesh.drop_holds.take_if_pending(&key, slot, || {
                    crate::consensus::reinstate_slot(&mesh.decision_makers, &key, slot)
                });
            }
        }
        Some(mesh_control_frame::Kind::RequestDrop(request)) => {
            let Ok(target) = u8::try_from(request.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = request.slot,
                    "mesh RequestDrop names a slot id out of range; dropping",
                );
                return;
            };
            // A manual drop request one peer relay's surviving member authored,
            // already `requester`-stamped by the origin. Honor it only if this relay
            // is the session authority and the target's drop has stood past the
            // unlock floor; otherwise ignore it. Deliberately NOT re-broadcast across
            // the mesh — the origin already sent a copy to every peer, so the
            // authority is among the receivers and re-flooding would only echo (the
            // same no-echo rule the chat and leave arms follow).
            routing::honor_drop_request(
                &mesh.drop_holds,
                &mesh.decision_makers,
                sessions,
                &mesh.links,
                &key,
                target,
                request.requester,
            );
        }
        Some(mesh_control_frame::Kind::DeliveryCursors(delivery)) => {
            // A peer-homed destination's delivered-through cursors: fold each
            // pair into the session's end-to-end delivery tracking. The mesh
            // link the frame arrived on IS the destination's home relay (the
            // same inference the origin side uses), and the fold ignores
            // regressing cursors, so a reordered share is harmless. Never
            // re-broadcast — the home relay sent a copy to every session peer.
            let Ok(dest) = u8::try_from(delivery.dest_slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = delivery.dest_slot,
                    "mesh DeliveryCursors names a dest slot id out of range; dropping",
                );
                return;
            };
            for cursor in &delivery.cursors {
                let Ok(origin) = u8::try_from(cursor.origin_slot).map(SlotId) else {
                    continue;
                };
                crate::consensus::observe_delivery(
                    &mesh.decision_makers,
                    &key,
                    dest,
                    origin,
                    cursor.delivered_seq,
                    crate::delivery::DeliveryHome::Peer(peer_id),
                );
            }
        }
        // A kind this build predates (or the empty keepalive, already dropped by
        // the reader): nothing to do.
        None => {
            tracing::debug!(
                session = session_id.0,
                "unknown mesh control frame kind; skipping"
            );
        }
    }
}

/// Re-sends this relay's known leave state for `key` down a freshly registered
/// link's control channel, so a link that died and redialed converges. Every
/// recorded departure goes out as a `SlotDeparted` and every cached directive as
/// a `LeaveDirective`, unconditionally — a leave is pushed once at decision time
/// and re-pushed on every link re-join (and on an authority promotion); the relay
/// has no sound way to tell "every survivor applied it" from "every survivor is
/// still stalled waiting for it", so it never tries. All idempotent (dedup by
/// slot on receipt) and cheap — a session has <=12 slots and leaves are rare.
fn reconcile_leaves_on_join(
    decision_makers: &crate::consensus::DecisionMakers,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let (departures, directives) = crate::consensus::leave_reconcile(decision_makers, key);
    // Unbounded send only fails on a closed channel; the driver we are
    // registering into is alive here, so these always enqueue.
    for (slot, last_frame, reachable_frame, result, reason) in departures {
        let _ = control_tx.send(slot_departed_frame(
            key.session,
            slot,
            last_frame.map(|f| f.0),
            reachable_frame,
            result,
            reason,
        ));
    }
    for leave in directives {
        let _ = control_tx.send(leave_directive_frame(key.session, leave));
    }
    // If the session already started, re-send the directive down the fresh link
    // too: a peer relay that dialed in (or redialed) after the authority fired
    // would otherwise never hear it, stranding its local slots. Idempotent — a
    // relay that already started latches it again and re-fans to its own locals.
    if crate::consensus::session_started(decision_makers, key) {
        let _ = control_tx.send(session_start_frame(key.session));
    }
}

/// Pushes each joined session's live home-client count to the peer when it
/// differs from what the peer last heard, reading the truth straight from the
/// slot roster. Push-on-change over a reliable stream: a stable roster writes
/// nothing, and a transition (the handoff trigger) cannot be lost the way a
/// datagram sidecar could — which matters precisely because the relay whose
/// players just left has no datagrams left to ride.
///
/// An `Err` means the stream (and so the connection) is gone; the caller exits
/// with `ConnectionFailed` like any other send failure.
async fn reconcile_presence(
    presence_tx: &mut rally_point_transport::quinn::SendStream,
    presence_sent: &mut HashMap<rally_point_proto::ids::SessionId, u32>,
    sessions: &routing::Sessions,
    joined: &HashMap<rally_point_proto::ids::SessionId, SessionState>,
) -> Result<(), rally_point_transport::quinn::WriteError> {
    for (&session_id, state) in joined {
        let live = {
            let roster = sessions.lock();
            roster.get(&state.key).map_or(0, |slots| slots.len() as u32)
        };
        if presence_sent.get(&session_id) == Some(&live) {
            continue;
        }
        let frame = rally_point_proto::mesh::MeshPresence {
            session: session_id,
            live_players: live,
        }
        .encode();
        presence_tx.write_all(&frame).await?;
        presence_sent.insert(session_id, live);
    }
    Ok(())
}

/// One session's per-link driver state: its routing key (tenant-correct), its own
/// flush deadline (independent per session — one game's flush cadence doesn't reset
/// another's), and the RAII guard that deregisters its mesh forward channel.
struct SessionState {
    key: SessionKey,
    flush_deadline: tokio::time::Instant,
    /// Deregisters this session's mesh forward channel when the `SessionState` is
    /// dropped — on a `Leave`, a normal wind-down, or the driver task being
    /// cancelled. Never read; its `Drop` is the point.
    _registration: MeshLinkRegistration,
}

/// An RAII guard tying a session's mesh forward-channel registration to the
/// lifetime of its [`SessionState`]. Dropping it deregisters the channel, so the
/// registration is torn down on *every* exit from [`run_mesh_link`]: a `Leave`
/// removes the `SessionState`; a normal wind-down or a **cancelled** driver task (a
/// dialer retargeting or removing this peer drops the whole driver future) drops the
/// `joined` map. Without it, task cancellation would skip the cleanup and leave a
/// dead forward channel in `mesh.links` for a session this link no longer serves —
/// a leak, since session ids are never reused.
struct MeshLinkRegistration {
    links: MeshLinks,
    key: SessionKey,
    /// The registered channel's id, so the guard removes only this link's entry
    /// from the session's fan-out vec — never the peers still serving it.
    id: u64,
}

impl Drop for MeshLinkRegistration {
    fn drop(&mut self) {
        deregister_mesh_link(&self.links, &self.key, self.id);
    }
}

/// Converts a QUIC smoothed-RTT estimate to the conditions sidecar's `u32`
/// microseconds. The single conversion both sampling sites share — the mesh
/// link's backbone hop and the slot link's client path in `routing` — so the
/// convention stays in one place: a connection with no RTT sample yet reports
/// `0` ("no measurement", never "zero latency"), clamped to the field width.
pub(crate) fn rtt_us(rtt: std::time::Duration) -> u32 {
    rtt.as_micros().min(u32::MAX as u128) as u32
}

/// The mesh link's smoothed round-trip time in microseconds — the hop across
/// the backbone a remote slot's turns travel, added to each remote slot's
/// effective path in the decision-maker.
fn link_rtt_us(connection: &rally_point_transport::quinn::Connection) -> u32 {
    rtt_us(connection.stats().path.rtt)
}

/// Validates a list of sessions for a mesh link, refusing if two tenants share
/// the same session id — the wire's bare `session: u64` can't disambiguate them,
/// so the second is refused rather than overwriting the first.
///
/// A batch pre-validation helper: a caller that collected a session list before
/// driving the link can refuse the whole batch at once. `run_mesh_link` runs the
/// same check on every `Join`, so a caller that sends sessions one at a time —
/// or skips this helper — still can't silently cross-wire tenants.
pub fn join_sessions(links: &MeshLinks, keys: &[SessionKey]) -> Result<(), SessionIdCollision> {
    let mut roster = links.lock();
    let mut seen: HashMap<
        rally_point_proto::ids::SessionId,
        &rally_point_proto::control::TenantId,
    > = HashMap::new();
    for key in keys {
        if let Some(existing_tenant) = seen.get(&key.session)
            && **existing_tenant != key.tenant
        {
            return Err(SessionIdCollision {
                session: key.session,
                existing_tenant: (*existing_tenant).clone(),
                new_tenant: key.tenant.clone(),
            });
        }
        seen.insert(key.session, &key.tenant);
        roster.entry(key.clone()).or_default();
    }
    Ok(())
}

/// A session id collision: the wire's bare `session: u64` can't disambiguate
/// two tenants that both assigned the same number. The second join is refused.
#[derive(Debug, thiserror::Error)]
#[error(
    "session id {session} collision: already joined by tenant {existing_tenant:?}, refused for {new_tenant:?}"
)]
pub struct SessionIdCollision {
    pub session: rally_point_proto::ids::SessionId,
    pub existing_tenant: rally_point_proto::control::TenantId,
    pub new_tenant: rally_point_proto::control::TenantId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_first_delivery_new_and_redelivery_duplicate() {
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::Duplicate);
    }

    #[test]
    fn keeps_slots_independent() {
        let mut seen = MeshSeen::new();
        // Two slots both have seq 0; both are new — identity is (slot, seq).
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(1), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
        assert_eq!(seen.mark_forwarded(SlotId(1), 0), Seen::Duplicate);
    }

    #[test]
    fn collapses_out_of_order_arrival() {
        // A turn arrives via path A at seq 3 (gap at 1, 2), then via path B at
        // seq 0. Seq 3 is new; seq 0 is new (it fills the gap). A second copy of
        // seq 3 via path B is a duplicate.
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 3), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 2), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 3), Seen::Duplicate);
    }

    #[test]
    fn drops_late_redundant_copy_below_prefix() {
        // After forwarding 0..3, a late redundant copy of seq 0 arriving via a
        // second path is dropped as below the prefix.
        let mut seen = MeshSeen::new();
        for seq in 0..4 {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
    }

    #[test]
    fn conditions_registry_snapshot_unpublish_contract() {
        // snapshot returns slots sorted by slot id (deterministic diff order),
        // None when the session has no published conditions. unpublish removes
        // a slot, and when the last slot leaves, the session's entry is gone
        // (no stale empty key lingering). Covers the registry's own contract
        // independent of the transport round-trip tests.
        let registry = new_conditions_registry();
        let key = SessionKey {
            tenant: rally_point_proto::control::TenantId("t".to_owned()),
            session: rally_point_proto::ids::SessionId(1),
        };

        // No local clients yet: no conditions.
        assert!(snapshot_conditions(&registry, &key).is_none());

        // Publish two slots out of order; snapshot sorts them by slot.
        publish_conditions(
            &registry,
            &key,
            SlotId(1),
            SlotConditions {
                slot: 1,
                rtt_us: 45_000,
                lost_packets: 10,
                sent_packets: 500,
            },
        );
        publish_conditions(
            &registry,
            &key,
            SlotId(0),
            SlotConditions {
                slot: 0,
                rtt_us: 12_000,
                lost_packets: 3,
                sent_packets: 1000,
            },
        );

        let snap = snapshot_conditions(&registry, &key).expect("two slots published");
        assert_eq!(snap.slots.len(), 2);
        assert_eq!(snap.slots[0].slot, 0, "sorted by slot");
        assert_eq!(snap.slots[1].slot, 1, "sorted by slot");

        // Unpublish one: snapshot now has a single slot.
        unpublish_conditions(&registry, &key, SlotId(0));
        let snap = snapshot_conditions(&registry, &key).expect("one slot remains");
        assert_eq!(snap.slots.len(), 1);
        assert_eq!(snap.slots[0].slot, 1);

        // Unpublish the last: snapshot is None again, and the session's entry
        // was removed (re-publishing a fresh slot starts clean, not appended).
        unpublish_conditions(&registry, &key, SlotId(1));
        assert!(snapshot_conditions(&registry, &key).is_none());
    }

    #[test]
    fn join_sessions_refuses_a_colliding_session_id_across_tenants() {
        // The wire carries a bare session id with no tenant. Two tenants that
        // both assigned session id 1 can't be told apart on recv, so the second
        // join is refused rather than overwriting the first.
        let links = new_mesh_links();
        let tenant_a = rally_point_proto::control::TenantId("tenant-a".to_owned());
        let tenant_b = rally_point_proto::control::TenantId("tenant-b".to_owned());
        let key_a = SessionKey {
            tenant: tenant_a.clone(),
            session: rally_point_proto::ids::SessionId(1),
        };
        let key_b = SessionKey {
            tenant: tenant_b.clone(),
            session: rally_point_proto::ids::SessionId(1),
        };

        // Same tenant, same session id: not a collision (the game rejoins).
        join_sessions(&links, std::slice::from_ref(&key_a)).expect("same tenant is fine");

        // Different tenant, same session id: collision — refuse.
        let err = join_sessions(&links, &[key_a.clone(), key_b]).unwrap_err();
        assert_eq!(err.session, rally_point_proto::ids::SessionId(1));
        assert_eq!(err.existing_tenant, tenant_a);
        assert_eq!(err.new_tenant, tenant_b);
    }

    fn control_key() -> SessionKey {
        SessionKey {
            tenant: rally_point_proto::control::TenantId("t".to_owned()),
            session: SessionId(1),
        }
    }

    /// Registers one link's `(forward, control)` pair into the mesh-links registry
    /// and returns the receivers a test drains to observe what the link was told.
    fn register_link_channels(
        links: &MeshLinks,
        key: &SessionKey,
    ) -> (
        mpsc::Receiver<(SessionId, Payload)>,
        mpsc::UnboundedReceiver<MeshControlFrame>,
    ) {
        let (forward, forward_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (control, control_rx) = mpsc::unbounded_channel();
        links
            .lock()
            .entry(key.clone())
            .or_default()
            .push(MeshLinkTx {
                id: next_mesh_link_id(),
                forward,
                control,
            });
        (forward_rx, control_rx)
    }

    /// Bundles the registries a `dispatch_mesh_control` test already built
    /// (so it can register members and observe echoes against them) into the
    /// `MeshState` its signature now takes. `conditions` and `presence` are not
    /// under test here, so fresh empty ones are enough.
    fn test_mesh_state(
        mesh_links: &MeshLinks,
        seen: &SeenRegistries,
        makers: &Arc<crate::consensus::DecisionMakers>,
        lobby: &crate::lobby::LobbyRegistry,
        chat: &crate::chat::ChatRegistry,
    ) -> MeshState {
        MeshState {
            links: mesh_links.clone(),
            seen: seen.clone(),
            conditions: new_conditions_registry(),
            decision_makers: makers.clone(),
            presence: Arc::new(crate::presence::new_presence_registry()),
            lobby: lobby.clone(),
            chat: chat.clone(),
            // A zero unlock floor so a held drop is "past the floor" from the first
            // instant, letting a `RequestDrop` dispatch test drive the honor path
            // without a real wait. Tests that only hold and release a drop are
            // unaffected by the floor. The abandoned-session window keeps its
            // production value — no dispatch test drives that path.
            drop_holds: crate::drop_hold::DropHolds::new(
                std::time::Duration::ZERO,
                crate::drop_hold::ABANDONED_SESSION_TIMEOUT,
            ),
            turn_ring: crate::turn_ring::TurnRing::new(),
        }
    }

    /// Deregistering one peer relay's mesh link for a session must leave every
    /// other peer's registration for that session intact. Regression: a session's
    /// whole fan-out vec was once removed on any single link's teardown, so a
    /// `Leave` to (or cancellation of) one peer's driver silently cut turns and
    /// synced-leave frames to every *other* peer's clients.
    #[test]
    fn deregister_one_mesh_link_leaves_the_other_peers_registration() {
        let links = new_mesh_links();
        let key = control_key();

        // Two peer relays mesh the same session: each registers its own fan-out
        // entry, so the session's vec holds one element per peer.
        let (peer_b_fwd, mut peer_b_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (peer_b_ctl, _peer_b_ctl_rx) = mpsc::unbounded_channel();
        let reg_b = register_mesh_link(&links, key.clone(), peer_b_fwd, peer_b_ctl);

        let (peer_c_fwd, mut peer_c_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (peer_c_ctl, _peer_c_ctl_rx) = mpsc::unbounded_channel();
        let reg_c = register_mesh_link(&links, key.clone(), peer_c_fwd, peer_c_ctl);

        assert_eq!(
            links.lock().get(&key).map(Vec::len),
            Some(2),
            "both peers registered for the session",
        );

        // Peer B's driver winds down (a `Leave`, or the task being cancelled):
        // its RAII guard drops and deregisters — but only its own entry.
        drop(reg_b);
        assert_eq!(
            links.lock().get(&key).map(Vec::len),
            Some(1),
            "only peer B's entry was removed; peer C survives",
        );

        // Fan-out still reaches the surviving peer C, and not the removed peer B.
        let payload = Payload {
            seq: 7,
            slot: 1,
            ..Default::default()
        };
        fan_out_to_mesh(&links, &key, payload);
        let (session, got) = peer_c_rx.try_recv().expect("peer C is still reached");
        assert_eq!(session, key.session);
        assert_eq!(got.seq, 7);
        assert!(
            peer_b_rx.try_recv().is_err(),
            "peer B was deregistered and gets nothing",
        );

        // Dropping the last registration empties the key entirely — no stale
        // empty vec left behind.
        drop(reg_c);
        assert!(
            links.lock().get(&key).is_none(),
            "the session key is removed once its last link deregisters",
        );
    }

    /// `fan_out_control` reaches every link serving the session (with the frame's
    /// session stamped), and a link whose driver has exited (closed channel) is
    /// tolerated without disturbing the healthy ones.
    #[test]
    fn fan_out_control_reaches_every_link_and_tolerates_a_closed_channel() {
        let links = new_mesh_links();
        let key = control_key();
        let (_fwd1, mut ctl1) = register_link_channels(&links, &key);
        let (_fwd2, mut ctl2) = register_link_channels(&links, &key);

        fan_out_slot_departed(&links, &key, SlotId(2), Some(41), Some(38), None, 3);
        for rx in [&mut ctl1, &mut ctl2] {
            let frame = rx.try_recv().expect("every link is told");
            assert_eq!(
                frame.session, 1,
                "the frame is stamped with the key's session"
            );
            match frame.kind {
                Some(mesh_control_frame::Kind::SlotDeparted(sd)) => {
                    assert_eq!(sd.slot, 2);
                    assert_eq!(sd.last_frame, Some(41));
                    assert_eq!(sd.reason, 3);
                }
                other => panic!("expected SlotDeparted, got {other:?}"),
            }
        }

        // The second link's driver exits (receiver dropped): the next fan-out
        // tolerates the closed channel and still reaches the healthy first link.
        drop(ctl2);
        let leave = LeaveDirective {
            slot: 2,
            reason: 3,
            apply_at_frame: 42,
            leave_seq: 1,
        };
        fan_out_leave_directive(&links, &key, leave);
        match ctl1.try_recv().expect("the live link still gets it").kind {
            Some(mesh_control_frame::Kind::LeaveDirective(got)) => assert_eq!(got, leave),
            other => panic!("expected LeaveDirective, got {other:?}"),
        }
    }

    /// A `Join`-time reconcile re-sends this relay's known leave state for the
    /// session down the freshly registered link: a `SlotDeparted` for each
    /// recorded departure and a `LeaveDirective` for each cached leave — so a
    /// link that died and redialed reconverges.
    #[test]
    fn reconcile_leaves_on_join_re_announces_known_state() {
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let makers = Arc::new(crate::consensus::new_decision_makers());
        let key = control_key();
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        // The authority decided one slot's leave (caches a directive and records a
        // departure), and separately recorded a bare departure for another slot.
        crate::consensus::observe_frame(&makers, &key, SlotId(1), GameFrameCount(50));
        let leave = crate::consensus::decide_leave(&makers, &key, SlotId(1), 3)
            .expect("the authority decides slot 1's leave");
        crate::consensus::record_departure(
            &makers,
            &key,
            SlotId(2),
            Some(GameFrameCount(60)),
            None,
            None,
            0x4000_0006,
        );

        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        reconcile_leaves_on_join(&makers, &control_tx, &key);

        let mut departed = Vec::new();
        let mut directives = Vec::new();
        while let Ok(frame) = control_rx.try_recv() {
            assert_eq!(frame.session, 1);
            match frame.kind {
                Some(mesh_control_frame::Kind::SlotDeparted(sd)) => departed.push(sd.slot),
                Some(mesh_control_frame::Kind::LeaveDirective(d)) => directives.push(d),
                other => panic!("unexpected reconcile frame {other:?}"),
            }
        }
        departed.sort_unstable();
        assert_eq!(departed, vec![1, 2], "both departures re-announced");
        assert_eq!(
            directives,
            vec![leave],
            "the cached leave re-announced verbatim"
        );
    }

    /// An oversize turn arriving over the mesh control stream folds back into
    /// the normal receive path — its frame feeds the consensus coordinate and
    /// the topological dedup marks it delivered (so a copy arriving by any
    /// other path is dropped) — and it is NOT re-broadcast to other mesh links:
    /// the origin relay diverted a copy to every link itself, so re-flooding
    /// would only echo. (Actual delivery to a local client link is covered by
    /// the end-to-end mesh test; the slot inbox is private to `routing`.)
    #[test]
    fn an_oversize_turn_dispatch_marks_seen_observes_and_never_echoes() {
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let key = control_key();
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );

        // A peer mesh link that must NOT hear an echo of the received turn.
        let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

        // The per-link joined state the dispatch resolves the bare session
        // id through, as the driver would hold it after a Join.
        let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );

        let payload = Payload {
            seq: 0,
            slot: 0,
            commands: vec![0xAB; 5000].into(),
            game_frame_count: Some(7),
            ..Default::default()
        };
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::OversizeTurn(payload)),
        };
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        // The remote slot's frame fed the consensus coordinate, exactly as a
        // datagram-delivered turn's would.
        assert_eq!(
            crate::consensus::slot_frame(&makers, &key, SlotId(0)),
            Some(GameFrameCount(7)),
        );
        // The turn was marked in the topological dedup: a copy arriving by any
        // other path is a duplicate now.
        assert_eq!(
            mark_seen(&seen, &key, SlotId(0), 0),
            Seen::Duplicate,
            "the dispatch delivered (and marked) the turn",
        );
        // No echo: neither a datagram forward nor a control frame went back out
        // to the mesh.
        assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
        assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
    }

    /// A lobby command arriving over the mesh control stream is folded into this
    /// relay's local delivery — appended to the replay log and fanned to local
    /// members — and NOT re-broadcast to other mesh links: the origin relay
    /// already sent a copy to every link serving the session, so re-flooding would
    /// only echo. Mirrors the oversize-turn dispatch test.
    #[test]
    fn a_lobby_command_dispatch_delivers_locally_and_never_echoes() {
        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();

        // A local member on this relay (slot 5) that must receive the mesh command.
        let mut member = crate::lobby::register_member(&lobby, &key, SlotId(5));
        // A peer mesh link that must NOT hear an echo of the received command.
        let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

        let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );

        // A command a remote member (slot 0) authored, already slot-stamped.
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::LobbyCommand(LobbyCommand {
                slot: 0,
                payload: vec![0xAB].into(),
            })),
        };
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        // The local member received the command with the origin's authoritative slot.
        let delivered = member.try_recv().expect("the local member received it");
        assert_eq!(delivered.slot, 0);
        assert_eq!(delivered.payload.as_ref(), &[0xAB]);
        // No echo back out to the mesh on either path.
        assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
        assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
    }

    /// A game-chat message arriving over the mesh control stream is folded into
    /// this relay's local delivery — fanned to local members, no log to append
    /// to — and NOT re-broadcast to other mesh links: the origin relay already
    /// sent a copy to every link serving the session, so re-flooding would only
    /// echo. Mirrors the lobby-command dispatch test.
    #[test]
    fn a_game_chat_dispatch_delivers_locally_and_never_echoes() {
        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();

        // A local member on this relay (slot 5) that must receive the mesh message.
        let mut member = crate::chat::register_member(&chat, &key, SlotId(5));
        // A peer mesh link that must NOT hear an echo of the received message.
        let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

        let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );

        // A message a remote member (slot 0) authored, already slot-stamped.
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::GameChat(GameChat {
                slot: 0,
                target_kind: 2,
                target_slot: 0,
                text: "hi from relay A".to_owned(),
            })),
        };
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        // The local member received the message with the origin's authoritative
        // slot, and its scope fields intact — the relay never interprets them.
        let delivered = member.try_recv().expect("the local member received it");
        assert_eq!(delivered.slot, 0);
        assert_eq!(delivered.target_kind, 2);
        assert_eq!(delivered.text, "hi from relay A");
        // No echo back out to the mesh on either path.
        assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
        assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
    }

    /// A slot-connectivity change arriving over the mesh control stream is fanned
    /// to this relay's local slots and NOT re-broadcast to other mesh links: the
    /// origin relay already sent a copy to every peer, so re-flooding would only
    /// echo. Mirrors the lobby/chat dispatch tests, but the local recipient is a
    /// routing slot (connectivity is a client-edge concern, not a lobby/chat one).
    #[test]
    fn a_slot_connectivity_dispatch_fans_to_local_slots_and_never_echoes() {
        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();

        // A local routing slot (slot 5) that must receive the fanned change.
        let (mut guard, mut inbox) =
            routing::register(&sessions, &key, SlotId(5)).expect("slot 5 registers");
        guard.disarm();
        // A peer mesh link that must NOT hear an echo of the received change.
        let (mut echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);

        let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );

        // A remote relay reports its home client (slot 0) lost its link.
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SlotConnectivity(
                SlotConnectivity {
                    slot: 0,
                    connected: false,
                },
            )),
        };
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        // The local slot heard the change, naming the disconnected subject slot.
        assert_eq!(
            inbox.try_recv_connectivity(),
            Some((SlotId(0), false)),
            "the mesh connectivity change fanned to the local slot",
        );
        // No echo back out to the mesh on either path.
        assert!(echo_fwd_rx.try_recv().is_err(), "no datagram-path echo");
        assert!(echo_ctl_rx.try_recv().is_err(), "no control-stream echo");
    }

    /// A `SlotConnectivity{connected: true}` arriving over the mesh is a slot coming
    /// back: a client that re-registered on a peer relay while its drop was still
    /// undecided. This relay marked its own hold on the earlier `SlotDeparted`, so
    /// the "it's back" signal must release that hold — the symmetric mesh half of
    /// the reconnect release, which is what stops a peer-homed authority from ever
    /// honoring a drop for a slot that has already resumed elsewhere.
    #[tokio::test]
    async fn a_mesh_slot_connectivity_true_releases_a_local_drop_hold() {
        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();

        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);

        // This relay observed slot 0 drop and marked a hold on its leave. A hold
        // never fires on its own — the release is what clears it.
        mesh_state.drop_holds.hold(key.clone(), SlotId(0));
        assert!(
            mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "the drop marked a hold",
        );

        let mut joined: HashMap<SessionId, SessionState> = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );

        // The peer relay reports slot 0 back — it re-registered there while its drop
        // was still undecided.
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SlotConnectivity(
                SlotConnectivity {
                    slot: 0,
                    connected: true,
                },
            )),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        assert!(
            !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "the it's-back signal released the held drop",
        );
    }

    /// Registers a single joined-session state for a mesh dispatch test, resolving
    /// the frame's bare session id to `key` exactly as a post-`Join` driver would.
    fn joined_state(mesh_links: &MeshLinks, key: &SessionKey) -> HashMap<SessionId, SessionState> {
        let mut joined = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: MeshLinkRegistration {
                    links: mesh_links.clone(),
                    key: key.clone(),
                    id: next_mesh_link_id(),
                },
            },
        );
        joined
    }

    /// A `RequestDrop` arriving over the mesh at the session authority, for a slot
    /// whose drop is past the unlock floor, decides the leave: the hold is released
    /// and a `LeaveDirective` for the target is broadcast to the peer links — and
    /// the request itself is NOT re-broadcast (no echo).
    #[tokio::test]
    async fn a_mesh_request_drop_at_the_authority_decides_the_leave_and_never_echoes() {
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        // The target slot dropped: a frame basis for its leave, a recorded departure,
        // and a hold this relay marked. `test_mesh_state` uses a zero unlock floor,
        // so the hold is "past the floor" from the first instant.
        crate::consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(50));
        crate::consensus::record_departure(
            &makers,
            &key,
            SlotId(0),
            Some(GameFrameCount(50)),
            None,
            None,
            0x4000_0006,
        );

        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        mesh_state.drop_holds.hold(key.clone(), SlotId(0));

        // A peer mesh link, to observe the decided leave broadcast and prove the
        // request was not re-broadcast.
        let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);
        let joined = joined_state(&mesh_links, &key);

        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
                slot: 0,
                requester: 3,
            })),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        assert!(
            !mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "the honored request released the hold",
        );
        let mut saw_leave = false;
        while let Ok(frame) = echo_ctl_rx.try_recv() {
            match frame.kind {
                Some(mesh_control_frame::Kind::LeaveDirective(directive)) => {
                    assert_eq!(directive.slot, 0);
                    assert_eq!(
                        directive.reason, 0x4000_0006,
                        "a manual drop uses the dropped reason"
                    );
                    saw_leave = true;
                }
                Some(mesh_control_frame::Kind::RequestDrop(_)) => {
                    panic!("the request must not be re-broadcast across the mesh")
                }
                other => panic!("unexpected mesh frame {other:?}"),
            }
        }
        assert!(saw_leave, "the authority decided and broadcast the leave");
    }

    /// A `RequestDrop` arriving over the mesh at a non-authority relay does nothing:
    /// the hold stays, no leave is decided, and nothing is echoed back out — the
    /// authority is a different relay among the broadcast's receivers.
    #[tokio::test]
    async fn a_mesh_request_drop_at_a_non_authority_does_nothing() {
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        crate::consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(50));
        crate::consensus::record_departure(
            &makers,
            &key,
            SlotId(0),
            Some(GameFrameCount(50)),
            None,
            None,
            0x4000_0006,
        );

        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        mesh_state.drop_holds.hold(key.clone(), SlotId(0));

        let (_echo_fwd_rx, mut echo_ctl_rx) = register_link_channels(&mesh_links, &key);
        let joined = joined_state(&mesh_links, &key);

        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::RequestDrop(RequestDrop {
                slot: 0,
                requester: 3,
            })),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);

        assert!(
            mesh_state.drop_holds.is_pending(&key, SlotId(0)),
            "a non-authority leaves the hold standing",
        );
        assert!(
            echo_ctl_rx.try_recv().is_err(),
            "a non-authority decides nothing and echoes nothing",
        );
    }

    /// Builds a single-command turn payload carrying one `0x37` sync command
    /// (`ring` = the ordinal mod 16), plus a made-up `game_frame_count`.
    fn sync_payload(seq: u64, slot: u8, ordinal: u8, value: [u8; 5]) -> Payload {
        let mut commands = vec![0x37u8, (slot << 4) | (ordinal % 16)];
        commands.extend_from_slice(&value);
        Payload {
            seq,
            slot: u32::from(slot),
            commands: commands.into(),
            game_frame_count: Some(1000 + u32::from(ordinal)),
            ..Default::default()
        }
    }

    /// The desync comparator must observe each distinct `(slot, seq)` turn
    /// exactly once, even though the mesh legitimately delivers the same turn
    /// to the authority via more than one path. `deliver_turn_to_locals` is
    /// the one choke point every turn-delivery path funnels through (client
    /// edge, mesh datagram, mesh oversize), so the comparator's feed lives
    /// there, right after the `mark_seen` dedup — this proves a redelivered
    /// duplicate doesn't reach it twice (which would silently drift the
    /// slot's ordinal count and eventually misalign an otherwise-honest
    /// comparison into a false desync).
    #[test]
    fn duplicate_turn_delivery_does_not_double_count_the_desync_comparator() {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;

        let sessions = routing::Sessions::default();
        let seen = new_seen_registries();
        let decision_makers = Arc::new(consensus::new_decision_makers());
        let turn_ring = crate::turn_ring::TurnRing::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        decision_makers.set_notice_notifier(tx);
        let key = control_key();
        let _ = consensus::sync_maker(
            &decision_makers,
            &key,
            BufferBounds::new(1, 6).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );

        // Slot 0's very first turn (seq 0, sync ordinal 0), delivered TWICE at
        // the exact choke point every mesh path funnels through — simulating
        // the legitimate multi-relay redundant flood, not a sender bug.
        let value = [1, 2, 3, 4, 5];
        let first = sync_payload(0, 0, 0, value);
        assert!(
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                first.clone()
            )
            .is_some(),
            "the first delivery is fresh",
        );
        assert!(
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                first
            )
            .is_none(),
            "the redelivery is caught by mark_seen and never reaches the comparator",
        );

        // Slot 1 agrees at ordinal 0, then both slots race forward in
        // lockstep agreement far enough to clear the comparator's evaluation
        // margin. If the duplicate above had been double-counted, slot 0's
        // internal ordinal count would run one ahead of its true progress and
        // this honest agreement would eventually misalign into a false
        // mismatch.
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(1),
            sync_payload(0, 1, 0, value),
        );
        for ordinal in 1..12u8 {
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                sync_payload(u64::from(ordinal), 0, ordinal, value),
            );
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(1),
                sync_payload(u64::from(ordinal), 1, ordinal, value),
            );
        }

        assert!(
            rx.try_recv().is_err(),
            "no desync notice: the duplicate delivery did not perturb ordinal alignment",
        );
    }
}
