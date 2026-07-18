//! The relay mesh: peer-relay links and session-level topological dedup.
//!
//! A relay's client edge ([`routing`]) fans each validated turn out to the
//! session's local slots. The mesh adds a second fan-out path: to connected peer
//! relays, so a turn one relay receives from a local client reaches every other
//! relay's local clients too. Each relay↔relay link is a
//! [`MeshLink`](rally_point_transport::MeshLink) — one QUIC
//! connection shared across every game both relays jointly serve, with per-session
//! transport state.
//!
//! Because a turn can reach a relay by more than one mesh path (A→B directly, and
//! A→C→B), the relay dedups **topologically**: it forwards each turn to its local
//! clients exactly once, on whichever copy arrives first. [`MeshSeen`] is that
//! session-level dedup — distinct from the per-link `Dedup` on each mesh link,
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
use rally_point_transport::MeshSessionKey;
use tokio::sync::{Notify, mpsc};

use crate::routing::{self, SessionKey};

/// Converts a relay-local [`SessionKey`] into the transport layer's
/// [`MeshSessionKey`] — the lightweight `(session, tenant)` pair `MeshLink`
/// keys its per-session transport state by. The relay always knows its own
/// session's tenant, so every mesh-link call this relay originates is
/// tenant-scoped; `MeshLink`'s own tenant-less path only ever arises from a
/// peer's wire packet that didn't stamp one (see `MeshSessionKey`'s own doc).
fn mesh_session_key(key: &SessionKey) -> MeshSessionKey {
    MeshSessionKey::new(key.session, key.tenant.as_ref())
}

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
/// than re-checked against a growing set. The out-of-prefix sparse set that
/// backs that slide is itself capped (`SPARSE_SEEN_CAP`): a seq stream that
/// leaves permanent gaps below its high-water mark — an authenticated peer that
/// keeps reconnecting with an advancing resume anchor is the motivating case —
/// would otherwise pin those gaps in the set for the life of the session, so
/// beyond the cap the prefix collapses forward over the lowest gap rather than
/// hold it forever.
#[derive(Default)]
pub struct MeshSeen {
    /// Per-slot forward-gate state.
    slots: HashMap<SlotId, SlotSeen>,
}

/// The largest number of out-of-prefix seqs one slot's forward gate holds before
/// it collapses its contiguous prefix forward to reclaim the space. Sized to the
/// transport's per-slot receive window (`RECEIVE_WINDOW` in
/// `rally_point_transport`, 4096): a link that legitimately runs that far ahead
/// of its contiguous prefix is already treated as broken there, so a sparse set
/// grown this deep is not in-flight reordering but permanent gaps — seqs that
/// will never arrive to fill them. Holding them forever is a memory-growth
/// vector on an authenticated-but-hostile peer; the cap bounds each slot's sparse
/// set to this many entries, independent of how far the seqs ahead of it climb.
const SPARSE_SEEN_CAP: usize = 4096;

/// One slot's topological-dedup state.
struct SlotSeen {
    /// Top of the contiguous forwarded prefix; `None` until seq 0 is forwarded.
    forwarded_through: Option<u64>,
    /// Forwarded seqs above the prefix, kept until the gaps below them fill.
    /// Mirrors `Dedup::SlotDedup::ahead` so out-of-order mesh arrival doesn't
    /// cause a false "new" on a seq that was already forwarded out of order.
    /// Bounded to [`SPARSE_SEEN_CAP`] entries: past that the prefix collapses
    /// forward over the lowest gap (see [`SlotSeen::collapse_to_cap`]).
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
        // can be forgotten, then bound the sparse remainder so a stream of
        // permanent gaps can't grow it without limit.
        state.absorb_contiguous_run();
        state.collapse_to_cap();
        Seen::New
    }
}

impl SlotSeen {
    /// Folds the run of seqs sitting immediately above the contiguous prefix out
    /// of the sparse set and into the prefix. Called after a fresh seq lands: if
    /// it closed the gap the prefix was stalled behind, the whole run above it
    /// becomes contiguous and the seqs below can be forgotten.
    fn absorb_contiguous_run(&mut self) {
        let mut next = self.forwarded_through.map_or(0, |t| t + 1);
        while self.ahead.remove(&next) {
            self.forwarded_through = Some(next);
            next += 1;
        }
    }

    /// Bounds the sparse out-of-prefix set to [`SPARSE_SEEN_CAP`] by collapsing
    /// the prefix forward over the lowest sparse seq (and any run contiguous
    /// above it) whenever the set is over the cap. The gap swallowed by that
    /// advance — every seq between the old prefix top and that lowest sparse seq
    /// — is thereafter reported as seen, so a turn that later arrives in it reads
    /// as a `Duplicate`, never a fresh forward.
    ///
    /// That is the safe failure direction for an echo guard. A gap left this far
    /// below the highest seen seq never fills in normal operation — its turn is
    /// lost for good, or the only thing that would arrive there is a replay — and
    /// the two ways to be wrong about it are not symmetric: a false `Duplicate`
    /// merely drops a re-forward, while a false `New` re-floods the mesh with an
    /// already-delivered turn, a duplicate into a lockstep slot that desyncs it.
    /// Collapsing chooses the `Duplicate` side deliberately.
    fn collapse_to_cap(&mut self) {
        while self.ahead.len() > SPARSE_SEEN_CAP {
            let lowest = self
                .ahead
                .pop_first()
                .expect("a set over a positive cap is non-empty");
            self.forwarded_through = Some(lowest);
            self.absorb_contiguous_run();
        }
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

/// A snapshot of `key`'s forward-gate cursors, as "next needed seq" per slot —
/// the seq immediately past each slot's contiguous forwarded-to-locals prefix.
/// A slot with no contiguous prefix (nothing forwarded yet, or a gap below
/// what has) is omitted entirely, not given a `0`. What an absent slot then
/// asks of the reply depends on [`has_resumable_state`] alongside this
/// snapshot: nothing, for a session with no forward-gate history at all
/// (a fresh join); that slot's turns from the very start, for a session that
/// does (see the wire frame's own doc for the full two-mode story — this
/// snapshot only ever answers "how far did I get", never "should an absent
/// slot mean nothing or everything").
///
/// Read from the same registry [`mark_forwarded`](MeshSeen::mark_forwarded)
/// writes, so the snapshot reflects exactly what this session has actually
/// delivered to its locals so far — by any path, not just this one link —
/// which is what makes it safe to read straight from here rather than from
/// any one mesh link's own transport state: a link dying and redialing never
/// touches this registry, so the cursors it hands the fresh link on rejoin are
/// unaffected by the death that made rejoining necessary in the first place.
pub fn resume_cursor_snapshot(registries: &SeenRegistries, key: &SessionKey) -> Vec<(SlotId, u64)> {
    let roster = registries.lock();
    let Some(seen) = roster.get(key) else {
        return Vec::new();
    };
    seen.slots
        .iter()
        .filter_map(|(&slot, state)| state.forwarded_through.map(|through| (slot, through + 1)))
        .collect()
}

/// Whether `key` has ANY forward-gate history at all — an entry in the same
/// registry [`resume_cursor_snapshot`] reads, regardless of whether any slot
/// in it has formed a contiguous prefix yet. This is the `resuming` a
/// resume-cursor ask carries: `true` means "I have genuinely exchanged mesh
/// traffic for this session before" (even if every slot in the accompanying
/// snapshot is gapped or absent), which is what licenses a resume reply to
/// treat an absent slot as "everything from the start" rather than "nothing
/// asked for" — see the wire frame's own doc. `false` — no entry at all — is
/// indistinguishable from a first Join, so the conservative first-join
/// reading (nothing) is exactly what a session with no history should get.
pub fn has_resumable_state(registries: &SeenRegistries, key: &SessionKey) -> bool {
    registries.lock().contains_key(key)
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
    /// Provisional-admission deadlines: a session a client admitted with no
    /// applied descriptor yet is marked here, and the relay's periodic sweep
    /// tears it down if no descriptor claims it in time. Local and ephemeral
    /// like `drop_holds`, and threaded through the same admission and
    /// descriptor-apply paths. See [`crate::provisional`].
    pub provisional: crate::provisional::ProvisionalSessions,
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

/// [`new_mesh_state`] with an explicit provisional-admission window, so a test
/// can drive a client-admitted, undescribed session to its deadline without
/// waiting out the production 10-second window. Every other timing keeps its
/// production value.
pub fn new_mesh_state_with_provisional_window(window: std::time::Duration) -> MeshState {
    MeshState {
        provisional: crate::provisional::ProvisionalSessions::new(window),
        ..new_mesh_state()
    }
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
        provisional: crate::provisional::ProvisionalSessions::new(
            crate::provisional::PROVISIONAL_WINDOW,
        ),
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
    /// Signals this link's driver to reset when its shared forward queue is
    /// full — see [`fan_out_to_mesh`]. One `Notify` per link (shared by every
    /// session registered on it, since they all drain the same queue), cloned
    /// in here so a full-queue observation for *this* session's entry resets
    /// only the one congested link, never a sibling peer link serving the same
    /// session. Mirrors [`crate::routing::SlotEntry`]'s `shutdown` field.
    shutdown: Arc<Notify>,
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

/// The hard ceiling on one session's payloads sent but not yet known-delivered
/// on one mesh link -- the relay-pair backstop mirroring the client edge's
/// `UNACKED_WINDOW_CAP` (`client::driver`, 1024). [`reconcile_ack_cursors`]'s
/// push-on-advance beacon keeps the window bounded under *reverse*-path loss
/// (the peer received the turns; its acks back were lost); this cap catches
/// what the beacon cannot -- sustained *forward*-path loss, where the peer
/// genuinely hasn't received the turns at all. Tripping resets the link
/// ([`MeshLinkExit::ConnectionFailed`], the same exit the full forward-queue
/// takes), which is safe to do because the redial's Join/reconcile and the
/// resume-cursor exchange (`MeshResumeCursors`) recover every session on the
/// link from where its own forward-gate left off.
///
/// Bounded per session, not per link: the `AckManager` this checks
/// (`MeshLink::payloads_in_flight`) is itself instantiated per session, one
/// independent window per `SessionLink` sharing the connection -- summing
/// them into a single link-wide bound would let one quiet session's slack
/// mask another session's genuine stall, and a link carrying only one session
/// would then trip at a fraction of the intended cap.
///
/// Sized generously above the client edge's 1024: a client's `Link` carries
/// one slot's outbound stream, but a mesh session's single `AckManager`
/// multiplexes every slot this relay-pair jointly forwards for that game (up
/// to the ~8-slot roster a real game carries). A shared relay-pair outage can
/// therefore grow several slots' windows at once inside the one instance this
/// checks, well before any single home client's own 1024-turn cap would have
/// tripped *that* client's separate link first. 8x -- roughly one player's
/// worth of headroom per plausible slot -- is generous margin without being
/// effectively unbounded.
const MESH_UNACKED_WINDOW_CAP: usize = 8 * 1024;

/// How long one write on a mesh link's reliable streams (a control frame, a
/// presence push) may sit suspended on QUIC stream flow control before the
/// link is treated as failed.
///
/// The driver writes these streams inline in its select loop, so a suspended
/// write suspends the whole loop — no datagram receives, no turn fan-out, no
/// presence — for every session on the relay-pair, while the outbound control
/// queue keeps growing. QUIC's own idle timeout never ends that state: it
/// tears down a *silent* peer, but a peer whose connection stays alive
/// (keepalives are answered by the QUIC stack itself) while its application
/// stops reading a stream's receive half stalls the write indefinitely.
/// Resetting the link instead puts recovery on the same path a full forward
/// queue already takes: the dial supervisor redials, and the Join-time
/// reconcile + resume-cursor exchange re-sync what the reset interrupted.
///
/// Generous against the normal case — a control frame drains in microseconds
/// on a healthy backbone link, so only a wedged, overloaded, or hostile peer
/// ever holds a write this long — and it also bounds how much the unbounded
/// outbound control queue can grow during a stall (a stall window's worth of
/// rare, small frames, not an open-ended accumulation).
const MESH_STREAM_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether one session's mesh-link unacked window has crossed
/// [`MESH_UNACKED_WINDOW_CAP`] -- the driver's cue to reset the link rather
/// than let the window grow further. Mirrors the client edge's own
/// `check_cap` (`client::driver`) in shape, split out so the arithmetic is
/// testable on its own, independent of the full select-loop machinery that
/// applies it.
fn mesh_window_exhausted(in_flight: usize) -> bool {
    in_flight > MESH_UNACKED_WINDOW_CAP
}

/// Why a mesh-link driver exited. The dial-side reconnect supervisor uses this to
/// distinguish intentional teardown from a dropped connection: only the
/// latter is worth retrying, since `Idle` means a deliberate wind-down and
/// `CommandChannelClosed` means the relay itself is shutting the link down.
///
/// `ConnectionFailed` covers every transport-level exit — a QUIC idle
/// timeout, a read/send error, a keepalive that stopped round-tripping, the
/// peer's control-stream reader ending while the rest of the connection was
/// still alive (a one-sided reset, an over-cap frame, a decode failure), or
/// this link's own shared forward queue filling (a congested peer whose
/// dropped turn would otherwise leave the peer's clients stalled forever).
/// Those all surface the same from the driver's perspective (the link is
/// gone, or no longer trustworthy); the reconnect supervisor treats them all
/// as retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLinkExit {
    /// The link had at least one session, went empty, and stayed empty past
    /// [`IDLE_TIMEOUT`]. An intentional wind-down, not a failure.
    Idle,
    /// The connection failed: a recv/send error, QUIC idle timeout, a dead
    /// control-stream reader, or a full forward queue reset. The peer is
    /// unreachable, dead, or the link is no longer trustworthy for
    /// correctness-critical traffic.
    ConnectionFailed,
    /// The command channel closed (the relay is tearing the link down — its
    /// `MeshCommand` sender was dropped). An intentional shutdown.
    CommandChannelClosed,
}

/// Registers one peer-relay link's `(forward, control)` senders and its
/// reset signal for `key`, appending them as a new element in that session's
/// fan-out vec, and returns the RAII guard that removes *only this* element
/// when dropped. Each session's entry holds one element per connected peer
/// relay, so registering must never clobber the peers already serving the
/// session. `shutdown` is the link's own `Notify` (shared across every session
/// registered on it), so [`fan_out_to_mesh`] can reset exactly this link on a
/// full forward queue without touching any sibling peer link.
fn register_mesh_link(
    links: &MeshLinks,
    key: SessionKey,
    forward: MeshForwardTx,
    control: MeshControlTx,
    shutdown: Arc<Notify>,
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
            shutdown,
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
/// blocking on a slow peer. Mirrors `routing::fan_out` but for mesh links
/// instead of local slots.
///
/// Fans out to **all** mesh links for the session — including the one a turn
/// arrived on. The echo is caught not by excluding the ingress link (there's no
/// link id in the registry to exclude) but by `MeshSeen`: every ingress — local
/// client or mesh peer — marks `(slot, seq)` before forwarding to locals, so the
/// echo arrives, is seen as `Duplicate`, and is dropped before it reaches local
/// clients. This is why the flood-with-dedup model requires marking on *every*
/// forward-to-local, not just mesh ingress.
///
/// A full forward queue is *not* the same recoverable case a full local slot
/// queue is: a local client's own transport re-carries a dropped datagram from
/// its own unacked window, but this queue feeds the mesh link's `AckManager` —
/// a turn dropped here never enters it, so the link has nothing to re-carry on
/// its own. So, like `routing::fan_out`'s lagging peer, a full queue signals
/// the link to reset (see `MeshLinkTx`'s `shutdown` field) rather than silently
/// dropping the turn: the dial supervisor redials, the Join-time reconcile
/// re-syncs leave state, and each side's resume-cursor exchange on that fresh
/// link (see `reconcile_resume_cursors_on_join`) replays whatever the
/// peer's forward-gate is still missing from this relay's own
/// locally-originated turns — turning what would otherwise be a permanent
/// per-(slot, seq) gap into a recovered one. Never a per-packet retransmit:
/// the recovery is resume-from-cursor on the next Join, not acknowledgement
/// of this specific drop.
pub fn fan_out_to_mesh(links: &MeshLinks, key: &SessionKey, payload: Payload) {
    let targets: Vec<(MeshForwardTx, Arc<Notify>)> = {
        let roster = links.lock();
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs
                .iter()
                .map(|tx| (tx.forward.clone(), Arc::clone(&tx.shutdown)))
                .collect(),
            None => Vec::new(),
        }
    };
    for (tx, shutdown) in targets {
        // Tag with the session id so the driver's merged receiver can demux.
        match tx.try_send((key.session, payload.clone())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "mesh forward queue full; resetting the congested link",
                );
                shutdown.notify_one();
            }
            // The driver already exited (a redial, if warranted, is already
            // in motion via whatever ended it); nothing more to signal.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
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
                        .map(
                            |&(origin, seq)| rally_point_proto::messages::DeliveryCursor {
                                origin_slot: u32::from(origin.0),
                                delivered_seq: seq,
                            },
                        )
                        .collect(),
                },
            )),
        },
    );
}

/// Builds a `MeshResumeCursors` mesh control frame for `session`, from
/// `cursors` — each entry an origin slot and the next seq this relay's
/// forward-gate still needs from it — and `resuming`, which decides what an
/// absent slot means to the receiver (see the wire frame's own doc).
fn resume_cursors_frame(
    session: SessionId,
    cursors: Vec<(SlotId, u64)>,
    resuming: bool,
) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: cursors
                    .into_iter()
                    .map(
                        |(slot, next_seq)| rally_point_proto::messages::MeshResumeCursor {
                            origin_slot: u32::from(slot.0),
                            next_seq,
                        },
                    )
                    .collect(),
                resuming,
            },
        )),
    }
}

/// Builds a `MeshAckCursors` mesh control frame for `session`, from `cursors`
/// -- each entry a slot and this link's own delivered-through cursor for it.
/// See [`reconcile_ack_cursors`] for the push-on-advance discipline that
/// drives this, and `MeshControlFrame.mesh_ack_cursors` for why this rides the
/// control stream rather than a dedicated beacon uni-stream.
fn ack_cursors_frame(session: SessionId, cursors: Vec<(SlotId, u64)>) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::MeshAckCursors(
            rally_point_proto::messages::MeshAckCursors {
                cursors: cursors
                    .into_iter()
                    .map(
                        |(slot, delivered_through)| rally_point_proto::messages::MeshAckCursor {
                            slot: u32::from(slot.0),
                            delivered_through,
                        },
                    )
                    .collect(),
            },
        )),
    }
}

/// Applies a peer's `MeshAckCursors` push to this link's own transport: for
/// each named slot, force-retires this link's unacked window through the
/// peer-confirmed cursor -- the mesh-link counterpart of a client-edge
/// driver's `Link::retire_through` call off its beacon reader. A no-op for
/// any other frame kind, a zero session, or a slot id out of `SlotId` range
/// (defensive; wire values are validated upstream). A cursor for a session
/// this link hasn't opened is harmless: `MeshLink::retire_through` already
/// returns `0` for one, matching how every other control-frame kind here
/// tolerates a stale or unknown session.
///
/// Called from [`run_mesh_link`]'s own select branch, before the ordinary
/// [`dispatch_mesh_control`] -- like [`resume_replay_for_frame`], it needs
/// direct access to this link's transport state, which that function does
/// not have.
///
/// `joined` supplies the session's tenant (this relay always knows it for a
/// session it has joined), so the retire targets the same tenant-scoped
/// [`MeshSessionKey`] the datagram path opened. A frame naming a session this
/// relay hasn't joined (predating a Leave, or a stale peer echo) is harmless:
/// there is no key to build, so it falls through as a no-op exactly like an
/// unopened session already does.
fn apply_ack_cursors(
    link: &mut rally_point_transport::MeshLink,
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
) {
    if frame.session == 0 {
        return;
    }
    let Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) = &frame.kind else {
        return;
    };
    let session = SessionId(frame.session);
    let Some(state) = joined.get(&session) else {
        return;
    };
    let key = mesh_session_key(&state.key);
    for cursor in &cursors.cursors {
        let Ok(slot) = u8::try_from(cursor.slot).map(SlotId) else {
            continue;
        };
        link.retire_through(key.clone(), slot, cursor.delivered_through);
    }
}

/// Folds an `OversizeTurn` frame's `(slot, seq)` into this link's per-session
/// receive dedup — the stream-delivered turn must advance the same
/// delivered-through prefix a datagram delivery would, or the seq holds a
/// permanent gap that stalls the ack-cursor push and pins the peer's unacked
/// window (mirroring the client edge's own `deliver_external` fold on its
/// oversize ingress). Returns whether the frame should still be dispatched:
/// `false` only for an oversize turn the link's dedup has already delivered
/// (dropping a redundant copy before it burns a session-level dedup pass);
/// every other frame kind, and every defensively-skipped case (zero/unjoined
/// session, out-of-range slot — the dispatch's own arms log and drop those),
/// passes through as `true`.
///
/// Called from [`run_mesh_link`]'s own select branch before
/// [`dispatch_mesh_control`], like [`apply_ack_cursors`]: it needs direct
/// access to this link's transport state, which the dispatch does not have.
/// A fold failure is logged and the turn still dispatched — delivering a turn
/// whose transport bookkeeping hiccuped merely leans on the session-level
/// dedup, while dropping it would strand a gap in every local client.
fn fold_oversize_into_link(
    link: &mut rally_point_transport::MeshLink,
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
) -> bool {
    let Some(mesh_control_frame::Kind::OversizeTurn(payload)) = &frame.kind else {
        return true;
    };
    if frame.session == 0 {
        return true;
    }
    let Some(state) = joined.get(&SessionId(frame.session)) else {
        return true;
    };
    let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
        return true;
    };
    match link.deliver_external(mesh_session_key(&state.key), slot, payload.seq) {
        Ok(fresh) => {
            if !fresh {
                tracing::debug!(
                    tenant = state.key.tenant.as_ref(),
                    session = frame.session,
                    slot = slot.0,
                    seq = payload.seq,
                    "oversize mesh turn already delivered on this link; dropping",
                );
            }
            fresh
        }
        Err(error) => {
            tracing::warn!(
                %error,
                session = frame.session,
                slot = slot.0,
                seq = payload.seq,
                "folding oversize mesh turn into link dedup failed; delivering anyway",
            );
            true
        }
    }
}

/// Pushes each joined session's mesh-link delivered-through cursors to the
/// peer when they've advanced past what it last heard -- the mesh-link
/// counterpart of the client edge's ack-beacon push. Riding the same flush
/// tick [`reconcile_presence`] uses (rather than a dedicated timer) keeps this
/// off the hot datagram path while staying prompt enough to rescue a window
/// stuck only on lost reverse-path acks before [`MESH_UNACKED_WINDOW_CAP`]
/// would otherwise trip. Push-on-advance: a slot with nothing new since the
/// last push sends nothing, so a healthy link stays quiet.
fn reconcile_ack_cursors(
    link: &rally_point_transport::MeshLink,
    control_tx: &MeshControlTx,
    ack_cursors_sent: &mut HashMap<(SessionId, SlotId), u64>,
    joined: &HashMap<SessionId, SessionState>,
) {
    for state in joined.values() {
        let session_id = state.key.session;
        let advanced: Vec<(SlotId, u64)> = link
            .delivered_through_all(mesh_session_key(&state.key))
            .into_iter()
            .filter(|&(slot, cursor)| {
                !matches!(
                    ack_cursors_sent.get(&(session_id, slot)),
                    Some(&prev) if prev >= cursor
                )
            })
            .collect();
        if advanced.is_empty() {
            continue;
        }
        for &(slot, cursor) in &advanced {
            ack_cursors_sent.insert((session_id, slot), cursor);
        }
        let _ = control_tx.send(ack_cursors_frame(session_id, advanced));
    }
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
/// relay serving `key`, so each fans it down its own local slots — carrying the
/// authority's computed initial buffer depth (`None` when it sized none) so each
/// peer adopts the same depth. A relay that receives this latches the session
/// started and fans it locally but does not re-broadcast it — the authority
/// already sent it to every relay — so there is no echo.
pub(crate) fn fan_out_session_start(
    links: &MeshLinks,
    key: &SessionKey,
    initial_buffer_turns: Option<u32>,
) {
    fan_out_control(
        links,
        key,
        session_start_frame(key.session, initial_buffer_turns),
    );
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

/// Builds a `SessionStart` mesh control frame for `session`, stamping the
/// computed initial buffer depth (`None` when the authoring relay sized none).
fn session_start_frame(session: SessionId, initial_buffer_turns: Option<u32>) -> MeshControlFrame {
    MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns,
        })),
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
        // Every leave reaching this point was already accepted by this
        // relay's own consensus (`decide_leave`/`observe_leave`), which
        // validates the slot before caching it -- so this should always
        // succeed. Refusing gracefully rather than truncating keeps that
        // true by construction instead of by this call path's current
        // shape, so a future caller that skips consensus can't silently
        // alias a leave onto the wrong slot.
        let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = leave.slot,
                "synced leave broadcast names a slot id out of range; dropping",
            );
            continue;
        };
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
    home: crate::delivery::DeliveryHome,
) {
    if let Some(payload) = deliver_turn_to_locals(
        sessions,
        seen,
        decision_makers,
        turn_ring,
        key,
        slot,
        payload,
        home,
    ) {
        fan_out_to_mesh(mesh_links, key, payload);
    }
}

/// The local half of [`forward_turn`]: topological dedup, buffer-directive
/// stamping, and fan-out to this relay's local slots — everything except the
/// mesh flood. Returns the (possibly stamped) payload when it was fresh, so
/// [`forward_turn`] can flood it onward, or `None` for a topological duplicate
/// already delivered via an earlier path. `home` names where this specific
/// delivery arrived from — this relay's own client edge, or a peer relay over
/// the mesh — feeding both the delivery-tracking home stamp and the replay
/// ring's [`crate::turn_ring::TurnOrigin`].
///
/// Also the whole receive step for an oversize turn arriving over the mesh
/// control stream: the origin relay diverted a copy to *every* link serving the
/// session itself, so the receiver delivers locally and deliberately does not
/// re-flood — re-broadcasting would only produce the echo the dedup exists to
/// drop (harmless, but pure waste on a reliable stream).
// Same escape hatch as `forward_turn` just above (see its own comment): one
// more reference (`home`) alongside its existing bundle-worthy set, not
// worth the call-site churn of a struct.
#[allow(clippy::too_many_arguments)]
fn deliver_turn_to_locals(
    sessions: &routing::Sessions,
    seen: &SeenRegistries,
    decision_makers: &crate::consensus::DecisionMakers,
    turn_ring: &crate::turn_ring::TurnRing,
    key: &SessionKey,
    slot: SlotId,
    mut payload: Payload,
    home: crate::delivery::DeliveryHome,
) -> Option<Payload> {
    if mark_seen(seen, key, slot, payload.seq) == Seen::Duplicate {
        // Only the duplicate (mesh-echo) branch touches the recorder's maps —
        // the fresh-turn common path stays lock-free for the recorder.
        decision_makers.flight_recorder().note_dedup_drop(key, slot);
        return None;
    }
    // The frame observation's one and only feed point, right after the
    // `mark_seen` dedup, for the same reason as the desync comparator just
    // below: the mesh legitimately delivers the same turn to a relay via more
    // than one path, and while the per-slot frame max is a harmless monotone,
    // the seq-keyed frame *history* behind the leave-frame clamp is a bounded
    // append — duplicates walked twice would evict genuine history and shrink
    // the clamp's window — and the delivery-tracking home stamp must follow
    // the slot's true source, not whichever flooded copy raced in. Lobby turns
    // carry no frame and don't move the consensus coordinate. Every turn here
    // was validated at its ingress client edge (the mesh never re-validates),
    // so only validated turns feed the coordinate.
    if let Some(frame) = payload.game_frame_count {
        crate::consensus::observe_turn_frame(
            decision_makers,
            key,
            slot,
            payload.seq,
            rally_point_proto::ids::GameFrameCount(frame),
            home,
        );
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
    // and must not be double-buffered here. The session's slot count rides along
    // so the ring's bounds fit the session's actual shape rather than assuming
    // the largest possible game.
    if let Some(slots) = crate::consensus::started_session_slot_count(decision_makers, key) {
        let origin = match home {
            crate::delivery::DeliveryHome::Local => crate::turn_ring::TurnOrigin::Local,
            crate::delivery::DeliveryHome::Peer(_) => crate::turn_ring::TurnOrigin::Mesh,
        };
        turn_ring.record(key, &payload, origin, slots);
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

/// Whether `frame` is a resume-cursor ask, and if so, the local-origin turns
/// this relay's own client edge produced that the peer's cursors say it's
/// still missing, paired with the session they belong to. `None` for any
/// other frame kind, a session this link hasn't joined, or a resume ask this
/// relay has nothing to answer (an empty replay list — the ordinary case for
/// a session with no locally-homed slots). The frame's own `resuming` flag
/// governs a slot absent from its cursors — see
/// [`crate::turn_ring::TurnRing::replay_local`]'s doc for the two meanings
/// that carries.
///
/// Reads straight from the turn ring rather than mutating any session state,
/// so — unlike [`dispatch_mesh_control`] — this never needs to run inside
/// that function; [`run_mesh_link`]'s own select branch calls it separately,
/// before the dispatch, because the reply it computes has to go out over
/// *this* link directly (see [`send_resume_replay`]), which `dispatch_mesh_control`
/// has no way to do.
fn resume_replay_for_frame(
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
    mesh: &MeshState,
) -> Option<(SessionKey, Vec<Payload>)> {
    let Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) = &frame.kind else {
        return None;
    };
    let key = joined.get(&SessionId(frame.session))?.key.clone();
    let cursors: HashMap<SlotId, u64> = resume
        .cursors
        .iter()
        .filter_map(|c| {
            u8::try_from(c.origin_slot)
                .ok()
                .map(|s| (SlotId(s), c.next_seq))
        })
        .collect();
    let payloads = mesh.turn_ring.replay_local(&key, &cursors, resume.resuming);
    (!payloads.is_empty()).then_some((key, payloads))
}

/// Sends one turn over `link`'s datagram path for `key`'s session, diverting
/// to the reliable control stream when it doesn't fit — mirroring the client
/// edge's own oversize divert. Shared by a freshly forwarded turn and a
/// resume-cursor replay, so a replayed turn enters the link's `AckManager` and
/// rides its redundancy exactly like a live one: no special bypass a live
/// send doesn't also go through. `context` only labels the failure log
/// (`"forward"` or `"resume replay"`); the send logic itself is identical
/// either way.
///
/// Returns whether the link is still good. `false` is the caller's cue to
/// close it, exactly as a live send failure already does; a payload that
/// slips past the divert pre-check as oversize is logged and treated as
/// delivered (there is nothing to retry it with), not a link failure.
async fn send_turn_over_link(
    link: &mut rally_point_transport::MeshLink,
    control_send: &mut rally_point_transport::quinn::SendStream,
    key: &SessionKey,
    payload: Payload,
    conditions: Option<LinkConditions>,
    context: &'static str,
) -> bool {
    let session_id = key.session;
    let fits = match link.payload_fits(&payload, conditions.as_ref(), Some(key.tenant.as_ref())) {
        Ok(fits) => fits,
        Err(error) => {
            tracing::info!(%error, context, "mesh send failed; closing link");
            return false;
        }
    };
    if !fits {
        tracing::debug!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = payload.slot,
            seq = payload.seq,
            context,
            "diverting oversize turn to the mesh control stream",
        );
        let frame = MeshControlFrame {
            session: session_id.0,
            kind: Some(mesh_control_frame::Kind::OversizeTurn(payload)),
        };
        // Deadline-bounded like every reliable-stream write the driver makes
        // inline: a peer that stops reading its control receive-half would
        // otherwise suspend the whole driver loop on this write indefinitely.
        // See `MESH_STREAM_WRITE_TIMEOUT`.
        match tokio::time::timeout(
            MESH_STREAM_WRITE_TIMEOUT,
            rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                control_send,
                &frame,
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::info!(%error, context, "mesh control send failed; closing link");
                return false;
            }
            Err(_) => {
                tracing::warn!(context, "mesh control send stalled; closing link");
                return false;
            }
        }
        return true;
    }
    match link.send(mesh_session_key(key), Some(payload), conditions) {
        Ok(_) => true,
        // The pre-check above diverts anything that can never ride a
        // datagram, so this arm is reachable only if the path budget moved
        // between the check and the send (no await separates them, so in
        // practice it isn't). The payload was consumed by the failed send;
        // log it loudly rather than pretend it was delivered.
        Err(rally_point_transport::MeshLinkError::PayloadTooLarge { needed, budget }) => {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                needed,
                budget,
                context,
                "oversize turn slipped past the divert pre-check; dropped",
            );
            true
        }
        Err(error) => {
            tracing::info!(%error, context, "mesh send failed; closing link");
            false
        }
    }
}

/// Sends every payload in `payloads` over `link`'s datagram path for `key`, in
/// order, stopping at the first link-fatal failure — the resume-reply analog
/// of the live forward branch's own per-turn send, going straight out this
/// link rather than through the shared, `try_send`-based forward queue: a
/// large replay pumped through that bounded queue could itself fill it and
/// trip the very full-queue reset this exists to recover from. Samples the
/// outgoing conditions sidecar once for the whole batch — a backlog
/// catch-up burst does not need per-turn-fresh telemetry — rather than
/// resampling for each payload. Returns whether every payload sent (or was
/// diverted) without a link-fatal error.
async fn send_resume_replay(
    link: &mut rally_point_transport::MeshLink,
    control_send: &mut rally_point_transport::quinn::SendStream,
    conditions: &ConditionsRegistry,
    key: &SessionKey,
    payloads: Vec<Payload>,
) -> bool {
    let outgoing = snapshot_conditions(conditions, key);
    for payload in payloads {
        if !send_turn_over_link(
            link,
            control_send,
            key,
            payload,
            outgoing.clone(),
            "resume replay",
        )
        .await
        {
            return false;
        }
    }
    true
}

/// Drives a shared [`MeshLink`](rally_point_transport::MeshLink) for every session both relays jointly serve on
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

    // The last delivered-through cursor pushed to the peer per (session, slot)
    // -- the mesh-link ack-beacon's own "last_sent", mirroring the client
    // edge's `flush_beacon`. Tracked here (rather than inside `MeshLink`,
    // which is transport state, not a record of what's already been shared)
    // so a repeat cursor push-on-advance check costs a hash lookup, not a
    // stream write the peer's monotonic guard would just discard anyway.
    let mut ack_cursors_sent: HashMap<(SessionId, SlotId), u64> = HashMap::new();

    // One merged forward channel for every session on this link: fan_out_to_mesh
    // pushes (SessionId, Payload) tagged with the session id, so a single
    // select! branch drains all sessions' outbound turns without polling N
    // per-session receivers. One sender is cloned into the mesh-links registry
    // for each session; the driver task owns the receiver.
    let (forward_tx, mut forward_rx) =
        mpsc::channel::<(rally_point_proto::ids::SessionId, Payload)>(routing::FORWARD_CAPACITY);

    // This link's reset signal: `fan_out_to_mesh` notifies it when this shared
    // forward queue is full, since a dropped fresh turn never enters the
    // `AckManager` for this link's transport to re-carry — a permanent gap for
    // the peer, not a recoverable one. One `Notify` per link, cloned into the
    // mesh-links registry for each session registered on it (mirroring
    // `forward_tx`/`control_forward_tx` above), so a reset here only ever
    // affects this one relay-pair link.
    let shutdown = Arc::new(Notify::new());

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
                            // NOTE: no frame-observation or desync-comparator
                            // call here. This relay may also reach the same
                            // turn via a different mesh path (or the client
                            // edge, if it's local), so feeding consensus here
                            // — before dedup — would double-count it.
                            // `forward_turn` below funnels into
                            // `deliver_turn_to_locals`, which feeds both
                            // exactly once, right after its mark_seen check.
                            forward_turn(
                                &sessions,
                                &mesh_links,
                                &seen_registries,
                                &decision_makers,
                                &mesh_for_dispatch.turn_ring,
                                &key,
                                slot,
                                payload,
                                crate::delivery::DeliveryHome::Peer(peer_id),
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
                        // Deadline-bounded: a peer that keeps its connection
                        // alive but stops reading this stream would otherwise
                        // suspend the whole loop here indefinitely while the
                        // unbounded forward channel keeps growing. See
                        // `MESH_STREAM_WRITE_TIMEOUT`.
                        match tokio::time::timeout(
                            MESH_STREAM_WRITE_TIMEOUT,
                            rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                                &mut control_send,
                                &frame,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                tracing::info!(%error, "mesh control send failed; closing link");
                                break MeshLinkExit::ConnectionFailed;
                            }
                            Err(_) => {
                                tracing::warn!("mesh control send stalled; closing link");
                                break MeshLinkExit::ConnectionFailed;
                            }
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
                    Some(frame) => {
                        // A resume-cursor ask answers with turns THIS relay
                        // originated, sent straight out this link — computed
                        // and sent before the ordinary dispatch below, which
                        // has no link to send a reply over (see
                        // `resume_replay_for_frame`'s own doc).
                        // A peer's push of its own link-level receive cursors:
                        // force-retire this link's unacked window through them
                        // before anything else touches the frame. Needs direct
                        // link access `dispatch_mesh_control` doesn't have, so
                        // it's handled here, like the resume-cursor reply below.
                        apply_ack_cursors(&mut link, &frame, &joined);
                        if let Some((key, payloads)) =
                            resume_replay_for_frame(&frame, &joined, &mesh_for_dispatch)
                            && !send_resume_replay(
                                &mut link,
                                &mut control_send,
                                &conditions,
                                &key,
                                payloads,
                            )
                            .await
                        {
                            break MeshLinkExit::ConnectionFailed;
                        }
                        // An oversize turn's transport-dedup fold also needs
                        // direct link access, so it too runs here. A copy the
                        // link has already delivered stops before dispatch.
                        if fold_oversize_into_link(&mut link, &frame, &joined) {
                            dispatch_mesh_control(
                                frame,
                                peer_id,
                                &joined,
                                &sessions,
                                &mesh_for_dispatch,
                            );
                        }
                    }
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
                        if !send_turn_over_link(
                            &mut link,
                            &mut control_send,
                            &key,
                            payload,
                            outgoing,
                            "forward",
                        )
                        .await
                        {
                            break MeshLinkExit::ConnectionFailed;
                        }
                        continue;
                    }
                    None => break MeshLinkExit::CommandChannelClosed,
                }
            }
            // `fan_out_to_mesh` found this shared forward queue full and
            // notified: a dropped fresh turn here never enters this link's
            // `AckManager`, so its transport has nothing to re-carry on its
            // own. Reset the link instead — the dial supervisor redials, the
            // Join-time reconcile re-syncs leave state, and the resume-cursor
            // exchange on the fresh link replays this relay's own
            // locally-originated turns the peer's forward-gate is still
            // missing, closing the gap this very reset opened.
            _ = shutdown.notified() => {
                tracing::info!("mesh forward queue was full; resetting link");
                break MeshLinkExit::ConnectionFailed;
            }
            _ = tokio::time::sleep_until(next_flush) => {
                let now = tokio::time::Instant::now();
                let mut failed = None;
                let mut window_exhausted = false;
                for state in joined.values_mut() {
                    let key = mesh_session_key(&state.key);
                    // Checked every tick, independent of this session's own
                    // flush deadline: a stuck window is a safety-net condition
                    // the driver must not sit on for up to a whole flush cycle
                    // longer than necessary. See `MESH_UNACKED_WINDOW_CAP` for
                    // why this reads per session, not summed across the link.
                    if mesh_window_exhausted(link.payloads_in_flight(key.clone())) {
                        window_exhausted = true;
                        break;
                    }
                    if state.flush_deadline > now {
                        continue;
                    }
                    if link.payloads_in_flight(key.clone()) > 0
                        && let Err(error) = link.send(key, None, None)
                    {
                        failed = Some(error);
                        break;
                    }
                    state.flush_deadline = now + routing::FLUSH_INTERVAL;
                }
                if window_exhausted {
                    // The ack-cursor beacon (`reconcile_ack_cursors`, below)
                    // could not keep this session's window bounded -- a
                    // genuine forward gap, not lost reverse-path acks. Reset
                    // the whole link like the full-forward-queue case: the
                    // redial's Join/reconcile and resume-cursor exchange
                    // recover every session on it, including this one.
                    tracing::warn!("mesh unacked window exceeded cap; resetting link");
                    break MeshLinkExit::ConnectionFailed;
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
                // Deadline-bounded like the control-stream writes: the
                // presence stream is written inline here too, so a peer that
                // stops reading it could suspend the whole loop. See
                // `MESH_STREAM_WRITE_TIMEOUT`.
                match tokio::time::timeout(
                    MESH_STREAM_WRITE_TIMEOUT,
                    reconcile_presence(&mut presence_tx, &mut presence_sent, &sessions, &joined),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => {
                        tracing::info!("mesh presence push failed or stalled; closing link");
                        break MeshLinkExit::ConnectionFailed;
                    }
                }
                // Reconcile this link's own receive cursors on the same tick:
                // push each session's per-slot delivered-through advance to
                // the peer, so lost reverse-path acks alone can't grow its
                // view of our unacked window without bound.
                reconcile_ack_cursors(&link, &control_forward_tx, &mut ack_cursors_sent, &joined);
                continue;
            }
            // A presence report from the peer: how many live home clients it
            // serves for one session. Record it and re-derive the session's
            // buffer-authority verdict — this is the handoff path when the
            // authority relay's players all leave. The reader task assembled
            // the complete frame off a cancel-safe path; `recv` is cancel-safe.
            received = presence_rx.recv() => {
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
                            routing::reconcile_abandon(&sessions, &mesh_for_dispatch, &state.key);
                        }
                    }
                    // The reader task ended: the peer's presence stream reset
                    // or closed while the connection lives on. Presence is the
                    // authority-handoff signal — live-player counts drive
                    // `record_peer`/`recompute` and with them who decides the
                    // session's buffer and leaves — so a link that keeps
                    // carrying turns while its presence view is frozen can
                    // strand a session with no authority (or two) when the
                    // peer's players leave. There is no read-side re-open (the
                    // outbound reconcile is write-only), so treat it exactly
                    // like the control-stream reader dying just above: end the
                    // driver and let the dial supervisor bring up a fresh
                    // connection with every stream new.
                    None => {
                        tracing::info!("mesh presence stream reader ended; closing link");
                        break MeshLinkExit::ConnectionFailed;
                    }
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
                        link.open_session(mesh_session_key(&key));
                        // Anchor each slot's receive window at the seq this
                        // session actually still needs — its forwarded-to-locals
                        // cursor — rather than 0. A session joins a link
                        // mid-stream whenever the link redialed (or this relay
                        // joined a running session), so an unanchored window
                        // would open a full window's width behind the live
                        // stream. The peer's resume replay (asked for just
                        // below) starts from these same cursors, so the window
                        // and the replay agree on where the stream resumes.
                        // No-op on slots with no contiguous forwarded prefix;
                        // the window's own forward collapse covers those.
                        for (slot, next_needed) in resume_cursor_snapshot(&seen_registries, &key) {
                            link.anchor_receive_window(mesh_session_key(&key), slot, next_needed);
                        }
                        let registration = register_mesh_link(
                            &mesh_links,
                            key.clone(),
                            forward_tx.clone(),
                            control_forward_tx.clone(),
                            Arc::clone(&shutdown),
                        );
                        // Re-send this relay's known leave state for the session
                        // down the fresh registration, so a link that died and
                        // redialed (its `joined` empty again) reconverges. All of
                        // these are idempotent (dedup by slot everywhere).
                        reconcile_leaves_on_join(&decision_makers, &control_forward_tx, &key);
                        // Ask the peer, over the same fresh registration, to
                        // replay whatever this relay's forward-gate is still
                        // missing for the session — the resume-cursor mesh
                        // counterpart of the leave re-sync just above.
                        reconcile_resume_cursors_on_join(
                            &seen_registries,
                            &control_forward_tx,
                            &key,
                        );
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
                        // nothing yet. Deadline-bounded like every inline
                        // stream write here — see `MESH_STREAM_WRITE_TIMEOUT`.
                        match tokio::time::timeout(
                            MESH_STREAM_WRITE_TIMEOUT,
                            reconcile_presence(
                                &mut presence_tx,
                                &mut presence_sent,
                                &sessions,
                                &joined,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => {
                                tracing::info!(
                                    "mesh presence push failed or stalled; closing link"
                                );
                                break MeshLinkExit::ConnectionFailed;
                            }
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
                            link.close_session(mesh_session_key(&key));
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
/// - **`MeshResumeCursors`**: the peer's per-origin-slot resume cursors.
///   Answered before this function ever runs — the reply is a replay of this
///   relay's own turns, sent directly over the link that received the ask, not
///   a session-state fold this dispatch performs. This arm exists only so the
///   match stays exhaustive.
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
            let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
                // Out of `u8` range: `observe_leave` below would reject it the
                // same way internally, but check here first so this specific
                // case gets its own diagnostic rather than reading as an
                // ordinary rejected/redundant directive.
                tracing::warn!(
                    session = session_id.0,
                    slot = leave.slot,
                    "mesh LeaveDirective names a slot id out of range; dropping",
                );
                return;
            };
            // A `false` here means this relay's own consensus state didn't
            // accept the directive as new: either an ordinary redundant copy
            // (already fanned out on its own first insert, so re-forwarding
            // is unnecessary) or -- the case that matters -- a genuine
            // conflicting duplicate for the slot, which must never reach
            // local clients. Forwarding it anyway would hand them a decision
            // this relay's own cache just flagged as disagreeing with what it
            // already holds.
            if !crate::consensus::observe_leave(&mesh.decision_makers, &key, &leave) {
                return;
            }
            routing::fan_out_leave(sessions, &key, slot, leave);
            // A peer authority deciding a slot this relay homes may have been
            // the last undecided departure deferring this relay's
            // session-emptied close — re-evaluate it.
            routing::maybe_close_emptied_session(sessions, mesh, &key);
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
            // The same receive step a datagram-delivered mesh turn runs: the
            // shared local delivery (dedup, frame observation, stamp, local
            // fan-out). Delivery below the fan-out needs nothing new — a slot
            // link whose client's path can't take the turn diverts it onto
            // that client's own control stream. The transport-level dedup fold
            // for this stream-delivered seq already ran in the driver's own
            // select branch (`fold_oversize_into_link`), which has the link
            // access this dispatch doesn't.
            let _ = deliver_turn_to_locals(
                sessions,
                &mesh.seen,
                &mesh.decision_makers,
                &mesh.turn_ring,
                &key,
                slot,
                payload,
                crate::delivery::DeliveryHome::Peer(peer_id),
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
                // Coverage fired here (this relay is the authority): the maker
                // sized and stored the initial buffer depth as the latch fired, so
                // both fan-out legs carry it.
                let initial_buffer_turns =
                    crate::consensus::session_initial_buffer_turns(&mesh.decision_makers, &key);
                routing::fan_out_session_start(sessions, &key, initial_buffer_turns);
                fan_out_session_start(&mesh.links, &key, initial_buffer_turns);
            }
        }
        Some(mesh_control_frame::Kind::SessionStart(start)) => {
            // The authority's session-start directive. Adopt the carried initial
            // buffer depth into this relay's maker — its buffer and its stored
            // depth — so a later promotion reasons from the right base and this
            // relay's own re-pushes stamp the same depth; a depth-less directive (an
            // old authority, or a resumed re-home re-push) leaves the buffer
            // untouched. Latching started keeps this relay's own late-registering
            // local slots getting a re-push. Then fan it down every current local
            // slot. Deliberately NOT re-broadcast across the mesh: the authority
            // already sent a copy to every link serving the session, so re-flooding
            // would only echo.
            crate::consensus::adopt_session_start(
                &mesh.decision_makers,
                &key,
                start.initial_buffer_turns,
            );
            let initial_buffer_turns =
                crate::consensus::session_initial_buffer_turns(&mesh.decision_makers, &key);
            routing::fan_out_session_start(sessions, &key, initial_buffer_turns);
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
            // An honored request just decided a held drop; if it was the last
            // undecided departure deferring this relay's session-emptied close
            // (the requester survives on a peer relay, so the local roster can
            // be empty here), re-evaluate the close.
            routing::maybe_close_emptied_session(sessions, mesh, &key);
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
        Some(mesh_control_frame::Kind::MeshResumeCursors(_)) => {
            // Handled before this dispatch runs, by `resume_replay_for_frame` +
            // `send_resume_replay` in the driver's own select branch — the reply
            // must go out over this driver's own link, not through anything this
            // function has access to. Nothing left to update here: unlike every
            // other kind, a resume ask carries no session state to fold, only a
            // reply to send.
        }
        Some(mesh_control_frame::Kind::MeshAckCursors(_)) => {
            // Handled before this dispatch runs, by `apply_ack_cursors` in the
            // driver's own select branch — it force-retires this link's own
            // transport state, which this function has no access to.
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
    // Carries this relay's stored initial buffer depth, which is `None` on a
    // resumed relay (it never sized one), so a re-push into a running game never
    // resizes a live buffer.
    if crate::consensus::session_started(decision_makers, key) {
        let initial_buffer_turns =
            crate::consensus::session_initial_buffer_turns(decision_makers, key);
        let _ = control_tx.send(session_start_frame(key.session, initial_buffer_turns));
    }
}

/// Sends this relay's resume cursors for `key` down a freshly registered
/// link's control channel — the mesh counterpart of
/// [`reconcile_leaves_on_join`], closing the gap a redialed link's fresh
/// transport state otherwise leaves: turns in flight or queued at the moment
/// the old link died are gone from that link's own state, but this session's
/// forward-gate cursors survive it (see [`resume_cursor_snapshot`]), so the
/// fresh link can still ask for exactly what's missing. Every Join sends one.
///
/// The frame's `resuming` flag ([`has_resumable_state`]) is what keeps a
/// first join and a real mid-game recovery from being confused with each
/// other even though both can produce the exact same (empty) cursor list: a
/// first join has no forward-gate entry at all, so `resuming` is `false` and
/// the empty cursors ask for nothing; a session recovering from a death whose
/// every slot happens to be gapped or never-seen also has an empty cursor
/// list, but its forward-gate entry exists (`resuming` true), so the SAME
/// empty list instead asks the peer to replay every slot it can, from the
/// start.
fn reconcile_resume_cursors_on_join(
    seen: &SeenRegistries,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let cursors = resume_cursor_snapshot(seen, key);
    let resuming = has_resumable_state(seen, key);
    let _ = control_tx.send(resume_cursors_frame(key.session, cursors, resuming));
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

    /// Reaches into one slot's private forward-gate state so the sparse-set tests
    /// can assert on the exact bound; the `mark_forwarded` API deliberately
    /// exposes only the `New`/`Duplicate` verdict, not the representation.
    fn slot_ahead_len(seen: &MeshSeen, slot: SlotId) -> usize {
        seen.slots.get(&slot).map_or(0, |s| s.ahead.len())
    }

    #[test]
    fn ordinary_in_order_and_small_reorder_traffic_never_grows_the_sparse_set() {
        // The common case must be untouched by the cap: an in-order stream keeps
        // an empty sparse set (each seq folds straight into the prefix), and a
        // small reorder window holds only the handful of seqs still ahead of the
        // gap, collapsing to empty the moment the gap fills.
        let mut seen = MeshSeen::new();
        for seq in 0..1000 {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
            assert_eq!(
                slot_ahead_len(&seen, SlotId(0)),
                0,
                "in-order holds nothing"
            );
        }

        // Deliver a small window out of order: 1005..1010 arrive before 1000..1005.
        for seq in 1005..1010 {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        assert!(
            slot_ahead_len(&seen, SlotId(0)) <= SPARSE_SEEN_CAP,
            "a small reorder window stays far under the cap",
        );
        for seq in 1000..1005 {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        assert_eq!(
            slot_ahead_len(&seen, SlotId(0)),
            0,
            "the filled gap collapses the sparse set back to empty",
        );
    }

    #[test]
    fn gap_heavy_traffic_never_exceeds_the_sparse_cap() {
        // Every other seq is dropped, so the gap below the high-water mark never
        // fills and each arrival lands in the sparse set. Left unbounded the set
        // would grow one entry per arrival for the life of the session; the cap
        // holds it flat.
        let mut seen = MeshSeen::new();
        // seq 0 forms the prefix; from there only even seqs arrive, leaving every
        // odd seq a permanent gap.
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        for seq in (2..20_000).step_by(2) {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
            assert!(
                slot_ahead_len(&seen, SlotId(0)) <= SPARSE_SEEN_CAP,
                "sparse set stayed within the cap after seq {seq}",
            );
        }
        // Well past the cap's worth of arrivals, it is pinned at the bound, not
        // growing with the seq stream.
        assert_eq!(slot_ahead_len(&seen, SlotId(0)), SPARSE_SEEN_CAP);
    }

    #[test]
    fn collapsing_preserves_duplicate_verdicts_for_already_seen_seqs() {
        // The seqs the collapse swallows into the prefix must still read as
        // duplicates: a re-forward of one of them arriving after the collapse is
        // dropped, exactly as it would have been before the prefix moved.
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        // Push enough even seqs to force at least one collapse.
        let last = 2 * (SPARSE_SEEN_CAP as u64 + 10);
        for seq in (2..=last).step_by(2) {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        // Every even seq that has ever been forwarded is still a duplicate,
        // whether the collapse swept it into the prefix or it remains in the
        // sparse set.
        for seq in (0..=last).step_by(2) {
            assert_eq!(
                seen.mark_forwarded(SlotId(0), seq),
                Seen::Duplicate,
                "a re-forward of already-seen seq {seq} must not re-flood",
            );
        }
    }

    #[test]
    fn a_gap_seq_arriving_after_the_collapse_is_treated_as_a_duplicate() {
        // A seq in a gap the collapse has already swallowed reads as a duplicate
        // even though it was never actually forwarded — the safe direction: the
        // echo guard would rather drop a lost/replayed gap turn than re-flood the
        // mesh with what it can no longer prove is new.
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        let last = 2 * (SPARSE_SEEN_CAP as u64 + 10);
        for seq in (2..=last).step_by(2) {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        // The prefix has collapsed forward over the low odd gaps. A low odd seq —
        // one that was skipped and never forwarded — now arrives late and is
        // rejected as below the collapsed prefix.
        assert_eq!(
            seen.mark_forwarded(SlotId(0), 1),
            Seen::Duplicate,
            "a swallowed gap seq is seen, not fresh",
        );
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
                // Unobserved by every caller of this helper (none of them test
                // the reset signal); a fresh, otherwise-untouched `Notify` per
                // registration keeps them independent regardless.
                shutdown: Arc::new(Notify::new()),
            });
        (forward_rx, control_rx)
    }

    /// A synced leave's slot is a raw wire `u32`. A malformed one past `u8`
    /// range must be dropped entirely -- neither pushed to local survivors nor
    /// broadcast across the mesh -- rather than forwarded with a slot id that
    /// can't name any real player. A well-formed leave in the same batch must
    /// still go through normally.
    #[test]
    fn broadcast_leaves_drops_an_out_of_range_slot_and_still_delivers_the_rest() {
        let sessions = routing::Sessions::default();
        let mesh_links = new_mesh_links();
        let key = control_key();

        // Slot 0 is the one that actually left; slot 1 is the surviving peer
        // that should hear about it.
        let (_reg0, _inbox0) = routing::register(&sessions, &key, SlotId(0)).unwrap();
        let (_reg1, mut inbox1) = routing::register(&sessions, &key, SlotId(1)).unwrap();
        let (_forward_rx, mut control_rx) = register_link_channels(&mesh_links, &key);

        let real_leave = LeaveDirective {
            slot: 0,
            reason: 0,
            apply_at_frame: 10,
            leave_seq: 1,
        };
        let malformed_leave = LeaveDirective {
            slot: 300,
            reason: 0,
            apply_at_frame: 10,
            leave_seq: 2,
        };

        broadcast_leaves(
            &sessions,
            &mesh_links,
            &key,
            vec![real_leave, malformed_leave],
        );

        assert_eq!(
            inbox1.try_recv_leave(),
            Some(real_leave),
            "the well-formed departure still reaches the surviving slot"
        );
        assert_eq!(
            inbox1.try_recv_leave(),
            None,
            "the malformed leave was never pushed to any survivor"
        );
        let frame = control_rx
            .try_recv()
            .expect("the well-formed leave is still broadcast across the mesh");
        assert!(
            matches!(
                frame.kind,
                Some(mesh_control_frame::Kind::LeaveDirective(d)) if d == real_leave
            ),
            "the one mesh frame sent is the well-formed leave",
        );
        assert!(
            control_rx.try_recv().is_err(),
            "the malformed leave was never broadcast across the mesh"
        );
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
            provisional: crate::provisional::ProvisionalSessions::new(
                crate::provisional::PROVISIONAL_WINDOW,
            ),
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
        let reg_b = register_mesh_link(
            &links,
            key.clone(),
            peer_b_fwd,
            peer_b_ctl,
            Arc::new(Notify::new()),
        );

        let (peer_c_fwd, mut peer_c_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (peer_c_ctl, _peer_c_ctl_rx) = mpsc::unbounded_channel();
        let reg_c = register_mesh_link(
            &links,
            key.clone(),
            peer_c_fwd,
            peer_c_ctl,
            Arc::new(Notify::new()),
        );

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

    /// The bug this guards: a full mesh forward queue used to just drop the fresh
    /// turn (`let _ = tx.try_send(...)`) — a turn that never enters the link's
    /// `AckManager` has nothing for that link's redundancy to re-carry, so the
    /// peer relay's clients see a permanent per-(slot, seq) gap and stall in
    /// lockstep forever. The fix mirrors `routing::fan_out`'s lagging-peer path:
    /// a full queue resets the congested link (via its `Notify`) instead of
    /// silently dropping into it, so the dial supervisor redials a fresh
    /// connection. Also proves the reset is scoped to *only* the congested
    /// link — a healthy sibling peer link serving the same session keeps
    /// receiving every turn and is never signaled.
    #[tokio::test]
    async fn fan_out_to_mesh_resets_a_full_link_and_keeps_delivering_to_a_healthy_one() {
        let links = new_mesh_links();
        let key = control_key();

        // Peer B is drained every turn and so never fills; peer C is never
        // drained and fills.
        let (peer_b_fwd, mut peer_b_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (peer_b_ctl, _peer_b_ctl_rx) = mpsc::unbounded_channel();
        let peer_b_shutdown = Arc::new(Notify::new());
        let _reg_b = register_mesh_link(
            &links,
            key.clone(),
            peer_b_fwd,
            peer_b_ctl,
            Arc::clone(&peer_b_shutdown),
        );

        let (peer_c_fwd, _peer_c_rx) = mpsc::channel(routing::FORWARD_CAPACITY);
        let (peer_c_ctl, _peer_c_ctl_rx) = mpsc::unbounded_channel();
        let peer_c_shutdown = Arc::new(Notify::new());
        let _reg_c = register_mesh_link(
            &links,
            key.clone(),
            peer_c_fwd,
            peer_c_ctl,
            Arc::clone(&peer_c_shutdown),
        );

        // Fan out past peer C's capacity.
        let mut delivered_to_b = 0;
        for _ in 0..(routing::FORWARD_CAPACITY + 8) {
            fan_out_to_mesh(
                &links,
                &key,
                Payload {
                    ..Default::default()
                },
            );
            if peer_b_rx.try_recv().is_ok() {
                delivered_to_b += 1;
            }
        }

        // The healthy peer received every turn — the congested one never
        // blocked it.
        assert_eq!(delivered_to_b, routing::FORWARD_CAPACITY + 8);

        // The congested peer's link was signaled to reset...
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peer_c_shutdown.notified(),
        )
        .await
        .expect("peer C's full queue must signal its link to reset");
        // ...but peer B's link — never full — was never touched.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                peer_b_shutdown.notified(),
            )
            .await
            .is_err(),
            "a healthy sibling link must not be reset by another link's full queue",
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

    #[test]
    fn resume_cursor_snapshot_is_the_forward_gate_prefix_plus_one() {
        let seen = new_seen_registries();
        let key = control_key();
        // Slot 0 has a contiguous 0..3 prefix; slot 1 has forwarded nothing yet
        // (an out-of-order arrival alone, still gapped at 0) and so has no
        // prefix at all; slot 2 has forwarded exactly seq 0.
        for seq in 0..3 {
            mark_seen(&seen, &key, SlotId(0), seq);
        }
        mark_seen(&seen, &key, SlotId(1), 5); // gapped: no contiguous prefix yet
        mark_seen(&seen, &key, SlotId(2), 0);

        let mut cursors = resume_cursor_snapshot(&seen, &key);
        cursors.sort_by_key(|&(slot, _)| slot);
        assert_eq!(
            cursors,
            vec![(SlotId(0), 3), (SlotId(2), 1)],
            "slot 1's gapped, prefix-less state is absent, not zeroed",
        );
        // Slot 1's omission is not the same as "nothing known about this
        // session" -- the session has genuine forward-gate history (this
        // relay HAS exchanged mesh traffic for it), which is exactly what
        // licenses a resume reply to answer the omitted slot from the start
        // rather than read the omission as a first join.
        assert!(
            has_resumable_state(&seen, &key),
            "a gapped slot still counts as forward-gate history for the session",
        );
    }

    #[test]
    fn resume_cursor_snapshot_of_an_untouched_session_is_empty() {
        let seen = new_seen_registries();
        let key = control_key();
        assert!(resume_cursor_snapshot(&seen, &key).is_empty());
        assert!(
            !has_resumable_state(&seen, &key),
            "no forward-gate entry at all reads as a first join, not a resume",
        );
    }

    #[test]
    fn reconcile_resume_cursors_on_join_sends_an_empty_frame_for_a_first_join() {
        // A session this relay has never forwarded anything for -- a first
        // Join, or a peer that predates this link entirely -- sends a frame
        // with no cursors AND `resuming = false`, which the wire's own doc
        // marks as "replay nothing", never as "replay from the very start".
        let seen = new_seen_registries();
        let key = control_key();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();

        reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

        let frame = control_rx.try_recv().expect("a frame was sent");
        assert_eq!(frame.session, key.session.0);
        match frame.kind {
            Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
                assert!(resume.cursors.is_empty());
                assert!(!resume.resuming, "no forward-gate history to resume from");
            }
            other => panic!("expected MeshResumeCursors, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_resume_cursors_on_join_sends_the_current_snapshot() {
        let seen = new_seen_registries();
        let key = control_key();
        mark_seen(&seen, &key, SlotId(0), 0);
        mark_seen(&seen, &key, SlotId(0), 1);

        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

        let frame = control_rx.try_recv().expect("a frame was sent");
        match frame.kind {
            Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
                assert_eq!(resume.cursors.len(), 1);
                assert_eq!(resume.cursors[0].origin_slot, 0);
                assert_eq!(resume.cursors[0].next_seq, 2);
                assert!(resume.resuming, "the session has forward-gate history");
            }
            other => panic!("expected MeshResumeCursors, got {other:?}"),
        }
    }

    #[test]
    fn a_wholly_gapped_session_still_sends_an_empty_but_resuming_frame() {
        // The case a naive "cursors is empty means fresh join" reading would
        // get wrong: every slot this relay has EVER seen for the session is
        // still gapped (no contiguous prefix on any of them), so the cursor
        // list is empty exactly like a first join's -- but the session has
        // real forward-gate history, so `resuming` must still be true. This
        // is what stops that history from being silently dropped on the floor
        // when the shape of the data alone can't tell the two cases apart.
        let seen = new_seen_registries();
        let key = control_key();
        mark_seen(&seen, &key, SlotId(0), 5); // arrived, but gapped below 5

        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

        let frame = control_rx.try_recv().expect("a frame was sent");
        match frame.kind {
            Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
                assert!(
                    resume.cursors.is_empty(),
                    "no slot formed a contiguous prefix"
                );
                assert!(
                    resume.resuming,
                    "the gap does not erase the session's forward-gate history",
                );
            }
            other => panic!("expected MeshResumeCursors, got {other:?}"),
        }
    }

    #[test]
    fn resume_replay_answers_only_with_this_relays_own_locally_originated_turns() {
        // The ring holds a mix of origins for the same slot (whichever copy won
        // the topological dedup); a resume reply must carry only the `Local`
        // ones -- the no-echo rule a mesh reply is not allowed to violate.
        let mesh = new_mesh_state();
        let key = control_key();
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 0,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Local,
            crate::turn_ring::MAX_GAME_SLOTS,
        );
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 1,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Mesh,
            crate::turn_ring::MAX_GAME_SLOTS,
        );
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 2,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Local,
            crate::turn_ring::MAX_GAME_SLOTS,
        );

        let mut joined = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: register_mesh_link(
                    &mesh.links,
                    key.clone(),
                    mpsc::channel(1).0,
                    mpsc::unbounded_channel().0,
                    Arc::new(tokio::sync::Notify::new()),
                ),
            },
        );

        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
                rally_point_proto::messages::MeshResumeCursors {
                    cursors: vec![rally_point_proto::messages::MeshResumeCursor {
                        origin_slot: 0,
                        next_seq: 0,
                    }],
                    // A listed slot's cursor is honored by seq either way --
                    // `resuming` only changes the answer for a slot the
                    // cursors omit, and every recorded slot here is listed.
                    resuming: false,
                },
            )),
        };

        let (got_key, payloads) =
            resume_replay_for_frame(&frame, &joined, &mesh).expect("something to replay");
        assert_eq!(got_key, key);
        assert_eq!(
            payloads.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![0, 2],
            "only the two locally-originated seqs are replayed",
        );
    }

    #[test]
    fn resume_replay_answers_an_unlisted_slot_from_zero_only_when_the_ask_is_resuming() {
        // The mesh-side counterpart of `TurnRing::replay_local`'s own unit test,
        // but exercised through the actual wire frame and `resume_replay_for_frame`
        // -- proves the `resuming` bit is correctly read off the frame and
        // threaded through, not just that `TurnRing` honors it in isolation.
        let mesh = new_mesh_state();
        let key = control_key();
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 0,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Local,
            crate::turn_ring::MAX_GAME_SLOTS,
        );
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 1,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Local,
            crate::turn_ring::MAX_GAME_SLOTS,
        );

        let mut joined = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: register_mesh_link(
                    &mesh.links,
                    key.clone(),
                    mpsc::channel(1).0,
                    mpsc::unbounded_channel().0,
                    Arc::new(tokio::sync::Notify::new()),
                ),
            },
        );

        // Slot 0 is entirely unlisted in both asks -- this relay's own
        // gap-tracking never formed a contiguous prefix for it before the
        // asker's link died.
        let non_resuming_ask = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
                rally_point_proto::messages::MeshResumeCursors {
                    cursors: vec![],
                    resuming: false,
                },
            )),
        };
        assert!(
            resume_replay_for_frame(&non_resuming_ask, &joined, &mesh).is_none(),
            "a first-join ask with an unlisted slot still replays nothing for it",
        );

        let resuming_ask = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
                rally_point_proto::messages::MeshResumeCursors {
                    cursors: vec![],
                    resuming: true,
                },
            )),
        };
        let (_, payloads) = resume_replay_for_frame(&resuming_ask, &joined, &mesh)
            .expect("a resuming ask replays the unlisted slot from the start");
        assert_eq!(
            payloads.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![0, 1],
        );
    }

    #[test]
    fn resume_replay_is_none_for_an_unjoined_session_or_an_empty_result() {
        let mesh = new_mesh_state();
        let key = control_key();
        let joined = HashMap::new();

        let empty_ask = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
                rally_point_proto::messages::MeshResumeCursors {
                    cursors: vec![],
                    resuming: false,
                },
            )),
        };
        assert!(
            resume_replay_for_frame(&empty_ask, &joined, &mesh).is_none(),
            "an unjoined session has no key to reply under",
        );

        // A different frame kind is never mistaken for a resume ask.
        let other = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::SessionStart(
                rally_point_proto::messages::SessionStart::default(),
            )),
        };
        assert!(resume_replay_for_frame(&other, &joined, &mesh).is_none());
    }

    #[test]
    fn a_first_joins_empty_cursors_ask_for_no_replay_even_on_a_populated_ring() {
        // A first-join peer's cursor frame carries no entries AND `resuming =
        // false` (proven by
        // `reconcile_resume_cursors_on_join_sends_an_empty_frame_for_a_first_join`
        // above); this proves the receiving side honors that absent-means-nothing
        // semantic even when it has plenty it COULD reply with -- a newly-added
        // relay's own clients get their backfill from their own client-side
        // reconnect, not from a mesh peer's unsolicited replay. Contrast
        // `resume_replay_answers_an_unlisted_slot_from_zero_only_when_the_ask_is_resuming`,
        // where the identical empty cursor list means the opposite because
        // `resuming` is true there.
        let mesh = new_mesh_state();
        let key = control_key();
        mesh.turn_ring.record(
            &key,
            &Payload {
                slot: 0,
                seq: 0,
                ..Default::default()
            },
            crate::turn_ring::TurnOrigin::Local,
            crate::turn_ring::MAX_GAME_SLOTS,
        );

        let mut joined = HashMap::new();
        joined.insert(
            key.session,
            SessionState {
                key: key.clone(),
                flush_deadline: tokio::time::Instant::now(),
                _registration: register_mesh_link(
                    &mesh.links,
                    key.clone(),
                    mpsc::channel(1).0,
                    mpsc::unbounded_channel().0,
                    Arc::new(tokio::sync::Notify::new()),
                ),
            },
        );

        let first_join_ask = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
                rally_point_proto::messages::MeshResumeCursors {
                    cursors: vec![],
                    resuming: false,
                },
            )),
        };
        assert!(
            resume_replay_for_frame(&first_join_ask, &joined, &mesh).is_none(),
            "a non-resuming empty cursor map replays nothing, regardless of what the ring holds",
        );
    }

    #[test]
    fn resume_cursor_snapshot_survives_the_links_own_registration_ending() {
        // The forward-gate cursors live in `SeenRegistries`, a session-keyed
        // registry entirely separate from `MeshLinks` -- a link dying (its
        // `MeshLinkRegistration` dropping) must not touch the cursors a fresh
        // link on the same session will read on its own next Join.
        let seen = new_seen_registries();
        let links = new_mesh_links();
        let key = control_key();

        mark_seen(&seen, &key, SlotId(0), 0);
        mark_seen(&seen, &key, SlotId(0), 1);
        let before = resume_cursor_snapshot(&seen, &key);

        // A link registers for the session, then dies (its registration drops,
        // deregistering it from `MeshLinks` -- the RAII path a redial's old
        // link and this test both exercise).
        let registration = register_mesh_link(
            &links,
            key.clone(),
            mpsc::channel(1).0,
            mpsc::unbounded_channel().0,
            Arc::new(tokio::sync::Notify::new()),
        );
        drop(registration);
        assert!(
            links.lock().get(&key).is_none(),
            "the dead link's registration is gone from MeshLinks",
        );

        assert_eq!(
            resume_cursor_snapshot(&seen, &key),
            before,
            "the cursors a fresh link's Join will read are unaffected by the dead link",
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

    /// A mesh-received `LeaveDirective` that this relay's own consensus state
    /// accepts (a first insert for the slot) is fanned to local survivors; one
    /// that conflicts with what this relay already cached (a different
    /// reason or apply frame for the same slot -- an authority bug) is
    /// dropped at this relay's own edge, never reaching local clients.
    /// Forwarding a rejected directive would hand survivors a decision this
    /// relay's own state just flagged as disagreeing with the one it already
    /// holds.
    #[test]
    fn a_leave_directive_dispatch_forwards_only_the_accepted_copy_never_a_rejected_conflict() {
        let sessions: routing::Sessions = Arc::default();
        let mesh_links = new_mesh_links();
        let seen = new_seen_registries();
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let lobby = crate::lobby::new_lobby_registry();
        let chat = crate::chat::new_chat_registry();
        let key = control_key();
        let mesh_state = test_mesh_state(&mesh_links, &seen, &makers, &lobby, &chat);
        // A maker for the session -- `observe_leave` (a Peer-relay concern:
        // only a non-authority relay observes a leave off the mesh) is a
        // no-op with no maker to cache into, so one must exist first.
        let _ = crate::consensus::sync_maker(
            &makers,
            &key,
            rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );

        // A local survivor (slot 5) that must hear an accepted leave and must
        // NOT hear a rejected, conflicting one.
        let (mut guard, mut inbox) =
            routing::register(&sessions, &key, SlotId(5)).expect("slot 5 registers");
        guard.disarm();

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

        let first = LeaveDirective {
            slot: 0,
            reason: 3,
            apply_at_frame: 90,
            leave_seq: 7,
        };
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::LeaveDirective(first)),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
        assert_eq!(
            inbox.try_recv_leave(),
            Some(first),
            "the first, accepted copy is fanned to the local survivor",
        );

        // A second, CONFLICTING directive for the same slot -- a different
        // reason and apply frame, the authority-bug shape `observe_leave`
        // rejects. It must never reach the local survivor.
        let conflicting = LeaveDirective {
            slot: 0,
            reason: 6, // any reason differing from `first`'s -- the conflict is what matters
            apply_at_frame: 150,
            leave_seq: 8,
        };
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::LeaveDirective(conflicting)),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
        assert_eq!(
            inbox.try_recv_leave(),
            None,
            "a rejected, conflicting directive must never be forwarded",
        );

        // An ordinary redundant copy of the FIRST directive is likewise not
        // re-forwarded (already delivered once) -- but this is the harmless
        // case, not the bug this test guards.
        let frame = MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::LeaveDirective(first)),
        };
        dispatch_mesh_control(frame, RelayId(9), &joined, &sessions, &mesh_state);
        assert_eq!(
            inbox.try_recv_leave(),
            None,
            "no re-forward of a redundant copy"
        );
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

    /// The replay ring's bounds must follow the session's actual shape through
    /// the production path: `deliver_turn_to_locals` reads the decision-maker's
    /// slot count and sizes the ring with it, so a 2-slot session's ring caps
    /// at the 2-slot bound rather than the largest-game bound. Exercised
    /// through the choke point itself (not `TurnRing` in isolation) to prove
    /// the count actually arrives there.
    #[test]
    fn the_replay_ring_is_bounded_by_the_sessions_actual_slot_count() {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;

        let sessions = routing::Sessions::default();
        let seen = new_seen_registries();
        let decision_makers = Arc::new(consensus::new_decision_makers());
        let turn_ring = crate::turn_ring::TurnRing::new();
        let key = control_key();
        let _ = consensus::sync_maker(
            &decision_makers,
            &key,
            BufferBounds::new(1, 6).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0), SlotId(1)].into(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        consensus::mark_session_started(&decision_makers, &key);

        // Overfill past the 2-slot count bound (empty commands, so the byte
        // bound never binds): the ring holds exactly the 2-slot cap, proving
        // it was not sized for the largest possible game.
        let cap = crate::turn_ring::max_turns(2);
        for seq in 0..(cap + 5) as u64 {
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                Payload {
                    seq,
                    slot: 0,
                    ..Default::default()
                },
                crate::delivery::DeliveryHome::Local,
            );
        }
        assert_eq!(turn_ring.len(&key), cap);
        assert!(
            cap < crate::turn_ring::max_turns(crate::turn_ring::MAX_GAME_SLOTS),
            "the 2-slot bound is genuinely tighter than the full-game bound",
        );
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
                first.clone(),
                crate::delivery::DeliveryHome::Local,
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
                first,
                crate::delivery::DeliveryHome::Local,
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
            crate::delivery::DeliveryHome::Local,
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
                crate::delivery::DeliveryHome::Local,
            );
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(1),
                sync_payload(u64::from(ordinal), 1, ordinal, value),
                crate::delivery::DeliveryHome::Local,
            );
        }

        assert!(
            rx.try_recv().is_err(),
            "no desync notice: the duplicate delivery did not perturb ordinal alignment",
        );
    }

    /// The leave-frame clamp's history must record each distinct `(slot, seq)`
    /// turn exactly once, even though a multi-relay mesh legitimately delivers
    /// the same turn to a relay via more than one path (a peer's direct copy
    /// plus another peer's reflood). The history is a bounded append — unlike
    /// the per-slot frame max, which is a harmless monotone — so duplicates
    /// walked twice would evict genuine low-seq history and leave
    /// `reachable_frame` with nothing at or below its threshold, pushing its
    /// fallback frames too high: exactly the opening a departing slot's
    /// inflated frame claim needs to strand survivors past a reachable frame.
    #[test]
    fn duplicate_turn_delivery_does_not_corrupt_the_leave_frame_clamp_history() {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;

        let sessions = routing::Sessions::default();
        let seen = new_seen_registries();
        let decision_makers = Arc::new(consensus::new_decision_makers());
        let turn_ring = crate::turn_ring::TurnRing::new();
        let key = control_key();
        let _ = consensus::sync_maker(
            &decision_makers,
            &key,
            BufferBounds::new(1, 6).unwrap(),
            Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );

        // The survivor's turns each arrive twice: the home peer's direct copy,
        // then another peer's reflood of the same turn. Only the first passes
        // the topological dedup; the reflood must leave no trace in the frame
        // history.
        for seq in 0..=21u64 {
            let payload = Payload {
                seq,
                slot: 0,
                game_frame_count: Some(100 + seq as u32),
                commands: vec![0x05].into(),
                ..Default::default()
            };
            assert!(
                deliver_turn_to_locals(
                    &sessions,
                    &seen,
                    &decision_makers,
                    &turn_ring,
                    &key,
                    SlotId(0),
                    payload.clone(),
                    crate::delivery::DeliveryHome::Peer(RelayId(2)),
                )
                .is_some(),
                "the direct copy is fresh",
            );
            assert!(
                deliver_turn_to_locals(
                    &sessions,
                    &seen,
                    &decision_makers,
                    &turn_ring,
                    &key,
                    SlotId(0),
                    payload,
                    crate::delivery::DeliveryHome::Peer(RelayId(3)),
                )
                .is_none(),
                "the reflood is a topological duplicate",
            );
        }

        // With bounds max 6 the history keeps 10 entries (seqs 12..=21) and the
        // frontier is seq 21, so the proven-executed threshold is seq 15: the
        // survivor's provable frame is 115. Doubled appends would have evicted
        // everything at or below the threshold (leaving seqs 17..=21 twice) and
        // pushed the fallback to 117 — past what the survivor provably reached.
        assert_eq!(
            consensus::reachable_frame(&decision_makers, &key, SlotId(1)),
            Some(115),
            "the clamp ceiling reflects single-counted history",
        );
    }

    #[test]
    fn mesh_window_exhausted_trips_only_strictly_past_the_cap() {
        assert!(!mesh_window_exhausted(0));
        assert!(!mesh_window_exhausted(MESH_UNACKED_WINDOW_CAP));
        assert!(mesh_window_exhausted(MESH_UNACKED_WINDOW_CAP + 1));
    }

    fn self_signed() -> (
        Vec<rally_point_transport::rustls::pki_types::CertificateDer<'static>>,
        rally_point_transport::rustls::pki_types::PrivateKeyDer<'static>,
        rally_point_transport::rustls::pki_types::CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = rally_point_transport::rustls::pki_types::PrivateKeyDer::try_from(
            cert.signing_key.serialize_der(),
        )
        .unwrap();
        (vec![cert_der.clone()], key, cert_der)
    }

    /// A loopback mesh-link QUIC connection, wrapped as a [`MeshLink`]. Only one
    /// side is needed for the ack-cursor tests below: `apply_ack_cursors` and
    /// `reconcile_ack_cursors` operate purely on in-memory transport state
    /// (`payloads_in_flight`, `delivered_through_all`, `retire_through`), so
    /// what matters is a genuinely established connection to build a
    /// `MeshLink` from, not a live peer on the other end.
    async fn connected_mesh_link() -> (
        rally_point_transport::MeshLink,
        rally_point_transport::quinn::Endpoint,
        rally_point_transport::quinn::Endpoint,
    ) {
        use std::net::{Ipv4Addr, SocketAddr};

        use rally_point_transport::quic::{mesh_client_config, server_config};
        use rally_point_transport::quinn;

        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();
        let mut roots = rally_point_transport::rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let (dial_chain, dial_key, _) = self_signed();
        let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let accept = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let _server_conn = accept.await.unwrap();

        (
            rally_point_transport::MeshLink::new(client_conn),
            client,
            server,
        )
    }

    /// A minimal `SessionState` for `reconcile_ack_cursors`'s `joined` map --
    /// a real `MeshLinkRegistration` (needed so its `Drop` doesn't panic) but
    /// otherwise inert: nothing in this test drains the registry it points at.
    fn bare_session_state(key: SessionKey) -> SessionState {
        let links = new_mesh_links();
        let (fwd, _fwd_rx) = mpsc::channel(8);
        let (ctl, _ctl_rx) = mpsc::unbounded_channel();
        let registration =
            register_mesh_link(&links, key.clone(), fwd, ctl, Arc::new(Notify::new()));
        SessionState {
            key,
            flush_deadline: tokio::time::Instant::now(),
            _registration: registration,
        }
    }

    /// `apply_ack_cursors` force-retires exactly the named slots' unacked
    /// windows through the peer-confirmed cursor, ignores a frame naming a
    /// different session or the wrong kind, and tolerates a malformed slot id
    /// rather than panicking -- the mesh-link counterpart of a client-edge
    /// driver's beacon-reader-fed `retire_through` call.
    #[tokio::test]
    async fn apply_ack_cursors_retires_the_named_slots_unacked_window() {
        let (mut link, _client_ep, _server_ep) = connected_mesh_link().await;
        let key = control_key();
        let session = key.session;
        link.open_session(mesh_session_key(&key));
        let mut joined = HashMap::new();
        joined.insert(session, bare_session_state(key.clone()));

        for slot in [0u8, 1] {
            for seq in 0..3u64 {
                let payload = Payload {
                    seq,
                    slot: u32::from(slot),
                    commands: vec![0xAA].into(),
                    ..Default::default()
                };
                link.send(mesh_session_key(&key), Some(payload), None)
                    .unwrap();
            }
        }
        assert_eq!(link.payloads_in_flight(mesh_session_key(&key)), 6);

        // A frame for a different (unjoined) session is a no-op.
        let other_session_frame = ack_cursors_frame(SessionId(2), vec![(SlotId(0), 2)]);
        apply_ack_cursors(&mut link, &other_session_frame, &joined);
        assert_eq!(link.payloads_in_flight(mesh_session_key(&key)), 6);

        // Retire only slot 0 through seq 1 (seq 2 stays in flight); slot 1 is
        // untouched.
        let frame = ack_cursors_frame(session, vec![(SlotId(0), 1)]);
        apply_ack_cursors(&mut link, &frame, &joined);
        assert_eq!(
            link.payloads_in_flight(mesh_session_key(&key)),
            4,
            "slot 0's seqs 0 and 1 retired; its seq 2 and all of slot 1 remain",
        );

        // A malformed slot id (out of u8 range) in the cursor list is
        // skipped, not a panic; the rest of the frame still applies.
        let mixed = MeshControlFrame {
            session: session.0,
            kind: Some(mesh_control_frame::Kind::MeshAckCursors(
                rally_point_proto::messages::MeshAckCursors {
                    cursors: vec![
                        rally_point_proto::messages::MeshAckCursor {
                            slot: 300,
                            delivered_through: 0,
                        },
                        rally_point_proto::messages::MeshAckCursor {
                            slot: 1,
                            delivered_through: 2,
                        },
                    ],
                },
            )),
        };
        apply_ack_cursors(&mut link, &mixed, &joined);
        assert_eq!(
            link.payloads_in_flight(mesh_session_key(&key)),
            1,
            "slot 1 fully retired despite the malformed entry alongside it; \
             only slot 0's seq 2 remains",
        );
    }

    /// `fold_oversize_into_link` records a stream-delivered oversize turn in
    /// the link's per-session receive dedup — advancing the delivered-through
    /// cursor the ack-beacon pushes — and gates dispatch: a fresh turn (and
    /// every non-oversize frame) proceeds, an already-delivered copy is
    /// dropped before it burns a session-level dedup pass, and a frame for an
    /// unjoined session passes through for the dispatch's own defensive drop.
    #[tokio::test]
    async fn fold_oversize_into_link_advances_the_dedup_and_gates_dispatch() {
        let (mut link, _client_ep, _server_ep) = connected_mesh_link().await;
        let key = control_key();
        let session = key.session;
        link.open_session(mesh_session_key(&key));
        let mut joined = HashMap::new();
        joined.insert(session, bare_session_state(key.clone()));

        let oversize = MeshControlFrame {
            session: session.0,
            kind: Some(mesh_control_frame::Kind::OversizeTurn(Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xAB; 2000].into(),
                ..Default::default()
            })),
        };

        assert!(
            fold_oversize_into_link(&mut link, &oversize, &joined),
            "a fresh oversize turn proceeds to dispatch",
        );
        assert_eq!(
            link.delivered_through(mesh_session_key(&key), SlotId(0)),
            Some(0),
            "the stream-delivered seq advances the link's delivered prefix",
        );

        assert!(
            !fold_oversize_into_link(&mut link, &oversize, &joined),
            "a redundant copy is dropped before dispatch",
        );

        // Any other frame kind passes straight through.
        let other = ack_cursors_frame(session, vec![(SlotId(0), 0)]);
        assert!(fold_oversize_into_link(&mut link, &other, &joined));

        // A session this link hasn't joined has no transport state to fold
        // into; the frame still reaches the dispatch's own unjoined-session
        // drop.
        let unjoined = MeshControlFrame {
            session: 99,
            ..oversize.clone()
        };
        assert!(fold_oversize_into_link(&mut link, &unjoined, &joined));
    }

    /// `reconcile_ack_cursors` pushes a session's advanced cursors exactly
    /// once each, stays quiet once the peer has heard the latest value, and
    /// resumes pushing on the next genuine advance -- the push-on-advance
    /// discipline the mesh-link ack-beacon needs to stay off the hot path on
    /// a healthy, quiet link.
    #[tokio::test]
    async fn reconcile_ack_cursors_pushes_only_on_advance() {
        let key = control_key();
        let session = key.session;

        // `delivered_through_all` reads receive state, so this needs a real
        // sender-to-receiver round trip (mirroring the transport-level
        // tests), not just one side of a connection.
        let (mut sender, mut receiver, _e1, _e2) = connected_mesh_link_pair().await;
        receiver.open_session(mesh_session_key(&key));
        sender.open_session(mesh_session_key(&key));
        sender
            .send(mesh_session_key(&key), Some(turn_payload(0, 0)), None)
            .unwrap();
        receiver.recv().await.unwrap();

        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let mut sent: HashMap<(SessionId, SlotId), u64> = HashMap::new();
        let mut joined = HashMap::new();
        joined.insert(session, bare_session_state(key.clone()));

        reconcile_ack_cursors(&receiver, &control_tx, &mut sent, &joined);
        let frame = control_rx.try_recv().expect("the fresh cursor is pushed");
        match frame.kind {
            Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) => {
                assert_eq!(cursors.cursors.len(), 1);
                assert_eq!(cursors.cursors[0].slot, 0);
                assert_eq!(cursors.cursors[0].delivered_through, 0);
            }
            other => panic!("expected MeshAckCursors, got {other:?}"),
        }

        // Nothing advanced: a second reconcile with no new receipt sends
        // nothing.
        reconcile_ack_cursors(&receiver, &control_tx, &mut sent, &joined);
        assert!(
            control_rx.try_recv().is_err(),
            "no advance since the last push -- the beacon stays quiet",
        );

        // A genuine advance (seq 1) is pushed again.
        sender
            .send(mesh_session_key(&key), Some(turn_payload(0, 1)), None)
            .unwrap();
        receiver.recv().await.unwrap();
        reconcile_ack_cursors(&receiver, &control_tx, &mut sent, &joined);
        let frame = control_rx.try_recv().expect("the advance is pushed");
        match frame.kind {
            Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) => {
                assert_eq!(cursors.cursors[0].delivered_through, 1);
            }
            other => panic!("expected MeshAckCursors, got {other:?}"),
        }
    }

    /// A second loopback mesh-link pair (both sides), for the one test above
    /// that needs a real receive to observe `delivered_through_all` advance —
    /// distinct from `connected_mesh_link`, which only needs one live side.
    pub(crate) async fn connected_mesh_link_pair() -> (
        rally_point_transport::MeshLink,
        rally_point_transport::MeshLink,
        rally_point_transport::quinn::Endpoint,
        rally_point_transport::quinn::Endpoint,
    ) {
        use std::net::{Ipv4Addr, SocketAddr};

        use rally_point_transport::quic::{mesh_client_config, server_config};
        use rally_point_transport::quinn;

        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();
        let mut roots = rally_point_transport::rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let (dial_chain, dial_key, _) = self_signed();
        let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let accept = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = accept.await.unwrap();

        (
            rally_point_transport::MeshLink::new(client_conn),
            rally_point_transport::MeshLink::new(server_conn),
            client,
            server,
        )
    }

    fn turn_payload(slot: u8, seq: u64) -> Payload {
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![0xAA].into(),
            ..Default::default()
        }
    }
}
