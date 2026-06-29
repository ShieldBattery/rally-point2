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

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{LinkConditions, Payload, SlotConditions};
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
/// Shared across all connection + mesh-link tasks. A plain (non-async) mutex is
/// deliberate: every critical section is a short, await-free roster edit —
/// senders are cloned out before any send — so the lock is never held across a
/// turn's delivery, mirroring [`routing::Sessions`].
pub type MeshLinks = Arc<Mutex<HashMap<SessionKey, Vec<MeshForwardTx>>>>;

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
}

/// Creates a `MeshState` with empty registries for a relay that has no peer-relay
/// links, no sessions, and no local clients yet.
pub fn new_mesh_state() -> MeshState {
    MeshState {
        links: new_mesh_links(),
        seen: new_seen_registries(),
        conditions: new_conditions_registry(),
    }
}
/// The channel that pushes a turn to a peer-relay's mesh-link task. Tagged with
/// the session id so one merged receiver per link can demux to the right
/// session's transport state — every game on a relay-pair shares one QUIC
/// connection, so a single driver task drains all sessions' outbound turns from
/// one channel.
type MeshForwardTx = mpsc::Sender<(rally_point_proto::ids::SessionId, Payload)>;
/// Capacity of a mesh-link driver's `MeshCommand` channel — the Join/Leave
/// stream the test (today) or the coordinator's session-descriptor push
/// (Phase 3) sends on. These are low-frequency control messages (a handful
/// per game over its life, not the turn stream), so a small bounded capacity
/// is right: enough headroom that a slow driver draining one Join doesn't
/// block the next, without reserving for a traffic burst that never comes.
pub(crate) const COMMAND_CAPACITY: usize = 32;

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
/// coordinator's future `Join` source (the binary holds its command sender for
/// exactly this; tearing never-joined links down would strand the pair, since
/// the dial side runs once with no reconnect supervisor yet).
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Why a mesh-link driver exited. A reconnect supervisor (when one lands)
/// distinguishes intentional teardown from a dropped connection: only the
/// latter is worth retrying, since `Idle` means a deliberate wind-down and
/// `CommandChannelClosed` means the relay itself is shutting the link down.
///
/// `ConnectionFailed` covers every transport-level exit — a QUIC idle
/// timeout, a read/send error, or a keepalive that stopped round-tripping.
/// Those surface the same from the driver's perspective (the link is gone);
/// the reconnect supervisor treats them all as retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshLinkExit {
    /// The link had at least one session, went empty, and stayed empty past
    /// [`IDLE_TIMEOUT`]. An intentional wind-down, not a failure.
    Idle,
    /// The connection failed: a recv/send error or QUIC idle timeout. The
    /// peer is unreachable or dead.
    ConnectionFailed,
    /// The command channel closed (the relay is tearing the link down — its
    /// `MeshCommand` sender was dropped). An intentional shutdown.
    CommandChannelClosed,
}

/// Removes all mesh forward channels for `key` (the peer-relay link for that
/// session has closed). Idempotent.
pub fn deregister_mesh_link(links: &MeshLinks, key: &SessionKey) {
    let mut roster = links.lock();
    roster.remove(key);
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
            Some(mesh_txs) => mesh_txs.clone(),
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
    mut commands: mpsc::Receiver<MeshCommand>,
    sessions: routing::Sessions,
    mesh: MeshState,
    idle_timeout: std::time::Duration,
) -> MeshLinkExit {
    let MeshState {
        links: mesh_links,
        seen: seen_registries,
        conditions,
    } = mesh;

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
                        if let Some(peer_conditions) = &mesh_received.conditions {
                            tracing::trace!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slots = peer_conditions.slots.len(),
                                "received peer-relay link conditions",
                            );
                        }
                        for payload in mesh_received.delivery.fresh {
                            let slot = rally_point_proto::ids::SlotId(payload.slot as u8);
                            if mark_seen(&seen_registries, &key, slot, payload.seq)
                                == Seen::Duplicate
                            {
                                continue;
                            }
                            routing::fan_out(&sessions, &key, slot, payload.clone());
                            fan_out_to_mesh(&mesh_links, &key, payload);
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
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some((session_id, payload)) => {
                        let Some(state) = joined.get(&session_id) else {
                            continue;
                        };
                        let key = state.key.clone();
                        let outgoing = snapshot_conditions(&conditions, &key);
                        if let Err(error) = link.send(session_id, Some(payload), outgoing) {
                            tracing::info!(%error, "mesh send failed; closing link");
                            break MeshLinkExit::ConnectionFailed;
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
                continue;
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
                        {
                            let mut roster = mesh_links.lock();
                            roster
                                .entry(key.clone())
                                .or_default()
                                .push(forward_tx.clone());
                        }
                        joined.insert(
                            session_id,
                            SessionState {
                                key,
                                flush_deadline: tokio::time::Instant::now() + routing::FLUSH_INTERVAL,
                            },
                        );
                        idle_since = None;
                        continue;
                    }
                    Some(MeshCommand::Leave(key)) => {
                        let session_id = key.session;
                        if joined.remove(&session_id).is_some() {
                            link.close_session(session_id);
                            deregister_mesh_link(&mesh_links, &key);
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

    for state in joined.values() {
        deregister_mesh_link(&mesh_links, &state.key);
    }
    exit
}

/// One session's per-link driver state: its routing key (tenant-correct), and
/// its own flush deadline (independent per session — one game's flush cadence
/// doesn't reset another's).
struct SessionState {
    key: SessionKey,
    flush_deadline: tokio::time::Instant,
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
}
