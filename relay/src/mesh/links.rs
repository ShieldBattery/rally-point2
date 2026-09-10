//! Per-link plumbing: the session→peer-relay fan-out registry, the channels
//! and reset signal one link driver registers per session, the process-local
//! provenance lease that decides which physical connection to a peer is
//! current, and the link-wide RTT cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_proto::messages::{MeshControlFrame, Payload};
use rally_point_transport::noq;
use tokio::sync::{Notify, mpsc};

use crate::routing::SessionKey;

use super::{MeshCommand, MeshState};

/// Live mesh links for every session on this relay: each `SessionKey` → the
/// channels that reach each connected peer-relay's mesh-link task for that
/// session. Only turns received from this relay's local clients are fanned out
/// through this registry; mesh-origin turns stop after local delivery.
///
/// Each link registers a [`MeshLinkTx`] bundling two senders into the same driver:
/// the bounded per-turn forward channel and the unbounded control-frame channel
/// (synced-leave propagation). Bundling them means a session's registration —
/// created on `Join`, torn down on `Leave` or driver exit — governs both together.
///
/// Shared across all connection + mesh-link tasks. A plain (non-async) mutex is
/// deliberate: every critical section is a short, await-free roster edit —
/// senders are cloned out before any send — so the lock is never held across a
/// turn's delivery, mirroring [`crate::routing::Sessions`].
pub type MeshLinks = Arc<Mutex<HashMap<SessionKey, Vec<MeshLinkTx>>>>;

/// Creates an empty mesh-link registry for a relay with no peer-relay links yet.
/// Used by the server edge and tests to obtain a `MeshLinks` without referencing
/// the private `MeshForwardTx` type.
pub fn new_mesh_links() -> MeshLinks {
    Arc::new(Mutex::new(HashMap::new()))
}
/// Process-local provenance for the currently accepted physical connection to
/// each peer relay. The generation never crosses the wire; it only prevents a
/// superseded driver's already-decoded ingress from mutating shared relay
/// state. Entries remain as high-water tombstones after a driver exits.
pub(crate) type CurrentMeshLinks = Arc<Mutex<HashMap<RelayId, Arc<Mutex<CurrentMeshLink>>>>>;

pub(crate) struct CurrentMeshLink {
    generation: u64,
    superseded: Arc<Notify>,
}

/// Identity minted when a connection attempt is created, before handshake
/// completion can reorder attempts. The per-generation notification both wakes
/// an old driver promptly and retains a permit if replacement wins before that
/// driver starts waiting.
pub struct MeshLinkAttempt {
    generation: u64,
    pub(super) superseded: Arc<Notify>,
}

/// Stable per-peer provenance lease returned by a successful claim. Drivers
/// retain this `Arc`, so every hot-path check takes only the peer's mutex and
/// never re-enters the fleet-wide peer map.
pub struct MeshLinkLease {
    generation: u64,
    current: Arc<Mutex<CurrentMeshLink>>,
    pub(super) superseded: Arc<Notify>,
}

fn next_mesh_link_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn new_mesh_link_attempt() -> MeshLinkAttempt {
    MeshLinkAttempt {
        generation: next_mesh_link_generation(),
        superseded: Arc::new(Notify::new()),
    }
}

impl MeshLinkAttempt {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Claims `attempt` as the locally current physical link to `peer_id`, returning
/// the stable per-peer lease the driver uses thereafter. A slow older handshake
/// can finish after its replacement; numeric comparison makes that late claim a
/// no-op and preserves the newer driver's provenance.
pub fn claim_mesh_link(
    mesh: &MeshState,
    peer_id: RelayId,
    attempt: &MeshLinkAttempt,
) -> Option<MeshLinkLease> {
    let peer = {
        let mut links = mesh.current_links.lock();
        Arc::clone(links.entry(peer_id).or_insert_with(|| {
            Arc::new(Mutex::new(CurrentMeshLink {
                generation: 0,
                superseded: Arc::new(Notify::new()),
            }))
        }))
    };
    let mut current = peer.lock();
    if current.generation >= attempt.generation {
        attempt.superseded.notify_one();
        return None;
    }
    current.superseded.notify_one();
    current.generation = attempt.generation;
    current.superseded = Arc::clone(&attempt.superseded);
    drop(current);
    Some(MeshLinkLease {
        generation: attempt.generation,
        current: peer,
        superseded: Arc::clone(&attempt.superseded),
    })
}

/// The verdict of [`claim_verified_mesh_link`]: claimed and cleared to serve,
/// or refused — with the two refusals distinguished so each edge maps them to
/// its own retry policy (a superseded dial stops; an under-floor peer retries
/// like any failed attempt).
pub enum MeshLinkAdmission {
    /// Verified and claimed: this attempt is now the peer's current link.
    Claimed(MeshLinkLease),
    /// The peer's advertised datagram budget undercuts the guaranteed floor —
    /// an unsupported configuration, refused before it could claim anything.
    UnderFloor(rally_point_transport::quic::DatagramBudgetTooSmall),
    /// A newer attempt already claimed the peer.
    Superseded,
}

/// Verifies `connection` clears the guaranteed datagram floor, then claims
/// `attempt` as the current link to `peer_id`. The order is load-bearing:
/// claiming supersedes the peer's current driver (advancing the generation
/// and waking that driver to exit), so an attempt that is going to be refused
/// must be refused BEFORE it can claim — otherwise an authenticated but
/// misconfigured connection kills a healthy mesh link on its way to being
/// rejected and leaves nothing serving the peer. Both mesh establishment
/// directions admit through this one function so the ordering cannot drift
/// between them.
pub fn claim_verified_mesh_link(
    mesh: &MeshState,
    peer_id: RelayId,
    attempt: &MeshLinkAttempt,
    connection: &noq::Connection,
) -> MeshLinkAdmission {
    if let Err(error) = rally_point_transport::quic::verify_datagram_budget(connection) {
        return MeshLinkAdmission::UnderFloor(error);
    }
    match claim_mesh_link(mesh, peer_id, attempt) {
        Some(lease) => MeshLinkAdmission::Claimed(lease),
        None => MeshLinkAdmission::Superseded,
    }
}

impl MeshLinkLease {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether this lease still names the peer's current link — false once a
    /// newer claim has superseded it. Drivers gate their work through the
    /// gated `with_current` dispatch / the supersession notification rather
    /// than polling this; it is the direct observable for asserting a refused
    /// admission left the standing link untouched.
    pub fn is_current(&self) -> bool {
        self.current.lock().generation == self.generation
    }

    /// Runs one synchronous ingress or command mutation while holding the
    /// per-peer provenance lock. A replacement claim therefore linearizes
    /// either before this closure (and rejects it) or after all shared-state
    /// effects, never halfway through.
    pub(super) fn with_current<T>(&self, dispatch: impl FnOnce() -> T) -> Option<T> {
        let current = self.current.lock();
        if current.generation != self.generation {
            return None;
        }
        Some(dispatch())
    }
}

pub(super) enum LeaseAwait<T> {
    Completed(T),
    Superseded,
}

pub(super) async fn await_while_current<T>(
    lease: &MeshLinkLease,
    future: impl std::future::Future<Output = T>,
) -> LeaseAwait<T> {
    tokio::select! {
        biased;
        _ = lease.superseded.notified() => LeaseAwait::Superseded,
        result = future => LeaseAwait::Completed(result),
    }
}

/// The channel that pushes a turn to a peer-relay's mesh-link task. Tagged with
/// the session id so one merged receiver per link can demux to the right
/// session's transport state — every game on a relay-pair shares one QUIC
/// connection, so a single driver task drains all sessions' outbound turns from
/// one channel.
pub(crate) type MeshForwardTx = mpsc::Sender<(SessionId, Payload)>;

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
pub(crate) type MeshControlTx = mpsc::UnboundedSender<MeshControlFrame>;

/// The pair of senders one session registers into [`MeshLinks`] for one link: the
/// bounded per-turn forward channel and the unbounded control-frame channel, both
/// draining into the same link driver. Held together so a session's registration
/// governs both. Public only because it appears in the [`MeshLinks`] alias; its
/// fields are private, so the registry is built and read solely through this module.
pub struct MeshLinkTx {
    /// Distinguishes this entry from every other peer relay's entry in the same
    /// session's fan-out vec, so a driver deregisters only its own on teardown.
    pub(super) id: u64,
    /// Bounded per-turn forward channel (turns, redundancy re-carried on drop).
    pub(super) forward: MeshForwardTx,
    /// Unbounded control-frame channel (synced-leave propagation, never dropped).
    pub(super) control: MeshControlTx,
    /// Signals this link's driver to reset when its shared forward queue is
    /// full — see [`fan_out_to_mesh`]. One `Notify` per link (shared by every
    /// session registered on it, since they all drain the same queue), cloned
    /// in here so a full-queue observation for *this* session's entry resets
    /// only the one congested link, never a sibling peer link serving the same
    /// session. Mirrors [`crate::routing::SlotEntry`]'s `shutdown` field.
    pub(super) shutdown: Arc<Notify>,
}

/// Hands out a process-unique id for each mesh-link registration. A session's
/// [`MeshLinks`] entry is a vec with one element per connected peer relay; the id
/// tags each element so its owning driver can remove exactly that element when it
/// winds down, without disturbing the other peers still serving the session.
pub(super) fn next_mesh_link_id() -> u64 {
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
/// ([`mesh::control`](crate::mesh::control)) treats as a dead link to re-sync on
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
/// [`run_mesh_link`](super::run_mesh_link); tests pass a shorter real duration so the teardown is
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
pub(super) const MESH_UNACKED_WINDOW_CAP: usize = 8 * 1024;

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
pub(super) const MESH_STREAM_WRITE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

/// Whether one session's mesh-link unacked window has crossed
/// [`MESH_UNACKED_WINDOW_CAP`] -- the driver's cue to reset the link rather
/// than let the window grow further. Mirrors the client edge's own
/// `check_cap` (`client::driver`) in shape, split out so the arithmetic is
/// testable on its own, independent of the full select-loop machinery that
/// applies it.
pub(super) fn mesh_window_exhausted(in_flight: usize) -> bool {
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
    /// A newer physical connection to the same peer claimed local provenance.
    /// Intentional: the old supervisor must not redial and compete with it.
    Superseded,
}

/// Registers one peer-relay link's `(forward, control)` senders and its
/// reset signal for `key`, appending them as a new element in that session's
/// fan-out vec, and returns the RAII guard that removes *only this* element
/// when dropped. Each session's entry holds one element per connected peer
/// relay, so registering must never clobber the peers already serving the
/// session. `shutdown` is the link's own `Notify` (shared across every session
/// registered on it), so [`fan_out_to_mesh`] can reset exactly this link on a
/// full forward queue without touching any sibling peer link.
pub(crate) fn register_mesh_link(
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

/// One session's per-link driver state: its routing key (tenant-correct), its own
/// flush deadline (independent per session — one game's flush cadence doesn't reset
/// another's), and the RAII guard that deregisters its mesh forward channel.
pub(super) struct SessionState {
    pub(super) key: SessionKey,
    pub(super) flush_deadline: tokio::time::Instant,
    /// Deregisters this session's mesh forward channel when the `SessionState` is
    /// dropped — on a `Leave`, a normal wind-down, or the driver task being
    /// cancelled. Never read; its `Drop` is the point.
    pub(super) _registration: MeshLinkRegistration,
}

/// An RAII guard tying a session's mesh forward-channel registration to the
/// lifetime of its [`SessionState`]. Dropping it deregisters the channel, so the
/// registration is torn down on *every* exit from [`run_mesh_link`]: a `Leave`
/// removes the `SessionState`; a normal wind-down or a **cancelled** driver task (a
/// dialer retargeting or removing this peer drops the whole driver future) drops the
/// `joined` map. Without it, task cancellation would skip the cleanup and leave a
/// dead forward channel in `mesh.links` for a session this link no longer serves —
/// a leak, since session ids are never reused.
pub(crate) struct MeshLinkRegistration {
    pub(super) links: MeshLinks,
    pub(super) key: SessionKey,
    /// The registered channel's id, so the guard removes only this link's entry
    /// from the session's fan-out vec — never the peers still serving it.
    pub(super) id: u64,
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
fn link_rtt_us(connection: &rally_point_transport::noq::Connection) -> u32 {
    rtt_us(
        connection
            .path_stats(rally_point_transport::noq::PathId::ZERO)
            .unwrap_or_default()
            .rtt,
    )
}

/// Maximum age of the relay-pair RTT used to ingest remote conditions. RTT is
/// link-wide, so one sample can serve all sessions and sidecars on the same
/// connection for 150ms without making consensus meaningfully less current.
pub(super) const MESH_RTT_CACHE_TTL: std::time::Duration = std::time::Duration::from_millis(150);

/// A timestamped, on-use cache for the relay-pair RTT. An empty cache always
/// samples; an old cache refreshes immediately before the next sidecar is
/// ingested. No timer drives it, so a dormant connection neither wakes nor
/// returns a value retained from before the idle period.
#[derive(Debug, Default)]
pub(super) struct MeshRttCache {
    rtt_us: u32,
    sampled_at: Option<tokio::time::Instant>,
}

impl MeshRttCache {
    pub(super) fn get_or_refresh(
        &mut self,
        connection: &rally_point_transport::noq::Connection,
        now: tokio::time::Instant,
    ) -> u32 {
        self.get_or_refresh_with(now, || link_rtt_us(connection))
    }

    /// The cache policy separated from the noq stats read so deterministic
    /// tests can advance an explicit clock and count samples.
    pub(super) fn get_or_refresh_with(
        &mut self,
        now: tokio::time::Instant,
        sample: impl FnOnce() -> u32,
    ) -> u32 {
        if self
            .sampled_at
            .is_none_or(|sampled_at| now.duration_since(sampled_at) >= MESH_RTT_CACHE_TTL)
        {
            self.rtt_us = sample();
            self.sampled_at = Some(now);
        }
        self.rtt_us
    }
}
