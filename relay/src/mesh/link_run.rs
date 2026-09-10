//! The mesh-link driver's entry point: the command and I/O types one
//! established relay-pair connection is started with, the link-wide
//! maintenance schedule, and `run_mesh_link`'s setup and `select!` skeleton.
//!
//! The longer arm bodies live beside this in `link_arms` and `link_commands`,
//! as methods on the [`LinkDriver`] this function builds.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::sync::Arc;

use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{MeshControlFrame, Payload};
use tokio::sync::{Notify, mpsc};

use crate::routing::{self, SessionKey};

use super::MeshState;
use super::link_arms::LinkDriver;
use super::links::{MeshLinkExit, MeshLinkLease, MeshRttCache, SessionState};

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

/// An established physical link surfaced to the descriptor-driven Join source:
/// peer id, process-local generation, and its command sender.
pub type MeshLinkHandle = (RelayId, u64, mpsc::UnboundedSender<MeshCommand>);

/// The mesh control stream's I/O for one established link, handed to the link
/// driver: the send half this relay writes its outbound `MeshControlFrame`s on,
/// and the channel the peer's frames arrive over (fed by a
/// [`spawn_mesh_control_reader`](rally_point_transport::mesh_control_stream::spawn_mesh_control_reader)
/// task). Bundled so the driver's signature stays within the argument count the
/// codebase holds elsewhere, mirroring [`PresenceIo`](crate::session::presence::PresenceIo).
pub struct MeshControlIo {
    /// The send half of the bidirectional control stream — outbound frames.
    pub tx: rally_point_transport::noq::SendStream,
    /// The peer's control frames, assembled off its recv half by a reader task.
    pub rx: mpsc::Receiver<MeshControlFrame>,
}

/// All side-channel I/O and process-local provenance for one physical mesh
/// link. Keeping these together makes it hard to start a driver without the
/// generation fence that authorizes its ingress.
pub struct MeshLinkIo {
    /// The peer presence stream.
    pub presence: crate::session::presence::PresenceIo,
    /// The peer mesh-control stream.
    pub control: MeshControlIo,
    /// The process-local per-peer provenance lease won after this link's
    /// handshake.
    pub lease: MeshLinkLease,
}

/// The one maintenance timer shared by every session multiplexed over a mesh
/// link. It is armed when the first session joins, left unchanged by later
/// joins, advanced once after each link-wide maintenance pass, and disarmed
/// when the last session leaves. An unarmed timer has no Tokio sleep behind it,
/// so a connected link with no joined sessions stays parked indefinitely.
#[derive(Debug, Default)]
pub(super) struct MeshMaintenanceTimer {
    deadline: Option<tokio::time::Instant>,
}

impl MeshMaintenanceTimer {
    pub(super) fn arm(&mut self, now: tokio::time::Instant) {
        if self.deadline.is_none() {
            self.deadline = Some(now + routing::FLUSH_INTERVAL);
        }
    }

    pub(super) fn complete_tick(&mut self, now: tokio::time::Instant) {
        debug_assert!(self.deadline.is_some());
        self.deadline = Some(now + routing::FLUSH_INTERVAL);
    }

    pub(super) fn disarm(&mut self) {
        self.deadline = None;
    }

    pub(super) fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }
}

/// Defers one session's maintenance flush only when a normal datagram send
/// already re-carried an unacked turn. A fresh-only or reliable-stream send
/// leaves the deadline alone, so the maintenance pass still supplies the
/// redundancy that send could not.
pub(super) fn defer_flush_after_send(
    flush_deadline: &mut tokio::time::Instant,
    carried_redundancy: bool,
    now: tokio::time::Instant,
) {
    if carried_redundancy {
        *flush_deadline = now + routing::FLUSH_INTERVAL;
    }
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
/// - **Marks `MeshSeen`** before fanning out to local clients, so reconnect,
///   resume, or re-home overlap is caught as `Duplicate` and dropped.
/// - **Stops peer turns locally**. A turn received from this peer reaches this
///   relay's local clients and is never sent onto another mesh link. The
///   driver's outbound queue carries only turns originated by this relay's
///   local clients.
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
/// [`IDLE_TIMEOUT`](super::IDLE_TIMEOUT); tests pass a shorter real duration. This is distinct from
/// QUIC's own idle timeout (see [`IDLE_TIMEOUT`](super::IDLE_TIMEOUT)).
///
/// # Tenant scoping
///
/// The wire carries a bare `session: u64` with no tenant (see `MeshPacket`).
/// Session ids are unique only *within* a tenant, so the driver keys its
/// per-session state by `SessionKey` (tenant + session) — never the bare id —
/// and a `SessionId -> SessionState` map demultiplexes a received datagram to
/// the right session. The collision guard runs on every `Join`: a caller that
/// skips [`join_sessions`](super::join_sessions) still can't silently cross-wire two tenants
/// sharing a session id — the second is logged and dropped, never overwrites
/// the first. This is fail-closed, not fail-open.
pub async fn run_mesh_link(
    link: rally_point_transport::MeshLink,
    link_io: MeshLinkIo,
    mut commands: mpsc::UnboundedReceiver<MeshCommand>,
    sessions: routing::Sessions,
    mesh: MeshState,
    idle_timeout: std::time::Duration,
) -> MeshLinkExit {
    let MeshLinkIo {
        presence: presence_io,
        control: mesh_control_io,
        lease,
    } = link_io;
    if !lease.is_current() {
        return MeshLinkExit::Superseded;
    }
    // Cloned (cheap — every field is an `Arc`) before the destructure below
    // pulls `mesh` apart, so `dispatch_mesh_control` can take the whole bundle
    // as one argument rather than a growing list of its individual registries
    // (mirroring `run_slot_link`'s `mesh_for_teardown`). `lobby`, `chat`, and
    // `skins` are used only inside that dispatch, via the clone, so this
    // destructure omits them (`..`) rather than binding names this function
    // never reads.
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
    let crate::session::presence::PresenceIo {
        peer_id,
        tx: presence_tx,
        rx: mut presence_rx,
    } = presence_io;
    let MeshControlIo {
        tx: control_send,
        rx: mut peer_control_rx,
    } = mesh_control_io;
    // One merged outbound control channel for externally produced frames from
    // every session on this link: `fan_out_control` pushes a self-describing
    // `MeshControlFrame` here, and the driver writes it on the shared control
    // stream. Maintenance-generated ack cursors bypass this self-channel and are
    // written as one link-wide batch. One sender is cloned into the mesh-links
    // registry per session (alongside the forward sender); the driver owns the
    // receiver and holds the original sender for the loop's life, so `recv()`
    // returns `None` only on a genuine shutdown.
    let (control_forward_tx, mut control_forward_rx) =
        mpsc::unbounded_channel::<MeshControlFrame>();

    // The live-player count last pushed to the peer, per session — presence is
    // pushed on change (reconciled against the local slot roster on every
    // flush tick and on each Join), so a stable roster sends nothing.
    let presence_sent: HashMap<rally_point_proto::ids::SessionId, u32> = HashMap::new();

    // Sessions for which this link has received at least one peer-presence
    // report since joining. The peer sends its first report only after its own
    // Join is installed, making that report a one-shot rendezvous barrier for
    // replaying state that may have raced ahead of the peer's Join. Cleared on
    // Leave, so Leave -> Join reuse on the same physical link is safe; a redial
    // gets a fresh driver and therefore a fresh set. Deliberately do not buffer
    // pre-Join reports or frames: their wire session id has no tenant scope.
    let peer_presence_seen: HashSet<SessionId> = HashSet::new();

    // The last delivered-through cursor pushed to the peer per (session, slot)
    // -- the mesh-link ack-beacon's own "last_sent", mirroring the client
    // edge's `flush_beacon`. Tracked here (rather than inside `MeshLink`,
    // which is transport state, not a record of what's already been shared)
    // so a repeat cursor push-on-advance check costs a hash lookup, not a
    // stream write the peer's monotonic guard would just discard anyway.
    let ack_cursors_sent: HashMap<(SessionId, SlotId), u64> = HashMap::new();

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
    let joined: HashMap<rally_point_proto::ids::SessionId, SessionState> = HashMap::new();

    // Idle teardown state. `idle_since` is the instant the last session left
    // (None while sessions are joined, or before the first Join); the driver
    // tears down when `idle_since + idle_timeout` passes without a re-Join.
    //
    // This alone encodes "has served traffic": it is only set to `Some` after a
    // `joined.remove()` that emptied `joined`, which can only follow a prior
    // successful Join. A never-joined link keeps `idle_since = None` and stays
    // parked indefinitely, ready for the coordinator's future Join source (the
    // binary holds its command sender for exactly this).
    let idle_since: Option<tokio::time::Instant> = None;

    // One cadence for every per-session maintenance responsibility on this
    // relay-pair link. It is armed by the first Join and disarmed by the last
    // Leave, so an idle connection has no periodic wakeup. Per-session flush
    // deadlines remain independent inside `SessionState`; the shared tick only
    // decides when to scan them (along with presence, ack cursors, and the
    // unacked-window safety cap) once as a batch.
    let maintenance = MeshMaintenanceTimer::default();
    // One persistent sleep backs that schedule. Hot turn/control events leave
    // it in place instead of registering and cancelling a new timer on every
    // trip through `select!`; the guard below stops polling it while the
    // schedule is disarmed. Its initial deadline is irrelevant because the
    // first Join resets it before arming the branch.
    let maintenance_sleep = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(maintenance_sleep);

    // One relay-pair RTT serves every session on this connection. Sample it
    // lazily on the first received conditions sidecar, then reuse it briefly;
    // a never-used or long-idle link therefore cannot feed consensus a stale
    // handshake-time value when traffic eventually arrives.
    let mesh_rtt = MeshRttCache::default();
    // Every loop local the extracted `select!` arm bodies touch, bundled so
    // each takes one `&mut` rather than a dozen parameters. The channel
    // receivers stay out: each is polled by exactly one branch, which hands
    // the arm only the value it yielded.
    let mut driver = LinkDriver {
        link,
        control_send,
        presence_tx,
        control_forward_tx,
        forward_tx,
        shutdown,
        presence_sent,
        peer_presence_seen,
        ack_cursors_sent,
        joined,
        idle_since,
        maintenance,
        mesh_rtt,
        lease,
        peer_id,
        sessions,
        mesh_for_dispatch,
        mesh_links,
        seen_registries,
        conditions,
        decision_makers,
        presence,
        drop_holds,
    };

    // Each break carries its `MeshLinkExit` inline, so a reconnect supervisor
    // can tell an intentional wind-down (Idle, CommandChannelClosed) from a
    // dropped connection (ConnectionFailed). Non-exit paths `continue` the
    // loop; the value a `break` carries becomes the function's return.
    let exit = loop {
        if !driver.lease.is_current() {
            break MeshLinkExit::Superseded;
        }
        // Service due maintenance synchronously, before selecting on the data
        // paths. The select below is biased toward the hot branches, and a
        // saturated link keeps them continuously ready — so if maintenance
        // only ran as a (lower-priority) select branch, sustained traffic
        // could postpone it without bound. Maintenance carries work that must
        // not lose to throughput: the per-session fresh-free flushes (the only
        // packets a wide payload blocked at the refill's head of line can ride
        // — see the head-of-line gate in the transport's redundancy refill),
        // the ack-cursor beacon that keeps unacked windows bounded, the
        // window-cap check, and presence. Running the due check at the top of
        // every loop iteration bounds its delay by one event's servicing time,
        // independent of select polling order.
        if let ControlFlow::Break(exit) =
            driver.run_due_maintenance(maintenance_sleep.as_mut()).await
        {
            break exit;
        }
        // The idle-teardown deadline. Only armed once the link has served at
        // least one session and is now empty (`idle_since` is Some); otherwise
        // the fallback (a day out) keeps the branch dormant. Cancel-safe like
        // the flush timer.
        let idle_deadline = driver
            .idle_since
            .map(|t| t + idle_timeout)
            .unwrap_or(tokio::time::Instant::now() + std::time::Duration::from_secs(86_400));

        tokio::select! {
            biased;
            _ = driver.lease.superseded.notified() => {
                break MeshLinkExit::Superseded;
            }
            // `fan_out_to_mesh` found this shared forward queue full and
            // notified: this reset must not lose to the continuously-ready hot
            // branches below (biased select polls top-down), so it sits above
            // them. A dropped fresh turn here never enters this link's
            // `AckManager`, so its transport has nothing to re-carry on its
            // own. Reset the link instead — the dial supervisor redials, the
            // Join-time reconcile re-syncs leave state, and the resume-cursor
            // exchange on the fresh link replays this relay's own
            // locally-originated turns the peer's forward-gate is still
            // missing, closing the gap this very reset opened.
            _ = driver.shutdown.notified() => {
                tracing::info!("mesh forward queue was full; resetting link");
                break MeshLinkExit::ConnectionFailed;
            }
            received = driver.link.recv() => {
                if let ControlFlow::Break(exit) = driver.handle_datagram(received) {
                    break exit;
                }
            }
            // An outbound control frame (a `SlotDeparted` or `LeaveDirective` a
            // slot-link task or a handoff fanned out to this link): write it on
            // the shared reliable control stream. A write failure is a dead
            // connection — like a datagram send failure, it closes the link. The
            // frame is self-describing (its session field), so no demux is needed.
            outbound = control_forward_rx.recv() => {
                if let ControlFlow::Break(exit) = driver.write_outbound_control(outbound).await {
                    break exit;
                }
            }
            // A control frame from the peer relay: a departure it observed, a
            // synced leave its authority authored, or an oversize turn its
            // datagram path could not carry. The reader task assembled the
            // complete frame off a cancel-safe path; `recv` is cancel-safe.
            received = peer_control_rx.recv() => {
                if let ControlFlow::Break(exit) = driver.handle_peer_control(received).await {
                    break exit;
                }
            }
            forwarded = forward_rx.recv() => {
                if let ControlFlow::Break(exit) = driver.send_forwarded_turn(forwarded).await {
                    break exit;
                }
            }
            _ = &mut maintenance_sleep, if driver.maintenance.deadline().is_some() => {
                // Just a wake-up: the due-maintenance pass at the top of
                // the loop does the work, so an idle link still ticks on
                // time. Every data event re-enters the loop top too, which
                // is what keeps maintenance serviced under saturation.
                continue;
            }
            // A presence report from the peer: how many live home clients it
            // serves for one session. Record it and re-derive the session's
            // buffer-authority verdict — this is the handoff path when the
            // authority relay's players all leave. The reader task assembled
            // the complete frame off a cancel-safe path; `recv` is cancel-safe.
            received = presence_rx.recv() => {
                if let ControlFlow::Break(exit) = driver.handle_presence_report(received).await {
                    break exit;
                }
            }
            // Idle teardown: the link served at least one session, went empty,
            // and stayed empty past `idle_timeout`. An intentional wind-down —
            // not a failure to retry. The `if` guard keeps this branch dormant
            // until `idle_since` is Some (armed after the first Join→empty
            // transition); `idle_deadline`'s day-out fallback makes the guard
            // the sole gate.
            _ = tokio::time::sleep_until(idle_deadline), if driver.idle_since.is_some() => {
                tracing::info!("mesh link idle; closing");
                break MeshLinkExit::Idle;
            }
            command = commands.recv() => {
                if let ControlFlow::Break(exit) = driver
                    .handle_command(command, maintenance_sleep.as_mut())
                    .await
                {
                    break exit;
                }
            }
        }
    };

    // A replacement can claim provenance in the same scheduler turn as an old
    // connection error. Normalize that coincidence to Superseded so the old
    // dial supervisor cannot redial and compete with the working replacement.
    let exit = if driver.lease.is_current() {
        exit
    } else {
        MeshLinkExit::Superseded
    };

    // No explicit teardown here: each joined session's `SessionState`
    // deregisters its own forward channel when dropped, and the driver holding
    // them is dropped as this function returns — or when the driver task is
    // cancelled — so the cleanup runs on every exit path.
    exit
}
