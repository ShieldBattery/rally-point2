//! Per-session turn routing: take a validated turn from one slot and deliver it
//! to that session's other slots.
//!
//! Each authorized connection becomes a [`Link`] owned by one task. That task is
//! the single owner of its link's send and receive state, so it multiplexes three
//! things over `tokio::select!`: receiving turns from its own client, sending turns
//! that other slots produced, and — when it owes the client acks but has no turn to
//! send back — flushing an ack-only packet. Cross-slot delivery is therefore not a
//! shared lock on anyone's link but a message to its task — every slot has an
//! inbound channel of payloads waiting to go to its client, and fan-out just pushes
//! onto the channels of the *other* slots.
//!
//! The relay carries its acks for a client on the packets it sends back, which are
//! normally the other slots' forwarded turns. A client with no return traffic — a
//! lone slot, a quiet session, a one-way sender — would otherwise never see an ack
//! and re-send its turns forever, so a maintenance flush sends an ack-only packet
//! whenever a forwarded turn is still unacked or acks are owed. That same packet
//! re-carries unacked turns oldest-first, which retransmits a forwarded turn whose
//! fresh packets were too full to re-carry it (a near-MTU stream). Its timer is reset
//! by any forwarded turn that does re-carry redundancy, so a normal two-way game
//! never triggers an extra packet; it fires only when the forward stream stops
//! covering the unacked turns or goes idle, and stays silent when nothing is unacked.
//!
//! On a received turn the owning task runs it through [`validate_turn`]: the slot
//! is rebound to the one the client is authorized for (never the slot on the
//! wire), commands are bounds-checked, and the controls a live turn may not carry
//! are stripped. A turn that fails validation is a misbehaving or hostile client,
//! so its connection is closed. The fanned-out payload keeps its source slot — a
//! client needs to know whose commands these are — and is handed to each peer's
//! link. The payload's `(slot, seq)` origin identity — assigned once by the
//! sending client — is preserved verbatim across this seam and every later hop;
//! no relay restamps it. Each peer link stamps its own *packet* seq (a separate,
//! per-link ack handle naming the datagram, not the turn); the payload `seq` it
//! forwards is the sender's, untouched.
//!
//! Forwarding is immediate, never reordered here: a turn is fanned out the moment
//! it validates, because a peer must have a turn in hand *before* it simulates that
//! turn — buffering turns to wait for an earlier one and forward them in order would
//! add exactly the latency the relay exists to avoid. The *packet* seq a peer link
//! stamps is only an ack handle (it names the datagram, not the turn); the payload's
//! origin `seq` is a separate identity, preserved untouched. Putting each slot's
//! turns back in order before the game runs them is the client's job. Loss is
//! covered without an explicit resend delay: each outbound packet leads with the new
//! turn and fills the rest of its budget with still-unacked ones, so a turn dropped
//! on one packet rides a later one.
//!
//! Each routing group's roster is scoped by tenant *and* session: session ids are
//! only unique within a tenant, so two tenants can be assigned the same number and
//! must never share a game. A connection is added before its client is told it's
//! authorized and removed when its task ends, so fan-out always sees exactly the
//! slots currently able to receive.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{LeaveDirective, LinkConditions, Payload, SlotConditions};
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::control::ControlInbound;
use rally_point_transport::quinn::VarInt;
use rally_point_transport::{Link, LinkError};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep_until};

use crate::consensus;
use crate::consensus::{LEAVE_REASON_DROPPED, LEAVE_REASON_LEFT, MAX_GAME_RESULT_PAYLOAD_LEN};
use crate::validation::validate_turn;

/// How many outbound payloads may queue for one slot before fan-out to it applies
/// backpressure. Turns are small and drained promptly; a slot this far behind is
/// effectively a dead client. A real capacity/backpressure model is future work,
/// so this is deliberately generous rather than tuned. Shared by the client-edge
/// slot link and the mesh-link task (same turn-magnitude, same drain cadence).
pub(crate) const FORWARD_CAPACITY: usize = 1024;

/// Depth of a slot's leave-push channel. Leaves are rare (at most one per other
/// player, and only on a departure), so a small buffer is ample.
const LEAVE_PUSH_CAPACITY: usize = 16;

/// QUIC application close code for a connection dropped because its client sent a
/// turn that failed validation.
const INVALID_TURN_CLOSE: u32 = 0x01;

/// QUIC application close code for a connection the relay disconnects because its
/// link fell hopelessly behind (its forward queue filled), isolating it so it can't
/// back-pressure healthy peers.
const ISOLATED_CLOSE: u32 = 0x04;

/// How often a link flushes a maintenance packet when the forward stream is not
/// already re-carrying unacked turns.
///
/// The timer is reset whenever a forwarded turn re-carries unacked turns as
/// redundancy — the common case, where recovery rides the forward stream and the
/// flush never fires, so it costs no extra packets. It is *not* reset by a forward
/// that carried no redundancy (a near-MTU turn that filled the datagram) or by an
/// idle stretch; in those cases it fires and sends an ack-only packet that re-carries
/// unacked turns oldest-first and folds in owed acks, so a client with no turns
/// coming back (a lone slot, a quiet session, a stalled peer) still retires what it
/// sent. It stays silent when nothing is unacked and no acks are owed. Set to a few
/// turns at the 24-per-second turn rate: clear of ordinary jitter, while keeping
/// retransmit latency and a one-way sender's backlog low.
pub(crate) const FLUSH_INTERVAL: Duration = Duration::from_millis(150);

/// The hard ceiling on payloads forwarded to a client but not yet known-delivered.
/// Mirrors the client's cap: under reverse-path loss (the client received the
/// turns but the acks riding the datagrams were lost), the beacon side-channel
/// force-advances the window via [`Link::retire_through`] and keeps it bounded.
/// Under forward-path sustained loss — the client genuinely receives slower than
/// the relay forwards — the beacon can retire only what the client *got*, so the
/// window still grows. When it crosses this cap the relay isolates the slot (the
/// same action it takes for a stuck forward queue) rather than let seqs race ahead
/// until the client's receive window rejects them. Sat below the client's receive
/// window (4096) so it trips before a hard reject.
const UNACKED_WINDOW_CAP: usize = 1024;

// The native SC:R `pending_leave_reason` value for a *dropped* player (shows
// "player was dropped") lives in `consensus`, which also classifies a departure
// notice from it — one source of truth for the dropped-vs-left boundary. A
// client's link ending (quit, network death, or isolation for lagging) surfaces
// as a drop; a clean quit sends a leave-intent first, decided under
// `LEAVE_REASON_LEFT` so survivors see "player left".

/// QUIC application close code for a connection the relay closes on its own
/// initiative after processing a client's leave-intent. Not an error: the
/// client's control-stream announcement is never acked on its own terms — the
/// relay closing the link *is* the confirmation the departing client's driver
/// waits for once it has sent its intent.
const LEAVE_PROCESSED_CLOSE: u32 = 0x05;

/// Whether a client's `GameResult` control frame should be forwarded to
/// `consensus::record_result`, or dropped at ingress before it ever reaches the
/// decision-maker. A zero-length payload is the wire sentinel a `SlotDeparted`
/// uses to mean "no result reported" (see `wire.proto`), so recording one as a
/// genuine report would make a real empty result indistinguishable from no
/// result at all once the slot departs; an over-cap payload is simply an
/// ill-formed report. Pulled out as its own predicate — returning the reason
/// for a caller to log — so the ingress rule is unit-testable without standing
/// up the control-stream serve loop.
fn game_result_admissible(payload: &[u8]) -> Result<(), &'static str> {
    if payload.is_empty() {
        Err("empty")
    } else if payload.len() > MAX_GAME_RESULT_PAYLOAD_LEN {
        Err("oversize")
    } else {
        Ok(())
    }
}

/// The largest client turn the relay will accept on the oversize-turn divert path.
///
/// A turn too big for a datagram rides the reliable control stream
/// ([`ControlInbound::OversizeTurn`]) and is then fanned out to the other slots'
/// forward queues. Those queues are bounded by payload *count* ([`FORWARD_CAPACITY`]),
/// not by bytes, and the control-stream framing only caps a single frame at 64 KiB
/// ([`MAX_CONTROL_FRAME_LEN`](rally_point_proto::control_stream::MAX_CONTROL_FRAME_LEN)).
/// A datagram-sized turn buffered in one of those queues costs on the order of the
/// path MTU (~1 KiB); an oversize one can cost up to that 64 KiB frame cap. So a
/// malicious client spraying maximum-size oversize turns occupies far more buffered
/// memory per queued turn than a normal player -- and it does so across *every*
/// receiving slot's queue at once.
///
/// A legitimate SC:R turn is at most a few hundred bytes of commands (well under a
/// datagram); the divert path exists only for the rare turn that just clears the
/// datagram budget. Capping accepted oversize turns here -- comfortably above any
/// real turn and the e2e divert fixtures (~4-5 KiB), far below the 64 KiB framing
/// cap -- bounds that per-turn amplification at the source. An over-cap turn is not
/// one any real client produces, so it is rejected exactly like a malformed turn:
/// the link is closed, which routes the offender through the normal departure/leave
/// machinery so survivors get a synced leave and play on. (Silently *dropping* the
/// turn instead would leave a permanent gap in the slot's seq stream and stall every
/// peer in lockstep forever -- hurting honest players, not just the offender.) Peer
/// relays are trusted infrastructure and clamp at their own client ingress, so the
/// mesh-side divert needs no separate check.
const MAX_OVERSIZE_TURN_COMMANDS_LEN: usize = 8192;

/// The channel sink delivering payloads to one slot's link task.
type ForwardTx = mpsc::Sender<Payload>;

/// What the roster holds for one connected slot: the channel that reaches its link
/// task, and a signal the relay fires to make that task close its connection and
/// leave. Removing the slot from the roster is *not* how a link is stopped — that
/// would free the slot while the old task is still alive and could let a
/// replacement register a second sender for the same player — so isolation goes
/// through this signal and the task deregisters itself once it has actually exited.
///
/// Public only because it appears in the [`Sessions`] alias; its fields are
/// private, so the roster is built and read solely through this module.
pub struct SlotEntry {
    forward: ForwardTx,
    /// Synced player-leaves to push down THIS client's reliable control stream.
    /// Fed by [`fan_out_leave`] when a *different* slot leaves; drained by this
    /// slot's link task, which writes each to its control stream. Separate from
    /// `forward` (datagram turns) because a leave must reach a stalled client,
    /// whose datagram turn flow has stopped — only the reliable stream still does.
    leave_push: mpsc::Sender<LeaveDirective>,
    /// Session-start directives to push down THIS client's reliable control
    /// stream. Fed by [`fan_out_session_start`] when the session's authority
    /// decides every expected slot has connected, and by
    /// [`deliver_session_start_to_slot`] for a slot that registers after the
    /// session already started; drained by this slot's link task, which writes a
    /// `SessionStart` frame to its control stream. Fieldless — a unit per
    /// directive, carrying nothing but the fact.
    start_push: mpsc::Sender<()>,
    /// Slot-connectivity changes to push down THIS client's reliable control
    /// stream. Fed by [`fan_out_connectivity`] when any slot's link dies or
    /// (re)registers; drained by this slot's link task, which writes a
    /// `SlotConnectivity` frame. Rides the reliable stream like a leave so it
    /// still reaches a client whose datagram turn flow has stalled behind the
    /// very disconnect being reported. Carries `(slot, connected)`.
    conn_push: mpsc::Sender<(SlotId, bool)>,
    shutdown: Arc<Notify>,
}

/// The receiving end of a registered slot, handed to its link task: the queue of
/// turns to deliver to the client, and the signal to shut the link down.
pub struct SlotInbox {
    forward_rx: mpsc::Receiver<Payload>,
    /// Leaves to push down this client's control stream (see [`SlotEntry::leave_push`]).
    leave_push_rx: mpsc::Receiver<LeaveDirective>,
    /// Session-start directives to push down this client's control stream (see
    /// [`SlotEntry::start_push`]).
    start_push_rx: mpsc::Receiver<()>,
    /// Slot-connectivity changes to push down this client's control stream (see
    /// [`SlotEntry::conn_push`]).
    conn_push_rx: mpsc::Receiver<(SlotId, bool)>,
    shutdown: Arc<Notify>,
}

impl SlotInbox {
    /// The slot's shutdown signal, for a cross-module test that drives a close and
    /// asserts the link task would be told to exit.
    #[cfg(test)]
    pub(crate) fn shutdown_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown)
    }

    /// Non-blockingly pulls the next slot-connectivity change pushed to this slot,
    /// for a cross-module test asserting a connectivity frame fanned to a local
    /// slot. `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_connectivity(&mut self) -> Option<(SlotId, bool)> {
        self.conn_push_rx.try_recv().ok()
    }
}

/// Identifies one game's routing group. Session ids are unique only *within* a
/// tenant, so two tenants can independently be assigned the same number; the
/// tenant is therefore part of the key. Slot occupancy and fan-out are scoped by
/// this whole key, never by the session number alone, so one tenant's game can
/// neither block nor receive another's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Tenant that owns the game — the registry's tenant, never a token claim.
    pub tenant: TenantId,
    /// Session id, unique only within `tenant`.
    pub session: SessionId,
}

/// Live membership of every routing group on this relay: each `(tenant, session)`
/// key → its connected slots. Shared across all connection tasks. A plain
/// (non-async) mutex is deliberate: every critical section here is a short,
/// await-free roster edit — senders are cloned out before any send — so the lock is
/// never held across a turn's delivery, and freeing a slot can run from a `Drop`
/// without an executor.
pub type Sessions = Arc<Mutex<HashMap<SessionKey, HashMap<SlotId, SlotEntry>>>>;

/// A held slot registration that frees its slot when dropped.
///
/// [`register`] returns one so the slot is released on every path out of
/// connection setup — a failed acknowledgement write, a panic — rather than
/// sticking occupied until the relay restarts. Once [`run_slot_link`] takes over
/// the connection (and will deregister on its own exit), the owner calls
/// [`disarm`](Self::disarm) so the slot isn't freed twice.
pub struct SlotRegistration {
    sessions: Sessions,
    key: SessionKey,
    slot: SlotId,
    armed: bool,
}

impl SlotRegistration {
    /// Relinquishes responsibility for freeing the slot, because the running link
    /// task now owns its lifetime and will deregister when it ends.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SlotRegistration {
    fn drop(&mut self) {
        if self.armed {
            deregister(&self.sessions, &self.key, self.slot);
        }
    }
}

/// Adds `slot` to the `key` routing group's roster, returning a guard that frees
/// the slot on drop plus the inbox its link task drains — or `None` if the slot is
/// already connected.
///
/// Refusing a duplicate keeps two connections from claiming one slot; a real
/// reconnect/takeover path is a later concern.
pub fn register(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
) -> Option<(SlotRegistration, SlotInbox)> {
    let (tx, rx) = mpsc::channel(FORWARD_CAPACITY);
    // Leaves are rare (one per departing peer), so a small channel is ample.
    let (leave_tx, leave_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Session-start directives are rarer still (the fire, plus any re-push on a
    // late register or an authority handoff); the same small channel suits them.
    let (start_tx, start_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Connectivity changes are rare (a slot flips a small number of times over a
    // game); the same small channel suits them.
    let (conn_tx, conn_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    let shutdown = Arc::new(Notify::new());
    {
        let mut roster = sessions.lock();
        let slots = roster.entry(key.clone()).or_default();
        if slots.contains_key(&slot) {
            return None;
        }
        slots.insert(
            slot,
            SlotEntry {
                forward: tx,
                leave_push: leave_tx,
                start_push: start_tx,
                conn_push: conn_tx,
                shutdown: Arc::clone(&shutdown),
            },
        );
    }
    let registration = SlotRegistration {
        sessions: Arc::clone(sessions),
        key: key.clone(),
        slot,
        armed: true,
    };
    let inbox = SlotInbox {
        forward_rx: rx,
        leave_push_rx: leave_rx,
        start_push_rx: start_rx,
        conn_push_rx: conn_rx,
        shutdown,
    };
    Some((registration, inbox))
}

/// Removes `slot` from the `key` routing group's roster, dropping the group entry
/// once its last slot leaves. Idempotent: removing an absent slot is a no-op, so a
/// guard and a link task can both run it without double-free hazard.
///
/// Returns whether this call removed the group's **last** slot — the relay now
/// serves no player for the session, so its caller fires the coordinator's
/// `SessionClosed` for it (computed under the roster lock, so two slots leaving
/// concurrently report the emptying exactly once).
fn deregister(sessions: &Sessions, key: &SessionKey, slot: SlotId) -> bool {
    let mut roster = sessions.lock();
    if let Some(slots) = roster.get_mut(key) {
        let removed = slots.remove(&slot).is_some();
        if slots.is_empty() {
            roster.remove(key);
            return removed;
        }
    }
    false
}

/// Whether this relay currently holds any connected slot in any routing group —
/// its "am I serving a player" signal, used by the coordinated-drain shutdown path
/// to know when the relay is idle enough to exit.
///
/// A group entry is created only when a slot registers and dropped the moment its
/// last slot deregisters (see [`deregister`]), so the map is empty *exactly* when no
/// slot is held. A session ending therefore shrinks this — the last slot's link task
/// deregisters on exit — which is what lets the drain wait converge.
pub fn holds_any_slots(sessions: &Sessions) -> bool {
    !sessions.lock().is_empty()
}

/// The live roster: every routing group with at least one connected slot, each
/// paired with its currently-connected slots (sorted, for a stable order).
///
/// A slot appears exactly while it is registered — the same property
/// [`holds_any_slots`] documents — so this is the truth the relay's heartbeat
/// reports up to the coordinator's active-player presence store: connected right
/// now, nothing softer. A snapshot taken under the roster lock, cheap at a
/// relay's scale (a handful of sessions, a dozen slots each).
pub fn live_slots(sessions: &Sessions) -> Vec<(SessionKey, Vec<SlotId>)> {
    sessions
        .lock()
        .iter()
        .map(|(key, slots)| {
            let mut slot_ids: Vec<SlotId> = slots.keys().copied().collect();
            slot_ids.sort_by_key(|s| s.0);
            (key.clone(), slot_ids)
        })
        .collect()
}

/// Delivers `payload` to every slot in the `key` routing group except `source`,
/// without ever blocking on a slow peer.
///
/// Senders and shutdown signals are cloned out under the lock and the lock dropped
/// before any delivery, then each peer is offered the payload with a non-blocking
/// `try_send`, so one client can never park the source's link task (nor deadlock
/// two saturated peers against each other). A peer whose queue is full is
/// hopelessly behind — a live link drains its queue every turn, and in lockstep the
/// game is already stalled waiting on a peer this far back — so it is *signaled to
/// disconnect* rather than allowed to back-pressure healthy peers. Crucially it is
/// **not** removed from the roster here: its slot stays occupied until its own link
/// task acts on the signal and exits, so no replacement can register a second
/// sender for it in the meantime. A send to an already-departed peer is ignored. A
/// turn is therefore never silently dropped for a keeping-up peer.
pub(crate) fn fan_out(sessions: &Sessions, key: &SessionKey, source: SlotId, payload: Payload) {
    let targets: Vec<(SlotId, ForwardTx, Arc<Notify>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => slots
                .iter()
                .filter(|(slot, _)| **slot != source)
                .map(|(slot, entry)| (*slot, entry.forward.clone(), Arc::clone(&entry.shutdown)))
                .collect(),
            None => Vec::new(),
        }
    };
    for (slot, tx, shutdown) in targets {
        match tx.try_send(payload.clone()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "forward queue full; signaling lagging slot to disconnect",
                );
                shutdown.notify_one();
            }
            // The peer's task already ended; it deregisters itself.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

/// Pushes `leave` down every *surviving* slot's control stream in the `key` group
/// (every slot except `departing`, the one that just left). A leave rides the
/// reliable control stream, not the datagram turn path, because the departing
/// player's exit stalls the survivors and stops their turn flow — the reliable
/// stream is the only channel that still reaches them to unstall. Senders are
/// cloned under the lock and the lock dropped before delivery, as in [`fan_out`].
pub(crate) fn fan_out_leave(
    sessions: &Sessions,
    key: &SessionKey,
    departing: SlotId,
    leave: LeaveDirective,
) {
    let targets: Vec<(SlotId, mpsc::Sender<LeaveDirective>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => slots
                .iter()
                .filter(|(slot, _)| **slot != departing)
                .map(|(slot, entry)| (*slot, entry.leave_push.clone()))
                .collect(),
            None => Vec::new(),
        }
    };
    for (slot, tx) in targets {
        match tx.try_send(leave) {
            // A full leave-push queue is unexpected (leaves are rare); log rather
            // than drop silently — a missed leave leaves that survivor stalled.
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "leave-push queue full; a synced leave may be delayed for this slot",
            ),
            // The peer already left; it needs no leave for a third slot.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Pushes the session-start directive down every slot's control stream in the
/// `key` group — every currently-registered local slot, with no exclusion (unlike
/// [`fan_out_leave`], a start is for everyone). Senders are cloned under the lock
/// and the lock dropped before delivery, as in [`fan_out`]. A slot whose start
/// queue is full is unexpected (starts are rare and the queue is drained
/// promptly); it is logged rather than dropped silently.
pub(crate) fn fan_out_session_start(sessions: &Sessions, key: &SessionKey) {
    let targets: Vec<(SlotId, mpsc::Sender<()>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => slots
                .iter()
                .map(|(slot, entry)| (*slot, entry.start_push.clone()))
                .collect(),
            None => Vec::new(),
        }
    };
    for (slot, tx) in targets {
        match tx.try_send(()) {
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "session-start queue full; the start directive may be delayed for this slot",
            ),
            // The slot's task already ended; it needs no start.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Pushes a slot-connectivity change down every currently-registered local
/// slot's control stream in the `key` group, with no exclusion — a connectivity
/// change is informational for everyone, and a client receiving its own slot's
/// change treats it as a no-op. Senders are cloned under the lock and the lock
/// dropped before delivery, as in [`fan_out`]. A full queue is logged rather than
/// dropped silently, though a lost connectivity frame costs only a stale display,
/// not correctness (the synced leave is the authoritative removal).
pub(crate) fn fan_out_connectivity(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    connected: bool,
) {
    let targets: Vec<(SlotId, mpsc::Sender<(SlotId, bool)>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => slots
                .iter()
                .map(|(s, entry)| (*s, entry.conn_push.clone()))
                .collect(),
            None => Vec::new(),
        }
    };
    for (target, tx) in targets {
        match tx.try_send((slot, connected)) {
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = target.0,
                subject = slot.0,
                "connectivity queue full; a slot-connectivity frame may be dropped for this slot",
            ),
            // The slot's task already ended; it needs no connectivity update.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Broadcasts a slot-connectivity change session-wide: fans it to every local
/// slot ([`fan_out_connectivity`]) and across the mesh so every peer relay fans
/// it to its own local slots ([`crate::mesh::fan_out_slot_connectivity`]). Sent
/// the moment a slot's link dies (`connected` false) or (re)registers
/// (`connected` true). Independent of the synced-leave path and of any hold: a
/// disconnect signal goes out immediately so survivors learn who dropped ~at
/// once, while the leave that removes the slot is decided separately.
pub(crate) fn broadcast_connectivity(
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    connected: bool,
) {
    fan_out_connectivity(sessions, key, slot, connected);
    crate::mesh::fan_out_slot_connectivity(mesh_links, key, slot, connected);
}

/// Pushes the session-start directive down a single slot's control stream — the
/// re-push a slot gets when it registers after the session already started. A
/// slot absent from the roster (already gone) is skipped.
pub(crate) fn deliver_session_start_to_slot(sessions: &Sessions, key: &SessionKey, slot: SlotId) {
    let sender = {
        let roster = sessions.lock();
        roster
            .get(key)
            .and_then(|slots| slots.get(&slot))
            .map(|entry| entry.start_push.clone())
    };
    if let Some(tx) = sender {
        let _ = tx.try_send(());
    }
}

/// Delivers the session-start directive session-wide: fans it to every local
/// slot ([`fan_out_session_start`]) and broadcasts it across the mesh so every
/// peer relay fans it to its own local slots ([`crate::mesh::fan_out_session_start`]).
/// The one call the authority makes when full slot presence is reached, and the
/// same one an authority-churn re-evaluation makes.
pub(crate) fn deliver_session_start(
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
) {
    fan_out_session_start(sessions, key);
    crate::mesh::fan_out_session_start(mesh_links, key);
}

/// Re-evaluates a session's start condition after an authority change and, if the
/// newly-promoted authority now covers the expected set, delivers the directive
/// session-wide. The authority-churn path (point where a promotion may fire a
/// start the previous authority never got to). A no-op when the condition is not
/// met — a non-authority relay, an already-started session, or an incomplete set.
pub fn maybe_start_session(
    sessions: &Sessions,
    decision_makers: &consensus::DecisionMakers,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
) {
    if consensus::reevaluate_session_start(decision_makers, key) {
        deliver_session_start(sessions, mesh_links, key);
    }
}

/// Announces a freshly registered slot's presence and, if the session has already
/// started, re-delivers the start directive to it.
///
/// Broadcasts a `SlotPresent` to the session's mesh peers, records the slot into
/// the session's live-slot set, and — when that completes the authority's expected
/// set — delivers the `SessionStart` directive session-wide (every local slot plus
/// every peer relay). If the session already started before this slot arrived (a
/// late or reconnecting slot), pushes `SessionStart` straight down this slot's own
/// control stream so it is not left waiting. A session run without descriptors (no
/// maker, no expected set) does nothing here.
pub fn announce_slot_present(
    sessions: &Sessions,
    decision_makers: &consensus::DecisionMakers,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
) {
    // Tell every peer relay this slot is here, so the authority (wherever it is)
    // can accumulate it toward the expected set.
    crate::mesh::fan_out_slot_present(mesh_links, key, slot);
    // Record it locally. On the authority, completing the expected set fires the
    // directive session-wide; otherwise, if the session already started, this
    // late slot still needs the directive pushed to it directly.
    if consensus::note_slot_present(decision_makers, key, slot) {
        deliver_session_start(sessions, mesh_links, key);
    } else if consensus::session_started(decision_makers, key) {
        deliver_session_start_to_slot(sessions, key, slot);
    }
}

/// Fires the shutdown signal for each of `slots` in the `key` routing group, so
/// each named slot's link task closes its connection and leaves — the coordinator's
/// reap directive. A slot this relay does not currently hold (never homed it, or it
/// already departed) is simply absent from the roster and skipped, so the
/// coordinator can name every slot of a session without tracking which relay holds
/// which. The closed link then flows through the ordinary link-death path (a synced
/// leave, a departure notice), which is what makes the reap self-resolving.
///
/// Signals rather than yanking the roster entry, exactly like [`fan_out`]'s lagging-
/// peer path: the slot stays occupied until its own task acts on the signal and
/// deregisters itself, so no replacement can register a second sender in the interim.
pub fn close_slots(sessions: &Sessions, key: &SessionKey, slots: &[SlotId]) {
    let roster = sessions.lock();
    let Some(group) = roster.get(key) else {
        return;
    };
    for slot in slots {
        if let Some(entry) = group.get(slot) {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "coordinator reap: closing slot link",
            );
            entry.shutdown.notify_one();
        }
    }
}

/// Drives one authorized client's link until it closes.
///
/// Owns `link` outright and alternates between receiving its client's turns
/// (validate, then fan out to the group's other slots), sending it the turns other
/// slots produced, flushing idle acks, and obeying a relay shutdown signal. Any
/// link error, a failed validation, or that signal ends the loop; the slot is
/// deregistered on the way out so peers stop routing to a connection that's gone.
/// Because deregistration happens here, on exit, the slot stays occupied for this
/// connection's whole life — a lagging peer is asked to leave via the shutdown
/// signal, not by yanking its roster entry out from under it.
pub async fn run_slot_link(
    mut link: Link,
    key: SessionKey,
    slot: SlotId,
    mut resume_cursors: std::collections::HashMap<SlotId, u64>,
    inbox: SlotInbox,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
) {
    let SlotInbox {
        mut forward_rx,
        mut leave_push_rx,
        mut start_push_rx,
        mut conn_push_rx,
        shutdown,
    } = inbox;
    // Cloned (cheap — every field is an `Arc`) before the destructure below
    // pulls `mesh` apart, so every exit path can hand the whole bundle to
    // `end_slot_link` without ballooning that function's argument count.
    let mesh_for_teardown = mesh.clone();
    // The flight recorder's per-slot counter handle, fetched ONCE here so the
    // per-turn arms below bump plain atomics — no lock, no map lookup on the
    // hot path. The connect event marks a resumed dial (any presented resume
    // cursors: a reconnect or a re-home re-dial) apart from a fresh one.
    let flight_counters = mesh
        .decision_makers
        .flight_recorder()
        .slot_counters(&key, slot);
    mesh.decision_makers.flight_recorder().record(
        &key,
        crate::flight_recorder::FlightEvent::SlotConnected {
            slot: slot.0,
            resumed: !resume_cursors.is_empty(),
        },
    );
    let crate::mesh::MeshState {
        links: mesh_links,
        seen: seen_registries,
        conditions,
        decision_makers,
        presence,
        lobby,
        chat,
        drop_holds,
        turn_ring,
    } = mesh;

    // This client joining may change who decides the session's buffer — most
    // notably a first client arriving on the relay that heads the authority
    // order, which turns the descriptor-time verdict into a live one. The
    // roster already includes this slot (registration preceded this task), so
    // report it and re-derive. The peers learn the new count from the mesh
    // drivers' presence reconcile, off the same roster.
    report_own_presence(
        &presence,
        &decision_makers,
        &sessions,
        &mesh_links,
        &drop_holds,
        &key,
    );

    // Announce this slot's presence to the mesh and record it into the session's
    // live-slot set. On the authority relay, this slot completing the descriptor's
    // expected set fires the session-start directive to every slot (local and
    // across the mesh); if the session already started before this slot arrived (a
    // late or reconnecting slot), the directive is re-pushed straight to it. The
    // roster already includes this slot (registration preceded this task), so
    // `fan_out_session_start` reaches it too.
    announce_slot_present(&sessions, &decision_makers, &mesh_links, &key, slot);

    // Announce this slot's link as connected to every slot in the session (local
    // and across the mesh), so survivors' connectivity displays reflect it. A
    // pre-start frame (this is the initial dial for most slots) is harmless — a
    // client ignores connectivity until it cares — and a re-register (a later
    // reconnect feature) reuses this same signal. Independent of the session-start
    // and leave paths.
    broadcast_connectivity(&sessions, &mesh_links, &key, slot, true);

    // The ack-beacon side-channel, mirroring the client driver. The relay opens
    // its outbound uni-stream (open_uni completes locally); the client's stream
    // is accepted lazily inside the reader task so a one-way-traffic client that
    // never sends a beacon doesn't block on an accept that never completes. The
    // reader assembles complete frames off a cancel-safe path and forwards each
    // `(slot, cursor)` over an mpsc channel — cursors are per-slot, so they
    // don't subsume each other across slots and can't collapse to one latest.
    let mut beacon_send = match link.connection().open_uni().await {
        Ok(send) => send,
        Err(error) => {
            log_link_closed(&key, slot, &LinkError::from(error));
            // The slot registered but never got a stream up, so it forwarded
            // nothing — still run the full departure/close protocol below so
            // peers and the coordinator hear about it now rather than only
            // after the coordinator's holdout reap.
            end_slot_link(&sessions, &mesh_for_teardown, &key, slot, false);
            return;
        }
    };
    let mut beacon_rx = spawn_beacon_reader(link.connection().clone());
    // The reliable control stream — the divert path for a turn too large to
    // ever ride a datagram, in both directions: the client's own oversize turn
    // arrives on the stream the client opened (read by the reader task below),
    // and an oversize forwarded turn goes out on this stream the relay opens.
    // Each side writes only on the stream it opened, so this send half exists
    // from here on; the reader accepts the client's lazily.
    let (mut control_send, _our_stream_recv) = match link.connection().open_bi().await {
        Ok(halves) => halves,
        Err(error) => {
            log_link_closed(&key, slot, &LinkError::from(error));
            // Same rationale as the open_uni failure above: the beacon stream
            // came up but the control stream didn't, so this slot still never
            // forwarded a turn and gets the same full teardown.
            end_slot_link(&sessions, &mesh_for_teardown, &key, slot, false);
            return;
        }
    };
    let mut control_rx =
        rally_point_transport::control::spawn_control_reader(link.connection().clone());
    // Mirrors `beacon_alive` below: a `None` from an ended reader task must
    // disarm the branch, not spin the loop.
    let mut control_alive = true;
    // Whether this slot's leave-push channel still has a sender. It lives in the
    // roster while the slot is registered, so `None` is unreachable during the
    // loop; the flag disarms the branch defensively so a closed channel can't spin.
    let mut leave_push_alive = true;
    // Mirrors `leave_push_alive` for the session-start push channel: it lives in
    // the roster while the slot is registered, so `None` is unreachable during the
    // loop; the flag disarms the branch defensively.
    let mut start_push_alive = true;
    // Mirrors `leave_push_alive` for the connectivity push channel, disarmed
    // defensively the same way.
    let mut conn_push_alive = true;
    // Register this member for lobby fan-out now that its control stream is up:
    // it starts receiving other members' lobby commands, and — crucially — the
    // per-session replay log is snapshotted into `lobby_rx` under the lobby lock
    // right here, so a member that joined after the host already sent its setup
    // commands catches up on every earlier command, in order, before any live
    // one. The exactly-once handoff is the lobby module's (append + fan-out and
    // register + snapshot share one lock); this task just drains `lobby_rx` in the
    // branch below and writes each command down its own control stream.
    let mut lobby_rx = crate::lobby::register_member(&lobby, &key, slot);
    // Mirrors `leave_push_alive`: this member's lobby sender lives in the lobby
    // registry until its own teardown drops it, so a `None` is unreachable during
    // the loop; the flag disarms the branch defensively.
    let mut lobby_alive = true;
    // Register this member for chat fan-out too — the mid-game counterpart to
    // the lobby registration above. No log to snapshot: chat keeps none, so this
    // member simply starts tailing whatever other members send from here on.
    let mut chat_rx = crate::chat::register_member(&chat, &key, slot);
    // Mirrors `lobby_alive`: this member's chat sender lives in the chat
    // registry until its own teardown drops it, so a `None` is unreachable
    // during the loop; the flag disarms the branch defensively.
    let mut chat_alive = true;
    // The highest cursor the relay has pushed to the client, per slot. Push only
    // on advance.
    let mut last_beacon_sent: HashMap<SlotId, u64> = HashMap::new();
    // Whether the inbound beacon reader task is still feeding cursors. Once it
    // ends (the client's beacon uni-stream closed or errored), `recv()` returns
    // `None` — an always-ready future that would spin the loop at 100% CPU.
    // Disabling this branch on the first `None` keeps the task asleep; the real
    // link failure surfaces via `link.recv()`.
    let mut beacon_alive = true;

    // Whether this slot's departure has already been announced to the mesh and
    // decided (a clean leave-intent, handled inline with the "left" reason). The
    // post-loop Trigger-A departure pass is the fallback for every *other* exit (a
    // dropped link, an isolation): it announces a "dropped" departure. Skipping it
    // once a clean leave was announced avoids a redundant "dropped" SlotDeparted
    // chasing the "left" one across the mesh (which is idempotent, but noise).
    let mut leave_announced = false;
    // Whether we've received from this client since we last sent it a packet. Every
    // packet we send folds in the latest acks, so a forwarded turn clears this too,
    // and the flush only needs to carry acks when no forward has.
    let mut acks_owed = false;
    // The next maintenance flush. Pushed out whenever a forwarded turn re-carries
    // unacked turns (recovery is riding the forward stream, so no flush is due); left
    // to fire when a forward carries no redundancy or the link is idle, so a turn the
    // fresh packets can't re-carry is still retransmitted.
    let mut flush_deadline = Instant::now() + FLUSH_INTERVAL;

    // Anchor this connection's own-slot receive window. A re-homing client presents
    // a cursor for *its own* slot (peers present per-peer cursors; a slot never
    // resumes from itself) whose value is the oldest seq it will re-send — its
    // retention ring's front. This fresh relay's dedup would otherwise base that
    // slot's window at 0 and, once the resumed high-seq stream passed the window,
    // reject it as out-of-window and drop the link — which, because every re-homed
    // slot crosses the window at the same absolute seq, tears down the whole group
    // at once and leaves a later peer death unconfirmable to the survivor. Removing
    // the own-slot entry here also keeps it out of the replay below (a slot is never
    // replayed its own turns). Absent (a fresh dial or a peer-only reconnect), this
    // is a no-op and the window bases at 0 as before.
    if let Some(anchor) = resume_cursors.remove(&slot) {
        link.anchor_receive_window(slot, anchor);
    }

    // Replay to a reconnecting client the turns it missed while it was gone. A fresh
    // dial presents no resume cursors, so this replays nothing; a reconnect presents
    // its per-peer-slot delivery position, and every recorded turn at or past a
    // slot's cursor is written down the reliable control stream, oldest-first. They
    // ride the stream as ordinary oversize-turn frames — the same path the client
    // already folds back into its per-slot reorder buffer — so the replayed turns
    // splice ahead of the live datagram turns that resume once this loop runs, and
    // the client's per-slot seq ordering holds regardless of which path delivered
    // each turn. Done before the serve loop so no live forward can outrun the
    // replay on the control stream.
    for payload in turn_ring.replay(&key, &resume_cursors) {
        if let Err(error) =
            rally_point_transport::control::send_control_turn(&mut control_send, payload).await
        {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                %error,
                "replaying a missed turn to a reconnecting client failed; closing slot link",
            );
            end_slot_link(&sessions, &mesh_for_teardown, &key, slot, leave_announced);
            return;
        }
    }

    'serve: loop {
        tokio::select! {
            received = link.recv() => {
                let received = match received {
                    Ok(received) => received,
                    Err(error) => {
                        log_link_closed(&key, slot, &error);
                        break 'serve;
                    }
                };
                // Only a payload-bearing packet needs an ack in return; owing one for
                // a client's ack-only packet would bounce ack-only packets back and
                // forth on an idle link.
                if received.carried_payloads {
                    acks_owed = true;
                }
                // Sample this client's QUIC path stats on every received packet.
                // A turn arrives every game step under active play, so this keeps
                // the mesh's outgoing conditions current exactly when the
                // decision-maker needs them. Quinn stats don't change while idle,
                // so a quiet slot's last sample stays valid. Sampling once per
                // packet (not per payload) is enough — all payloads in one packet
                // share the same connection's path.
                let sample = sample_slot_conditions(link.connection(), slot);
                crate::mesh::publish_conditions(&conditions, &key, slot, sample);
                // Feed the same sample into this session's decision-maker. The
                // decision it may fire schedules against the frames observed off
                // validated turns below — never off this packet's raw claims.
                let observed = LinkConditions {
                    slots: vec![sample],
                };
                // Any decision it fires is logged by the helper and broadcast
                // later, at fan-out; nothing to do with it here.
                let _ = consensus::ingest_local_conditions(&decision_makers, &key, &observed);
                for payload in received.fresh {
                    match validate_turn(
                        slot,
                        payload.seq,
                        payload.game_frame_count,
                        &payload.commands,
                    ) {
                        Ok(turn) => {
                            let payload = turn.payload;
                            flight_counters.note_validated(payload.seq);
                            // Only a *validated* turn's frame feeds the consensus
                            // coordinate — a rejected packet must not leave a
                            // trace in decision state. (And the coordinate is the
                            // minimum across slots, so even a validated turn's
                            // inflated claim can only mislead its own slot.)
                            if let Some(frame) = payload.game_frame_count {
                                consensus::observe_turn_frame(
                                    &decision_makers,
                                    &key,
                                    slot,
                                    payload.seq,
                                    rally_point_proto::ids::GameFrameCount(frame),
                                );
                            }
                            // NOTE: the desync comparator is NOT fed here. The
                            // mesh delivers a turn to the authority via more
                            // than one path, so counting has to happen exactly
                            // once per distinct (slot, seq) turn -- that's
                            // `deliver_turn_to_locals`, right after its
                            // mark_seen dedup, which `forward_turn` below
                            // funnels into.
                            crate::mesh::forward_turn(
                                &sessions,
                                &mesh_links,
                                &seen_registries,
                                &decision_makers,
                                &turn_ring,
                                &key,
                                slot,
                                payload,
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "rejecting client turn and closing connection",
                            );
                            link.connection()
                                .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"invalid turn");
                            break 'serve;
                        }
                    }
                }
                // Push the advanced delivered-through cursor to the client so it can
                // force-advance its unacked window. The relay receives only this
                // client's own slot, so one per-slot cursor suffices. Push only on
                // advance.
                if let Some(cursor) = link.delivered_through(slot) {
                    flush_beacon(
                        &mut beacon_send,
                        &mut last_beacon_sent,
                        [(slot, cursor)].into(),
                    )
                    .await;
                }
                if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        slot = slot.0,
                        in_flight = link.payloads_in_flight(),
                        "unacked window exhausted; isolating slot",
                    );
                    link.connection()
                        .close(VarInt::from_u32(ISOLATED_CLOSE), b"unacked window exhausted");
                    break 'serve;
                }
            }
            // A synced leave for another slot, to push down this client's reliable
            // control stream. This is the whole fix for the turn-envelope deadlock:
            // a departing peer stalls this client and stops its datagram turn flow,
            // so the leave that must unstall it can only arrive on the reliable
            // stream, which keeps flowing.
            pushed = leave_push_rx.recv(), if leave_push_alive => {
                match pushed {
                    Some(leave) => {
                        if let Err(error) = rally_point_transport::control::send_control_leave(
                            &mut control_send,
                            leave,
                        )
                        .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "leave control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => leave_push_alive = false,
                }
            }
            // The session-start directive for this client, to push down its
            // reliable control stream. Fired session-wide when the authority
            // decides every expected slot has connected, or re-pushed to this slot
            // alone if it registered after the session already started. A write
            // failure ends the link like every other control-stream write here —
            // the stream is dead regardless of which frame kind hit it.
            pushed = start_push_rx.recv(), if start_push_alive => {
                match pushed {
                    Some(()) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_session_start(
                                &mut control_send,
                            )
                            .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "session-start control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => start_push_alive = false,
                }
            }
            // A slot-connectivity change for this client, to push down its reliable
            // control stream: some member's link died or (re)registered. Rides the
            // reliable stream like a leave, so it still reaches a client whose
            // datagram turn flow has stalled behind the very disconnect being
            // reported. A write failure ends the link like every other
            // control-stream write here.
            pushed = conn_push_rx.recv(), if conn_push_alive => {
                match pushed {
                    Some((subject, connected)) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_connectivity(
                                &mut control_send,
                                subject.0,
                                connected,
                            )
                            .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "connectivity control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => conn_push_alive = false,
                }
            }
            // A lobby command another member authored (or the replay of an earlier
            // one), to push down this client's reliable control stream. Like a
            // leave, it rides the reliable stream because a lobby has no datagram
            // turn flow to piggyback on; unlike a leave, this branch also drains
            // the per-session replay log that `register_member` queued here, so an
            // early command and a live one write down the stream on one ordered
            // path. The `slot` is the relay-stamped author, so the receiving game
            // attributes the bytes correctly.
            pushed = lobby_rx.recv(), if lobby_alive => {
                match pushed {
                    Some(command) => {
                        if let Err(error) = rally_point_transport::control::send_control_lobby(
                            &mut control_send,
                            command,
                        )
                        .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "lobby control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => lobby_alive = false,
                }
            }
            // A game-chat message another member authored (or a mesh-forwarded
            // one), to push down this client's reliable control stream — the
            // mid-game counterpart to the lobby branch above. Unlike lobby, there
            // is no replay log to drain first: this branch only ever tails live
            // messages, so a member whose stream comes up after a message
            // already flowed simply never sees it. A write failure here ends the
            // link exactly like every other control-stream write in this loop —
            // the underlying stream is dead regardless of which frame kind hit
            // it — which is a different call than the client-edge driver makes
            // for its own *outbound* chat sends (best-effort, logged and
            // ignored): there, the link may still be otherwise healthy; here,
            // the failure *is* evidence the link is not.
            pushed = chat_rx.recv(), if chat_alive => {
                match pushed {
                    Some(chat_msg) => {
                        if let Err(error) = rally_point_transport::control::send_control_chat(
                            &mut control_send,
                            chat_msg,
                        )
                        .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "chat control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => chat_alive = false,
                }
            }
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some(payload) => {
                        // Counts every turn delivered to this client, datagram
                        // and control-stream divert alike.
                        flight_counters.note_forwarded();
                        let fits = match link.payload_fits(&payload) {
                            Ok(fits) => fits,
                            Err(error) => {
                                log_link_closed(&key, slot, &error);
                                break 'serve;
                            }
                        };
                        if !fits {
                            flight_counters.note_oversize_divert();
                            // Too large for any datagram on this client's path:
                            // divert to the reliable control stream, whose QUIC
                            // reliability replaces redundancy for this turn. A
                            // write failure closes the link — nothing re-carries
                            // a diverted turn, and dropping it would desync
                            // lockstep.
                            if let Err(error) = rally_point_transport::control::send_control_turn(
                                &mut control_send,
                                payload,
                            )
                            .await
                            {
                                tracing::info!(
                                    tenant = key.tenant.as_ref(),
                                    session = key.session.0,
                                    slot = slot.0,
                                    %error,
                                    "control stream send failed; closing slot link",
                                );
                                break 'serve;
                            }
                            continue;
                        }
                        // The forwarded turn goes out carrying our acks. If it
                        // also re-carried unacked turns, recovery is riding the
                        // stream, so push the flush out; if it carried none (a
                        // near-MTU turn), leave the timer so the flush
                        // retransmits them.
                        match send_packet(&mut link, Some(payload)) {
                            Ok(carried_redundancy) => {
                                acks_owed = false;
                                if carried_redundancy {
                                    flush_deadline = Instant::now() + FLUSH_INTERVAL;
                                }
                                if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
                                    tracing::warn!(
                                        tenant = key.tenant.as_ref(),
                                        session = key.session.0,
                                        slot = slot.0,
                                        in_flight = link.payloads_in_flight(),
                                        "unacked window exhausted; isolating slot",
                                    );
                                    link.connection()
                                        .close(VarInt::from_u32(ISOLATED_CLOSE), b"unacked window exhausted");
                                    break 'serve;
                                }
                            }
                            Err(error) => {
                                log_link_closed(&key, slot, &error);
                                break 'serve;
                            }
                        }
                    }
                    // The roster dropped our sender: we've been deregistered.
                    None => break 'serve,
                }
            }
            // The client's oversize turn, arriving over the reliable control
            // stream because no datagram could carry it. It is the same
            // attacker-facing ingress as a datagram turn: fold it through the
            // link's dedup first (a duplicate must not double-forward; a seq
            // beyond the window closes the link exactly as on the datagram
            // path), then validate and forward it like any other turn.
            received = control_rx.recv(), if control_alive => {
                match received {
                    // A client only ever *sends* oversize turns up; it never sends
                    // a leave (those are relay → client only). Ignore a stray one.
                    Some(ControlInbound::Leave(_)) => {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "ignoring unexpected client-sent leave control frame",
                        );
                    }
                    // Likewise the session-start directive is relay → client only;
                    // a client never sends one up. Ignore a stray one, mirroring the
                    // leave case above.
                    Some(ControlInbound::SessionStart) => {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "ignoring unexpected client-sent session-start control frame",
                        );
                    }
                    // Connectivity frames are relay → client only; a client never
                    // sends one up. Ignore a stray one, mirroring the cases above.
                    Some(ControlInbound::Connectivity(_)) => {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "ignoring unexpected client-sent connectivity control frame",
                        );
                    }
                    // The client announcing its own clean departure. The
                    // client already flushed its outstanding turns and waited
                    // for their acks before sending this, so nothing of its
                    // game state is lost by cutting it off right here.
                    //
                    // Decide the leave immediately rather than waiting for
                    // the link to actually die: it gives survivors the
                    // "left" reason straight away instead of stalling
                    // through the idle-timeout drop path. `break 'serve`
                    // right after is the determinism cut this whole
                    // mechanism rests on -- this task is the single place
                    // that serializes the client's control frames against
                    // its datagram turns, so once it has processed the
                    // intent, no turn from this slot is forwarded again;
                    // every survivor ends up with the identical final-turn
                    // prefix and the same apply frame.
                    //
                    // The post-loop Trigger-A departure pass is skipped for
                    // this exit (via `leave_announced`), since the clean
                    // departure is announced here with the "left" reason --
                    // deregistration, the presence report, and the
                    // decision-maker's per-slot cleanup still all run as they
                    // would for a dropped client. This client is homed on THIS
                    // relay, so its own decision-maker records the departure and,
                    // if this relay is the authority, decides the leave; either
                    // way the departure is announced to the peer relays as a
                    // `SlotDeparted` so their survivors (and the authority, if it
                    // is a peer) hear of it.
                    Some(ControlInbound::LeaveIntent) => {
                        tracing::info!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "client announced clean leave",
                        );
                        announce_departure(
                            &drop_holds,
                            &decision_makers,
                            &sessions,
                            &mesh_links,
                            &key,
                            slot,
                            LEAVE_REASON_LEFT,
                        );
                        leave_announced = true;
                        // The client's driver never expects an ack for the
                        // intent itself -- closing the link is the
                        // confirmation it waits on, so give it one now
                        // rather than leaving the connection to linger
                        // until some other path notices it's unused.
                        link.connection().close(
                            VarInt::from_u32(LEAVE_PROCESSED_CLOSE),
                            b"leave processed",
                        );
                        break 'serve;
                    }
                    Some(ControlInbound::OversizeTurn(payload)) => {
                        // A turn larger than any legitimate one can ever be is
                        // rejected before it can occupy the count-bounded forward
                        // queues (see `MAX_OVERSIZE_TURN_COMMANDS_LEN`). Closing
                        // the link — rather than dropping the turn and stranding
                        // peers on the seq gap — is the same response a malformed
                        // turn gets, and only removes the offending client.
                        if payload.commands.len() > MAX_OVERSIZE_TURN_COMMANDS_LEN {
                            tracing::warn!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                len = payload.commands.len(),
                                cap = MAX_OVERSIZE_TURN_COMMANDS_LEN,
                                "rejecting over-cap oversize client turn and closing connection",
                            );
                            link.connection()
                                .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"oversize turn");
                            break 'serve;
                        }
                        // Dedup under the *authorized* slot — the wire slot is a
                        // claim the relay never trusts (validate_turn rebinds it
                        // the same way on the datagram path), so a lied-about
                        // slot can't open a second seq space.
                        let fresh = match link.deliver_external(slot, payload.seq) {
                            Ok(fresh) => fresh,
                            Err(error) => {
                                log_link_closed(&key, slot, &error);
                                break 'serve;
                            }
                        };
                        if !fresh {
                            continue;
                        }
                        match validate_turn(slot, payload.seq, payload.game_frame_count, &payload.commands) {
                            Ok(turn) => {
                                let payload = turn.payload;
                                // A validated turn's frame feeds the consensus
                                // coordinate, exactly as on the datagram path —
                                // via the seq-aware path so the leave-frame clamp
                                // has this turn's history too.
                                if let Some(frame) = payload.game_frame_count {
                                    consensus::observe_turn_frame(
                                        &decision_makers,
                                        &key,
                                        slot,
                                        payload.seq,
                                        rally_point_proto::ids::GameFrameCount(frame),
                                    );
                                }
                                // NOTE: no desync-comparator call here either —
                                // see the datagram path's note above.
                                crate::mesh::forward_turn(
                                    &sessions,
                                    &mesh_links,
                                    &seen_registries,
                                    &decision_makers,
                                    &turn_ring,
                                    &key,
                                    slot,
                                    payload,
                                );
                            }
                            Err(error) => {
                                tracing::warn!(
                                    tenant = key.tenant.as_ref(),
                                    session = key.session.0,
                                    slot = slot.0,
                                    %error,
                                    "rejecting oversize client turn and closing connection",
                                );
                                link.connection()
                                    .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"invalid turn");
                                break 'serve;
                            }
                        }
                    }
                    // The client's end-of-game result report. Processed in stream
                    // order like any other control frame — a report that arrives
                    // before a leave-intent is handled before the intent closes the
                    // link — and, unlike the intent, it does not end the link: the
                    // client keeps playing (a mid-game defeat report). The bytes are
                    // opaque; the relay only enforces the ingress rule and forwards
                    // them up the coordinator pipeline. The reporting slot is this
                    // authenticated connection's slot, never a value from the
                    // payload. An inadmissible payload is dropped without closing
                    // the link.
                    Some(ControlInbound::GameResult(payload)) => {
                        if let Err(reason) = game_result_admissible(&payload) {
                            tracing::debug!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                len = payload.len(),
                                cap = MAX_GAME_RESULT_PAYLOAD_LEN,
                                reason,
                                "dropping inadmissible game-result payload",
                            );
                        } else {
                            consensus::record_result(&decision_makers, &key, slot, payload.to_vec());
                        }
                    }
                    // The client's lobby command. Bind it to the authenticated
                    // slot — never the client-asserted `slot` on the wire, exactly
                    // as `validate_turn` rebinds a turn's slot — then deliver it to
                    // local members (appended to the per-session replay log and
                    // fanned to every other local member; the author is not echoed,
                    // its own game echoes locally) and forward one copy across each
                    // mesh link serving the session so peer relays fan it to their
                    // locals. The bytes are opaque; the relay frames nothing of its
                    // own around them.
                    Some(ControlInbound::Lobby(mut command)) => {
                        command.slot = u32::from(slot.0);
                        crate::lobby::deliver(&lobby, &key, command.clone());
                        crate::mesh::fan_out_lobby_command(&mesh_links, &key, command);
                    }
                    // The client's in-game chat message. Admit it against the
                    // relay's size and rate caps first — either failure drops
                    // the message without closing the link, since a lost chat
                    // line is not correctness-critical the way a turn or lobby
                    // command is. An admitted message is bound to the
                    // authenticated slot — never the client-asserted `slot` on
                    // the wire, exactly as a lobby command is — then delivered
                    // to local members (no replay log; the author is not
                    // echoed) and forwarded once across each mesh link serving
                    // the session.
                    Some(ControlInbound::Chat(mut chat_msg)) => {
                        if crate::chat::admit(&chat, &key, slot, chat_msg.text.len()) {
                            chat_msg.slot = u32::from(slot.0);
                            crate::chat::deliver(&chat, &key, chat_msg.clone());
                            crate::mesh::fan_out_chat(&mesh_links, &key, chat_msg);
                        }
                    }
                    // The client's manual request to drop a disconnected slot. The
                    // requester is this authenticated connection's slot, never a
                    // value from the wire. Reject silently (log at info, never close
                    // the link — a mis-click must not disconnect the requester) when
                    // it names itself or a slot this relay has no reason to believe is
                    // gone; rate-limit per requester so a double-click storm can't
                    // flood the mesh. An accepted request is handled locally (this
                    // relay may be the authority) and broadcast to every peer so a
                    // peer-homed authority honors it too.
                    Some(ControlInbound::RequestDrop(wire_target)) => {
                        handle_drop_request(
                            &drop_holds,
                            &decision_makers,
                            &sessions,
                            &mesh_links,
                            &key,
                            slot,
                            wire_target,
                        );
                    }
                    None => control_alive = false,
                }
            }
            // The client pushed a delivered-through cursor over the beacon stream.
            // The reader task assembled the complete frame off a cancel-safe path;
            // `mpsc::Receiver::recv` is cancel-safe in select!. The
            // `if beacon_alive` precondition disables this branch once the reader
            // task ends — otherwise `recv()` returns `None` on every poll, an
            // always-ready future that would spin the loop at 100% CPU.
            received = beacon_rx.recv(), if beacon_alive => {
                match received {
                    Some((beacon_slot, cursor)) => {
                        link.retire_through(beacon_slot, cursor);
                        if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
                            tracing::warn!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                in_flight = link.payloads_in_flight(),
                                "unacked window exhausted; isolating slot",
                            );
                            link.connection()
                                .close(VarInt::from_u32(ISOLATED_CLOSE), b"unacked window exhausted");
                            break 'serve;
                        }
                    }
                    // The reader task ended (client's beacon stream closed or
                    // errored). Stop polling it: the real link failure, if any,
                    // surfaces via `link.recv()`.
                    None => beacon_alive = false,
                }
            }
            _ = sleep_until(flush_deadline) => {
                // The fixed-cadence maintenance flush. When a forwarded turn is
                // unacked or we owe acks, send an ack-only packet: it re-carries
                // unacked turns oldest-first (its full budget has room the near-MTU
                // forwarded packets did not) and folds in any acks owed. This is what
                // retransmits a forwarded turn the fresh stream can't re-carry, and
                // what acks a client with no return traffic; it stays silent when
                // nothing is unacked and nothing is owed.
                if acks_owed || link.payloads_in_flight() > 0 {
                    if let Err(error) = send_packet(&mut link, None) {
                        log_link_closed(&key, slot, &error);
                        break 'serve;
                    }
                    acks_owed = false;
                }
                flush_deadline = Instant::now() + FLUSH_INTERVAL;
            }
            _ = shutdown.notified() => {
                // The relay is isolating this slot: it fell hopelessly behind and was
                // back-pressuring its peers. Close the link and leave; deregistration
                // below then frees the slot, only now that this task is actually gone.
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "isolating lagging slot; closing connection",
                );
                break 'serve;
            }
        }
    }

    end_slot_link(&sessions, &mesh_for_teardown, &key, slot, leave_announced);
}

/// Runs the full departure/close protocol for a slot link that has ended,
/// however far it got: deregisters the slot, drops its condition history,
/// announces its departure to the mesh (unless a clean leave-intent already
/// announced it with the "left" reason), re-derives this relay's presence
/// verdict, and — if that deregistration emptied the session's local roster —
/// tells the coordinator the session is closed.
///
/// This is the single teardown path for every way `run_slot_link` can end: a
/// link that dies before its streams even come up has registered a slot and
/// forwarded nothing, but peers and the coordinator still need to hear it left
/// — skipping this would only delay that news to the coordinator's holdout
/// reap, not avoid the need for it.
fn end_slot_link(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    slot: SlotId,
    leave_announced: bool,
) {
    mesh.decision_makers.flight_recorder().record(
        key,
        crate::flight_recorder::FlightEvent::SlotDisconnected { slot: slot.0 },
    );
    // Drop this member's lobby-push channel before the roster deregister below.
    // The roster refuses a duplicate slot, so a reconnecting slot cannot register
    // (and re-register its lobby member) until this deregister frees the roster
    // slot — doing the lobby deregister first keeps a fresh connection's
    // `register_member` from being clobbered by this one's cleanup.
    crate::lobby::deregister_member(&mesh.lobby, key, slot);
    // Same rationale for chat: deregister before the roster frees the slot, so
    // a reconnect can't clobber this connection's cleanup.
    crate::chat::deregister_member(&mesh.chat, key, slot);
    let session_emptied = deregister(sessions, key, slot);
    crate::mesh::unpublish_conditions(&mesh.conditions, key, slot);
    // Trigger A (synced player-leave): this client's link ended, so it has left
    // the game. Announce the departure — unless a clean leave-intent already did,
    // with the "left" reason — as a "dropped" one: record it, tell the peer relays
    // (`SlotDeparted`, so a peer-homed authority and peer survivors hear it), and,
    // if this relay is the session's authority, decide the coordinated leave so
    // every remaining client drops the slot from lockstep at the same frame
    // (rather than stalling on a slot that will never send another turn).
    // Recording the departure captures the slot's last observed frame into its
    // record — the apply-frame basis — and retires the slot's live state in the
    // decision-maker. On a decision, the leave is pushed down every surviving
    // local client's reliable control stream (the departing slot is already off
    // the roster from `deregister` above, so `fan_out_leave` targets only
    // survivors) and across the mesh to peer survivors — the turn stream has
    // stopped for them, so the reliable stream is the only channel that unstalls.
    if !leave_announced {
        // The link died without a clean leave — a disconnect. Tell every slot
        // (local and across the mesh) this one is no longer connected, immediately
        // and independent of the hold below, so survivors' displays reflect the
        // disconnect ~at once even while their turn stream stalls waiting on it.
        broadcast_connectivity(sessions, &mesh.links, key, slot, false);
        announce_departure(
            &mesh.drop_holds,
            &mesh.decision_makers,
            sessions,
            &mesh.links,
            key,
            slot,
            LEAVE_REASON_DROPPED,
        );
    }
    // Forget this slot's condition history in the decision-maker so a departed
    // client's stale stats don't outlive its connection — a no-op when the
    // departure announce above already retired the slot; it still covers exits
    // where no maker-side departure applies. The maker itself lives until the
    // session ends (the coordinator drops the descriptor); the departure record
    // and any cached leave are kept, so a promotion can still re-derive the leave.
    if let Some(maker) = mesh.decision_makers.lock().get_mut(key) {
        maker.remove_slot(slot);
    }
    // This client leaving may hand the session's buffer authority to the next
    // relay in the order — the presence-driven half of the handoff. The local
    // verdict moves here; the peers hear the emptied roster from the mesh
    // drivers' presence reconcile.
    report_own_presence(
        &mesh.presence,
        &mesh.decision_makers,
        sessions,
        &mesh.links,
        &mesh.drop_holds,
        key,
    );
    // This was the relay's last local slot for the session: it has torn down its
    // serving state, so tell the coordinator. Fired here, after `announce_departure`
    // already put this slot's departure on the same ordered notice channel, so the
    // coordinator can treat a delivered `SessionClosed` as proof no earlier notice
    // for the session is still in flight — the ordering the final `sessionClosed`
    // webhook rests on.
    if session_emptied {
        consensus::session_closed(&mesh.decision_makers, key);
        // The relay's last local member for the session is gone, so its lobby log
        // and (now-empty) member set can be dropped — mirroring how the roster
        // group is dropped when its last slot leaves.
        crate::lobby::end_session(&mesh.lobby, key);
        // Same for chat's (log-free) per-session state.
        crate::chat::end_session(&mesh.chat, key);
        // Same for the forwarded-turn replay ring: no local slot remains to resume,
        // so nothing more will be replayed from it.
        mesh.turn_ring.end_session(key);
        // Same for request limiters, and for any hold whose slot's leave is already
        // decided — but NOT for an undecided hold: the disconnect just above may
        // itself have marked one (this relay's own last local slot leaving is
        // exactly what both creates its hold and empties the roster, on a session
        // split across relays this happens on every single disconnect), and that
        // hold is still the reconnect-admission token and unlock clock for a drop
        // nobody has decided yet. See `crate::drop_hold` module docs.
        let decided = consensus::decided_slots(&mesh.decision_makers, key);
        mesh.drop_holds.end_session(key, &decided);
    }
}

/// Announces a home client's departure from the game: records it, tells the peer
/// relays over the mesh (`SlotDeparted`), and — if this relay is the session's
/// authority — decides the one synced leave and pushes it to local survivors and
/// across the mesh to peer survivors.
///
/// Every relay records the departure (for authority-handoff robustness) and
/// announces it to its peers regardless of whether it is the authority: a
/// peer-homed authority learns of a client it never served only through this
/// `SlotDeparted`, and a receiving authority dedups by slot so a double-decide is
/// impossible. Recording the departure captures the slot's last observed frame
/// into its record — the leave's apply-frame basis — and retires the slot's live
/// state in the decision-maker.
fn announce_departure(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
) {
    // Read the last observed frame, the reachability ceiling, and the slot's
    // retained end-of-game result before recording retires the slot's live state;
    // all fill the departure record and the SlotDeparted the peers receive. The
    // ceiling and the result are home-authored here (only this relay, the slot's
    // home, holds the retained report and computes the ceiling), so every relay
    // clamps to the identical apply frame and folds the identical result — see
    // `consensus::reachable_frame` / `consensus::result_for`.
    let last_frame = consensus::slot_frame(decision_makers, key, slot);
    let reachable = consensus::reachable_frame(decision_makers, key, slot);
    let result = consensus::result_for(decision_makers, key, slot);
    consensus::record_departure(
        decision_makers,
        key,
        slot,
        last_frame,
        reachable,
        result.clone(),
        reason,
    );
    crate::mesh::fan_out_slot_departed(
        mesh_links,
        key,
        slot,
        last_frame.map(|f| f.0),
        reachable,
        result,
        reason,
    );
    // Turn the recorded departure into the synced leave — but a *drop* is only
    // marked as an undecided hold, never decided here: survivors are removed on a
    // disconnect only when a human's `RequestDrop` is honored past the unlock
    // floor, or never. A *clean* leave decides at once. See `hold_or_decide_leave`.
    // The departure above is already recorded and announced, so a promoted
    // authority can re-derive the leave (or leave the hold standing) if this relay
    // is lost.
    hold_or_decide_leave(
        drop_holds,
        decision_makers,
        sessions,
        mesh_links,
        key,
        slot,
        reason,
    );
}

/// Turns a recorded departure into the one synced leave — but only for a *clean*
/// leave. A *drop* is marked as an undecided hold and decided by nothing here:
/// there is no timer and no automatic firing, so a disconnected slot stays held
/// (survivors stalled but alive) until a surviving member's `RequestDrop` is
/// honored past the unlock floor, or forever.
///
/// A clean leave (`reason` != [`LEAVE_REASON_DROPPED`]) releases any hold this
/// slot's earlier drop observation marked — the ordering where a clean-leave
/// intent arrives while a drop is still held — and decides at once, so the "left"
/// outcome supersedes the held "dropped" one. Every relay that observes the
/// departure marks its own hold, so the decision survives an authority handoff: a
/// promotion re-derives the leave from the shared departure record (skipping still
/// held drops), and an honored request on any relay decides against that record.
pub(crate) fn hold_or_decide_leave(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
) {
    if reason == LEAVE_REASON_DROPPED {
        // Mark the drop as undecided and stop. Nothing here removes the slot — only
        // an honored manual request ever does.
        drop_holds.hold(key.clone(), slot);
        decision_makers.flight_recorder().record(
            key,
            crate::flight_recorder::FlightEvent::DropHeld { slot: slot.0 },
        );
    } else {
        // A clean leave supersedes any pending drop hold for this slot, then
        // decides immediately.
        drop_holds.release(key, slot);
        decide_and_broadcast_leave(decision_makers, sessions, mesh_links, key, slot, reason);
    }
}

/// Validates and acts on a client's manual `RequestDrop` at the relay's client
/// edge. `requester` is the authenticated connection's slot (never a wire value);
/// `wire_target` is the slot the requester asked to drop.
///
/// Rejects silently — an info log, never a link close, because a mis-click must
/// not disconnect the survivor who made it — when the request names the requester
/// itself, names a slot this relay has no reason to believe is disconnected
/// (neither a pending hold nor a departure record), or exceeds the requester's
/// rate cap. A valid, admitted request is honored locally (this relay may be the
/// authority — see [`honor_drop_request`]) and broadcast to every peer so a
/// peer-homed authority honors it too.
fn handle_drop_request(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    requester: SlotId,
    wire_target: u32,
) {
    let Ok(target) = u8::try_from(wire_target).map(SlotId) else {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            requester = requester.0,
            target = wire_target,
            "ignoring drop request for a slot id out of range",
        );
        return;
    };
    if target == requester {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = requester.0,
            "ignoring drop request that names its own requester",
        );
        return;
    }
    // A cheap sanity check at the edge — the authoritative gate is at the
    // authority, which alone holds the unlock timer. A request for a slot this
    // relay sees as neither held nor departed is nonsense (a stale or hostile
    // client), so drop it before spending a mesh broadcast on it.
    if !drop_holds.is_pending(key, target)
        && !consensus::slot_departed(decision_makers, key, target)
    {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            requester = requester.0,
            target = target.0,
            "ignoring drop request for a slot that is not disconnected",
        );
        return;
    }
    // Rate-limit per requester so a double-click (or a hostile flood) cannot spray
    // the mesh with request broadcasts. Over-limit requests are dropped silently —
    // never a link close.
    if !drop_holds.admit_request(key, requester) {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            requester = requester.0,
            target = target.0,
            "dropping drop request; requester exceeded its request rate cap",
        );
        return;
    }
    decision_makers.flight_recorder().record(
        key,
        crate::flight_recorder::FlightEvent::DropRequested {
            requester: requester.0,
            target: target.0,
        },
    );
    // Honor it here (this relay may be the authority) and broadcast to every peer
    // so a peer-homed authority honors it too. The broadcast carries the
    // relay-stamped requester for logging/attribution.
    honor_drop_request(
        drop_holds,
        decision_makers,
        sessions,
        mesh_links,
        key,
        target,
        u32::from(requester.0),
    );
    crate::mesh::fan_out_request_drop(mesh_links, key, target, requester);
}

/// Honors a manual drop request against `target` if this relay is the session
/// authority and the target's drop has stood past the unlock floor. `requester` is
/// carried only for logging/attribution — the decision never keys on who asked.
///
/// Called both from the client edge (this relay's own local request) and from a
/// mesh `RequestDrop` frame (a peer's request). A non-authority does nothing: the
/// request was broadcast to every relay, so the one authority among the receivers
/// is the single relay that acts. On the authority, a hold past the floor is
/// released and the synced leave decided with the DROPPED reason; the decide path
/// dedups, so a duplicate request after the decide is a harmless no-op. A hold
/// short of the floor, or no hold at all (the slot reconnected or left cleanly), is
/// ignored — logged with the elapsed-vs-floor so a refused click is diagnosable.
pub(crate) fn honor_drop_request(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    target: SlotId,
    requester: u32,
) {
    if !consensus::is_authority(decision_makers, key) {
        // Not the authority — the authority is among the broadcast's receivers and
        // will act. Nothing to do, and the hold stays for a possible promotion.
        return;
    }
    match drop_holds.held_for(key, target) {
        Some(elapsed) if elapsed >= drop_holds.unlock() => {
            drop_holds.release(key, target);
            decide_and_broadcast_leave(
                decision_makers,
                sessions,
                mesh_links,
                key,
                target,
                LEAVE_REASON_DROPPED,
            );
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                target = target.0,
                requester,
                held_ms = elapsed.as_millis(),
                "honoring manual drop request",
            );
        }
        Some(elapsed) => tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            requester,
            held_ms = elapsed.as_millis(),
            floor_ms = drop_holds.unlock().as_millis(),
            "ignoring drop request; the target's drop has not stood past the unlock floor",
        ),
        None => tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            requester,
            "ignoring drop request; the target has no pending drop hold",
        ),
    }
}

/// Decides `slot`'s synced leave and broadcasts it session-wide — to local
/// survivors ([`fan_out_leave`]) and every peer relay
/// ([`crate::mesh::fan_out_leave_directive`]). `Some` only on the authority, and
/// only once per slot (`decide_leave` dedups), so a hold's expiry and a racing
/// clean decision cannot double-broadcast. The departing slot is already off the
/// roster, so `fan_out_leave` reaches only survivors.
fn decide_and_broadcast_leave(
    decision_makers: &crate::consensus::DecisionMakers,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
) {
    if let Some(leave) = consensus::decide_leave(decision_makers, key, slot, reason) {
        fan_out_leave(sessions, key, slot, leave);
        crate::mesh::fan_out_leave_directive(mesh_links, key, leave);
    }
}

/// Reports the current roster count for `key` into the presence registry and
/// re-derives the session's authority verdict when the report flipped this
/// relay's liveness. A session with no presence entry (no descriptor set an
/// order — dev/loopback harnesses that inject a verdict by hand) is left
/// untouched.
///
/// A verdict flip that *promotes* this relay (its own roster emptying is what
/// usually demotes it, but a re-derive can also promote it after a peer leaves)
/// yields any synced leave the departed authority never delivered; those are
/// pushed to local survivors and across the mesh via [`crate::mesh::broadcast_leaves`].
fn report_own_presence(
    presence: &crate::presence::PresenceRegistry,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    drop_holds: &crate::drop_hold::DropHolds,
    key: &SessionKey,
) {
    let live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    if crate::presence::record_own(presence, key, live) {
        // Slots whose drop is still held on this relay must not be decided by the
        // promotion a re-derive may trigger: a held drop is decided only by an
        // honored manual request, never by a promotion.
        let held = drop_holds.pending_slots(key);
        let leaves = crate::presence::recompute(presence, decision_makers, key, &held);
        crate::mesh::broadcast_leaves(sessions, mesh_links, key, leaves);
        // A recompute that promotes this relay to authority may make it the one
        // to observe full slot presence: re-evaluate and fire the session-start
        // directive if the accumulated live slots already cover the expected set.
        maybe_start_session(sessions, decision_makers, mesh_links, key);
        // This liveness change may have emptied the session session-wide (arming
        // the abandoned-session timer) or refilled it (cancelling any armed timer).
        reconcile_abandon(
            drop_holds,
            decision_makers,
            sessions,
            mesh_links,
            presence,
            key,
        );
    }
}

/// Arms or cancels `key`'s abandoned-session timer against the current presence and
/// departure state. Called after every presence liveness change (this relay's own
/// roster flip, or a peer's report), so the timer tracks session-wide emptiness.
///
/// A *started* session that is empty session-wide ([`crate::presence::all_empty`])
/// with at least one undecided departure ([`consensus::has_undecided_departure`]) is
/// abandoned: nobody is left to request the held drops, so a timer is armed that, on
/// expiry, decides them all (see [`decide_and_broadcast_abandoned`]). Any other
/// state — a slot still live, or nothing undecided — cancels any armed timer, so a
/// re-registering slot inside the window calls it off. Arming is idempotent (the
/// registry keeps the first timer), and every relay observing the abandonment arms
/// its own; the force-decide dedups, so a promotion mid-window loses nothing.
pub(crate) fn reconcile_abandon(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    presence: &crate::presence::PresenceRegistry,
    key: &SessionKey,
) {
    let abandoned = consensus::session_started(decision_makers, key)
        && crate::presence::all_empty(presence, key)
        && consensus::has_undecided_departure(decision_makers, key);
    if abandoned {
        // Owned clones for the timer task: it fires after the window with no
        // borrowed state, holding the shared registries by `Arc` (`DropHolds`
        // clones cheaply too — an `Arc` around each of its own maps). Named
        // distinctly from `drop_holds` itself, which stays the `&self` receiver of
        // `arm_abandon` below.
        let drop_holds_for_expire = drop_holds.clone();
        let decision_makers = Arc::clone(decision_makers);
        let sessions = Arc::clone(sessions);
        let mesh_links = Arc::clone(mesh_links);
        let key_for_expire = key.clone();
        drop_holds.arm_abandon(key.clone(), move || {
            decide_and_broadcast_abandoned(
                &drop_holds_for_expire,
                &decision_makers,
                &sessions,
                &mesh_links,
                &key_for_expire,
            );
        });
    } else {
        drop_holds.cancel_abandon(key);
    }
}

/// Decides every undecided departure for a fully-abandoned session and broadcasts
/// the leaves, funnelling the session into its normal close cascade. Force-decides
/// past the authority gate (an empty session names no authority; see
/// [`consensus::decide_abandoned_departures`]) and fires one departure notice per
/// slot as a side effect; the broadcast reaches no local survivor (the roster is
/// empty) but re-syncs any peer relay's cached leave state (dedup by slot).
///
/// Releases each freshly decided slot's drop hold — the decision is made now, so
/// the hold has nothing further to gate; without this it would sit "pending"
/// forever (a session-emptied teardown only sweeps a hold once it is decided, and
/// this session's already ran). A slot [`consensus::decide_abandoned_departures`]
/// dedups away (already decided) has no directive here, so its hold — if somehow
/// still present — is left for the next teardown's decided-sweep, not touched
/// twice for no reason.
fn decide_and_broadcast_abandoned(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &crate::consensus::DecisionMakers,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
) {
    let leaves = consensus::decide_abandoned_departures(decision_makers, key);
    if !leaves.is_empty() {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            count = leaves.len(),
            "abandoned session timed out with no live slots; deciding its held departures",
        );
        for leave in &leaves {
            if let Ok(slot) = u8::try_from(leave.slot) {
                drop_holds.release(key, SlotId(slot));
            }
        }
        crate::mesh::broadcast_leaves(sessions, mesh_links, key, leaves);
    }
}

/// Sends one packet, returning whether it re-carried any still-unacked turn — if so,
/// retransmission is already riding the forward stream and the flush can rest.
///
/// A refused datagram (`PayloadTooLarge`) here is a *bundle* that outgrew a
/// path-MTU shrink between sizing and sending — a recoverable loss the next,
/// smaller bundle re-carries, so it is not an error. It can never be a lone
/// turn too big for the path: the forward branch pre-checks with
/// [`Link::payload_fits`] and diverts those to the control stream (and the
/// link itself refuses one pre-registration as a second line of defense).
fn send_packet(link: &mut Link, payload: Option<Payload>) -> Result<bool, LinkError> {
    match link.send(payload) {
        Ok(redundant) => Ok(redundant > 0),
        Err(LinkError::PayloadTooLarge { needed, budget }) => {
            tracing::debug!(
                needed,
                budget,
                "datagram refused by a shrunken path; will re-carry"
            );
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Logs a link ending for ordinary reasons (peer closed, transport error) at a
/// low level — these are expected over a game's life, not faults.
fn log_link_closed(key: &SessionKey, slot: SlotId, error: &LinkError) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = slot.0,
        %error,
        "client link closed",
    );
}

/// Samples this client's QUIC connection path stats as a [`SlotConditions`], for
/// both the mesh sidecar and the decision-maker. RTT comes from QUIC's smoothed
/// path estimate (via [`crate::mesh::rtt_us`], which owns the "0 means no
/// measurement" convention); lost/sent are cumulative counters the
/// decision-maker differences between consecutive samples to get a loss rate
/// over the interval.
fn sample_slot_conditions(
    connection: &rally_point_transport::quinn::Connection,
    slot: SlotId,
) -> SlotConditions {
    let path = connection.stats().path;
    SlotConditions {
        slot: u32::from(slot.0),
        rtt_us: crate::mesh::rtt_us(path.rtt),
        lost_packets: path.lost_packets,
        sent_packets: path.sent_packets,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
        }
    }

    fn payload() -> Payload {
        Payload {
            seq: 0,
            slot: 0,
            commands: Vec::new().into(),
            ..Default::default()
        }
    }

    #[test]
    fn an_occupied_slot_is_refused() {
        let sessions: Sessions = Arc::default();
        let (_guard, _inbox) = register(&sessions, &key(), SlotId(0)).expect("first registers");
        assert!(register(&sessions, &key(), SlotId(0)).is_none());
    }

    #[test]
    fn dropping_an_armed_registration_frees_the_slot() {
        let sessions: Sessions = Arc::default();
        let (guard, _inbox) = register(&sessions, &key(), SlotId(0)).expect("first registers");
        drop(guard);
        // The slot — and the now-empty group — are gone, so it registers anew.
        assert!(register(&sessions, &key(), SlotId(0)).is_some());
    }

    #[test]
    fn live_slots_snapshots_registered_slots_per_group() {
        let sessions: Sessions = Arc::default();
        assert!(live_slots(&sessions).is_empty(), "a fresh roster is empty");

        let (mut g1, _i1) = register(&sessions, &key(), SlotId(2)).expect("slot 2 registers");
        let (mut g0, _i0) = register(&sessions, &key(), SlotId(0)).expect("slot 0 registers");
        g0.disarm();
        g1.disarm();

        let roster = live_slots(&sessions);
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].0, key());
        assert_eq!(
            roster[0].1,
            vec![SlotId(0), SlotId(2)],
            "the group's connected slots, in sorted order",
        );
    }

    #[tokio::test]
    async fn slot_teardown_records_flight_events_and_the_close_flushes() {
        // The real teardown flow, through `end_slot_link`: a dropped link records
        // its disconnect and the drop hold; the session-emptying teardown records
        // the close and flushes the recording (a logged discard — no sink here).
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        let k = key();
        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();
        let (mut g1, _i1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        g1.disarm();
        let flight = mesh.decision_makers.flight_recorder().clone();

        // Slot 1's link dies without a clean leave; slot 0 remains, so the
        // session stays open and the recording keeps accumulating.
        end_slot_link(&sessions, &mesh, &k, SlotId(1), false);
        let events: Vec<_> = flight.events(&k).into_iter().map(|r| r.event).collect();
        assert!(
            events.contains(&crate::flight_recorder::FlightEvent::SlotDisconnected { slot: 1 }),
            "the dropped link's disconnect is recorded: {events:?}",
        );
        assert!(
            events.contains(&crate::flight_recorder::FlightEvent::DropHeld { slot: 1 }),
            "the held drop decision is recorded: {events:?}",
        );

        // The last slot leaves: the close event seals the recording and the
        // detached flush retires it (discarded — no sink configured).
        end_slot_link(&sessions, &mesh, &k, SlotId(0), false);
        for _ in 0..100 {
            if flight.recorded_sessions().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            flight.recorded_sessions().is_empty(),
            "the session-emptying teardown flushed the recording",
        );
    }

    #[test]
    fn holds_any_slots_tracks_registration_and_release() {
        // The drain-idle predicate: empty until a slot registers, empty again once it
        // is freed — so the coordinated-drain wait converges when the last slot leaves.
        let sessions: Sessions = Arc::default();
        assert!(!holds_any_slots(&sessions), "a fresh roster holds no slots");
        let (guard, _inbox) = register(&sessions, &key(), SlotId(0)).expect("slot 0 registers");
        assert!(holds_any_slots(&sessions), "a registered slot is held");
        drop(guard);
        assert!(
            !holds_any_slots(&sessions),
            "freeing the last slot drops the group, so nothing is held",
        );
    }

    #[test]
    fn a_disarmed_registration_leaves_the_slot_held() {
        // disarm hands the slot's lifetime to the link task: dropping the guard must
        // not free it, so a concurrent reconnect is still refused.
        let sessions: Sessions = Arc::default();
        let (mut guard, _inbox) = register(&sessions, &key(), SlotId(0)).expect("first registers");
        guard.disarm();
        drop(guard);
        assert!(register(&sessions, &key(), SlotId(0)).is_none());
    }

    #[test]
    fn freeing_one_slot_leaves_a_peer_in_the_same_group() {
        let sessions: Sessions = Arc::default();
        let (slot0, _inbox0) = register(&sessions, &key(), SlotId(0)).expect("slot 0 registers");
        let (_slot1, _inbox1) = register(&sessions, &key(), SlotId(1)).expect("slot 1 registers");
        drop(slot0);
        // Slot 0 is reclaimable; slot 1 is untouched.
        assert!(register(&sessions, &key(), SlotId(0)).is_some());
        assert!(register(&sessions, &key(), SlotId(1)).is_none());
    }

    #[tokio::test]
    async fn close_slots_signals_a_held_slot_and_is_a_no_op_for_an_absent_one() {
        let sessions: Sessions = Arc::default();
        let k = key();
        let (mut g0, inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();

        // Closing a slot this relay does not hold (slot 5) is a no-op — no panic,
        // and the held slot is untouched.
        close_slots(&sessions, &k, &[SlotId(5)]);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbox0.shutdown.notified())
                .await
                .is_err(),
            "an absent slot's close must not signal a held one",
        );

        // Closing the held slot fires its shutdown signal (its task would then
        // close the link and deregister), but leaves it in the roster meanwhile.
        close_slots(&sessions, &k, &[SlotId(0), SlotId(9)]);
        tokio::time::timeout(Duration::from_millis(100), inbox0.shutdown.notified())
            .await
            .expect("the held slot is signaled to close");
        assert!(
            sessions.lock().get(&k).unwrap().contains_key(&SlotId(0)),
            "close_slots signals, it does not yank the roster entry",
        );
    }

    #[tokio::test]
    async fn fan_out_signals_a_full_peer_and_keeps_delivering_to_healthy_ones() {
        let sessions: Sessions = Arc::default();
        let k = key();
        // Source (0), a healthy peer (1) we keep drained, and a peer (2) we never
        // drain so its queue fills. Disarm the guards — the test owns the roster.
        let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        let (mut g2, inbox2) = register(&sessions, &k, SlotId(2)).expect("slot 2 registers");
        g0.disarm();
        g1.disarm();
        g2.disarm();

        // Fan out past slot 2's capacity. Slot 1 is drained every turn and so never
        // fills; slot 2 is never drained and fills, getting signaled to disconnect.
        let mut delivered_to_1 = 0;
        for _ in 0..(FORWARD_CAPACITY + 8) {
            fan_out(&sessions, &k, SlotId(0), payload());
            if inbox1.forward_rx.try_recv().is_ok() {
                delivered_to_1 += 1;
            }
        }

        // The healthy peer received every turn — the stuck one never blocked it.
        assert_eq!(delivered_to_1, FORWARD_CAPACITY + 8);

        // The stuck peer was signaled to shut down (its task would then close its
        // link and deregister)...
        tokio::time::timeout(Duration::from_millis(100), inbox2.shutdown.notified())
            .await
            .expect("slot 2 was signaled to disconnect");

        // ...but fan_out left it in the roster: the slot stays occupied until its own
        // task exits, so no replacement can register a second sender for it.
        let roster = sessions.lock();
        let slots = roster.get(&k).expect("group present");
        assert!(slots.contains_key(&SlotId(1)));
        assert!(slots.contains_key(&SlotId(2)));
    }

    #[tokio::test]
    async fn forward_turn_preserves_an_upstream_stamp_on_a_non_authority_relay() {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::messages::BufferDirective;

        let sessions: Sessions = Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let seen = crate::mesh::new_seen_registries();
        let makers = Arc::new(consensus::new_decision_makers());
        let turn_ring = crate::turn_ring::TurnRing::new();
        let k = key();

        // This relay is not the session's authority: its own maker never has a
        // directive, so the forward step must leave an incoming stamp alone.
        let _ = consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );

        // A local client to fan out to.
        let (mut guard, mut inbox) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        guard.disarm();

        // A turn stamped by the authority arrives over the mesh.
        let stamp = BufferDirective {
            buffer_turns: 6,
            apply_at_frame: 40,
            decision_seq: 5,
        };
        let stamped = Payload {
            buffer_directive: Some(stamp),
            commands: vec![0x05].into(),
            ..payload()
        };
        crate::mesh::forward_turn(
            &sessions,
            &mesh_links,
            &seen,
            &makers,
            &turn_ring,
            &k,
            SlotId(0),
            stamped,
        );

        let delivered = inbox
            .forward_rx
            .try_recv()
            .expect("the turn fans out to the local slot");
        assert_eq!(
            delivered.buffer_directive,
            Some(stamp),
            "the authority's stamp survives the hop through a non-authority relay",
        );
        // And the relay recorded the stamp's seq, so a later promotion to
        // authority numbers its own decisions above what clients already hold.
        {
            let mut registry = makers.lock();
            let maker = registry.get_mut(&k).unwrap();
            maker.observe_frame(SlotId(0), rally_point_proto::ids::GameFrameCount(1));
            let _ = maker.sync(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay);
        }
        consensus::ingest_local_conditions(
            &makers,
            &k,
            &rally_point_proto::messages::LinkConditions {
                slots: vec![rally_point_proto::messages::SlotConditions {
                    slot: 0,
                    rtt_us: 150_000,
                    lost_packets: 0,
                    sent_packets: 100,
                }],
            },
        )
        .expect("promoted, its first decision fires");
        let own = consensus::active_directive(&makers, &k).expect("a directive is queued");
        assert!(
            own.decision_seq > stamp.decision_seq,
            "a promoted relay continues the session's numbering",
        );

        // A duplicate of the stamped turn via a second mesh path is dropped
        // before fan-out, stamp and all.
        let duplicate = Payload {
            buffer_directive: Some(stamp),
            commands: vec![0x05].into(),
            ..payload()
        };
        crate::mesh::forward_turn(
            &sessions,
            &mesh_links,
            &seen,
            &makers,
            &turn_ring,
            &k,
            SlotId(0),
            duplicate,
        );
        assert!(
            inbox.forward_rx.try_recv().is_err(),
            "the topological duplicate is dropped",
        );
    }

    // -- GameResult ingress --

    /// An empty payload is the wire sentinel for "no result reported", never a
    /// real report, so it is inadmissible regardless of the size cap.
    #[test]
    fn empty_game_result_is_inadmissible() {
        assert_eq!(game_result_admissible(&[]), Err("empty"));
    }

    /// A payload over the cap is an ill-formed report.
    #[test]
    fn oversize_game_result_is_inadmissible() {
        let payload = vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN + 1];
        assert_eq!(game_result_admissible(&payload), Err("oversize"));
    }

    /// A non-empty, within-cap payload -- including one sized exactly at the
    /// cap -- is admissible.
    #[test]
    fn well_formed_game_result_is_admissible() {
        assert_eq!(game_result_admissible(&[0xDE, 0xAD]), Ok(()));
        let at_cap = vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN];
        assert_eq!(game_result_admissible(&at_cap), Ok(()));
    }

    // -- drop holds, manual drop requests, and connectivity fan-out --

    use crate::drop_hold::DropHolds;

    /// A drop-unlock floor a test can never reach by waiting, so a `RequestDrop`
    /// before it is provably refused.
    const UNREACHABLE_UNLOCK: Duration = Duration::from_secs(3600);

    /// A zero unlock floor, so a held drop is "past the floor" from the first
    /// instant and a `RequestDrop` is honored without any wait.
    const IMMEDIATE_UNLOCK: Duration = Duration::ZERO;

    /// Stands up a single-relay authority maker for `key` with a frame basis, plus
    /// a survivor slot registered so a decided leave has somewhere to fan out. The
    /// departing slot is given an observed frame too, so `decide_leave` schedules
    /// against it. Returns the shared registries and the survivor's inbox.
    fn drop_hold_harness(
        key: &SessionKey,
        survivor: SlotId,
        departing: SlotId,
    ) -> (
        Sessions,
        crate::mesh::MeshLinks,
        Arc<crate::consensus::DecisionMakers>,
        SlotInbox,
    ) {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;

        let sessions: Sessions = Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let makers = Arc::new(consensus::new_decision_makers());
        let _ = consensus::sync_maker(
            &makers,
            key,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        // Both slots have framed history: the survivor pins a session frame and the
        // departing slot gives the leave its apply-frame basis.
        consensus::observe_frame(
            &makers,
            key,
            survivor,
            rally_point_proto::ids::GameFrameCount(40),
        );
        consensus::observe_frame(
            &makers,
            key,
            departing,
            rally_point_proto::ids::GameFrameCount(50),
        );

        let (mut guard, inbox) = register(&sessions, key, survivor).expect("survivor registers");
        guard.disarm();
        (sessions, mesh_links, makers, inbox)
    }

    /// A dropped departure is never decided on its own: it marks an undecided hold
    /// and no leave ever reaches survivors without an explicit request, no matter
    /// how long passes. This is the no-auto-drop policy at the routing level.
    #[tokio::test]
    async fn a_dropped_departure_is_never_decided_on_its_own() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        // Even a zero unlock floor — "past the floor from the first instant" —
        // decides nothing without a request; only an honored `RequestDrop` does.
        let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );

        // The drop is held, and nothing has reached the survivor.
        assert!(holds.is_pending(&k, SlotId(1)), "the drop marked a hold");
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a drop is never decided on its own",
        );

        // Well past any window a timer could ever have used, still no leave — the
        // survivor stays stalled but alive, waiting on a human's decision.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "no auto-drop ever fires",
        );
        assert!(
            holds.is_pending(&k, SlotId(1)),
            "the hold still stands, undecided",
        );
    }

    /// A clean leave (a client's announced intent) decides immediately — no hold —
    /// so an F10 quit unstalls survivors at once.
    #[tokio::test]
    async fn a_clean_departure_decides_immediately() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_LEFT,
        );

        let leave = inbox
            .leave_push_rx
            .try_recv()
            .expect("a clean leave fires without any hold");
        assert_eq!(leave.slot, 1);
        assert_eq!(leave.reason, LEAVE_REASON_LEFT);
        assert!(!holds.is_pending(&k, SlotId(1)), "no hold was marked");
    }

    /// A clean-leave intent arriving while a drop for the same slot is still held
    /// releases the hold and decides immediately with the "left" reason — the
    /// ordering where a client's clean quit races its own link-death observation.
    #[tokio::test]
    async fn a_clean_intent_during_a_drop_hold_releases_it_and_proceeds() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

        // A drop marks the hold.
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );
        assert!(holds.is_pending(&k, SlotId(1)));
        assert!(inbox.leave_push_rx.try_recv().is_err(), "still held");

        // The clean intent arrives: it releases the hold and decides at once with
        // the "left" reason.
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_LEFT,
        );
        assert!(
            !holds.is_pending(&k, SlotId(1)),
            "the clean intent released the hold"
        );
        let leave = inbox
            .leave_push_rx
            .try_recv()
            .expect("the clean leave decided immediately");
        assert_eq!(leave.reason, LEAVE_REASON_LEFT, "the left outcome wins");
    }

    /// A `RequestDrop` before the unlock floor is refused: the target's drop has
    /// not stood long enough, so no leave is decided and the hold still stands.
    #[tokio::test]
    async fn a_request_before_the_unlock_is_refused() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );

        // A request while the hold is fresh (well before the unreachable floor) is
        // refused: no leave, and the hold is untouched.
        honor_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(1), 0);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a pre-unlock request decides no leave",
        );
        assert!(
            holds.is_pending(&k, SlotId(1)),
            "the refused request left the hold standing",
        );
    }

    /// A `RequestDrop` past the unlock floor decides the leave exactly once with the
    /// DROPPED reason, and a duplicate request after the decide is a harmless no-op.
    #[tokio::test]
    async fn a_request_past_the_unlock_decides_once_then_dedups() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );

        honor_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(1), 0);
        let leave = inbox
            .leave_push_rx
            .try_recv()
            .expect("the request past the unlock decides the leave");
        assert_eq!(leave.slot, 1);
        assert_eq!(
            leave.reason, LEAVE_REASON_DROPPED,
            "a manual drop uses the dropped reason",
        );
        assert!(
            !holds.is_pending(&k, SlotId(1)),
            "honoring the request released the hold",
        );

        // A duplicate request after the decide does nothing — the hold is gone and
        // the decision dedups.
        honor_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(1), 0);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a duplicate request after the decide is a no-op",
        );
    }

    /// A `RequestDrop` targeting a slot that already left cleanly (decided, no hold)
    /// is a no-op, and one targeting the requester itself is rejected at the edge.
    #[tokio::test]
    async fn a_request_for_a_decided_or_self_slot_is_a_no_op() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

        // Slot 1 leaves cleanly: decided immediately, no hold left behind.
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_LEFT,
        );
        let _ = inbox
            .leave_push_rx
            .try_recv()
            .expect("the clean leave decided");

        // A drop request for that already-decided slot finds no hold: no-op.
        honor_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(1), 0);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a request for an already-decided slot decides nothing further",
        );

        // A request naming the requester itself is rejected at the edge before any
        // hold check or fan-out — the survivor (slot 0) here is not disconnected.
        handle_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(0), 0);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a self-targeting request is rejected, deciding nothing",
        );
    }

    /// The client-edge validation rejects a request for a slot this relay has no
    /// reason to believe is disconnected (neither held nor departed), without a
    /// decide — the cheap sanity check before spending a mesh broadcast.
    #[tokio::test]
    async fn a_request_for_a_connected_slot_is_rejected_at_the_edge() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);

        // Slot 1 is fully connected (no departure, no hold). A request to drop it is
        // nonsense and is dropped at the edge.
        handle_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(0), 1);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a request for a connected slot decides nothing",
        );
    }

    /// The per-requester rate cap bounds how many requests one requester can spend a
    /// mesh broadcast on, and — crucially — an over-limit burst never multi-decides:
    /// the decision dedups regardless, so a double-click storm removes the slot at
    /// most once.
    #[tokio::test]
    async fn a_burst_of_requests_decides_at_most_once() {
        let k = key();
        let (sessions, mesh_links, makers, mut inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK);
        hold_or_decide_leave(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );

        // A burst of requests from the same survivor: the first decides, and every
        // later one — whether rate-admitted or not — finds the hold already gone.
        for _ in 0..8 {
            handle_drop_request(&holds, &makers, &sessions, &mesh_links, &k, SlotId(0), 1);
        }
        let leave = inbox
            .leave_push_rx
            .try_recv()
            .expect("the burst decided the leave once");
        assert_eq!(leave.slot, 1);
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "the burst decided the leave at most once",
        );
    }

    /// The reconnection race caught live: on a single relay, both clients' links
    /// blip and both re-dial. As the roster empties and refills, presence flaps the
    /// buffer authority to `Peer` and back — and the promotion on the way back must
    /// not decide the leaves of slots whose drop is still held (away) or already
    /// reinstated (returned). No leave is ever decided, and the game continues with
    /// both slots back.
    ///
    /// Removing either half of the fix breaks this: without the promotion's
    /// held-slot skip, the still-away slot's leave fires; without the re-register's
    /// departure reinstatement, the just-returned slot's does.
    #[tokio::test]
    async fn a_single_relay_flap_during_reconnect_decides_no_leave() {
        use crate::consensus::{self, Authority};
        use crate::presence::{self, Candidate};
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let makers = Arc::new(consensus::new_decision_makers());
        let presence = presence::new_presence_registry();
        // A hold never fires on its own; the re-registers release both holds
        // explicitly, exactly as the server's re-register path does.
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

        // A started single-relay session of two framed slots, this relay authority.
        let _ = consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0), SlotId(1)].into_iter().collect(),
        );
        consensus::observe_frame(&makers, &k, SlotId(0), GameFrameCount(50));
        consensus::observe_frame(&makers, &k, SlotId(1), GameFrameCount(50));
        presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);

        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, _i1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        g0.disarm();
        g1.disarm();
        let _ = consensus::note_slot_present(&makers, &k, SlotId(0));
        let _ = consensus::note_slot_present(&makers, &k, SlotId(1));
        report_own_presence(&presence, &makers, &sessions, &mesh_links, &holds, &k);
        assert!(
            makers.lock().get(&k).unwrap().is_authority(),
            "the relay starts as the session authority",
        );

        // Both links die: deregister, announce a dropped departure (marking a hold),
        // then report the changed roster — the end-of-link path, in order.
        deregister(&sessions, &k, SlotId(0));
        announce_departure(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(0),
            LEAVE_REASON_DROPPED,
        );
        report_own_presence(&presence, &makers, &sessions, &mesh_links, &holds, &k);
        deregister(&sessions, &k, SlotId(1));
        announce_departure(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
        );
        report_own_presence(&presence, &makers, &sessions, &mesh_links, &holds, &k);

        assert!(
            holds.is_pending(&k, SlotId(0)) && holds.is_pending(&k, SlotId(1)),
            "both drops marked a hold",
        );
        assert!(
            !makers.lock().get(&k).unwrap().is_authority(),
            "the emptied roster demoted the relay to a peer",
        );

        // Slot 0 re-registers while its drop is still held: register, then release +
        // reinstate as the server does, then report presence — which re-promotes.
        let (mut r0, _ri0) = register(&sessions, &k, SlotId(0)).expect("slot 0 re-registers");
        r0.disarm();
        holds.release(&k, SlotId(0));
        assert!(consensus::reinstate_slot(&makers, &k, SlotId(0)));
        report_own_presence(&presence, &makers, &sessions, &mesh_links, &holds, &k);
        assert!(
            makers.lock().get(&k).unwrap().is_authority(),
            "the first return re-promoted the relay — the flap the fix must survive",
        );

        // Slot 1 re-registers too.
        let (mut r1, _ri1) = register(&sessions, &k, SlotId(1)).expect("slot 1 re-registers");
        r1.disarm();
        holds.release(&k, SlotId(1));
        assert!(consensus::reinstate_slot(&makers, &k, SlotId(1)));
        report_own_presence(&presence, &makers, &sessions, &mesh_links, &holds, &k);

        // The whole flap decided no leave, and the session continues with both slots.
        let (departures, directives) = consensus::leave_reconcile(&makers, &k);
        assert!(
            directives.is_empty(),
            "no leave was ever decided across the flap",
        );
        assert!(
            departures.is_empty(),
            "both departures were reinstated on reconnect",
        );
        let roster = sessions.lock();
        let slots = roster.get(&k).expect("the session still has its roster");
        assert!(
            slots.contains_key(&SlotId(0)) && slots.contains_key(&SlotId(1)),
            "both slots are back",
        );
    }

    /// A connectivity change fans to every currently-registered local slot, each
    /// receiving `(subject, connected)` — the local half of a disconnect signal.
    #[tokio::test]
    async fn connectivity_fans_to_every_local_slot() {
        let k = key();
        let sessions: Sessions = Arc::default();
        let (mut g0, mut inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(3)).expect("slot 3 registers");
        g0.disarm();
        g1.disarm();

        fan_out_connectivity(&sessions, &k, SlotId(3), false);

        let a = inbox0.conn_push_rx.try_recv().expect("slot 0 hears it");
        assert_eq!(a, (SlotId(3), false));
        let b = inbox1.conn_push_rx.try_recv().expect("slot 3 hears it too");
        assert_eq!(b, (SlotId(3), false));
    }

    // -- fully-abandoned session teardown --

    /// A short abandoned-session window for tests, so the timer path can be driven
    /// with a real (tiny) sleep rather than the production 45 seconds.
    const TINY_ABANDON: Duration = Duration::from_millis(80);

    /// A started, single-relay authority session over slots {0, 1} with a frame
    /// basis for each and this relay's presence order set to itself. No departures
    /// are recorded — each test records exactly the ones it needs and drives the
    /// own-roster presence count. Returns the registries the abandoned-session tests
    /// reconcile against.
    fn abandoned_harness() -> (
        crate::presence::PresenceRegistry,
        Sessions,
        crate::mesh::MeshLinks,
        Arc<crate::consensus::DecisionMakers>,
        SessionKey,
    ) {
        use crate::consensus::{self, Authority};
        use crate::presence::Candidate;
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let makers = Arc::new(consensus::new_decision_makers());
        let presence = crate::presence::new_presence_registry();
        let _ = consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0), SlotId(1)].into_iter().collect(),
        );
        consensus::mark_session_started(&makers, &k);
        consensus::observe_frame(&makers, &k, SlotId(0), GameFrameCount(50));
        consensus::observe_frame(&makers, &k, SlotId(1), GameFrameCount(50));
        crate::presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);
        (presence, sessions, mesh_links, makers, k)
    }

    /// Records `slot` as a dropped departure and marks its hold — the maker/hold
    /// state `announce_departure` leaves behind for a disconnected slot.
    fn drop_slot(
        makers: &Arc<crate::consensus::DecisionMakers>,
        holds: &DropHolds,
        k: &SessionKey,
        slot: SlotId,
    ) {
        crate::consensus::record_departure(
            makers,
            k,
            slot,
            Some(rally_point_proto::ids::GameFrameCount(50)),
            None,
            None,
            LEAVE_REASON_DROPPED,
        );
        holds.hold(k.clone(), slot);
    }

    /// Every player dropping leaves the session empty session-wide with undecided
    /// departures; past the abandoned-session window, they are all decided so the
    /// session can proceed to its normal teardown.
    #[tokio::test]
    async fn all_players_dropping_decides_every_departure_after_the_abandon_timeout() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        // The session goes empty session-wide.
        crate::presence::record_own(&presence, &k, 0);

        assert!(crate::consensus::has_undecided_departure(&makers, &k));
        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        assert!(
            holds.abandon_armed(&k),
            "an empty session with undecided departures arms the timer",
        );

        // Past the window, every departure is decided — nothing is left held.
        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert!(
            !crate::consensus::has_undecided_departure(&makers, &k),
            "the abandoned session's departures are all decided",
        );
        assert!(!holds.abandon_armed(&k), "the fired timer removed itself");
    }

    /// A slot re-registering inside the window cancels the timer: nothing is decided,
    /// the returning slot is reinstated, and the other slot's drop stays held
    /// (undecided) — now requestable by that slot once it returns, or never.
    #[tokio::test]
    async fn a_re_register_inside_the_window_cancels_the_timer_and_decides_nothing() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);
        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        assert!(holds.abandon_armed(&k));

        // Slot 0 re-registers: release its hold, reinstate its departure, and report
        // the roster live again — the server's re-register path — then reconcile.
        holds.release(&k, SlotId(0));
        assert!(crate::consensus::reinstate_slot(&makers, &k, SlotId(0)));
        crate::presence::record_own(&presence, &k, 1);
        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        assert!(
            !holds.abandon_armed(&k),
            "the re-register cancelled the abandoned-session timer",
        );

        // Past the original window, nothing was decided.
        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert!(
            !crate::consensus::slot_departed(&makers, &k, SlotId(0)),
            "the reconnected slot is reinstated",
        );
        assert!(
            holds.is_pending(&k, SlotId(1)),
            "the other slot's drop is still held, undecided",
        );
        assert!(
            crate::consensus::has_undecided_departure(&makers, &k),
            "no departure was decided",
        );
    }

    /// The timer never arms while at least one slot is live session-wide, no matter
    /// how many others have dropped.
    #[tokio::test]
    async fn the_timer_never_arms_while_a_slot_is_live() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        drop_slot(&makers, &holds, &k, SlotId(1));
        // Slot 0 is still connected: the session is not empty session-wide.
        crate::presence::record_own(&presence, &k, 1);

        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        assert!(
            !holds.abandon_armed(&k),
            "a session with a live slot never arms the timer",
        );

        // Well past the window, the still-held slot 1 is not decided.
        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert!(
            crate::consensus::has_undecided_departure(&makers, &k),
            "no departure is decided while a slot remains live",
        );
    }

    /// A duplicate arm leaves a single timer, and a duplicate decide after expiry
    /// finds nothing left — the abandoned close is idempotent.
    #[tokio::test]
    async fn duplicate_arm_and_expiry_decide_at_most_once() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);

        // Arm twice: the second is idempotent, leaving a single timer.
        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        reconcile_abandon(&holds, &makers, &sessions, &mesh_links, &presence, &k);
        assert!(holds.abandon_armed(&k));

        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert!(
            !crate::consensus::has_undecided_departure(&makers, &k),
            "the departures decided once",
        );

        // A duplicate decide after the fact is a no-op — all already decided.
        let again = crate::consensus::decide_abandoned_departures(&makers, &k);
        assert!(
            again.is_empty(),
            "a duplicate abandoned-decide finds nothing left to decide",
        );
    }
}
