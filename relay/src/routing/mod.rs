//! Per-session turn routing: take a validated turn from one slot and deliver it
//! to that session's other slots.
//!
//! Each authorized connection becomes a [`Link`](rally_point_transport::Link) owned by one task. That task is
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
//! On a received turn the owning task runs it through [`validate_turn`](crate::validation::validate_turn): the slot
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
use std::sync::atomic::AtomicU8;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{LeaveDirective, Payload, PhaseDirective, RegionLabel};
use tokio::sync::{Notify, mpsc};

use forward::{ForwardRx, ForwardSink};

mod close;
mod departure;
mod drops;
mod fan_out;
mod forward;
mod lifecycle;
mod registry;
mod slot_link;

#[cfg(test)]
mod tests;

pub use lifecycle::{
    announce_slot_present, close_slots, close_slots_for_silence, maybe_start_session,
};
pub use registry::{
    SlotRegistration, holds_any_slots, live_session_slot_epochs, live_slots, register,
    session_count,
};
pub use slot_link::run_slot_link;

pub(crate) use close::maybe_close_emptied_session;
pub(crate) use departure::{
    announce_departure, announce_departure_recorded, hold_or_decide_leave, reconcile_abandon,
};
pub(crate) use drops::{complete_finalized_drop, honor_drop_request};
pub(crate) use fan_out::{
    broadcast_connectivity, deliver_phase_directive_to_slot, deliver_region_labels_to_slot,
    fan_out, fan_out_connectivity, fan_out_leave, fan_out_phase_directives, fan_out_region_labels,
    fan_out_session_start,
};
pub(crate) use lifecycle::{
    abandon_refused_admission, deliver_load_state_probe_to_slot, deliver_session_start,
    reap_provisional,
};

/// How many outbound payloads may queue for one slot before fan-out to it applies
/// backpressure. Turns are small and drained promptly; a slot this far behind is
/// effectively a dead client. A real capacity/backpressure model is future work,
/// so this is deliberately generous rather than tuned. Shared by the client-edge
/// slot link and the mesh-link task (same turn-magnitude, same drain cadence).
pub(crate) const FORWARD_CAPACITY: usize = 1024;

/// The aggregate resident-byte ceiling on one slot's forward queue, a second
/// bound sitting alongside the payload-*count* bound [`FORWARD_CAPACITY`].
///
/// The count bound alone lets a queue hold [`FORWARD_CAPACITY`] payloads of *any*
/// size up to the per-turn oversize cap ([`MAX_OVERSIZE_TURN_COMMANDS_LEN`]), so a
/// client spraying max-size oversize turns could pin
/// `MAX_OVERSIZE_TURN_COMMANDS_LEN * FORWARD_CAPACITY` (~8 MiB) of buffered turns
/// in one slot's queue, replicated across every receiving slot — memory no single
/// rejectable turn accounts for. This bounds the aggregate: whichever bound a slot
/// crosses first — too many payloads or too many resident bytes — isolates it, via
/// the same lagging-peer signal a count-full queue already uses (see [`fan_out`]).
///
/// Set to a quarter of that worst case (~2 MiB). A queue of normal turns never
/// approaches it: a legitimate turn is a few hundred command bytes, so a full
/// count-bounded queue of them is only a few hundred KiB, and the count bound is
/// what governs that honest-but-lagging case. A queue of max-oversize turns, by
/// contrast, trips this at a quarter of the count bound (256 turns), capping the
/// memory an oversize-spraying client can pin at ~2 MiB rather than ~8 MiB. The
/// byte bound thus never fires on honest traffic; it only caps the
/// oversize-amplification residual the count bound leaves open.
const FORWARD_BYTE_BUDGET: usize = MAX_OVERSIZE_TURN_COMMANDS_LEN * FORWARD_CAPACITY / 4;

/// Depth of a slot's leave-push channel. Leaves are rare (at most one per other
/// player, and only on a departure), so a small buffer is ample.
const LEAVE_PUSH_CAPACITY: usize = 16;

/// One relay-authored member-connectivity level change: subject slot, level,
/// and the physical connection generation the level describes.
type ConnectivityChange = (SlotId, bool, Option<u64>);

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

/// How often a slot's serve loop resamples its QUIC link conditions while the
/// session has not yet started. Lobby traffic rides the reliable control stream,
/// not datagrams, so the receive-driven sampler above never fires pre-start —
/// this tick keeps each slot's link stats current through the pre-start window so
/// the authority sizes the initial buffer depth from live conditions, not just
/// the handshake's first RTT. It stops the moment the session starts; the
/// receive-driven sampler covers the game from there.
const PRE_START_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// The hard ceiling on payloads forwarded to a client but not yet known-delivered.
/// Mirrors the client's cap: under reverse-path loss (the client received the
/// turns but the acks riding the datagrams were lost), the beacon side-channel
/// force-advances the window via [`Link::retire_through`](rally_point_transport::Link::retire_through) and keeps it bounded.
/// Under forward-path sustained loss — the client genuinely receives slower than
/// the relay forwards — the beacon can retire only what the client *got*, so the
/// window still grows. When it crosses this cap the relay isolates the slot (the
/// same action it takes for a stuck forward queue) rather than let seqs race ahead
/// until the client's receive window rejects them. Sat below the client's receive
/// window (4096) so it trips before a hard reject.
const UNACKED_WINDOW_CAP: usize = 1024;

/// A sane ceiling on a client-supplied resume-cursor anchor -- the same-relay
/// resume dial's own-slot cursor read off `resume_cursors` before it ever
/// reaches [`Link::anchor_receive_window`](rally_point_transport::Link::anchor_receive_window). The handshake's own
/// `MAX_RESUME_CURSORS` bounds how many entries a client may present
/// (`proto::handshake`, the failover-hardening gate); this bounds what one
/// entry's *value* may be, which that gate does not touch at all.
///
/// An anchor is the oldest seq the client claims it will re-send, feeding
/// straight into the dedup prefix fold (`Dedup::accept`/`anchor`). A hostile
/// or corrupted anchor near `u64::MAX`, paired with a payload at a seq near
/// it, drives that fold's arithmetic to its own ceiling -- the transport
/// layer now saturates rather than panics/wraps there (defense in depth),
/// but the real gate belongs here, at the one place an unvalidated client
/// value is about to become authoritative window state: reject it outright
/// before it can ever reach the fold.
///
/// A real client's anchor is its retention ring's front or its oldest
/// unacked seq — at the turn rate (tens per second) even a session running
/// for a full day is nowhere near this. Sized with enormous headroom (a
/// billion turns is ~1.3 continuous years at 24/sec) so no legitimate resume
/// is ever caught by it.
const MAX_SANE_RESUME_ANCHOR: u64 = 1_000_000_000;

/// How far past this relay's own forwarded prefix a presented resume anchor may
/// sit before it is logged as a probable lie (see the anchor handling in
/// [`run_slot_link`]). Sized to the transport's per-slot receive window: after
/// a re-home, the fresh relay's mesh-forwarded view of the slot can lag the old
/// home's acks by in-transit gaps, which that window bounds — an honest anchor
/// never runs further ahead of any relay's forwarded truth than that.
const RESUME_ANCHOR_LIE_MARGIN: u64 = 4096;

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

/// QUIC application close code for a connection the relay closes on its own
/// initiative because the client's control-stream reader ended while the
/// connection was otherwise alive (a one-sided stream reset, an over-cap
/// frame, a decode failure, or a clean EOF). That stream is the only channel
/// `RequestDrop` and a clean leave-intent arrive on, so losing it is a link
/// failure, not a degradation to limp on through: closing the connection here
/// pushes the client into its ordinary reconnect path, which redials and
/// reopens every stream fresh. Distinct from every other close code so it is
/// diagnosable in logs, though the client's driver treats it exactly like a
/// plain transport error (only [`crate::server::SLOT_DEPARTED_CLOSE`] gets
/// special client-side handling).
const CONTROL_STREAM_LOST_CLOSE: u32 = 0x07;

/// QUIC application close code for a connection refused because its presented
/// resume-cursor anchor exceeds [`MAX_SANE_RESUME_ANCHOR`]. Distinct from
/// [`INVALID_TURN_CLOSE`] (which means a live turn failed validation, not a
/// resume-time value) so it's diagnosable in logs.
const RESUME_ANCHOR_INVALID_CLOSE: u32 = 0x09;

/// QUIC application close code for a connection closed because its session was
/// admitted provisionally -- a client dial with no descriptor yet naming the
/// session -- and no descriptor claimed it within the provisional window (see
/// [`crate::session::provisional`]). Distinct from every other close so a client that
/// hits it can tell "the descriptor was simply slow" from a terminal refusal:
/// a fresh dial re-admits with its own new provisional window, so this only
/// ever delays a legitimate session, never bricks it.
pub const PROVISIONAL_EXPIRED_CLOSE: u32 = 0x0A;

/// QUIC application close code for a connection the relay closes because the
/// client stopped producing turns while its session advanced past it — its game
/// thread hung, or its process was suspended — and the lockstep simulation
/// cannot proceed until the slot is out. Distinct from every other close so the
/// cause is readable in a client's logs: nothing was wrong with the link.
const SILENT_SLOT_CLOSE: u32 = 0x0D;

/// Why a slot's shutdown signal was fired. The signaler stores it on the roster
/// entry before waking the slot's link task, which reads it to pick the log line
/// and QUIC close code that describe the cause. Anything unrecognized reads as
/// [`Unspecified`](Self::Unspecified), so a torn or absent value degrades to the
/// generic close rather than a wrong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SlotCloseReason {
    /// No more specific cause: the slot fell hopelessly behind and is being
    /// isolated, or a terminal directive (a coordinator reap, a final mesh
    /// leave) asked for its link to end.
    Unspecified = 0,
    /// The slot's client stopped producing turns while its session advanced past
    /// it, stalling every other player behind it.
    SilentSlot = 1,
}

impl SlotCloseReason {
    fn from_raw(raw: u8) -> Self {
        match raw {
            raw if raw == Self::SilentSlot as u8 => Self::SilentSlot,
            _ => Self::Unspecified,
        }
    }
}

///
/// A turn too big for a datagram rides the reliable control stream
/// ([`ControlInbound::OversizeTurn`](rally_point_transport::control::ControlInbound::OversizeTurn)) and is then fanned out to the other slots'
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
    forward: ForwardSink,
    /// Synced player-leaves to push down THIS client's reliable control stream.
    /// Fed by [`fan_out_leave`] when a *different* slot leaves; drained by this
    /// slot's link task, which writes each to its control stream. Separate from
    /// `forward` (datagram turns) because a leave must reach a stalled client,
    /// whose datagram turn flow has stopped — only the reliable stream still does.
    leave_push: mpsc::Sender<LeaveDirective>,
    /// Session-start directives to push down THIS client's reliable control
    /// stream. Fed by [`fan_out_session_start`] when the session's authority
    /// decides every expected slot has connected, and by
    /// [`deliver_session_start_to_slot`](lifecycle::deliver_session_start_to_slot) for a slot that registers after the
    /// session already started; drained by this slot's link task, which writes a
    /// `SessionStart` frame to its control stream. Carries the session's computed
    /// initial latency-buffer depth (`None` when the authoring relay sized none),
    /// which the frame stamps for the game to apply before frame 0.
    start_push: mpsc::Sender<Option<u32>>,
    /// Slot-connectivity changes to push down THIS client's reliable control
    /// stream. Fed by [`fan_out_connectivity`] when any slot's link dies or
    /// (re)registers; drained by this slot's link task, which writes a
    /// `SlotConnectivity` frame. Rides the reliable stream like a leave so it
    /// still reaches a client whose datagram turn flow has stalled behind the
    /// very disconnect being reported. Carries `(slot, connected, epoch)`.
    conn_push: mpsc::Sender<ConnectivityChange>,
    /// The session's relay → region-label map to push down THIS client's
    /// reliable control stream. Fed by [`fan_out_region_labels`] when the
    /// session's release gate opens (or a later descriptor changes the map), and
    /// by [`deliver_region_labels_to_slot`] for a slot that connects after the
    /// gate opened; drained by this slot's link task, which writes a
    /// `RegionLabels` frame. Each message is the complete map, so a client
    /// replaces rather than merges and a repeat is idempotent.
    region_push: mpsc::Sender<Vec<RegionLabel>>,
    /// THIS client's send-phase directive to push down its reliable control
    /// stream. Fed by [`fan_out_phase_directives`] when the session's phase
    /// controller issues corrections, and by the connect-time re-push for a
    /// slot that registers after one was issued; drained by this slot's link
    /// task, which writes a `PhaseDirective` frame. Unlike the region-label
    /// push, each slot's value is its own — corrections are per-slot, so
    /// there is no session-wide map to share. Each message carries the whole
    /// commanded delay (absolute, newest wins), so a repeat is idempotent.
    phase_push: mpsc::Sender<PhaseDirective>,
    /// Load-state fence probe ids to push down THIS client's reliable control
    /// stream. Fed by [`deliver_load_state_probe_to_slot`] when this relay is
    /// about to answer a coordinator load-state question and needs to rule out a
    /// report of this slot's still queued in its client; drained by this slot's
    /// link task, which writes a `LoadStateProbe` frame and later resolves the
    /// client's echoed ack against the fence. Purely a question about stream
    /// position — nothing here reaches the game.
    probe_push: mpsc::Sender<u64>,
    /// The lifecycle epoch of the QUIC connection this entry was registered for —
    /// the same value its link task carries and stamps on everything it publishes.
    /// A reconnect registers a *fresh* entry with a new epoch, so `(slot, epoch)`
    /// names one link generation where `slot` alone names only a seat that a
    /// different connection may have taken over in the meantime.
    connection_epoch: u64,
    shutdown: Arc<Notify>,
    /// The [`SlotCloseReason`] behind the pending `shutdown` signal, stored here
    /// before the signal is fired. Shared with the link task, which reads it when
    /// it wakes.
    close_reason: Arc<AtomicU8>,
    /// Fired by the provisional-admission sweep when this slot's session was
    /// admitted with no applied descriptor and its deadline passed with none
    /// arriving (see [`crate::session::provisional`]). Separate from `shutdown` so the
    /// closed connection carries [`PROVISIONAL_EXPIRED_CLOSE`] specifically,
    /// distinguishable from the generic reap/isolation close `shutdown` signals.
    provisional_reap: Arc<Notify>,
}

/// The receiving end of a registered slot, handed to its link task: the queue of
/// turns to deliver to the client, and the signal to shut the link down.
pub struct SlotInbox {
    forward_rx: ForwardRx,
    /// Leaves to push down this client's control stream (see [`SlotEntry::leave_push`]).
    leave_push_rx: mpsc::Receiver<LeaveDirective>,
    /// Session-start directives to push down this client's control stream (see
    /// [`SlotEntry::start_push`]).
    start_push_rx: mpsc::Receiver<Option<u32>>,
    /// Slot-connectivity changes to push down this client's control stream (see
    /// [`SlotEntry::conn_push`]).
    conn_push_rx: mpsc::Receiver<ConnectivityChange>,
    /// Region-label maps to push down this client's control stream (see
    /// [`SlotEntry::region_push`]).
    region_push_rx: mpsc::Receiver<Vec<RegionLabel>>,
    /// Send-phase directives to push down this client's control stream (see
    /// [`SlotEntry::phase_push`]).
    phase_push_rx: mpsc::Receiver<PhaseDirective>,
    /// Load-state fence probes to push down this client's control stream (see
    /// [`SlotEntry::probe_push`]).
    probe_push_rx: mpsc::Receiver<u64>,
    shutdown: Arc<Notify>,
    /// Why the `shutdown` signal was fired (see [`SlotEntry::close_reason`]).
    close_reason: Arc<AtomicU8>,
    /// The provisional-reap signal (see [`SlotEntry::provisional_reap`]).
    provisional_reap: Arc<Notify>,
}

impl SlotInbox {
    /// Non-blockingly pulls the next turn forwarded to this slot, for
    /// cross-module tests of the local-delivery boundary. `None` when nothing
    /// is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_forward(&mut self) -> Option<Payload> {
        self.forward_rx.try_recv()
    }

    /// The slot's shutdown signal, for a cross-module test that drives a close and
    /// asserts the link task would be told to exit.
    #[cfg(test)]
    pub(crate) fn shutdown_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown)
    }

    /// The slot's provisional-reap signal, for a test that drives the
    /// bounded-admission sweep's close path directly without waiting out a
    /// real deadline.
    #[cfg(test)]
    pub(crate) fn provisional_reap_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.provisional_reap)
    }

    /// Non-blockingly pulls the next slot-connectivity change pushed to this slot,
    /// for a cross-module test asserting a connectivity frame fanned to a local
    /// slot. `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_connectivity(&mut self) -> Option<(SlotId, bool)> {
        self.conn_push_rx
            .try_recv()
            .ok()
            .map(|(slot, connected, _)| (slot, connected))
    }

    /// Non-blockingly pulls the next synced leave pushed to this slot, for a
    /// cross-module test asserting whether (or that nothing) was fanned out.
    /// `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_leave(&mut self) -> Option<LeaveDirective> {
        self.leave_push_rx.try_recv().ok()
    }

    /// Non-blockingly pulls the next session-start directive pushed to this slot,
    /// for a cross-module test asserting the start directive reached a connected
    /// client. The outer `Option` reports whether a directive was queued; the
    /// inner carries the stamped initial buffer depth. `None` when nothing is
    /// queued.
    #[cfg(test)]
    pub(crate) fn try_recv_start(&mut self) -> Option<Option<u32>> {
        self.start_push_rx.try_recv().ok()
    }

    /// Non-blockingly pulls the next load-state fence probe pushed to this slot,
    /// for a cross-module test that stands in for the slot's link task and acks
    /// the probe. `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_load_state_probe(&mut self) -> Option<u64> {
        self.probe_push_rx.try_recv().ok()
    }

    /// Non-blockingly pulls the next region-label map pushed to this slot, for a
    /// cross-module test asserting whether (or that nothing) the release gate
    /// sent. `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_region_labels(&mut self) -> Option<Vec<RegionLabel>> {
        self.region_push_rx.try_recv().ok()
    }

    /// Non-blockingly pulls the next send-phase directive pushed to this slot,
    /// for a cross-module test asserting whether (or that nothing) the phase
    /// controller sent. `None` when nothing is queued.
    #[cfg(test)]
    pub(crate) fn try_recv_phase_directive(&mut self) -> Option<PhaseDirective> {
        self.phase_push_rx.try_recv().ok()
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
