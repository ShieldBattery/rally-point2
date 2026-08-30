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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{
    LeaveDirective, Payload, PhaseDirective, RegionLabel, SlotConditions,
};
use rally_point_transport::beacon::{BeaconWriter, spawn_beacon_reader};
use rally_point_transport::control::ControlInbound;
use rally_point_transport::quinn::VarInt;
use rally_point_transport::{Link, LinkError, Received};
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
/// force-advances the window via [`Link::retire_through`] and keeps it bounded.
/// Under forward-path sustained loss — the client genuinely receives slower than
/// the relay forwards — the beacon can retire only what the client *got*, so the
/// window still grows. When it crosses this cap the relay isolates the slot (the
/// same action it takes for a stuck forward queue) rather than let seqs race ahead
/// until the client's receive window rejects them. Sat below the client's receive
/// window (4096) so it trips before a hard reject.
const UNACKED_WINDOW_CAP: usize = 1024;

/// A sane ceiling on a client-supplied resume-cursor anchor -- the same-relay
/// resume dial's own-slot cursor read off `resume_cursors` before it ever
/// reaches [`Link::anchor_receive_window`]. The handshake's own
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
/// [`crate::provisional`]). Distinct from every other close so a client that
/// hits it can tell "the descriptor was simply slow" from a terminal refusal:
/// a fresh dial re-admits with its own new provisional window, so this only
/// ever delays a legitimate session, never bricks it.
pub const PROVISIONAL_EXPIRED_CLOSE: u32 = 0x0A;

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

/// The bytes a queued payload counts against a slot's resident forward budget.
/// Only the command stream varies in size; the envelope's fixed fields are
/// negligible and constant, so — like the per-turn oversize cap — the measure is
/// the command length. The enqueue reservation and the drain release share this
/// one definition so they can never disagree on a payload's cost.
fn forward_bytes(payload: &Payload) -> usize {
    payload.commands.len()
}

/// The outcome of offering a payload to a slot's [`ForwardSink`].
enum ForwardOutcome {
    /// Enqueued; its bytes are counted resident until the link task drains it.
    Delivered,
    /// The slot's queue is at the payload-count bound ([`FORWARD_CAPACITY`]).
    QueueFull,
    /// Accepting the payload would push the slot's resident forward bytes over
    /// [`FORWARD_BYTE_BUDGET`]; the payload was not enqueued.
    OverBudget,
    /// The slot's link task already exited and dropped its receiver.
    Gone,
}

/// One slot's forward channel paired with a live count of the payload bytes
/// resident in it. The channel bounds how many payloads may queue
/// ([`FORWARD_CAPACITY`]); the count bounds their aggregate size
/// ([`FORWARD_BYTE_BUDGET`]), because one oversize turn costs far more than a
/// normal one and a queue full of them pins far more memory than the count bound
/// alone implies.
///
/// Cloneable and shared: [`fan_out`] holds a producer clone per send, the link
/// task's [`SlotInbox`] holds the matching [`ForwardRx`] over the same counter,
/// and every producer's reservation and the consumer's release act on that one
/// shared count. The queue is many-producer (a turn from any local sibling slot
/// and a turn arriving over any mesh link both fan out to it), so the count is an
/// atomic and the reservation is taken before the payload is enqueued.
#[derive(Clone)]
struct ForwardSink {
    tx: ForwardTx,
    resident_bytes: Arc<AtomicUsize>,
}

impl ForwardSink {
    /// Offers `payload` to the slot without blocking, reporting whether it landed
    /// or the slot is too far behind to take it (its count bound or its byte
    /// budget).
    ///
    /// The byte reservation is taken *before* the payload is enqueued, so it is
    /// visible to the draining [`ForwardRx`] before the payload is: the drain's
    /// matching release can then never observe an un-reserved payload and underflow
    /// the count, which keeps the count sound even under the many producers that
    /// concurrently fan out to one slot. A reservation that would breach the budget,
    /// or a send that finds the queue full or the receiver gone, is backed out so
    /// only genuinely resident bytes stay counted.
    fn offer(&self, payload: &Payload) -> ForwardOutcome {
        let bytes = forward_bytes(payload);
        let resident = self.resident_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if resident > FORWARD_BYTE_BUDGET {
            self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
            return ForwardOutcome::OverBudget;
        }
        match self.tx.try_send(payload.clone()) {
            Ok(()) => ForwardOutcome::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
                ForwardOutcome::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
                ForwardOutcome::Gone
            }
        }
    }
}

/// The receiving half of a slot's forward channel, paired with the same resident-
/// byte count [`ForwardSink`] reserves against. Draining a payload releases its
/// bytes from the count, so the count tracks only what is still buffered.
struct ForwardRx {
    rx: mpsc::Receiver<Payload>,
    resident_bytes: Arc<AtomicUsize>,
}

impl ForwardRx {
    /// Waits for the next forwarded payload, releasing its reserved bytes from the
    /// resident count as it hands it over. `None` once every sender is dropped.
    ///
    /// Cancel-safe for `tokio::select!`: the only await is the inner `recv`, itself
    /// cancel-safe, and the release runs synchronously once a payload is in hand, so
    /// a cancelled poll neither takes a payload nor releases bytes.
    async fn recv(&mut self) -> Option<Payload> {
        let payload = self.rx.recv().await?;
        self.resident_bytes
            .fetch_sub(forward_bytes(&payload), Ordering::Relaxed);
        Some(payload)
    }

    /// Non-blockingly pulls the next forwarded payload, releasing its reserved
    /// bytes as [`recv`](Self::recv) does. `None` when the queue is empty.
    #[cfg(test)]
    fn try_recv(&mut self) -> Option<Payload> {
        let payload = self.rx.try_recv().ok()?;
        self.resident_bytes
            .fetch_sub(forward_bytes(&payload), Ordering::Relaxed);
        Some(payload)
    }
}

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
    /// [`deliver_session_start_to_slot`] for a slot that registers after the
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
    shutdown: Arc<Notify>,
    /// Fired by the provisional-admission sweep when this slot's session was
    /// admitted with no applied descriptor and its deadline passed with none
    /// arriving (see [`crate::provisional`]). Separate from `shutdown` so the
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
    shutdown: Arc<Notify>,
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
    // The forward queue's aggregate resident bytes, shared between the fan-out
    // producers (via the `ForwardSink` below) and the draining link task (via the
    // `ForwardRx` in the inbox), so the byte budget can bound it alongside the
    // channel's count bound.
    let forward_resident = Arc::new(AtomicUsize::new(0));
    // Leaves are rare (one per departing peer), so a small channel is ample.
    let (leave_tx, leave_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Session-start directives are rarer still (the fire, plus any re-push on a
    // late register or an authority handoff); the same small channel suits them.
    let (start_tx, start_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Connectivity changes are rare (a slot flips a small number of times over a
    // game); the same small channel suits them.
    let (conn_tx, conn_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Region labels arrive at most a handful of times (the gate opening, a direct
    // push on connecting after it opened, a re-fan when a re-home changes the
    // map); the same small channel suits them.
    let (region_tx, region_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Send-phase directives are similarly sparse (the controller dwells for
    // seconds between corrections, plus a connect-time re-push); the same small
    // channel suits them.
    let (phase_tx, phase_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    let shutdown = Arc::new(Notify::new());
    let provisional_reap = Arc::new(Notify::new());
    {
        let mut roster = sessions.lock();
        let slots = roster.entry(key.clone()).or_default();
        if slots.contains_key(&slot) {
            return None;
        }
        slots.insert(
            slot,
            SlotEntry {
                forward: ForwardSink {
                    tx,
                    resident_bytes: Arc::clone(&forward_resident),
                },
                leave_push: leave_tx,
                start_push: start_tx,
                conn_push: conn_tx,
                region_push: region_tx,
                phase_push: phase_tx,
                shutdown: Arc::clone(&shutdown),
                provisional_reap: Arc::clone(&provisional_reap),
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
        forward_rx: ForwardRx {
            rx,
            resident_bytes: forward_resident,
        },
        leave_push_rx: leave_rx,
        start_push_rx: start_rx,
        conn_push_rx: conn_rx,
        region_push_rx: region_rx,
        phase_push_rx: phase_rx,
        shutdown,
        provisional_reap,
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
/// last slot deregisters (see `deregister`), so the map is empty *exactly* when no
/// slot is held. A session ending therefore shrinks this — the last slot's link task
/// deregisters on exit — which is what lets the drain wait converge.
pub fn holds_any_slots(sessions: &Sessions) -> bool {
    !sessions.lock().is_empty()
}

/// The number of routing groups (distinct `(tenant, session)` keys) this relay
/// currently serves, regardless of how many slots each holds. A load signal to
/// pair with a resource sample (e.g. the task-stats reporter), not a substitute
/// for [`holds_any_slots`]: a relay can hold zero groups yet still have a slot
/// mid-deregistration, which `holds_any_slots` alone answers correctly and this
/// count does not need to.
pub fn session_count(sessions: &Sessions) -> usize {
    sessions.lock().len()
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
/// Sinks and shutdown signals are cloned out under the lock and the lock dropped
/// before any delivery, then each peer is offered the payload without blocking, so
/// one client can never park the source's link task (nor deadlock two saturated
/// peers against each other). A peer that cannot take the payload — its queue is at
/// the payload-count bound ([`FORWARD_CAPACITY`]), or accepting it would push the
/// peer's resident forward bytes over [`FORWARD_BYTE_BUDGET`] — is hopelessly
/// behind: a live link drains its queue every turn, and in lockstep the game is
/// already stalled waiting on a peer this far back, so it is *signaled to
/// disconnect* rather than allowed to back-pressure healthy peers. Crucially it is
/// **not** removed from the roster here: its slot stays occupied until its own link
/// task acts on the signal and exits, so no replacement can register a second
/// sender for it in the meantime. A send to an already-departed peer is ignored. A
/// turn is therefore never silently dropped for a keeping-up peer.
pub(crate) fn fan_out(sessions: &Sessions, key: &SessionKey, source: SlotId, payload: Payload) {
    let targets: Vec<(SlotId, ForwardSink, Arc<Notify>)> = {
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
    for (slot, sink, shutdown) in targets {
        match sink.offer(&payload) {
            ForwardOutcome::Delivered => {}
            ForwardOutcome::QueueFull => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "forward queue full; signaling lagging slot to disconnect",
                );
                shutdown.notify_one();
            }
            ForwardOutcome::OverBudget => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "forward byte budget exceeded; signaling lagging slot to disconnect",
                );
                shutdown.notify_one();
            }
            // The peer's task already ended; it deregisters itself.
            ForwardOutcome::Gone => {}
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
pub(crate) fn fan_out_session_start(
    sessions: &Sessions,
    key: &SessionKey,
    initial_buffer_turns: Option<u32>,
) {
    let targets: Vec<(SlotId, mpsc::Sender<Option<u32>>)> = {
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
        match tx.try_send(initial_buffer_turns) {
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

/// Pushes the session's relay → region-label map down every currently-registered
/// local slot's control stream in the `key` group, with no exclusion — the map
/// describes the whole session, so every member gets the same one. Called only
/// once the session's release gate has opened (the gate's own fan-out, and again
/// when a later descriptor changes the map); before that there is nothing to
/// call it with. Senders are cloned under the lock and the lock dropped before
/// delivery, as in [`fan_out`]. A full queue is logged rather than dropped
/// silently, though a lost map costs only a missing display label — a later map
/// (or the slot's own reconnect push) carries the whole thing again.
pub(crate) fn fan_out_region_labels(sessions: &Sessions, key: &SessionKey, labels: &[RegionLabel]) {
    let targets: Vec<(SlotId, mpsc::Sender<Vec<RegionLabel>>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => slots
                .iter()
                .map(|(slot, entry)| (*slot, entry.region_push.clone()))
                .collect(),
            None => Vec::new(),
        }
    };
    for (slot, tx) in targets {
        match tx.try_send(labels.to_vec()) {
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "region-label queue full; the label map may be delayed for this slot",
            ),
            // The slot's task already ended; it needs no labels.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Pushes the session's relay → region-label map down a single slot's control
/// stream — the push a slot gets when it connects after the session's release
/// gate already opened, so a late or reconnecting client is not left without the
/// labels every other member already has. A slot absent from the roster (already
/// gone) is skipped.
pub(crate) fn deliver_region_labels_to_slot(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    labels: Vec<RegionLabel>,
) {
    let sender = {
        let roster = sessions.lock();
        roster
            .get(key)
            .and_then(|slots| slots.get(&slot))
            .map(|entry| entry.region_push.clone())
    };
    if let Some(tx) = sender {
        let _ = tx.try_send(labels);
    }
}

/// Pushes each corrected slot's new send-phase delay down that slot's own
/// control stream. Per-slot targeted, unlike [`fan_out_region_labels`] — a
/// phase correction names one client's delay, so only that client receives it.
/// Senders are cloned under the lock and the lock dropped before delivery, as
/// in [`fan_out`]. Best-effort: a full queue is logged rather than treated as
/// fatal (an unaligned phase costs micro-stall exposure, never correctness),
/// a slot that already left needs no correction, and the connect-time re-push
/// restates the current delay to a slot that reconnects.
pub(crate) fn fan_out_phase_directives(
    sessions: &Sessions,
    key: &SessionKey,
    corrections: &[(SlotId, u32)],
) {
    let targets: Vec<(SlotId, u32, mpsc::Sender<PhaseDirective>)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => corrections
                .iter()
                .filter_map(|&(slot, delay_us)| {
                    slots
                        .get(&slot)
                        .map(|entry| (slot, delay_us, entry.phase_push.clone()))
                })
                .collect(),
            None => Vec::new(),
        }
    };
    for (slot, delay_us, tx) in targets {
        let directive = PhaseDirective {
            delay_us,
            slew_us_per_s: crate::phase::SLEW_US_PER_S,
        };
        match tx.try_send(directive) {
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "send-phase directive queue full; the correction may be delayed for this slot",
            ),
            // The slot's task already ended; it needs no correction.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Pushes the current commanded send-phase delay down a single slot's control
/// stream — the re-push a slot gets when it connects after the session's phase
/// controller already issued it a correction, so a reconnecting client resumes
/// the delay its peers' alignment was computed against. A slot absent from the
/// roster (already gone) is skipped.
pub(crate) fn deliver_phase_directive_to_slot(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    directive: PhaseDirective,
) {
    let sender = {
        let roster = sessions.lock();
        roster
            .get(key)
            .and_then(|slots| slots.get(&slot))
            .map(|entry| entry.phase_push.clone())
    };
    if let Some(tx) = sender {
        let _ = tx.try_send(directive);
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
    connection_epoch: Option<u64>,
) {
    let targets: Vec<(SlotId, mpsc::Sender<ConnectivityChange>)> = {
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
        match tx.try_send((slot, connected, connection_epoch)) {
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
    connection_epoch: Option<u64>,
) {
    fan_out_connectivity(sessions, key, slot, connected, connection_epoch);
    crate::mesh::fan_out_slot_connectivity(mesh_links, key, slot, connected, connection_epoch);
}

/// Pushes the session-start directive down a single slot's control stream — the
/// re-push a slot gets when it registers after the session already started —
/// stamping the session's stored initial buffer depth (`None` when the authoring
/// relay sized none, e.g. a resumed re-home). A slot absent from the roster
/// (already gone) is skipped.
pub(crate) fn deliver_session_start_to_slot(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    initial_buffer_turns: Option<u32>,
) {
    let sender = {
        let roster = sessions.lock();
        roster
            .get(key)
            .and_then(|slots| slots.get(&slot))
            .map(|entry| entry.start_push.clone())
    };
    if let Some(tx) = sender {
        let _ = tx.try_send(initial_buffer_turns);
    }
}

/// Delivers the session-start directive session-wide: fans it to every local
/// slot ([`fan_out_session_start`]) and broadcasts it across the mesh so every
/// peer relay fans it to its own local slots ([`crate::mesh::fan_out_session_start`]).
/// The one call the authority makes when full slot presence is reached, and the
/// same one an authority-churn re-evaluation makes. Both legs carry the maker's
/// stored initial buffer depth (the authority sized it at the coverage latch),
/// so every local slot and every peer relay learns the same stamped depth.
pub(crate) fn deliver_session_start(
    sessions: &Sessions,
    decision_makers: &consensus::DecisionMakers,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
) {
    let initial_buffer_turns = consensus::session_initial_buffer_turns(decision_makers, key);
    fan_out_session_start(sessions, key, initial_buffer_turns);
    crate::mesh::fan_out_session_start(mesh_links, key, initial_buffer_turns);
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
        deliver_session_start(sessions, decision_makers, mesh_links, key);
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
        deliver_session_start(sessions, decision_makers, mesh_links, key);
    } else if consensus::session_started(decision_makers, key) {
        let initial_buffer_turns = consensus::session_initial_buffer_turns(decision_makers, key);
        deliver_session_start_to_slot(sessions, key, slot, initial_buffer_turns);
    }
}

/// Fires the shutdown signal for each of `slots` in the `key` routing group, so
/// each named slot's link task closes its connection and leaves. This serves both
/// coordinator reaps and a final mesh leave that outran the subject's local link.
/// A slot this relay does not currently hold (never homed it, or already departed)
/// is simply absent from the roster and skipped. The closed link then flows through
/// the ordinary link-death path (a synced leave, a departure notice), making either
/// terminal path self-resolving.
///
/// Signals rather than yanking the roster entry, exactly like `fan_out`'s lagging-
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
                "closing slot link after terminal directive",
            );
            entry.shutdown.notify_one();
        }
    }
}

/// Light teardown for an admission the relay REFUSED after its registration
/// attempt had already created per-session scaffolding — the ingress gate on
/// first touch, and possibly an empty journal reservation. With no other
/// live slot, no maker, and nothing journaled or sealed, that scaffolding is
/// discarded; otherwise everything is left exactly as found. Without this,
/// every distinct valid session refused past the journal's session ceiling
/// would leave a live gate (and its map entry) behind forever — an
/// unbounded-memory vector one registry over from the one the ceiling
/// closes. Deliberately NOT the full emptied-session close: nothing was
/// served, so there is nothing to report, announce, or flush.
///
/// The ownership checks and the removal are ONE exclusive gate section
/// ([`SessionGates::discard_if`](crate::session_gate::SessionGates)), which
/// is what makes them trustworthy. A concurrent dial commits its roster seat
/// and its journal reservation inside ingress sections, so under the write
/// side either it already registered (the roster check sees the seat and
/// refuses the discard) or it is still waiting on the gate and will retry
/// onto a fresh one after the rotation — its admission then builds fresh
/// state that this cleanup, already finished, can never erase. A retirement
/// orders against the same write side: one that landed first leaves a
/// tombstone the discard refuses to touch, and one that arrives during the
/// rotation re-stamps the registry's current entry rather than the removed
/// orphan. Checking these signals over separate locks — the shape this
/// replaced — let a refusal erase a concurrent admission's reservation after
/// its `HANDSHAKE_OK`, or delete a tombstone installed between the check and
/// the removal.
///
/// The journal check remains [`ProvisionalTurnPen::discard_if_empty`]
/// (entries, an active drain, or a seal refuse it), so an emptied journal
/// reservation is dropped in the same breath as the gate.
///
/// [`ProvisionalTurnPen::discard_if_empty`]: crate::provisional_turns::ProvisionalTurnPen::discard_if_empty
pub(crate) fn abandon_refused_admission(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    let _ = mesh.gates.discard_if(key, || {
        if sessions.lock().contains_key(key) {
            return false;
        }
        if consensus::maker_exists(&mesh.decision_makers, key) {
            return false;
        }
        if !mesh.provisional_turns.discard_if_empty(key) {
            return false;
        }
        mesh.provisional.clear(key);
        true
    });
}

/// Fires the provisional-reap signal for each of `key`'s currently-registered
/// slots, closing every connection with [`PROVISIONAL_EXPIRED_CLOSE`] -- the
/// bounded-admission sweep's teardown when no descriptor named a provisionally
/// admitted session before its deadline (see [`crate::provisional`]). A
/// session absent from the roster (already gone) is simply a no-op.
///
/// Signals rather than yanking the roster entry, exactly like [`close_slots`]:
/// each slot's own link task closes its connection and deregisters itself, so
/// no replacement can register a second sender in the interim.
pub(crate) fn reap_provisional(sessions: &Sessions, key: &SessionKey) {
    let roster = sessions.lock();
    let Some(group) = roster.get(key) else {
        return;
    };
    for entry in group.values() {
        entry.provisional_reap.notify_one();
    }
}

/// Records one completed attempt to write a leave to a local client's control
/// stream. A successful write only proves local QUIC acceptance; client receipt
/// and native application are separate observations.
fn record_leave_control_write(
    decision_makers: &consensus::DecisionMakers,
    key: &SessionKey,
    recipient: SlotId,
    connection_epoch: u64,
    leave: &LeaveDirective,
    replayed: bool,
    succeeded: bool,
) {
    decision_makers.flight_recorder().record(
        key,
        crate::flight_recorder::FlightEvent::LeaveControlWrite {
            recipient: recipient.0,
            connection_epoch,
            slot: leave.slot as u8,
            reason: leave.reason,
            apply_frame: leave.apply_at_frame,
            leave_seq: leave.leave_seq,
            finalized: leave.finalized,
            final_turn_count: leave.final_turn_count,
            replayed,
            succeeded,
        },
    );
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
#[allow(clippy::too_many_arguments)]
pub async fn run_slot_link(
    mut link: Link,
    key: SessionKey,
    slot: SlotId,
    connection_epoch: u64,
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
        mut region_push_rx,
        mut phase_push_rx,
        shutdown,
        provisional_reap,
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
        conditions,
        decision_makers,
        lobby,
        chat,
        skins,
        drop_holds,
        turn_ring,
        ..
    } = mesh;

    // The activation prologue runs as ONE ingress critical section: the
    // admission gate (`server.rs`) necessarily released across the
    // handshake-ack await before this task started, so a retirement can land
    // in between — and these mutations would then recreate the close-report,
    // presence, and condition state the sweep just removed, for a session the
    // coordinator already ended. Under the gate, either the sweep waits for
    // this block or this block observes the retirement and the link is torn
    // down instead of serving.
    let activated = mesh_for_teardown.gates.with_ingress(&key, || {
        // A slot link is serving this session (again): any session-closed report an
        // earlier emptying latched no longer describes this relay, so the next
        // emptying must report anew. See `consensus::claim_close_report`.
        consensus::reopen_close_report(&decision_makers, &key);

        // This client joining may change who decides the session's buffer — most
        // notably a first client arriving on the relay that heads the authority
        // order, which turns the descriptor-time verdict into a live one. The
        // roster already includes this slot (registration preceded this task), so
        // report it and re-derive. The peers learn the new count from the mesh
        // drivers' presence reconcile, off the same roster.
        report_own_presence(&sessions, &mesh_for_teardown, &key);

        // Feed an immediate conditions sample from the completed QUIC handshake into
        // the session's decision-maker BEFORE announcing presence, so when this slot
        // completes the expected set and the authority sizes the initial buffer depth,
        // this slot's measured path RTT is already accounted for. A pre-start `ingest`
        // can emit no directive — `decide` bails until a framed turn gives it a
        // consensus coordinate — so this only accumulates state. Publishing it also
        // seeds the mesh sidecar for this slot.
        let handshake_sample = sample_slot_conditions(&link, slot, connection_epoch).conditions;
        crate::mesh::activate_conditions(&conditions, &key, slot, handshake_sample);
        let _ = consensus::ingest_local_condition(&decision_makers, &key, &handshake_sample);

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
        broadcast_connectivity(
            &sessions,
            &mesh_links,
            &key,
            slot,
            true,
            Some(connection_epoch),
        );
    });
    if activated.is_none() {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = slot.0,
            "session retired before slot-link activation; closing the link",
        );
        link.connection().close(
            VarInt::from_u32(crate::server::SESSION_RETIRED_CLOSE),
            b"session retired",
        );
        end_slot_link(
            &sessions,
            &mesh_for_teardown,
            &key,
            slot,
            connection_epoch,
            false,
        );
        return;
    }

    // The ack-beacon side-channel, mirroring the client driver. The relay opens
    // its outbound uni-stream (open_uni completes locally); the client's stream
    // is accepted lazily inside the reader task so a one-way-traffic client that
    // never sends a beacon doesn't block on an accept that never completes. The
    // reader assembles complete frames off a cancel-safe path and folds each
    // `(slot, cursor)` into a per-slot latest-value cell — a cursor is
    // cumulative within its slot, so the newest is all this loop needs, and the
    // final cursor before traffic stops survives however slowly this loop
    // drains (see `BeaconCursors`).
    let mut beacon_send = match link.connection().open_uni().await {
        Ok(send) => send,
        Err(error) => {
            log_link_closed(&key, slot, &LinkError::from(error));
            // The slot registered but never got a stream up, so it forwarded
            // nothing — still run the full departure/close protocol below so
            // peers and the coordinator hear about it now rather than only
            // after the coordinator's holdout reap.
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                false,
            );
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
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                false,
            );
            return;
        }
    };
    let mut control_rx =
        rally_point_transport::control::spawn_control_reader(link.connection().clone());
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
    // Mirrors `leave_push_alive` for the region-label push channel, disarmed
    // defensively the same way.
    let mut region_push_alive = true;
    // Mirrors `leave_push_alive` for the send-phase push channel, disarmed
    // defensively the same way.
    let mut phase_push_alive = true;
    // A session whose release gate opened before this slot's link came up has
    // labels every other member already holds, and no later gate opening will
    // fire for it — so push the map straight down this slot. The gate's own
    // fan-out may also have reached this slot (the roster seats it before this
    // task runs), which costs a duplicate frame at worst: each carries the
    // complete map, so a client applies it idempotently. A session whose gate is
    // still shut pushes nothing, and this slot picks the labels up from the
    // fan-out when the gate opens.
    if let Some(labels) = consensus::released_region_labels(&decision_makers, &key) {
        deliver_region_labels_to_slot(&sessions, &key, slot, labels);
    }
    // A slot connecting after the phase controller already issued it a delay
    // picks that delay back up, so a reconnecting client resumes the send
    // phase its peers' alignment was computed against instead of snapping back
    // to its natural one. A slot never corrected gets nothing.
    if let Some(delay_us) = consensus::commanded_phase_delay(&decision_makers, &key, slot) {
        deliver_phase_directive_to_slot(
            &sessions,
            &key,
            slot,
            PhaseDirective {
                delay_us,
                slew_us_per_s: crate::phase::SLEW_US_PER_S,
            },
        );
    }
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
    // Register this member for cosmetic-skin fan-out too. Like the lobby log,
    // the per-session latest-blob-per-slot map is snapshotted into `skin_rx`
    // under the skin lock right here, so a member that dialed in after other
    // members already broadcast their blobs replays each one (before any live
    // blob); unlike the lobby log the replay is unordered (a map, not a
    // sequence). The exactly-once handoff is the skin module's (store + fan-out
    // and register + snapshot share one lock); this task drains `skin_rx` in the
    // branch below and writes each blob down its own control stream.
    let mut skin_rx = crate::skin::register_member(&skins, &key, slot);
    // Mirrors `chat_alive`: this member's skin sender lives in the skin registry
    // until its own teardown drops it, so a `None` is unreachable during the
    // loop; the flag disarms the branch defensively.
    let mut skin_alive = true;
    // Pushes only advancing cursors and reuses one batch buffer for the life of
    // this link.
    let mut beacon_writer = BeaconWriter::new();
    // This destination's end-to-end cursor share to the session's mesh peers:
    // push-on-advance, at most one complete-map frame per
    // `DELIVERY_SYNC_MIN_INTERVAL`, so the authority (wherever it is) can fold
    // final delivery without the share ever getting chatty.
    let mut delivery_share =
        crate::delivery::CursorShare::new(crate::delivery::DELIVERY_SYNC_MIN_INTERVAL);
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
    // Whether to keep resampling this slot's link conditions on the pre-start tick.
    // Armed only while the session has not started (a late slot joining an already
    // started session leaves it to the receive-driven sampler); disarmed the tick
    // it observes the session started, so post-start sampling is never doubled.
    let mut pre_start_sampling = !consensus::session_started(&decision_makers, &key);
    let mut pre_start_deadline = Instant::now() + PRE_START_SAMPLE_INTERVAL;

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
    //
    // The anchor is transport state only: it bases this link's dedup window, and
    // nothing else. It never feeds the slot's final turn count — that comes from
    // the session-level forward gate (`crate::mesh::forwarded_count`), which
    // only ever advances over turns genuinely forwarded — so a fabricated
    // anchor cannot manufacture game state, only break this one connection's
    // own resume.
    if let Some(anchor) = resume_cursors.remove(&slot) {
        // Reject rather than clamp-and-continue: a client's own-slot anchor
        // this far beyond anything a real session could ever produce is a
        // corrupted or hostile value on a connection that hasn't sent a
        // single turn yet, not a resume worth attempting. Task-isolated to
        // this one connection -- see `MAX_SANE_RESUME_ANCHOR`. This slot may
        // already have been announced present/connected above, so it gets
        // the same full departure/close protocol every other early exit here
        // runs, not a bare return.
        if anchor > MAX_SANE_RESUME_ANCHOR {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                anchor,
                cap = MAX_SANE_RESUME_ANCHOR,
                "resume-cursor anchor exceeds the sane ceiling; refusing the reconnect",
            );
            link.connection().close(
                VarInt::from_u32(RESUME_ANCHOR_INVALID_CLOSE),
                b"resume anchor out of range",
            );
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                false,
            );
            return;
        }
        // A lie tripwire, not a gate: an honest anchor never names a seq past
        // what some relay acked to the client, so on this slot's long-term home
        // it sits at or below the forward gate's count. It can legitimately
        // exceed it after a re-home onto a relay whose mesh-forwarded view of
        // the slot lags its old home's acks — by transit gaps at most, roughly
        // a receive window — so anything far past that margin is a client
        // asserting acks for turns that were never forwarded. Warn-only: the
        // count is relay-authored regardless (see the comment above), so a
        // lying anchor gains nothing and hard-rejecting would risk refusing
        // that legitimate lagging-rehome resume.
        if let Some(count) = crate::mesh::forwarded_count(&mesh_for_teardown.seen, &key, slot)
            && anchor > count.saturating_add(RESUME_ANCHOR_LIE_MARGIN)
        {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                anchor,
                forwarded_count = count,
                margin = RESUME_ANCHOR_LIE_MARGIN,
                "resume-cursor anchor claims acks far past this relay's forwarded prefix",
            );
        }
        link.anchor_receive_window(slot, anchor);
        // Reconcile the fresh receive window with the receipts this relay
        // already holds for the slot. The client's anchor is its oldest
        // *unacked* seq, and selective packet acks make its unacked window
        // sparse: a seq above the anchor that was acknowledged to the client
        // will never be re-sent, so without a seed the fresh window's
        // contiguous prefix (and the ack-beacon cursor it drives) would wedge
        // at that hole until the live stream ran a full receive window past
        // the stuck base and the link was rejected as out-of-window.
        //
        // Two session-lifetime stores together cover every seq this relay has
        // ever acknowledged for the slot, across connection churn and every
        // phase of the session's life: the provisional journal (turns
        // accepted before a descriptor named the session; its overflow seals
        // the slot against readmission, so no resumable slot has an evicted
        // entry) and the forward gate's seen registry (every turn that passed
        // the gate, pre-start included — unlike the bounded replay ring, it
        // never evicts). The journal is read BEFORE the gate: a descriptor
        // drain only ever moves entries journal → gate, so a turn in transit
        // is seen by at least one of the two reads.
        for seq in mesh_for_teardown
            .provisional_turns
            .held_turn_seqs(&key, slot)
        {
            link.seed_delivered(slot, seq);
        }
        let receipts = crate::mesh::slot_receipts(&mesh_for_teardown.seen, &key, slot);
        if let Some(through) = receipts.forwarded_through {
            link.seed_delivered_through(slot, through);
        }
        for seq in receipts.ahead {
            link.seed_delivered(slot, seq);
        }
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
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                leave_announced,
            );
            return;
        }
    }

    // Replay the session's leave state the same way: a departure or a decided
    // leave is pushed to each survivor exactly once, at the moment it happens
    // (`broadcast_connectivity`, `fan_out_leave`), so a client whose link was
    // down at that moment never hears it — the turn replay above brings it to
    // the departed slot's last frame, and without the leave directive it then
    // stalls at the next frame forever. The client-side twin of the mesh's
    // `reconcile_leaves_on_join`: every recorded departure replays as a
    // connectivity-down (a departure record at this moment means the slot is
    // genuinely still gone — a re-registered slot's record was reinstated
    // away), and every decided leave replays as the directive itself. Both are
    // idempotent on the client (the leave tracker dedups by slot; connectivity
    // is a level signal), so copies the client already held are harmless, and
    // both skip this slot itself (a slot is never pushed its own departure —
    // and a reconnect for a slot whose own leave was decided was refused at
    // admission). Empty on a fresh dial: no session history, nothing missed.
    let (departures, directives) = consensus::leave_reconcile(&decision_makers, &key);
    for (departed, _, _, departed_epoch) in departures {
        if departed == slot {
            continue;
        }
        if let Err(error) = rally_point_transport::control::send_control_connectivity(
            &mut control_send,
            departed.0,
            false,
            departed_epoch,
        )
        .await
        {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                %error,
                "replaying a departure to a reconnecting client failed; closing slot link",
            );
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                leave_announced,
            );
            return;
        }
    }
    for leave in directives {
        if leave.slot == u32::from(slot.0) {
            continue;
        }
        let result =
            rally_point_transport::control::send_control_leave(&mut control_send, leave).await;
        record_leave_control_write(
            &decision_makers,
            &key,
            slot,
            connection_epoch,
            &leave,
            true,
            result.is_ok(),
        );
        if let Err(error) = result {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                %error,
                "replaying a decided leave to a reconnecting client failed; closing slot link",
            );
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                leave_announced,
            );
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
                // Stamped before validation, forwarding, and the registry
                // locks below: the phase controller measures *wire arrival*,
                // and everything this arm does after this line is relay
                // processing time that must not leak into the measurement.
                let received_at = std::time::Instant::now();
                // Only a payload-bearing packet needs an ack in return; owing one for
                // a client's ack-only packet would bounce ack-only packets back and
                // forth on an idle link.
                if received.carried_payloads {
                    acks_owed = true;
                }
                // Sample this client's QUIC path only when the packet advances
                // delivery. Ack-only packets and all-redundant recovery copies
                // cannot advance the game and would merely rotate the same
                // cumulative counters through the decision-maker again. During
                // active play a fresh turn arrives every game step, keeping the
                // published conditions current; Quinn stats do not change while
                // idle, so a quiet slot's last sample stays valid. Sampling once
                // per packet (not per payload) is enough — all fresh payloads in
                // one packet share the same connection path.
                if should_sample_active_conditions(&received) {
                    let sampled = sample_slot_conditions(&link, slot, connection_epoch);
                    flight_counters.note_link_gauges(
                        sampled.upstream_lost_packets,
                        sampled.cwnd,
                        sampled.congestion_events,
                    );
                    let sample = sampled.conditions;
                    let sample_is_current =
                        crate::mesh::publish_conditions(&conditions, &key, slot, sample);
                    // The decision it may fire schedules against frames observed
                    // off validated turns below — never off raw packet claims —
                    // and is broadcast later at fan-out.
                    if sample_is_current {
                        let _ = consensus::ingest_local_condition(
                            &decision_makers,
                            &key,
                            &sample,
                        );
                    }
                }
                // A packet that first-delivers exactly one turn times the
                // sender's phase; a catch-up burst (several previously-unseen
                // turns at once) times the recovery instead, so it is skipped.
                // Captured before the loop below moves the payloads, fed after
                // it so only a validated turn's arrival is ever measured.
                let solo_fresh_seq = match received.fresh.as_slice() {
                    [only] => Some(only.seq),
                    _ => None,
                };
                for payload in received.fresh {
                    match validate_turn(slot, payload) {
                        Ok(turn) => {
                            let payload = turn.payload;
                            flight_counters.note_validated(payload.seq);
                            // NOTE: neither the frame observation nor the
                            // desync comparator is fed here. Both client and
                            // mesh ingress funnel through the session-level
                            // dedup before consensus, so each distinct
                            // `(slot, seq)` turn is counted once. Only
                            // *validated* turns reach that
                            // feed point (a rejected packet breaks the link
                            // above without a trace in decision state), and
                            // the coordinate is the minimum across slots, so
                            // even a validated turn's inflated claim can only
                            // mislead its own slot.
                            crate::mesh::forward_client_turn(
                                &sessions,
                                &mesh_for_teardown,
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
                // Feed the send-phase controller from this relay's own client
                // edge — the only vantage that sees this slot's wire arrivals
                // first-hand (a mesh-forwarded copy would time another relay's
                // hop). The controller evaluates on its own sparse schedule,
                // so this almost always returns nothing; when it does issue
                // corrections, each named slot gets its own directive.
                if let Some(seq) = solo_fresh_seq {
                    let corrections = consensus::ingest_arrival_phase(
                        &decision_makers,
                        &key,
                        slot,
                        seq,
                        received_at,
                    );
                    if !corrections.is_empty() {
                        fan_out_phase_directives(&sessions, &key, &corrections);
                    }
                }
                // Push the advanced delivered-through cursor to the client so it can
                // force-advance its unacked window. The relay receives only this
                // client's own slot, so one per-slot cursor suffices. Push only on
                // advance.
                if let Some(cursor) = link.delivered_through(slot) {
                    beacon_writer
                        .flush(&mut beacon_send, std::iter::once((slot, cursor)))
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
                        let result = rally_point_transport::control::send_control_leave(
                            &mut control_send,
                            leave,
                        )
                        .await;
                        record_leave_control_write(
                            &decision_makers,
                            &key,
                            slot,
                            connection_epoch,
                            &leave,
                            false,
                            result.is_ok(),
                        );
                        if let Err(error) = result {
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
                    Some(initial_buffer_turns) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_session_start(
                                &mut control_send,
                                initial_buffer_turns,
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
                    Some((subject, connected, subject_epoch)) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_connectivity(
                                &mut control_send,
                                subject.0,
                                connected,
                                subject_epoch,
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
            // The session's relay → region-label map, to push down this client's
            // reliable control stream. Only ever queued once the session's release
            // gate has opened, so nothing this branch writes can reach a client
            // before enough gameplay elapsed that departing scores as a result.
            // Each message is the complete map, so a repeat (the gate's fan-out
            // racing this slot's own connect push, a re-fan after a re-home) costs
            // only a frame. A write failure ends the link like every other
            // control-stream write here.
            pushed = region_push_rx.recv(), if region_push_alive => {
                match pushed {
                    Some(labels) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_region_labels(
                                &mut control_send,
                                labels,
                            )
                            .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "region-label control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => region_push_alive = false,
                }
            }
            // THIS client's send-phase directive, to push down its reliable
            // control stream. Sparse (the controller dwells for seconds
            // between corrections) and absolute — each frame carries the whole
            // commanded delay, so a repeat (a correction racing this slot's
            // own connect re-push) is idempotent. A write failure ends the
            // link like every other control-stream write here.
            pushed = phase_push_rx.recv(), if phase_push_alive => {
                match pushed {
                    Some(directive) => {
                        if let Err(error) =
                            rally_point_transport::control::send_control_phase_directive(
                                &mut control_send,
                                directive,
                            )
                            .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "send-phase control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => phase_push_alive = false,
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
            // A cosmetic-skin blob another member authored (or a mesh-forwarded
            // one), or the replay of an earlier stored blob, to push down this
            // client's reliable control stream. Like the lobby branch this drains
            // the per-session replay the skin `register_member` snapshotted here,
            // so a stored blob and a live one write down the stream on one path;
            // like the chat branch the `slot` is the relay-stamped author and a
            // write failure ends the link exactly as every other control-stream
            // write in this loop does — the underlying stream is dead regardless
            // of which frame kind hit it (a different call than the client-edge
            // driver makes for its own *outbound* skin sends, which are
            // best-effort: there the link may still be healthy; here the failure
            // *is* evidence it is not).
            pushed = skin_rx.recv(), if skin_alive => {
                match pushed {
                    Some(skin) => {
                        if let Err(error) = rally_point_transport::control::send_control_skin(
                            &mut control_send,
                            skin,
                        )
                        .await
                        {
                            tracing::info!(
                                tenant = key.tenant.as_ref(),
                                session = key.session.0,
                                slot = slot.0,
                                %error,
                                "skin control-stream push failed; closing slot link",
                            );
                            break 'serve;
                        }
                    }
                    None => skin_alive = false,
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
                        match send_packet(&mut link, Some(payload), &flight_counters) {
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
            received = control_rx.recv() => {
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
                    Some(ControlInbound::SessionStart(_)) => {
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
                    // Region labels are relay → client only, and the relay's own
                    // copy comes from its coordinator descriptor — a client-sent
                    // map is never a source of truth for anything. Ignore a stray
                    // one, mirroring the cases above.
                    Some(ControlInbound::RegionLabels(_)) => {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "ignoring unexpected client-sent region-label control frame",
                        );
                    }
                    // Send-phase directives are relay → client only — the relay
                    // computes them from its own arrival measurements, and a
                    // client-sent one is never an input to anything. Ignore a
                    // stray one, mirroring the region-label case above.
                    Some(ControlInbound::PhaseDirective(_)) => {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "ignoring unexpected client-sent send-phase control frame",
                        );
                    }
                    // The client acknowledging that it adopted its send-phase
                    // directive. The slot is the authenticated connection's —
                    // never a wire claim — and the acknowledgement can release
                    // only that slot's own command fence, so this is a
                    // client-asserted input with strictly self-scoped effect.
                    Some(ControlInbound::PhaseApplied(delay_us)) => {
                        consensus::note_phase_applied(&decision_makers, &key, slot, delay_us);
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
                        // Retire the active generation before its terminal
                        // SlotDeparted is enqueued. A concurrently joining mesh
                        // link snapshots this same registry, so it now observes
                        // either true(E) before the departure or no active E at
                        // all â€” never departure followed by a stale replay-true.
                        let _ = crate::mesh::unpublish_conditions(
                            &conditions,
                            &key,
                            slot,
                            Some(connection_epoch),
                        );
                        // Gated like the teardown announce: a clean leave
                        // landing after the session's retirement must not
                        // write into swept state.
                        let announced = mesh_for_teardown.gates.with_ingress(&key, || {
                            announce_departure(
                                &drop_holds,
                                &decision_makers,
                                &sessions,
                                &mesh_links,
                                &mesh_for_teardown.provisional_turns,
                                &key,
                                slot,
                                LEAVE_REASON_LEFT,
                                // The one intent-origin exact count: this
                                // handler is the slot's single ingress, it
                                // stops forwarding in the same step (`break
                                // 'serve` below), and a decided leave refuses
                                // readmission, so nothing past this count can
                                // ever reach a client. Every other departure
                                // origin passes `None` — see `end_slot_link`
                                // (a finalized drop's count comes through
                                // `finalize_drop`'s own seal instead).
                                crate::mesh::forwarded_count(&mesh_for_teardown.seen, &key, slot),
                                Some(connection_epoch),
                            )
                        });
                        // Marked announced only when the announce (or its
                        // journal deposit) actually happened: a refused gate
                        // or a stood-down announce leaves the teardown's
                        // fallback drop-announcement armed as the recovery
                        // path rather than silently suppressed.
                        leave_announced = announced == Some(true);
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
                        match validate_turn(slot, payload) {
                            Ok(turn) => {
                                let payload = turn.payload;
                                flight_counters.note_validated(payload.seq);
                                // NOTE: no frame-observation or
                                // desync-comparator call here either —
                                // `forward_client_turn` funnels into the one
                                // post-dedup consensus feed point,
                                // exactly as on the datagram path (see its note
                                // above).
                                crate::mesh::forward_client_turn(
                                    &sessions,
                                    &mesh_for_teardown,
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
                    // The client's lobby command. Admit it against the relay's
                    // per-slot rate cap first — a failure drops the command
                    // without closing the link, mirroring chat. An admitted
                    // command is bound to the authenticated slot — never the
                    // client-asserted `slot` on the wire, exactly as
                    // `validate_turn` rebinds a turn's slot — then delivered to
                    // local members (appended to the per-session replay log and
                    // fanned to every other local member; the author is not
                    // echoed, its own game echoes locally) and, only if that
                    // delivery was itself admitted (the session's log cap can
                    // still refuse it), forwarded once across each mesh link
                    // serving the session so peer relays fan it to their
                    // locals. The bytes are opaque; the relay frames nothing of
                    // its own around them.
                    Some(ControlInbound::Lobby(mut command)) => {
                        if crate::lobby::admit(&lobby, &key, slot) {
                            command.slot = u32::from(slot.0);
                            if crate::lobby::deliver(&lobby, &key, command.clone()) {
                                crate::mesh::fan_out_lobby_command(&mesh_links, &key, command);
                            }
                        }
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
                    // The client's cosmetic-skin blob. Admit it against the
                    // relay's size and rate caps first — either failure drops the
                    // blob without closing the link, since a lost skin is cosmetic,
                    // not correctness-critical the way a turn or lobby command is.
                    // An admitted blob is bound to the authenticated slot — never
                    // the client-asserted `slot` on the wire, exactly as a lobby
                    // command or chat message is — then delivered to local members
                    // (stored in the latest-per-slot map and fanned to every other
                    // local member; the author is not echoed) and, only if that
                    // delivery was itself admitted (the session's distinct-slot cap
                    // can still refuse a brand-new slot), forwarded once across each
                    // mesh link serving the session so peer relays store and fan it
                    // to their locals. The bytes are opaque; the relay frames
                    // nothing of its own around them.
                    Some(ControlInbound::Skin(mut skin)) => {
                        if crate::skin::admit(&skins, &key, slot, skin.payload.len()) {
                            skin.slot = u32::from(slot.0);
                            if crate::skin::deliver(&skins, &key, skin.clone()) {
                                crate::mesh::fan_out_skin(&mesh_links, &key, skin);
                            }
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
                            &sessions,
                            &mesh_for_teardown,
                            &key,
                            slot,
                            wire_target,
                        );
                    }
                    // The reader task ended: a one-sided stream reset, an
                    // over-cap frame, a decode failure, or a clean EOF. This
                    // stream is the only channel `RequestDrop` and a clean
                    // leave-intent ever arrive on -- unlike the beacon
                    // side-channel below (a pure one-way cursor feed whose loss
                    // a real link failure surfaces separately via
                    // `link.recv()`), nothing else in this loop will ever
                    // notice this is gone. Disarming and limping on would
                    // silently strand an F10 quit as a drop+hold and lose
                    // `RequestDrop` outright, so instead close the connection
                    // and let the client's ordinary reconnect path rebuild
                    // every stream fresh -- harmless if the connection was
                    // already dying for the same reason this reader ended.
                    None => {
                        tracing::info!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "control stream reader ended; closing so the client reconnects with fresh streams",
                        );
                        link.connection().close(
                            VarInt::from_u32(CONTROL_STREAM_LOST_CLOSE),
                            b"control stream lost",
                        );
                        break 'serve;
                    }
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
                        // The same cursor is the end-to-end delivery truth:
                        // origin `beacon_slot`'s turns reached THIS client
                        // through `cursor`. Fold it locally and — throttled —
                        // re-share it to the session's mesh peers so a
                        // peer-homed authority can fold it too.
                        consensus::observe_delivery(
                            &decision_makers,
                            &key,
                            slot,
                            beacon_slot,
                            cursor,
                            crate::delivery::DeliveryHome::Local,
                        );
                        if let Some(snapshot) = delivery_share.advance(
                            beacon_slot,
                            cursor,
                            std::time::Instant::now(),
                        ) {
                            crate::mesh::fan_out_delivery_cursors(
                                &mesh_links,
                                &key,
                                slot,
                                &snapshot,
                            );
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
                    if let Err(error) = send_packet(&mut link, None, &flight_counters) {
                        log_link_closed(&key, slot, &error);
                        break 'serve;
                    }
                    acks_owed = false;
                }
                flush_deadline = Instant::now() + FLUSH_INTERVAL;
            }
            _ = sleep_until(pre_start_deadline), if pre_start_sampling => {
                // Pre-start conditions sampler. Lobby traffic rides the reliable
                // control stream, so no datagram arrives to drive the receive-path
                // sampler until the game starts — this keeps each slot's link stats
                // current so the authority's initial-depth computation at coverage
                // reflects live conditions. It stops once the session starts; the
                // receive-driven sampler covers the running game, so nothing is
                // double-sampled.
                if consensus::session_started(&decision_makers, &key) {
                    pre_start_sampling = false;
                } else {
                    let sample =
                        sample_slot_conditions(&link, slot, connection_epoch).conditions;
                    if crate::mesh::publish_conditions(&conditions, &key, slot, sample) {
                        let _ =
                            consensus::ingest_local_condition(&decision_makers, &key, &sample);
                    }
                    pre_start_deadline = Instant::now() + PRE_START_SAMPLE_INTERVAL;
                }
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
            _ = provisional_reap.notified() => {
                // This session was admitted with no applied descriptor and its
                // provisional deadline passed with none arriving. Close with a
                // distinct code so a redialing client can tell this apart from a
                // terminal refusal -- a fresh dial re-admits with its own new
                // provisional window.
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "provisional admission expired with no applied descriptor; closing connection",
                );
                link.connection().close(
                    VarInt::from_u32(PROVISIONAL_EXPIRED_CLOSE),
                    b"provisional admission expired",
                );
                // The teardown below announces (journals) an ordinary
                // dropped departure, exactly like any other link death: the
                // journal is append-only and survives the reap, so if the
                // slot redials (this close is retryable) the drain-time
                // reclaim check stands the stale drop down, and if it never
                // does, the departure drains truthfully once a descriptor
                // arrives — or is retained with the journal, whose retention
                // rule no local fact can safely cut short.
                break 'serve;
            }
        }
    }

    // Every exit path above converges here. Some already closed the
    // connection with a specific reason code (an invalid turn, an isolated
    // slot, an out-of-range resume anchor); a redundant close on one already
    // closing is a no-op. The paths that didn't — a plain client disconnect
    // (`link.recv()`'s own `Err` arm), a maintenance-flush send failure, and
    // notably the lagging-slot isolation signal (whose own comment above
    // says "close the link" but never actually did) — need this: the beacon
    // and control-stream reader tasks spawned above each hold their own
    // `connection.clone()`, parked on `accept_uni`/`accept_bi`, so `link`'s
    // own handle going out of scope at the end of this function is never the
    // last one. Without an explicit close, the connection — and the
    // relay-side slot it's still notionally serving — lingers until QUIC's
    // own idle timeout instead of freeing promptly.
    link.connection()
        .close(VarInt::from_u32(0), b"slot link ended");
    end_slot_link(
        &sessions,
        &mesh_for_teardown,
        &key,
        slot,
        connection_epoch,
        leave_announced,
    );
}

/// Runs the full departure/close protocol for a slot link that has ended,
/// however far it got: deregisters the slot, drops its condition history,
/// announces its departure to the mesh (unless a clean leave-intent already
/// announced it with the "left" reason), re-derives this relay's presence
/// verdict, and — if that deregistration emptied the session's local roster —
/// evaluates the session-emptied close (see [`maybe_close_emptied_session`]).
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
    connection_epoch: u64,
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
    // Same for skins: deregister the member before the roster frees the slot. The
    // session's blob map is left intact (like the lobby log), so a remaining or
    // reconnecting member still replays it.
    crate::skin::deregister_member(&mesh.skins, key, slot);
    let session_emptied = deregister(sessions, key, slot);
    let retired_connection =
        crate::mesh::unpublish_conditions(&mesh.conditions, key, slot, Some(connection_epoch));
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
    if retired_connection && !leave_announced {
        // The link died without a clean leave — a disconnect. Tell every slot
        // (local and across the mesh) this one is no longer connected, immediately
        // and independent of the hold below, so survivors' displays reflect the
        // disconnect ~at once even while their turn stream stalls waiting on it.
        // Under the session's ingress gate: a link that dies during (or after)
        // the session's retirement — the coordinator evicting a live relay
        // closes links exactly this way — must not announce a departure into
        // swept state, recreating a drop hold and a departure record nothing
        // will ever clean up. The roster and per-member cleanup above still
        // ran; a retired session has no one left to inform.
        let announced = mesh.gates.with_ingress(key, || {
            announce_departure(
                &mesh.drop_holds,
                &mesh.decision_makers,
                sessions,
                &mesh.links,
                &mesh.provisional_turns,
                key,
                slot,
                LEAVE_REASON_DROPPED,
                // A drop never carries an exact final turn count at the
                // announce: unlike the clean-leave intent, a dropped slot's
                // ingress was not cut in the same step a count would be
                // derived — the slot can be reconnecting here or on another
                // relay while a later drop-decide races it. An exact count
                // for a drop only ever comes from the finalization handshake
                // (`finalize_drop`), whose seal recreates the cut.
                None,
                Some(connection_epoch),
            )
        });
        if announced == Some(true) {
            broadcast_connectivity(
                sessions,
                &mesh.links,
                key,
                slot,
                false,
                Some(connection_epoch),
            );
        }
    }
    // Forget this slot's condition history in the decision-maker so a departed
    // client's stale stats don't outlive its connection — a no-op when the
    // departure announce above already retired the slot; it still covers exits
    // where no maker-side departure applies. The maker itself lives until the
    // session ends (the coordinator drops the descriptor); the departure record
    // and any cached leave are kept, so a promotion can still re-derive the leave.
    if retired_connection {
        // Keep the roster lock across the reoccupation check and maker cleanup,
        // matching `announce_departure`'s race fence. A replacement can register
        // after this old task deregisters but before it reaches cleanup; if it
        // won that race, even a maker whose new epoch has not been activated yet
        // belongs to the live replacement and must not be erased here.
        let roster = sessions.lock();
        let reoccupied = roster
            .get(key)
            .is_some_and(|slots| slots.contains_key(&slot));
        if !reoccupied {
            let _ = consensus::remove_slot_for_epoch(
                &mesh.decision_makers,
                key,
                slot,
                Some(connection_epoch),
            );
        }
    }
    // This client leaving may hand the session's buffer authority to the next
    // relay in the order — the presence-driven half of the handoff. The local
    // verdict moves here; the peers hear the emptied roster from the mesh
    // drivers' presence reconcile.
    report_own_presence(sessions, mesh, key);
    // This was the relay's last local slot for the session: evaluate the
    // session-emptied close. Evaluated here, after `announce_departure` already
    // put this slot's departure on the same ordered notice channel, so a close
    // that runs now fires its `SessionClosed` behind that departure — the
    // in-flight ordering the final `sessionClosed` webhook rests on. When the
    // close is deferred instead (this very disconnect's drop is still
    // undecided), the later evaluation runs behind whatever decide unblocked
    // it, preserving the same ordering.
    if session_emptied {
        maybe_close_emptied_session(sessions, mesh, key);
    }
}

/// Closes out this relay's serving state for a session whose local roster is
/// empty — the coordinator `SessionClosed` notice plus the per-session
/// registries (lobby log, chat, skin map, forwarded-turn replay ring,
/// session-level dedup, decided drop holds) — unless a still-held, undecided
/// departure of a homed slot promises a reconnect.
///
/// While such a departure is undecided, its drop hold is the admission token a
/// re-dial claims on this relay (`server.rs`), and the retained registries are
/// what make the admitted resume whole: the replay ring catches the client's
/// sim up and the lobby log restores its setup state. Closing eagerly would
/// also retire the session coordinator-side — on a single-relay session this
/// relay's notice alone satisfies the all-relays-closed condition — cutting
/// off the very reconnect the hold promises. So the close is re-evaluated
/// instead, from every place the blocking state can change: the roster
/// emptying (`end_slot_link`), a held drop decided by an honored request or by
/// a peer authority's leave directive (`mesh.rs`), and the abandoned-session
/// force-decide. The force-decide is what bounds the deferral for a *started*
/// session: the same emptying that defers here also flips the session empty
/// session-wide (single-relay), or the peers' own eventual emptying does
/// (multi-relay), and `reconcile_abandon` then arms the timer that decides
/// every held drop. A session that never started has no such bound — nothing
/// ever force-decides its holds — so its emptying closes immediately; the
/// undecided hold itself still survives the sweep below and admits a quick
/// re-dial, whose link re-opens the close latch when it starts serving.
///
/// Safe to call whenever the session *might* be closeable: a non-empty roster,
/// a deferral, or an already-claimed close all make it a no-op. The claim
/// latch (`consensus::claim_close_report`) keeps two concurrent evaluations
/// from both running the close; the roster lock, held from the emptiness
/// check through the last registry erase, keeps a concurrent re-dial's
/// `register` (which inserts under the same lock) from landing mid-teardown —
/// without it, a quick re-dial into a never-started session (whose emptying
/// closes immediately, with no deferral to hide the window) could be admitted
/// and then have its lobby log and replay state erased underneath it while a
/// premature `SessionClosed` retires the session coordinator-side. Every call
/// inside the held section touches only its own module's lock (consensus,
/// lobby, chat, skin, turn ring, seen, drop holds, provisional), never this
/// roster's, so holding it across them cannot deadlock or reenter — the same
/// discipline `announce_departure` documents for its own roster-lock hold.
pub(crate) fn maybe_close_emptied_session(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    maybe_close_emptied_session_inner(sessions, mesh, key, false)
}

/// [`maybe_close_emptied_session`] for the abandon timer's expiry: the close
/// claim additionally requires a decision-maker to still exist, in one atomic
/// registry acquisition (see [`consensus::claim_close_report_with_maker`]). The
/// timer only ever arms while a maker exists, so a missing one at expiry proves
/// the descriptor was retired mid-window and the close already ran — and a
/// separate exists-then-claim pair would leave a gap for that retirement to
/// land in, restoring `claim_close_report`'s no-maker default and duplicating
/// the close.
fn maybe_close_emptied_session_for_abandon_expiry(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    maybe_close_emptied_session_inner(sessions, mesh, key, true)
}

fn maybe_close_emptied_session_inner(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    close_claim_requires_maker: bool,
) {
    // The whole evaluation is one ingress critical section: an emptied-close
    // racing the session's retirement must land wholly before the sweeps (and
    // be swept) or observe the retirement and do nothing — without this, a
    // retired session's close evaluation would find no maker, claim the
    // no-maker close default, and report a second SessionClosed. Recursive
    // for the dispatch arms that already hold the gate.
    let _ = mesh.gates.with_ingress(key, || {
        maybe_close_emptied_session_gated(sessions, mesh, key, close_claim_requires_maker)
    });
}

fn maybe_close_emptied_session_gated(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    close_claim_requires_maker: bool,
) {
    let roster = sessions.lock();
    if roster.contains_key(key) {
        // A slot is locally connected (or a reconnect already reclaimed one);
        // that link's own teardown re-evaluates when it ends.
        return;
    }
    let held = mesh.drop_holds.pending_slots(key);
    if consensus::session_started(&mesh.decision_makers, key)
        && consensus::has_reconnectable_departure(&mesh.decision_makers, key, &held)
    {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            "deferring emptied-session close; a homed slot's drop is held undecided",
        );
        return;
    }
    let claimed = if close_claim_requires_maker {
        consensus::claim_close_report_with_maker(&mesh.decision_makers, key)
    } else {
        consensus::claim_close_report(&mesh.decision_makers, key)
    };
    if !claimed {
        return;
    }
    consensus::session_closed(&mesh.decision_makers, key);
    // An abandoned-session timer running for this session must not re-run the
    // close when its window elapses: the close has been reported now, and the
    // teardown below is what it would otherwise repeat. Its force-decide is still
    // owed, so the timer is marked rather than cancelled.
    mesh.drop_holds.note_session_closed(key);
    // The relay's last local member for the session is gone, so its lobby log
    // and (now-empty) member set can be dropped — mirroring how the roster
    // group is dropped when its last slot leaves.
    crate::lobby::end_session(&mesh.lobby, key);
    // Same for chat's (log-free) per-session state.
    crate::chat::end_session(&mesh.chat, key);
    // Same for the skin blob map and member set: no local member remains to
    // replay it to, so the whole per-session state can be dropped.
    crate::skin::end_session(&mesh.skins, key);
    // Same for request limiters, and for any hold whose slot's leave is already
    // decided — but NOT for an undecided hold: on a session that never started
    // (where a fresh undecided drop does not defer the close) that hold is
    // still the reconnect-admission token and unlock clock for a drop nobody
    // has decided yet. See `crate::drop_hold` module docs.
    let decided = consensus::decided_slots(&mesh.decision_makers, key);
    mesh.drop_holds.end_session(key, &decided);
    // The forwarded-turn replay ring and the forward-once seen state (whose
    // entry is created lazily on the first turn forwarded — there is no
    // explicit "join" counterpart to pair the teardown with) go down on the
    // same "last local slot gone" trigger as the registries above — UNLESS a
    // surviving hold still promises a reconnect this relay would admit. That
    // reconnect's resume seeds its fresh receive window from the seen state's
    // receipts (every transport-acked seq its sparse anchor will not re-send),
    // so destroying them here while honoring the hold would admit a resume
    // whose acked holes nothing can ever fill: the prefix wedges, and the
    // live stream eventually exits the receive window. Receipt-state lifetime
    // must match the reconnect-admission token's, exactly as the provisional
    // journal is retained while a descriptor could still drain it — so both
    // stores are kept until no such token remains: a reconnect re-opens the
    // close latch and this teardown re-runs at the next emptying, and
    // descriptor retirement sweeps them terminally (`MeshControl::end_session`)
    // if the reconnect never comes. (The retained ring is empty in practice —
    // it records only started sessions, and a started session's reconnectable
    // departure defers this close entirely above — but tying both stores to
    // the same token keeps the rule whole rather than shape-dependent.)
    let surviving_holds = mesh.drop_holds.pending_slots(key);
    if !consensus::has_reconnectable_departure(&mesh.decision_makers, key, &surviving_holds) {
        mesh.turn_ring.end_session(key);
        crate::mesh::deregister_seen(&mesh.seen, key);
    }
    // A session no descriptor ever named has no coordinator lifecycle, so the
    // retirement that ordinarily cleans up its ingress gate will never come —
    // drop the gate (and the provisional mark: a later dial for the same id
    // is a genuinely fresh admission with its own new deadline) here, at its
    // retirement-equivalent, or the entries live for the relay's lifetime. A
    // descriptor-named session keeps its gate until real retirement, and its
    // mark was already cleared at descriptor application.
    //
    // EXCEPT when the provisional journal still holds anything undrained:
    // journaled entries are transport-acknowledged (turns) or the only
    // record that a slot left at all (departures), and the journal is
    // retained until a descriptor drains it or retirement ends the session
    // — no local fact can prove it unneeded sooner (see the retention rule
    // in `crate::provisional_turns`) — so discarding it here would silently
    // hole an accepted sequence, or leave peer-homed survivors waiting
    // forever on an expected slot with neither presence nor a departure.
    // The empty-check and the removal are ONE atomic step
    // (`discard_if_empty`), so a departure deposited by a sibling
    // teardown's announce racing this close can never be classified away
    // and then deleted: it either refuses the discard or lands in a fresh,
    // retained journal.
    if consensus::maker_exists(&mesh.decision_makers, key) {
        mesh.provisional.clear(key);
    } else if mesh.provisional_turns.discard_if_empty(key) {
        mesh.provisional.clear(key);
        mesh.gates.discard(key);
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
///
/// For a *disconnect* (`reason` == [`LEAVE_REASON_DROPPED`]) this guards against
/// a reconnect that has already reclaimed the slot's roster seat by the time this
/// runs — the gap between `end_slot_link`'s earlier `deregister` and this call is
/// only a handful of synchronous instructions, but on a multi-threaded runtime a
/// concurrent `serve_connection` can still land its own `register` in it. The
/// roster lock is held across the presence check and the whole announcement
/// below, so a `register` racing this disconnect can't land in the gap:
/// whichever of the two acquires the roster lock first is authoritative. If this
/// disconnect wins (the seat is still empty), it announces normally, and a
/// reconnect that registers moments later (`server.rs`) reads the fresh hold and
/// reinstates. If the reconnect wins (the seat is already reoccupied), announcing
/// here would record a departure and mark a hold against a slot that is, as of
/// this check, already live again — an orphaned record would wrongly refuse
/// every later reconnect for the slot (nothing ever clears a record with no
/// hold to release), and an orphaned hold would let a survivor's `RequestDrop`
/// honor a drop against a connected player — so this stands down instead. Every
/// call this reaches into below (`consensus::record_departure`,
/// `mesh::fan_out_slot_departed`, `hold_or_decide_leave`'s DROPPED branch) touches
/// only its own lock, never this roster's, so holding it across them cannot
/// deadlock or reenter it. A clean leave (`reason` != `LEAVE_REASON_DROPPED`)
/// never takes this guard: it is announced by the still-connected client's own
/// control-stream handler, so no concurrent register for the same slot can be
/// racing it, and its own decide path (`decide_and_broadcast_leave` →
/// `fan_out_leave`) needs the roster lock itself — holding it here too would
/// deadlock.
/// The journal-aware wrapper around [`announce_departure_recorded`]. On a
/// coordinator-managed relay, the departure is deposited into the session's
/// provisional journal unless the journal has fully drained (the maker
/// provably exists) — a pre-descriptor announce would otherwise land in a
/// maker-less void: nothing records it, yet the caller marks it announced, so
/// when the descriptor arrives the slot is expected-but-absent and the
/// session stalls on it until the coordinator's holdout reap. Depositing
/// while the drain is mid-replay is journaled too, ordered after the batch in
/// flight, so a clean leave landing then still counts every one of its own
/// turns. The drain replays journaled departures through
/// [`announce_departure_recorded`] once the maker exists (a clean leave's
/// exact count recomputed there over exactly its drained turns; the
/// drain-time reclaim check stands a stale journaled drop down if the slot
/// reconnected meanwhile). Callers run this under the session's ingress gate,
/// so a racing retirement cannot have the deposit recreate journal state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn announce_departure(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    provisional_turns: &crate::provisional_turns::ProvisionalTurnPen,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
    final_turn_count: Option<u64>,
    connection_epoch: Option<u64>,
) -> bool {
    if provisional_turns.armed() {
        use crate::provisional_turns::{HoldOutcome, PennedIngress};
        match provisional_turns.hold(
            key,
            PennedIngress::Departure {
                slot,
                reason,
                connection_epoch,
                // Stamped by `hold`; see the variant's doc.
                revision: 0,
            },
        ) {
            HoldOutcome::Held => return true,
            // The journal fully drained: the maker provably exists, so
            // announce into it directly below.
            HoldOutcome::Resolved(_) => {}
            // Only the relay-wide session ceiling refuses a departure
            // (byte and per-session caps exempt them): the relay is under
            // session-churn pressure and may not grow the journal map for
            // yet another maker-less session. The departure is lost —
            // survivors of a genuine session in this state wait for the
            // coordinator's holdout reap — which is the deliberate
            // degraded mode: bounded memory over per-session fidelity,
            // only once thousands of undescribed sessions are already
            // being tracked.
            HoldOutcome::Overflow(_) => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "journal session ceiling reached; a pre-descriptor departure could not be                      journaled",
                );
                return false;
            }
        }
    }
    announce_departure_recorded(
        drop_holds,
        decision_makers,
        sessions,
        mesh_links,
        key,
        slot,
        reason,
        final_turn_count,
        connection_epoch,
    )
}

/// The journal-blind half of [`announce_departure`]: records, holds, and
/// broadcasts against the session's current state. Called directly by the
/// journal drain (whose deposits must not re-enter the journal) and by the
/// wrapper above once the journal is resolved.
#[allow(clippy::too_many_arguments)]
pub(crate) fn announce_departure_recorded(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
    final_turn_count: Option<u64>,
    connection_epoch: Option<u64>,
) -> bool {
    let roster_guard = (reason == LEAVE_REASON_DROPPED).then(|| sessions.lock());
    if let Some(roster) = &roster_guard
        && roster
            .get(key)
            .is_some_and(|slots| slots.contains_key(&slot))
    {
        // A reconnect already reclaimed this seat; its own post-register
        // admission (current state, not a stale snapshot) is the sole authority
        // on this slot now.
        return false;
    }

    // Read the last observed frame, the reachability ceiling, and the slot's
    // retained end-of-game result before recording retires the slot's live state;
    // all fill the departure record and the SlotDeparted the peers receive. The
    // ceiling and the result are home-authored here (only this relay, the slot's
    // home, holds the retained report and computes the ceiling), so every relay
    // clamps to the identical apply frame and folds the identical result — see
    // `consensus::reachable_frame` / `consensus::result_for`.
    let stamps = consensus::DepartureStamps {
        last_frame: consensus::slot_frame(decision_makers, key, slot),
        reachable_frame: consensus::reachable_frame(decision_makers, key, slot),
        result: consensus::result_for(decision_makers, key, slot),
        final_turn_count,
        // A link-death departure is never born finalized; the proof only ever
        // enters the record through `finalize_drop`'s stamp.
        finalized: false,
    };
    let outcome = if reason == LEAVE_REASON_DROPPED {
        // A dropped departure and its reconnect hold are one transition. The
        // hold lock stays held while `record` takes the maker lock, then the
        // hold is installed before either becomes externally observable.
        drop_holds.record_and_maybe_hold(key, slot, || {
            let outcome = consensus::record_departure_for_epoch_outcome(
                decision_makers,
                key,
                slot,
                stamps.clone(),
                reason,
                connection_epoch,
            );
            (
                outcome,
                outcome == consensus::DepartureRecordOutcome::Pending,
            )
        })
    } else if consensus::record_departure_for_epoch(
        decision_makers,
        key,
        slot,
        stamps.clone(),
        reason,
        connection_epoch,
    ) {
        consensus::DepartureRecordOutcome::Pending
    } else {
        consensus::DepartureRecordOutcome::Rejected
    };
    if outcome != consensus::DepartureRecordOutcome::Pending {
        return false;
    }
    crate::mesh::fan_out_slot_departed(mesh_links, key, slot, &stamps, reason, connection_epoch);
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
    true
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
        // A clean leave supersedes any pending drop hold for this slot -- and
        // decides regardless of whether one was even there: unlike an honored
        // `RequestDrop` or the abandoned-session force-decide, a clean
        // leave-intent's decision is never contingent on winning a claim over
        // the hold -- a slot leaving cleanly for the first time (no drop ever
        // observed) still decides here. So `release`'s bool return is
        // informational only in this branch, not a gate.
        let _ = drop_holds.release(key, slot);
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
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    requester: SlotId,
    wire_target: u32,
) {
    let drop_holds = &mesh.drop_holds;
    let decision_makers = &mesh.decision_makers;
    let mesh_links = &mesh.links;
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
    honor_drop_request(sessions, mesh, key, target, u32::from(requester.0));
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
/// claimed and, if the claim succeeds, the synced leave decided with the DROPPED
/// reason; the decide path also dedups, so a duplicate request after the decide
/// is a harmless no-op. A hold short of the floor, or no hold at all (the slot
/// reconnected or left cleanly), is ignored — logged with the elapsed-vs-floor so
/// a refused click is diagnosable.
///
/// `held_for`'s read and `release`'s claim below are two separate lock
/// acquisitions, not one atomic check-and-take — a concurrent reconnect's
/// `DropHolds::take_if_pending` (`server.rs`) can slip in between them and claim
/// the same hold first. That is exactly why the claim is checked: `release`
/// returning `false` means this call lost that race, and it must stand down
/// rather than decide anyway. Deciding unconditionally here would be a genuine
/// correctness bug, not just redundant work — `consensus::decide_leave` records
/// (or *re-records*) the departure before it checks anything, so calling it after
/// a reconnect's `reinstate_slot` already cleared the record would resurrect a
/// departure, and then commit a leave, against a slot that is live again.
pub(crate) fn honor_drop_request(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    target: SlotId,
    requester: u32,
) {
    let drop_holds = &mesh.drop_holds;
    let decision_makers = &mesh.decision_makers;
    let mesh_links = &mesh.links;
    let seen = &mesh.seen;
    if !consensus::is_authority(decision_makers, key) {
        // Not the authority — the authority is among the broadcast's receivers and
        // will act. Nothing to do, and the hold stays for a possible promotion.
        return;
    }
    match drop_holds.held_for(key, target) {
        Some(elapsed) if elapsed >= drop_holds.unlock() => {
            // In a handshake-enabled session, the drop is decided only
            // through home-side finalization: the home seals the slot's
            // generation (refusing admission and fencing its turn ingress)
            // and snapshots the gap-free count the leave then carries, so
            // every survivor applies it at the same consumed-turn step. The
            // hold is NOT released up front — a rejected finalization (a
            // live reconnect, or no sealable cursor) leaves the drop held
            // and undecided, never frame-scheduled.
            if consensus::finalized_drops_enabled(decision_makers, key) {
                if consensus::slot_strictly_homed(decision_makers, key, target) {
                    let outcome = consensus::finalize_drop(
                        decision_makers,
                        key,
                        target,
                        consensus::departure_epoch(decision_makers, key, target),
                        || crate::mesh::forwarded_count(seen, key, target),
                    );
                    tracing::info!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        target = target.0,
                        requester,
                        ?outcome,
                        "honoring manual drop request via local finalization",
                    );
                    if let consensus::FinalizeOutcome::Finalized { final_turn_count } = outcome {
                        complete_finalized_drop(
                            drop_holds,
                            decision_makers,
                            sessions,
                            mesh_links,
                            seen,
                            key,
                            target,
                            final_turn_count,
                        );
                    } else if outcome == consensus::FinalizeOutcome::RejectedNoCursor {
                        decision_makers.flight_recorder().record(
                            key,
                            crate::flight_recorder::FlightEvent::DropFinalizeRejected {
                                slot: target.0,
                                no_cursor: true,
                            },
                        );
                    }
                } else {
                    // A peer homes the target: ask it to finalize. The decide
                    // happens when its FinalizeDropResult arrives; until then
                    // the drop stays held, and a re-honored request simply
                    // re-sends this idempotent ask.
                    tracing::info!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        target = target.0,
                        requester,
                        held_ms = elapsed.as_millis(),
                        "requesting home-side finalization for a manual drop",
                    );
                    crate::mesh::fan_out_finalize_drop(
                        mesh_links,
                        key,
                        target,
                        consensus::departure_epoch(decision_makers, key, target),
                    );
                }
                return;
            }
            if drop_holds.release(key, target) {
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
            } else {
                // Lost the claim: a concurrent reconnect (or another relay's
                // honor of this same broadcast request) released the hold
                // first. The slot may already be live again, so standing down
                // -- not deciding anyway -- is what keeps this from
                // resurrecting a departure record for a connected player.
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    target = target.0,
                    requester,
                    "drop request lost the claim race; the hold was already released",
                );
            }
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

/// Completes a home-finalized drop on the authority: stamps the sealed count
/// (with its proof) into the slot's departure record, releases the hold, and
/// decides + broadcasts the leave, which then carries the count (see
/// `commit_leave`). Shared by the local-home fast path
/// ([`honor_drop_request`]) and the mesh `FinalizeDropResult` arm. A lost
/// hold-claim race stands down exactly like the legacy honor path — the slot
/// may be live again on a relay whose rejection is still in flight.
#[allow(clippy::too_many_arguments)]
pub(crate) fn complete_finalized_drop(
    drop_holds: &crate::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    seen: &crate::mesh::SeenRegistries,
    key: &SessionKey,
    target: SlotId,
    final_turn_count: u64,
) {
    // Local staleness proof, checked before anything is stamped: if this
    // relay's own gap-free forwarded prefix for the slot already extends
    // PAST the sealed count, turns beyond the count entered the mesh after
    // the seal the answer describes — the slot reconnected (on a new home)
    // and played on while this answer was in flight. The home is the slot's
    // single ingress, so past the seal no legitimate turn can ever exceed
    // the count; a longer prefix here is proof, not suspicion. The epoch
    // check at the mesh arm closes most of this; this closes the interleaving
    // where the reconnect's own connectivity update is still in flight while
    // its turns (datagrams, a different channel) have already arrived.
    if let Some(forwarded) = crate::mesh::forwarded_count(seen, key, target)
        && forwarded > final_turn_count
    {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            final_turn_count,
            forwarded,
            "finalized count is stale; this relay already forwarded past it — refusing",
        );
        decision_makers.flight_recorder().record(
            key,
            crate::flight_recorder::FlightEvent::DropFinalizeStaleCount {
                slot: target.0,
                sealed_count: final_turn_count,
                forwarded,
            },
        );
        return;
    }
    // The decide below silently short-circuits without a framed scheduling
    // basis — and by then the hold would already be released, leaving the
    // departure with no committed leave, no hold for a retry to claim, and
    // (with the home's seal standing) no reconnect path either: a stranded
    // session. Check the basis FIRST and keep the hold when it is missing;
    // the home's answer is idempotent, so a later honored drop request
    // completes once a framed turn exists. Safe as a check-then-act because
    // frames only accumulate — schedulable never reverts to unschedulable.
    if !consensus::leave_schedulable(decision_makers, key, target) {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            final_turn_count,
            "finalized drop has no framed scheduling basis yet; keeping the hold for a retry",
        );
        decision_makers.flight_recorder().record(
            key,
            crate::flight_recorder::FlightEvent::DropFinalizeRejected {
                slot: target.0,
                no_cursor: false,
            },
        );
        return;
    }
    consensus::record_departure(
        decision_makers,
        key,
        target,
        consensus::DepartureStamps {
            final_turn_count: Some(final_turn_count),
            finalized: true,
            ..consensus::DepartureStamps::default()
        },
        LEAVE_REASON_DROPPED,
    );
    if drop_holds.release(key, target) {
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
            final_turn_count,
            "decided a home-finalized drop",
        );
    } else {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            "finalized drop lost the hold-claim race; standing down",
        );
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
fn report_own_presence(sessions: &Sessions, mesh: &crate::mesh::MeshState, key: &SessionKey) {
    let live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    if crate::presence::record_own(&mesh.presence, key, live) {
        // Slots whose drop is still held on this relay must not be decided by the
        // promotion a re-derive may trigger: a held drop is decided only by an
        // honored manual request, never by a promotion.
        let held = mesh.drop_holds.pending_slots(key);
        let leaves = crate::presence::recompute(&mesh.presence, &mesh.decision_makers, key, &held);
        crate::mesh::broadcast_leaves(sessions, &mesh.links, key, leaves);
        // A recompute that promotes this relay to authority may make it the one
        // to observe full slot presence: re-evaluate and fire the session-start
        // directive if the accumulated live slots already cover the expected set.
        maybe_start_session(sessions, &mesh.decision_makers, &mesh.links, key);
        // This liveness change may have emptied the session session-wide (arming
        // the abandoned-session timer) or refilled it (cancelling any armed timer).
        reconcile_abandon(sessions, mesh, key);
    }
}

/// Reconciles a started session against its session-wide presence after every
/// liveness change (this relay's own roster flip, or a peer's report). A globally
/// empty session attempts the normal local close, and one whose departures still
/// need deciding also arms the abandoned-session timer.
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
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    // The roster is the authoritative answer for this relay, including the
    // important case where it never served a local slot and therefore never
    // emitted an own-presence transition. Peers still have to explicitly report
    // zero through `all_empty`; silence is never treated as absence.
    let own_live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    let session_started = consensus::session_started(&mesh.decision_makers, key);
    let globally_empty = crate::presence::all_empty(&mesh.presence, key, own_live);
    let abandoned = session_started
        && globally_empty
        && consensus::has_undecided_departure(&mesh.decision_makers, key);
    if abandoned {
        // Owned clones for the timer task: it fires after the window with no
        // borrowed state, holding the shared registries by `Arc` (`MeshState`
        // clones cheaply — every field is an `Arc`).
        let sessions_for_expire = Arc::clone(sessions);
        let mesh_for_expire = mesh.clone();
        let key_for_expire = key.clone();
        mesh.drop_holds
            .arm_abandon(key.clone(), move |close_reported| {
                decide_and_broadcast_abandoned(
                    &sessions_for_expire,
                    &mesh_for_expire,
                    &key_for_expire,
                    close_reported,
                );
            });
    } else {
        mesh.drop_holds.cancel_abandon(key);
    }

    // `end_slot_link` already evaluates the close when this relay's own last
    // slot leaves. This symmetric peer-report path is what closes a serving
    // relay that never had a local slot: once every peer has explicitly reported
    // zero, no future local teardown exists to trigger the normal close. The
    // close function retains the existing reconnect promise — a started session
    // with a homed, held departure defers until the abandoned timer decides it.
    if globally_empty {
        maybe_close_emptied_session(sessions, mesh, key);
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
/// the hold has nothing further to gate. A slot
/// [`consensus::decide_abandoned_departures`] dedups away (already decided) has
/// no directive here, so its hold — if somehow still present — is left for the
/// close's decided-sweep, not touched twice for no reason.
///
/// Deciding every held departure is exactly what unblocks a deferred
/// session-emptied close (see [`maybe_close_emptied_session`]), so that close is
/// re-evaluated here once the holds are released — this timer firing is the
/// bound on how long an abandoned session's close can be deferred. That
/// re-evaluation is skipped when `close_reported` says the relay already reported
/// this session's close (the deferral it exists to end never happened), and also
/// when no decision-maker exists anymore: the timer only ever armed while one
/// did, so a missing maker proves the descriptor was retired mid-window — the
/// close already ran and reached the coordinator — and
/// [`consensus::claim_close_report`]'s no-maker default (`true`, meant for
/// sessions that never had a maker) must not re-report it. The force-decide
/// above still runs either way — the undecided holds it releases outlive the
/// close, and nothing else ever releases them.
///
/// This release is cleanup, not a claim gate — unlike [`honor_drop_request`], it
/// does not need to check the boolean before deciding, because
/// `decide_abandoned_departures` already committed these decisions atomically
/// under the decision-maker's own lock (see that function's doc comment): a
/// concurrent reconnect's `reinstate_slot` for the same slot either ran entirely
/// before this call started (that slot has nothing undecided left to force-decide
/// here) or entirely after (`reinstate_slot`'s `decided_leaves` guard refuses it,
/// since this call already decided it). So by the time this loop runs, every
/// slot in `leaves` is irreversibly decided regardless of what its hold looks
/// like; releasing is just freeing the now-stale entry, whether or not it's
/// still there.
fn decide_and_broadcast_abandoned(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    close_reported: bool,
) {
    // Re-derive the abandoned condition before deciding anything. The timer's
    // expiry can race the cancellation a re-registering slot sends
    // (`cancel_abandon` and the elapsed sleep can both be ready in the same
    // poll), and a cancellation that loses that race must still win the
    // outcome: with a slot live again — here, or on a peer whose presence
    // report says so — the departures stay held for the live machinery (a
    // survivor's drop request, the slot's own reconnect, or a later
    // re-abandonment re-arming this timer) instead of being force-decided out
    // from under a live session. Presence is eventually consistent, so a
    // reconnect on a peer relay in the final instants can still slip past this
    // check — but the recheck narrows the race from the whole abandon window
    // to that propagation gap, and the decided-slot reinstate guard already
    // covers the reconnecting slot itself.
    let own_live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    if own_live > 0 || !crate::presence::all_empty(&mesh.presence, key, own_live) {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            "abandoned-session window elapsed but a slot is live again; leaving departures held",
        );
        return;
    }
    let leaves = consensus::decide_abandoned_departures(&mesh.decision_makers, key);
    if !leaves.is_empty() {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            count = leaves.len(),
            "abandoned session timed out with no live slots; deciding its held departures",
        );
        for leave in &leaves {
            if let Ok(slot) = u8::try_from(leave.slot) {
                let _ = mesh.drop_holds.release(key, SlotId(slot));
            }
        }
        crate::mesh::broadcast_leaves(sessions, &mesh.links, key, leaves);
    }
    if close_reported {
        tracing::debug!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            "abandoned-session window elapsed on an already-closed session; \
             leaving its reported close alone",
        );
        return;
    }
    // The `close_reported` flag can lose a race (the close lands after the
    // timer's entry was claimed, so `note_session_closed` had nothing to
    // mark); the maker's absence is the reliable signal for that ordering,
    // since the close cascade's descriptor retirement is what destroys it —
    // checked atomically with the close claim itself, so a retirement cannot
    // land between a separate existence check and the claim.
    maybe_close_emptied_session_for_abandon_expiry(sessions, mesh, key);
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
fn send_packet(
    link: &mut Link,
    payload: Option<Payload>,
    counters: &crate::flight_recorder::SlotCounters,
) -> Result<bool, LinkError> {
    match link.send(payload) {
        Ok(redundant) => {
            counters.note_redundancy(redundant);
            Ok(redundant > 0)
        }
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

/// Whether an active-game receive should refresh this client's path sample.
/// Transport dedup leaves both ack-only packets and packets containing only
/// redundant payloads with an empty `fresh` slice; neither represents new game
/// progress, while any fresh payload makes one sample for the whole datagram
/// worthwhile.
#[inline]
fn should_sample_active_conditions(received: &Received) -> bool {
    !received.fresh.is_empty()
}

/// Samples this client's link: the QUIC path stats that become a
/// [`SlotConditions`] for the mesh sidecar and the decision-maker, plus the
/// recording-only gauges taken from the same snapshot. RTT comes from QUIC's
/// smoothed path estimate (via [`crate::mesh::rtt_us`], which owns the "0 means
/// no measurement" convention); lost/sent are cumulative counters the
/// decision-maker differences between consecutive samples to get a loss rate
/// over the interval.
fn sample_slot_conditions(link: &Link, slot: SlotId, connection_epoch: u64) -> SampledLink {
    let path = link.connection().stats().path;
    SampledLink {
        conditions: SlotConditions {
            slot: u32::from(slot.0),
            rtt_us: crate::mesh::rtt_us(path.rtt),
            lost_packets: path.lost_packets,
            sent_packets: path.sent_packets,
            connection_epoch: Some(connection_epoch),
        },
        upstream_lost_packets: link.upstream_lost_packets(),
        cwnd: path.cwnd,
        congestion_events: path.congestion_events,
    }
}

/// One sampling of a client link: the conditions that travel (to the mesh
/// sidecar and the decision-maker) alongside the gauges that only ever land in
/// the flight recording. They are read from one `stats()` snapshot so the two
/// always describe the same instant.
struct SampledLink {
    conditions: SlotConditions,
    upstream_lost_packets: u64,
    cwnd: u64,
    congestion_events: u64,
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

    /// A payload carrying `len` command bytes, for exercising the forward queue's
    /// resident-byte budget (the only field the budget measures).
    fn payload_of(len: usize) -> Payload {
        Payload {
            seq: 0,
            slot: 0,
            commands: vec![0u8; len].into(),
            ..Default::default()
        }
    }

    #[test]
    fn active_conditions_sampling_requires_a_fresh_delivery() {
        let ack_only = Received {
            fresh: Vec::new(),
            carried_payloads: false,
        };
        assert!(!should_sample_active_conditions(&ack_only));

        let all_redundant = Received {
            fresh: Vec::new(),
            carried_payloads: true,
        };
        assert!(!should_sample_active_conditions(&all_redundant));

        let fresh = Received {
            fresh: vec![payload()],
            carried_payloads: true,
        };
        assert!(should_sample_active_conditions(&fresh));
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

    /// A refused admission's light teardown removes exactly the scaffolding
    /// the failed attempt created — the first-touch gate, the empty journal
    /// reservation, any mark — and nothing anyone else owns: not a retired
    /// tombstone, not an occupied session's gate, not a journal with
    /// entries.
    #[test]
    fn a_refused_admission_leaves_no_scaffolding() {
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        mesh.provisional_turns.arm();
        let k = key();

        // The refusal path's residue: the register attempt touched the gate,
        // the reservation created the empty journal entry.
        let _ = mesh.gates.with_ingress(&k, || ());
        assert!(mesh.provisional_turns.reserve(&k));
        abandon_refused_admission(&sessions, &mesh, &k);
        assert_eq!(
            mesh.gates.tracked(),
            0,
            "the refused session's gate is gone"
        );
        assert!(
            mesh.provisional_turns.discard_if_empty(&k),
            "the empty reservation is gone too (an absent journal reads empty)",
        );

        // A retired gate is a tombstone: kept.
        mesh.gates.retire(&k);
        abandon_refused_admission(&sessions, &mesh, &k);
        assert_eq!(mesh.gates.tracked(), 1, "the tombstone stands");
        mesh.gates.reopen(&k);

        // An occupied roster owns the session's state: kept.
        let (_reg, _inbox) = register(&sessions, &k, SlotId(0)).expect("registers");
        assert!(mesh.provisional_turns.reserve(&k));
        abandon_refused_admission(&sessions, &mesh, &k);
        assert_eq!(
            mesh.gates.tracked(),
            1,
            "a live occupant's gate (and journal state) is untouched",
        );
    }

    /// The session's ONLY local link cleanly leaves before the descriptor: its
    /// teardown empties the roster, but the emptied-session close must keep
    /// the journal (and the gate) holding that departure — discarding it
    /// would erase the only record of the leave, and the descriptor would
    /// then drain nothing while peer-homed survivors wait forever on an
    /// expected slot with neither presence nor a departure.
    #[tokio::test]
    async fn an_emptied_close_keeps_an_undrained_journal() {
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        mesh.provisional_turns.arm();
        let k = key();
        let (mut g1, _i1) = register(&sessions, &k, SlotId(1)).expect("the leaver registers");
        g1.disarm();
        // Admission marks the undescribed session for the provisional sweep.
        assert!(
            mesh.provisional
                .mark_if_undescribed(&mesh.decision_makers, &k)
        );

        // The clean-leave intent path: journal the departure, then the full
        // link teardown with the leave already announced.
        let announced = mesh.gates.with_ingress(&k, || {
            announce_departure(
                &mesh.drop_holds,
                &mesh.decision_makers,
                &sessions,
                &mesh.links,
                &mesh.provisional_turns,
                &k,
                SlotId(1),
                LEAVE_REASON_LEFT,
                None,
                Some(3),
            )
        });
        assert_eq!(announced, Some(true), "the pre-descriptor leave journals");
        end_slot_link(&sessions, &mesh, &k, SlotId(1), 3, true);

        assert!(
            mesh.provisional_turns.has_undrained(&k),
            "the emptied close keeps the journaled departure for the descriptor",
        );
        assert!(
            mesh.provisional_turns.slot_sealed(&k, SlotId(1)),
            "the clean leave's admission seal survives the emptied close",
        );
        assert!(
            mesh.provisional.is_marked(&k),
            "the sweep mark is retained WITH the journal — clearing it while \
             keeping the journal would leave the retained state immortal if \
             no descriptor ever comes",
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
        end_slot_link(&sessions, &mesh, &k, SlotId(1), 0, false);
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
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);
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
    fn session_emptying_teardown_drops_the_seen_registry_entry() {
        // `mesh.seen`'s entry for a session is created lazily on the first
        // turn forwarded (there is no explicit "join" to pair a deregister
        // with) and must be dropped once the relay's last local slot for the
        // session leaves -- otherwise it outlives every other per-session
        // registry the same teardown clears, leaking one `MeshSeen` per
        // session for the process lifetime.
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        let k = key();
        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();

        crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);
        assert!(
            mesh.seen.lock().contains_key(&k),
            "marking a turn forwarded creates the session's entry",
        );

        // The only local slot leaves: the session-emptying teardown fires.
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);
        assert!(
            !mesh.seen.lock().contains_key(&k),
            "the emptied session's seen-registry entry must not survive its teardown",
        );
    }

    /// A started session whose last local slot drops keeps its serving state and
    /// defers the coordinator close while that drop is undecided: the hold is
    /// the reconnect's admission token, and the retained registries (the seen
    /// entry standing in for the lobby log and replay ring here) are what make
    /// the resume whole. Deciding the departure is what runs the close.
    #[tokio::test]
    async fn an_undecided_drop_defers_the_emptied_session_close_until_decided() {
        use crate::consensus::{self, Authority, RelayNotice};
        use crate::presence::Candidate;
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.decision_makers.set_notice_notifier(tx);
        let _ = consensus::sync_maker(
            &mesh.decision_makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0)].into_iter().collect(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        consensus::mark_session_started(&mesh.decision_makers, &k);
        consensus::observe_frame(&mesh.decision_makers, &k, SlotId(0), GameFrameCount(50));
        crate::presence::set_order(&mesh.presence, &k, vec![Candidate::SelfRelay]);

        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();
        // The serve path reports own presence right after registering; without a
        // live report the session is never `ever_live` and the abandoned-expiry
        // recheck below would (correctly) refuse to treat it as abandoned.
        report_own_presence(&sessions, &mesh, &k);
        crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);

        // The only local slot's link dies without a clean leave — the emptying
        // that must NOT close the session while the drop is held.
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);

        assert!(
            mesh.drop_holds.is_pending(&k, SlotId(0)),
            "the drop marked a hold",
        );
        assert!(
            mesh.seen.lock().contains_key(&k),
            "the deferred close keeps the session's serving state",
        );
        while let Ok(notice) = rx.try_recv() {
            assert!(
                !matches!(notice, RelayNotice::SessionClosed { .. }),
                "no close is reported while the drop is undecided",
            );
        }

        // The abandoned-session force-decide (the expiry effect of the timer the
        // emptying armed) decides the held drop — which is what unblocks and
        // runs the deferred close. No close has been reported for the session:
        // the emptying above deferred it.
        decide_and_broadcast_abandoned(&sessions, &mesh, &k, false);

        assert!(
            !mesh.seen.lock().contains_key(&k),
            "the decided departure ran the close",
        );
        assert!(
            !mesh.drop_holds.is_pending(&k, SlotId(0)),
            "the decided hold was released and swept",
        );
        let mut saw_closed = false;
        while let Ok(notice) = rx.try_recv() {
            saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
        }
        assert!(saw_closed, "the close reported once the drop was decided");
    }

    /// The clean counterpart: a last local slot that leaves cleanly (its hold
    /// released by the leave-intent, so no reconnect is promised) closes
    /// immediately, exactly as an emptying with nothing held always has.
    #[tokio::test]
    async fn a_clean_leave_does_not_defer_the_emptied_session_close() {
        use crate::consensus::{self, Authority, RelayNotice};
        use rally_point_proto::control::BufferBounds;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.decision_makers.set_notice_notifier(tx);
        let _ = consensus::sync_maker(
            &mesh.decision_makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0)].into_iter().collect(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        consensus::mark_session_started(&mesh.decision_makers, &k);

        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();
        crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 0);

        // A clean leave, announced by the control-stream handler before the
        // link ends, so `end_slot_link` skips the drop announce. No framed turn
        // was observed, so the decide itself holds for a frame basis — but the
        // clean leave released any hold, and only a *held* departure promises a
        // reconnect, so the emptying still closes.
        hold_or_decide_leave(
            &mesh.drop_holds,
            &mesh.decision_makers,
            &sessions,
            &mesh.links,
            &k,
            SlotId(0),
            LEAVE_REASON_LEFT,
        );
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, true);

        assert!(
            !mesh.seen.lock().contains_key(&k),
            "a clean emptying closes at once",
        );
        let mut saw_closed = false;
        while let Ok(notice) = rx.try_recv() {
            saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
        }
        assert!(saw_closed, "the close reported on the emptying itself");
    }

    /// A NEVER-started session's emptying closes immediately — nothing defers
    /// it — but the undecided held drop still survives as the
    /// reconnect-admission token, and the receipts that reconnect's resume
    /// depends on must survive exactly as long. The teardown erasing the seen
    /// state while honoring the hold would admit a resume whose
    /// transport-acked holes (a pre-start turn the forward gate recorded)
    /// nothing could ever seed: the fresh window's prefix wedges permanently.
    #[tokio::test]
    async fn a_never_started_emptying_retains_receipts_while_the_hold_survives() {
        use crate::consensus::{self, Authority, RelayNotice};
        use rally_point_proto::control::BufferBounds;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.decision_makers.set_notice_notifier(tx);
        // Descriptor-backed (a maker exists, homing slot 0) but never started.
        let _ = consensus::sync_maker(
            &mesh.decision_makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0)].into_iter().collect(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );

        let (mut g0, _i0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        g0.disarm();
        // A pre-start turn passed the forward gate: seq 1 was received and
        // transport-acked while seq 0 never arrived — the acked hole the
        // resume's anchor-0 seeding must close from these receipts.
        crate::mesh::mark_seen(&mesh.seen, &k, SlotId(0), 1);

        // The only local slot's link dies without a clean leave.
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 0, false);

        assert!(
            mesh.drop_holds.is_pending(&k, SlotId(0)),
            "the drop marked a hold — the reconnect-admission token",
        );
        let mut saw_closed = false;
        while let Ok(notice) = rx.try_recv() {
            saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
        }
        assert!(
            saw_closed,
            "a never-started emptying still closes immediately",
        );
        let receipts = crate::mesh::slot_receipts(&mesh.seen, &k, SlotId(0));
        assert_eq!(
            receipts.ahead,
            vec![1],
            "the receipts survive the close for as long as the hold does",
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
            if inbox1.forward_rx.try_recv().is_some() {
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
    async fn normal_payloads_fill_the_count_bound_without_tripping_the_byte_budget() {
        // A queue filled to the payload-count bound with normal-size turns must not
        // be byte-isolated: the count bound is what governs honest lagging traffic.
        let sessions: Sessions = Arc::default();
        let k = key();
        let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, inbox1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        g0.disarm();
        g1.disarm();

        // A few hundred command bytes is a generous normal turn; a full
        // count-bounded queue of them is only ~FORWARD_CAPACITY * 512 bytes, far
        // under the byte budget.
        const { assert!(FORWARD_CAPACITY * 512 < FORWARD_BYTE_BUDGET) };
        for _ in 0..FORWARD_CAPACITY {
            fan_out(&sessions, &k, SlotId(0), payload_of(512));
        }

        // The queue holds exactly the count bound and never crossed the byte
        // budget, so the slot was not signaled to disconnect.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
                .await
                .is_err(),
            "a count-full queue of normal turns must not trip the byte budget",
        );
    }

    #[tokio::test]
    async fn oversize_payloads_trip_the_byte_budget_before_the_count_bound() {
        // Max-oversize turns pin far more per payload, so a queue of them must be
        // byte-isolated well before it reaches the payload-count bound.
        let sessions: Sessions = Arc::default();
        let k = key();
        let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        g0.disarm();
        g1.disarm();

        // Never drain slot 1: fan out max-oversize turns until the budget trips.
        // The byte budget admits exactly FORWARD_BYTE_BUDGET / oversize-len turns,
        // which is a quarter of the count bound.
        let admitted = FORWARD_BYTE_BUDGET / MAX_OVERSIZE_TURN_COMMANDS_LEN;
        assert!(
            admitted < FORWARD_CAPACITY,
            "the budget trips before the count bound"
        );
        for _ in 0..FORWARD_CAPACITY {
            fan_out(
                &sessions,
                &k,
                SlotId(0),
                payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
            );
        }

        // The slot was signaled to disconnect (the byte budget, not the count
        // bound)...
        tokio::time::timeout(Duration::from_millis(100), inbox1.shutdown.notified())
            .await
            .expect("the oversize spray trips the byte budget");

        // ...and only the under-budget turns were ever enqueued — far fewer than
        // the count bound would have allowed.
        let mut resident = 0;
        while inbox1.forward_rx.try_recv().is_some() {
            resident += 1;
        }
        assert_eq!(resident, admitted);
    }

    #[tokio::test]
    async fn draining_the_forward_queue_frees_the_byte_budget() {
        // The budget is resident bytes, not a cumulative total: a queue filled to
        // the budget accepts again once its turns are drained.
        let sessions: Sessions = Arc::default();
        let k = key();
        let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0)).expect("slot 0 registers");
        let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        g0.disarm();
        g1.disarm();

        let admitted = FORWARD_BYTE_BUDGET / MAX_OVERSIZE_TURN_COMMANDS_LEN;
        // Fill the queue right up to the budget — every turn lands, none isolates.
        for _ in 0..admitted {
            fan_out(
                &sessions,
                &k,
                SlotId(0),
                payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
                .await
                .is_err(),
            "a queue filled exactly to the budget must not isolate",
        );

        // Drain every turn; each drain releases its bytes from the resident count.
        for _ in 0..admitted {
            assert!(inbox1.forward_rx.recv().await.is_some());
        }

        // The freed budget accepts a fresh full batch, again without isolating —
        // proving the count tracks resident bytes, not a running total.
        for _ in 0..admitted {
            fan_out(
                &sessions,
                &k,
                SlotId(0),
                payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
                .await
                .is_err(),
            "a drained queue must accept a fresh batch up to the budget",
        );
        let mut resident = 0;
        while inbox1.forward_rx.try_recv().is_some() {
            resident += 1;
        }
        assert_eq!(resident, admitted);
    }

    #[tokio::test]
    async fn mesh_turn_preserves_an_upstream_stamp_on_a_non_authority_relay() {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::messages::BufferDirective;

        let sessions: Sessions = Arc::default();
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
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );

        // A local client to fan out to.
        let (mut guard, mut inbox) = register(&sessions, &k, SlotId(1)).expect("slot 1 registers");
        guard.disarm();

        // A turn stamped by the authority arrives over the mesh.
        let stamp = BufferDirective {
            buffer_turns: 6,
            apply_at_frame: 40,
            decision_seq: 5,
            authority_relay_id: None,
        };
        let stamped = Payload {
            buffer_directive: Some(stamp),
            commands: vec![0x05].into(),
            ..payload()
        };
        let mut mesh_state = crate::mesh::new_mesh_state();
        mesh_state.seen = seen.clone();
        mesh_state.decision_makers = makers.clone();
        mesh_state.turn_ring = turn_ring.clone();
        crate::mesh::deliver_mesh_turn(
            &sessions,
            &mesh_state,
            &k,
            SlotId(0),
            stamped,
            rally_point_proto::ids::RelayId(2),
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
            let _ = maker.sync(
                BufferBounds::new(0, 20).unwrap(),
                Authority::SelfRelay,
                &std::collections::HashSet::new(),
            );
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
                    connection_epoch: None,
                }],
            },
        )
        .expect("promoted, its first decision fires");
        let own = consensus::active_directive(&makers, &k).expect("a directive is queued");
        assert!(
            own.decision_seq > stamp.decision_seq,
            "a promoted relay continues the session's numbering",
        );

        // A redundant copy of the stamped turn is dropped before local fan-out,
        // stamp and all.
        let duplicate = Payload {
            buffer_directive: Some(stamp),
            commands: vec![0x05].into(),
            ..payload()
        };
        crate::mesh::deliver_mesh_turn(
            &sessions,
            &mesh_state,
            &k,
            SlotId(0),
            duplicate,
            rally_point_proto::ids::RelayId(2),
        );
        assert!(
            inbox.forward_rx.try_recv().is_none(),
            "the session-level duplicate is dropped",
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
    /// Like [`drop_hold_harness`], but the session runs the finalized-drop
    /// handshake and this relay strictly homes `homed`.
    fn finalized_drop_harness(
        key: &SessionKey,
        survivor: SlotId,
        departing: SlotId,
        homed: &[u8],
    ) -> (
        Sessions,
        crate::mesh::MeshLinks,
        Arc<crate::consensus::DecisionMakers>,
        crate::mesh::SeenRegistries,
        SlotInbox,
    ) {
        use crate::consensus::{self, Authority};
        use rally_point_proto::control::BufferBounds;

        let sessions: Sessions = Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let makers = Arc::new(consensus::new_decision_makers());
        let seen = crate::mesh::new_seen_registries();
        let _ = consensus::sync_maker(
            &makers,
            key,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            homed.iter().map(|&s| SlotId(s)).collect(),
            std::collections::HashSet::new(),
            None,
            true,
        );
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
        (sessions, mesh_links, makers, seen, inbox)
    }

    /// An honored drop in a finalized-drops session whose target this relay
    /// strictly homes: the finalization runs inline, the hold is claimed, and
    /// the decided leave carries the sealed count with its proof.
    #[tokio::test]
    async fn an_honored_drop_finalizes_at_the_local_home() {
        let k = key();
        let (sessions, mesh_links, makers, seen, mut inbox) =
            finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0, 1]);
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
        // Three of the departed slot's turns were forwarded before it died.
        for seq in 0..3 {
            let _ = crate::mesh::mark_seen(&seen, &k, SlotId(1), seq);
        }

        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            test_state.seen = seen.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };

        let leave = inbox
            .leave_push_rx
            .try_recv()
            .expect("the finalized drop's leave reaches the survivor");
        assert_eq!(leave.reason, LEAVE_REASON_DROPPED);
        assert_eq!(
            leave.final_turn_count,
            Some(3),
            "the leave carries the home's sealed gap-free count",
        );
        assert!(leave.finalized, "with its proof");
        assert!(!holds.is_pending(&k, SlotId(1)), "the hold was claimed");
    }

    /// The same honor with no gap-free cursor fails closed: no leave, and the
    /// hold stays for a retry — never a frame-scheduled fallback.
    #[tokio::test]
    async fn an_honored_drop_without_a_cursor_stays_undecided() {
        let k = key();
        let (sessions, mesh_links, makers, seen, mut inbox) =
            finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0, 1]);
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

        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            test_state.seen = seen.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };

        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "no leave is decided without a sealable cursor",
        );
        assert!(
            holds.is_pending(&k, SlotId(1)),
            "the hold stays for a retry (or a reconnect)",
        );
    }

    /// An honored drop whose target a peer homes asks that home over the mesh
    /// instead of deciding anything locally.
    #[tokio::test]
    async fn an_honored_drop_with_a_remote_home_asks_over_the_mesh() {
        let k = key();
        // Non-empty homed set that does NOT contain the target: a peer's job.
        let (sessions, mesh_links, makers, seen, mut inbox) =
            finalized_drop_harness(&k, SlotId(0), SlotId(1), &[0]);
        let (fwd_tx, _fwd_rx) = tokio::sync::mpsc::channel(FORWARD_CAPACITY);
        let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel();
        let _link = crate::mesh::register_mesh_link(
            &mesh_links,
            k.clone(),
            fwd_tx,
            ctl_tx,
            Arc::new(tokio::sync::Notify::new()),
        );
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

        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            test_state.seen = seen.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };

        let frame = ctl_rx.try_recv().expect("a FinalizeDrop went to the mesh");
        assert!(
            matches!(
                frame.kind,
                Some(rally_point_proto::messages::mesh_control_frame::Kind::FinalizeDrop(ref f))
                    if f.slot == 1
            ),
            "the home is asked to finalize; got {:?}",
            frame.kind,
        );
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "nothing is decided until the home answers",
        );
        assert!(holds.is_pending(&k, SlotId(1)), "the hold stays meanwhile");
    }

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
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
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
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };
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

        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };
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
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };
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
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            honor_drop_request(&sessions, &test_state, &k, SlotId(1), 0);
        };
        assert!(
            inbox.leave_push_rx.try_recv().is_err(),
            "a request for an already-decided slot decides nothing further",
        );

        // A request naming the requester itself is rejected at the edge before any
        // hold check or fan-out — the survivor (slot 0) here is not disconnected.
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            handle_drop_request(&sessions, &test_state, &k, SlotId(0), 0);
        };
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
        {
            let mut test_state = crate::mesh::new_mesh_state();
            test_state.drop_holds = holds.clone();
            test_state.decision_makers = makers.clone();
            test_state.links = mesh_links.clone();
            handle_drop_request(&sessions, &test_state, &k, SlotId(0), 1);
        };
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
            {
                let mut test_state = crate::mesh::new_mesh_state();
                test_state.drop_holds = holds.clone();
                test_state.decision_makers = makers.clone();
                test_state.links = mesh_links.clone();
                handle_drop_request(&sessions, &test_state, &k, SlotId(0), 1);
            };
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

    /// Guards against the stale-snapshot race the `serve_connection` admission fix
    /// closes: if a reconnect for the same slot wins the roster race and registers
    /// before this (now-stale) disconnect teardown reaches `announce_departure`,
    /// the disconnect must not mark a hold or record a departure for it. Doing so
    /// would orphan a hold against a connected player — a later `RequestDrop`
    /// could honor a drop against them — and would leave a permanent departure
    /// record with no hold to ever release it, wrongly refusing every later
    /// reconnect for the slot.
    #[tokio::test]
    async fn a_disconnect_announcement_stands_down_when_the_slot_has_already_reconnected() {
        let k = key();
        let (sessions, mesh_links, makers, _inbox) = drop_hold_harness(&k, SlotId(0), SlotId(1));
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);

        // Simulate a reconnect for slot 1 winning the roster race: it registers
        // before this (stale, racing) disconnect teardown reaches the
        // announcement below -- mirroring a concurrent `serve_connection`
        // acquiring the roster lock first.
        let (mut reconnect_guard, _reconnect_inbox) =
            register(&sessions, &k, SlotId(1)).expect("the reconnect claims the roster seat");
        reconnect_guard.disarm();

        // The disconnect's teardown -- unaware the seat was already reclaimed --
        // reaches its announcement.
        announce_departure(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &crate::provisional_turns::ProvisionalTurnPen::default(),
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
            None,
            None,
        );

        assert!(
            !holds.is_pending(&k, SlotId(1)),
            "no hold was marked against the already-reconnected slot",
        );
        assert!(
            !consensus::slot_departed(&makers, &k, SlotId(1)),
            "no departure record was written against the already-reconnected slot -- \
             an orphaned record would wrongly refuse every later reconnect for the slot",
        );
    }

    #[test]
    fn old_link_teardown_cannot_erase_a_replacement_epoch() {
        use crate::consensus::Authority;
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::GameFrameCount;
        use rally_point_proto::messages::SlotConditions;

        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        let k = key();
        let _ = consensus::sync_maker(
            &mesh.decision_makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::Peer,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        let replacement = SlotConditions {
            slot: 0,
            rtt_us: 30_000,
            lost_packets: 0,
            sent_packets: 1,
            connection_epoch: Some(22),
        };
        crate::mesh::activate_conditions(&mesh.conditions, &k, SlotId(0), replacement);
        let _ = consensus::ingest_local_condition(&mesh.decision_makers, &k, &replacement);
        consensus::observe_frame(&mesh.decision_makers, &k, SlotId(0), GameFrameCount(40));

        // The old task has already freed its roster seat and is finishing its
        // cleanup after the replacement published epoch 22.
        end_slot_link(&sessions, &mesh, &k, SlotId(0), 11, false);

        let published = crate::mesh::snapshot_conditions(&mesh.conditions, &k)
            .expect("replacement conditions survive stale teardown");
        assert_eq!(published.slots[0].connection_epoch, Some(22));
        assert_eq!(
            consensus::slot_frame(&mesh.decision_makers, &k, SlotId(0)),
            Some(GameFrameCount(40)),
        );
        assert!(!consensus::slot_departed(
            &mesh.decision_makers,
            &k,
            SlotId(0),
        ));
        assert!(!mesh.drop_holds.is_pending(&k, SlotId(0)));
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
        let presence = Arc::new(presence::new_presence_registry());
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
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
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
        report_own_presence(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
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
            &crate::provisional_turns::ProvisionalTurnPen::default(),
            &k,
            SlotId(0),
            LEAVE_REASON_DROPPED,
            None,
            None,
        );
        report_own_presence(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        deregister(&sessions, &k, SlotId(1));
        announce_departure(
            &holds,
            &makers,
            &sessions,
            &mesh_links,
            &crate::provisional_turns::ProvisionalTurnPen::default(),
            &k,
            SlotId(1),
            LEAVE_REASON_DROPPED,
            None,
            None,
        );
        report_own_presence(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );

        assert!(
            holds.is_pending(&k, SlotId(0)) && holds.is_pending(&k, SlotId(1)),
            "both drops marked a hold",
        );
        assert!(
            !makers.lock().get(&k).unwrap().is_authority(),
            "the emptied roster demoted the relay to a peer",
        );

        // Slot 0 re-registers while its drop is still held: register, then claim +
        // reinstate atomically as the server does, then report presence — which
        // re-promotes.
        let (mut r0, _ri0) = register(&sessions, &k, SlotId(0)).expect("slot 0 re-registers");
        r0.disarm();
        assert!(
            holds.take_if_pending(&k, SlotId(0), || consensus::reinstate_slot(
                &makers,
                &k,
                SlotId(0)
            )),
            "the hold was pending and reinstate succeeded",
        );
        report_own_presence(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        assert!(
            makers.lock().get(&k).unwrap().is_authority(),
            "the first return re-promoted the relay — the flap the fix must survive",
        );

        // Slot 1 re-registers too.
        let (mut r1, _ri1) = register(&sessions, &k, SlotId(1)).expect("slot 1 re-registers");
        r1.disarm();
        assert!(
            holds.take_if_pending(&k, SlotId(1), || consensus::reinstate_slot(
                &makers,
                &k,
                SlotId(1)
            )),
            "the hold was pending and reinstate succeeded",
        );
        report_own_presence(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );

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

        fan_out_connectivity(&sessions, &k, SlotId(3), false, None);

        let a = inbox0.conn_push_rx.try_recv().expect("slot 0 hears it");
        assert_eq!(a, (SlotId(3), false, None));
        let b = inbox1.conn_push_rx.try_recv().expect("slot 3 hears it too");
        assert_eq!(b, (SlotId(3), false, None));
    }

    // -- fully-abandoned session teardown --

    /// A short abandoned-session window for tests, so the timer path can be driven
    /// with a real (tiny) sleep rather than the production 45 seconds.
    const TINY_ABANDON: Duration = Duration::from_millis(80);

    /// Bundles individually-constructed registries into the `MeshState` that
    /// `report_own_presence` / `reconcile_abandon` take, leaving the registries a
    /// test doesn't drive at their empty defaults. Every field is a shared
    /// handle, so the test's own bindings and the bundle observe the same state.
    fn mesh_with(
        holds: &DropHolds,
        makers: &Arc<crate::consensus::DecisionMakers>,
        mesh_links: &crate::mesh::MeshLinks,
        presence: &Arc<crate::presence::PresenceRegistry>,
    ) -> crate::mesh::MeshState {
        crate::mesh::MeshState {
            drop_holds: holds.clone(),
            decision_makers: Arc::clone(makers),
            links: mesh_links.clone(),
            presence: Arc::clone(presence),
            ..crate::mesh::new_mesh_state()
        }
    }

    /// A started, single-relay authority session over slots {0, 1} with a frame
    /// basis for each and this relay's presence order set to itself. No departures
    /// are recorded — each test records exactly the ones it needs and drives the
    /// own-roster presence count. Returns the registries the abandoned-session tests
    /// reconcile against.
    fn abandoned_harness() -> (
        Arc<crate::presence::PresenceRegistry>,
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
        let presence = Arc::new(crate::presence::new_presence_registry());
        let _ = consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0), SlotId(1)].into_iter().collect(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        consensus::mark_session_started(&makers, &k);
        consensus::observe_frame(&makers, &k, SlotId(0), GameFrameCount(50));
        consensus::observe_frame(&makers, &k, SlotId(1), GameFrameCount(50));
        crate::presence::set_order(&presence, &k, vec![Candidate::SelfRelay]);
        crate::presence::record_own(&presence, &k, 1);
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
            crate::consensus::DepartureStamps {
                last_frame: Some(rally_point_proto::ids::GameFrameCount(50)),
                ..Default::default()
            },
            LEAVE_REASON_DROPPED,
        );
        holds.hold(k.clone(), slot);
    }

    /// Leaves `slot` departed with its hold already gone: undecided, so it arms
    /// the abandoned-session timer, but promising no reconnect, so the
    /// session-emptied close runs instead of deferring — the state a departure
    /// whose hold has been released leaves behind.
    fn depart_slot_unheld(
        makers: &Arc<crate::consensus::DecisionMakers>,
        holds: &DropHolds,
        k: &SessionKey,
        slot: SlotId,
    ) {
        drop_slot(makers, holds, k, slot);
        assert!(holds.release(k, slot), "the departure's hold is released");
    }

    /// Drains `rx` and counts the session-closed notices in it.
    fn closes_reported(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::consensus::RelayNotice>,
    ) -> usize {
        let mut closes = 0;
        while let Ok(notice) = rx.try_recv() {
            if matches!(notice, crate::consensus::RelayNotice::SessionClosed { .. }) {
                closes += 1;
            }
        }
        closes
    }

    /// Regression for a relay assigned to a multi-relay session whose own client
    /// never connected. The peer connected briefly but the full expected roster
    /// never formed, so the relay session never reached `started`; once that peer
    /// reports zero, this relay still has to run the ordinary close.
    #[test]
    fn peer_zero_closes_a_never_started_session_on_a_relay_with_no_local_slots() {
        use crate::consensus::{self, Authority, RelayNotice};
        use crate::presence::Candidate;
        use rally_point_proto::control::BufferBounds;
        use rally_point_proto::ids::RelayId;

        let k = key();
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
        let _ = consensus::sync_maker(
            &mesh.decision_makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            std::collections::HashSet::new(),
            [SlotId(0), SlotId(1)].into_iter().collect(),
            [SlotId(0)].into_iter().collect(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        assert!(
            !consensus::session_started(&mesh.decision_makers, &k),
            "only one peer ever connected, so the session never started",
        );
        crate::presence::set_order(
            &mesh.presence,
            &k,
            vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.decision_makers.set_notice_notifier(tx);

        // No slot was ever inserted into `sessions`, and deliberately no
        // `record_own(0)` call was made. The local roster itself is authoritative.
        // The peer was briefly live, matching the incident: activity happened,
        // but the full expected roster never formed on this relay.
        assert!(
            !crate::presence::record_peer(&mesh.presence, &k, RelayId(2), 1,),
            "the unknown peer was already conservatively treated as live"
        );
        reconcile_abandon(&sessions, &mesh, &k);
        assert!(
            rx.try_recv().is_err(),
            "a live peer keeps the serving state open",
        );
        assert!(crate::presence::record_peer(
            &mesh.presence,
            &k,
            RelayId(2),
            0,
        ));
        reconcile_abandon(&sessions, &mesh, &k);

        assert_eq!(
            rx.try_recv(),
            Ok(RelayNotice::SessionClosed {
                tenant: k.tenant.clone(),
                session: k.session,
            }),
        );
        assert!(
            !mesh.drop_holds.abandon_armed(&k),
            "a clean empty session has no departures to time out",
        );
    }

    /// A relay closes only after every named peer explicitly reports zero. Both
    /// silence and a positive report keep the session open even when the local
    /// roster is empty.
    #[test]
    fn unknown_or_live_peer_presence_blocks_the_empty_session_close() {
        use crate::presence::Candidate;
        use rally_point_proto::ids::RelayId;

        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        crate::presence::set_order(
            &presence,
            &k,
            vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
        );
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        let mesh = mesh_with(&holds, &makers, &mesh_links, &presence);

        reconcile_abandon(&sessions, &mesh, &k);
        assert!(
            rx.try_recv().is_err(),
            "an unknown peer is assumed live and blocks close",
        );

        crate::presence::record_peer(&presence, &k, RelayId(2), 1);
        reconcile_abandon(&sessions, &mesh, &k);
        assert!(
            rx.try_recv().is_err(),
            "an explicitly live peer blocks close",
        );
    }

    /// Every player dropping leaves the session empty session-wide with undecided
    /// departures; past the abandoned-session window, they are all decided so the
    /// session can proceed to its normal teardown — including the session-emptied
    /// close those undecided departures had been deferring.
    #[tokio::test]
    async fn all_players_dropping_decides_every_departure_after_the_abandon_timeout() {
        use crate::consensus::RelayNotice;

        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        // The session goes empty session-wide.
        crate::presence::record_own(&presence, &k, 0);

        assert!(crate::consensus::has_undecided_departure(&makers, &k));
        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
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
        let mut saw_closed = false;
        while let Ok(notice) = rx.try_recv() {
            saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
        }
        assert!(
            saw_closed,
            "the expiry's decides ran the deferred session-emptied close",
        );
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
        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        assert!(holds.abandon_armed(&k));

        // Slot 0 re-registers: claim its hold and reinstate its departure
        // atomically, and report the roster live again — the server's
        // re-register path — then reconcile.
        assert!(
            holds.take_if_pending(&k, SlotId(0), || crate::consensus::reinstate_slot(
                &makers,
                &k,
                SlotId(0)
            ))
        );
        let (_registration, _inbox) =
            register(&sessions, &k, SlotId(0)).expect("the returning slot registers");
        crate::presence::record_own(&presence, &k, 1);
        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
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

    /// An expiry that races a re-registration and loses the cancellation (the
    /// sleep completed in the same instant the cancel landed) must still not
    /// force-decide: the expiry re-derives the abandoned condition, finds a
    /// slot live again on the local roster, and stands down — leaving the other
    /// slot's drop held for the live machinery (the returned survivor's drop
    /// request, or a later re-abandonment) instead of force-deciding it out
    /// from under a live session.
    #[test]
    fn an_expiry_that_lost_the_cancel_race_stands_down_when_a_slot_is_live_again() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);

        // Slot 0 re-registers exactly as the server's re-register path does...
        assert!(
            holds.take_if_pending(&k, SlotId(0), || crate::consensus::reinstate_slot(
                &makers,
                &k,
                SlotId(0)
            ))
        );
        let (_registration, _inbox) =
            register(&sessions, &k, SlotId(0)).expect("the returning slot registers");
        crate::presence::record_own(&presence, &k, 1);

        // ...and the expiry callback fires anyway (the ordering where its sleep
        // completed before the cancellation reached the select).
        decide_and_broadcast_abandoned(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
            false,
        );

        assert!(
            crate::consensus::has_undecided_departure(&makers, &k),
            "the raced expiry decided nothing",
        );
        assert!(
            holds.is_pending(&k, SlotId(1)),
            "the other slot's drop is still held for the live session",
        );
        assert_eq!(closes_reported(&mut rx), 0, "no close was reported");
    }

    /// The same stand-down applies when the liveness is on a peer relay: an
    /// expiry that finds a peer explicitly reporting a live slot leaves the
    /// departures held.
    #[test]
    fn an_expiry_stands_down_when_a_peer_reports_a_live_slot() {
        use crate::presence::Candidate;
        use rally_point_proto::ids::RelayId;

        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        crate::presence::set_order(
            &presence,
            &k,
            vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
        );
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        drop_slot(&makers, &holds, &k, SlotId(0));
        drop_slot(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);
        crate::presence::record_peer(&presence, &k, RelayId(2), 1);

        decide_and_broadcast_abandoned(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
            false,
        );

        assert!(
            crate::consensus::has_undecided_departure(&makers, &k),
            "a peer's live slot keeps the departures held",
        );
        assert_eq!(closes_reported(&mut rx), 0, "no close was reported");
    }

    /// The timer never arms while at least one slot is live session-wide, no matter
    /// how many others have dropped.
    #[tokio::test]
    async fn the_timer_never_arms_while_a_slot_is_live() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        drop_slot(&makers, &holds, &k, SlotId(1));
        // Slot 0 is still connected: the session is not empty session-wide.
        let (_registration, _inbox) =
            register(&sessions, &k, SlotId(0)).expect("the live slot registers");
        crate::presence::record_own(&presence, &k, 1);

        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
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
        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
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

    /// A window that elapses on a session this relay already closed reports no
    /// A retired session's emptied-close evaluation is refused by the ingress
    /// gate outright: with the maker swept, the no-maker close default would
    /// otherwise claim and report a second SessionClosed.
    #[test]
    fn a_retired_sessions_emptied_close_reports_nothing() {
        let sessions: Sessions = Arc::default();
        let mesh = crate::mesh::new_mesh_state();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.decision_makers.set_notice_notifier(tx);
        let k = key();

        mesh.gates.retire(&k);
        maybe_close_emptied_session(&sessions, &mesh, &k);
        assert!(
            rx.try_recv().is_err(),
            "a retired session's close evaluation reports nothing",
        );
    }

    /// second close — not even once the decision-maker is gone, which is what a
    /// retired session's descriptor removal leaves behind and which takes the
    /// close-report latch with it.
    #[tokio::test]
    async fn an_elapsed_window_reports_no_second_close_for_a_closed_session() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        // Both slots are gone with nothing holding them: the timer arms, and the
        // close runs rather than deferring on a promised reconnect.
        depart_slot_unheld(&makers, &holds, &k, SlotId(0));
        depart_slot_unheld(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);

        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        assert!(holds.abandon_armed(&k), "the emptying armed the timer");
        assert_eq!(closes_reported(&mut rx), 1, "the emptying reported a close");

        // The coordinator retires the session and drops its descriptor.
        crate::consensus::deregister_maker(&makers, &k);

        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert_eq!(
            closes_reported(&mut rx),
            0,
            "the elapsed window left the reported close alone",
        );
    }

    /// The window still force-decides after a close: the close ends this relay's
    /// serving state, not the departures the timer was armed to decide.
    #[tokio::test]
    async fn an_elapsed_window_still_decides_departures_after_a_close() {
        let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        makers.set_notice_notifier(tx);
        depart_slot_unheld(&makers, &holds, &k, SlotId(0));
        depart_slot_unheld(&makers, &holds, &k, SlotId(1));
        crate::presence::record_own(&presence, &k, 0);

        reconcile_abandon(
            &sessions,
            &mesh_with(&holds, &makers, &mesh_links, &presence),
            &k,
        );
        assert_eq!(closes_reported(&mut rx), 1, "the emptying reported a close");
        assert!(
            crate::consensus::has_undecided_departure(&makers, &k),
            "the close decided nothing on its own",
        );

        tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
        assert!(
            !crate::consensus::has_undecided_departure(&makers, &k),
            "the elapsed window decided the abandoned session's departures",
        );
        assert_eq!(
            closes_reported(&mut rx),
            0,
            "deciding them reported no further close",
        );
    }

    /// Drives the send-phase control loop end to end across the module seams a
    /// real session crosses: client-edge arrivals fold into the session's
    /// controller, the correction it issues is fanned to exactly the slot it
    /// names, the connect-time re-push reads the same value back, and nothing
    /// at all happens before the session starts.
    #[test]
    fn phase_corrections_fan_to_the_corrected_slot_and_survive_for_repush() {
        use rally_point_proto::control::BufferBounds;
        use std::time::{Duration, Instant};

        let sessions: Sessions = Arc::default();
        let makers = Arc::new(consensus::new_decision_makers());
        let k = key();
        let _ = consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(1, 6).unwrap(),
            crate::consensus::Authority::SelfRelay,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            None,
            false,
        );
        let (_reg0, mut inbox0) = register(&sessions, &k, SlotId(0)).unwrap();
        let (_reg1, mut inbox1) = register(&sessions, &k, SlotId(1)).unwrap();

        let turn_us: u64 = 41_667;
        let base = Instant::now();
        let feed = |makers: &consensus::DecisionMakers, slot: u8, seq: u64, offset_us: u64| {
            let at = base + Duration::from_micros(seq * turn_us + offset_us);
            makers
                .lock()
                .get_mut(&k)
                .unwrap()
                .ingest_arrival_phase(SlotId(slot), seq, at)
        };

        // Before the session starts nothing is recorded, however long the flow.
        for seq in 0..400u64 {
            assert!(feed(&makers, 0, seq, 0).is_empty());
            assert!(feed(&makers, 1, seq, 15_000).is_empty());
        }
        consensus::mark_session_started(&makers, &k);

        // Steady post-start flow: slot 0 at the cycle's base phase, slot 1
        // fifteen milliseconds later. The controller evaluates on its own
        // schedule and eventually asks slot 0 (the early one) to delay onto
        // slot 1's phase; slot 1, already the latest, is left alone.
        let mut corrections = Vec::new();
        for seq in 400..900u64 {
            corrections = feed(&makers, 0, seq, 0);
            assert!(corrections.is_empty() || corrections[0].0 == SlotId(0));
            if !corrections.is_empty() {
                break;
            }
            corrections = feed(&makers, 1, seq, 15_000);
            assert!(corrections.is_empty(), "the latest slot is never corrected");
        }
        let &[(corrected, delay_us)] = corrections.as_slice() else {
            panic!("expected exactly one correction, got {corrections:?}");
        };
        assert_eq!(corrected, SlotId(0));
        assert!(
            (6_000..=8_000).contains(&delay_us),
            "slot 0 takes a capped first step toward slot 1's phase, got {delay_us}"
        );

        // Fan-out reaches exactly the corrected slot, carrying the delay.
        fan_out_phase_directives(&sessions, &k, &corrections);
        let directive = inbox0
            .try_recv_phase_directive()
            .expect("the corrected slot receives its directive");
        assert_eq!(directive.delay_us, delay_us);
        assert!(directive.slew_us_per_s > 0);
        assert_eq!(
            inbox1.try_recv_phase_directive(),
            None,
            "an uncorrected slot receives nothing",
        );

        // The commanded value survives on the maker for the connect-time
        // re-push a reconnecting slot gets.
        assert_eq!(
            consensus::commanded_phase_delay(&makers, &k, SlotId(0)),
            Some(delay_us),
        );
        assert_eq!(
            consensus::commanded_phase_delay(&makers, &k, SlotId(1)),
            None
        );
        deliver_phase_directive_to_slot(
            &sessions,
            &k,
            SlotId(0),
            PhaseDirective {
                delay_us,
                slew_us_per_s: crate::phase::SLEW_US_PER_S,
            },
        );
        assert_eq!(
            inbox0.try_recv_phase_directive().map(|d| d.delay_us),
            Some(delay_us),
        );
    }
}
