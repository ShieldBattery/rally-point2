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
use rally_point_transport::control::ControlInbound;
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::quinn::VarInt;
use rally_point_transport::{Link, LinkError};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep_until};

use crate::consensus;
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

/// The native SC:R `pending_leave_reason` value for a *dropped* player (shows
/// "player was dropped"), written into every remaining client's leave mailbox by
/// the synced-leave pass. A client's link ending — whether it quit, its network
/// died, or we isolated it for lagging — surfaces here as a drop; a clean quit
/// sends a leave-intent up the control stream first, which the relay decides
/// under [`LEAVE_REASON_LEFT`] instead so survivors see "player left", and the
/// game side supplies its own reason for a player-requested drop.
const LEAVE_REASON_DROPPED: u32 = 0x4000_0006;

/// The native SC:R `pending_leave_reason` value a voluntary quit produces on
/// every other client natively (shows "player left"): this is exactly what
/// SC:R's own quit path writes into a peer's leave mailbox, so a synced leave
/// decided from a client's leave-intent renders with the identical wording a
/// native (non-networked) game would already show. Any nonzero value other
/// than [`LEAVE_REASON_DROPPED`]'s `0x40000006` renders "player left", but this
/// one is chosen to match the native value rather than an arbitrary nonzero.
const LEAVE_REASON_LEFT: u32 = 3;

/// QUIC application close code for a connection the relay closes on its own
/// initiative after processing a client's leave-intent. Not an error: the
/// client's control-stream announcement is never acked on its own terms — the
/// relay closing the link *is* the confirmation the departing client's driver
/// waits for once it has sent its intent.
const LEAVE_PROCESSED_CLOSE: u32 = 0x05;

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
    shutdown: Arc<Notify>,
}

/// The receiving end of a registered slot, handed to its link task: the queue of
/// turns to deliver to the client, and the signal to shut the link down.
pub struct SlotInbox {
    forward_rx: mpsc::Receiver<Payload>,
    /// Leaves to push down this client's control stream (see [`SlotEntry::leave_push`]).
    leave_push_rx: mpsc::Receiver<LeaveDirective>,
    shutdown: Arc<Notify>,
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
        shutdown,
    };
    Some((registration, inbox))
}

/// Removes `slot` from the `key` routing group's roster, dropping the group entry
/// once its last slot leaves. Idempotent: removing an absent slot is a no-op, so a
/// guard and a link task can both run it without double-free hazard.
fn deregister(sessions: &Sessions, key: &SessionKey, slot: SlotId) {
    let mut roster = sessions.lock();
    if let Some(slots) = roster.get_mut(key) {
        slots.remove(&slot);
        if slots.is_empty() {
            roster.remove(key);
        }
    }
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
    inbox: SlotInbox,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
) {
    let SlotInbox {
        mut forward_rx,
        mut leave_push_rx,
        shutdown,
    } = inbox;
    let crate::mesh::MeshState {
        links: mesh_links,
        seen: seen_registries,
        conditions,
        decision_makers,
        presence,
    } = mesh;

    // This client joining may change who decides the session's buffer — most
    // notably a first client arriving on the relay that heads the authority
    // order, which turns the descriptor-time verdict into a live one. The
    // roster already includes this slot (registration preceded this task), so
    // report it and re-derive. The peers learn the new count from the mesh
    // drivers' presence reconcile, off the same roster.
    report_own_presence(&presence, &decision_makers, &sessions, &key);

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
            deregister(&sessions, &key, slot);
            report_own_presence(&presence, &decision_makers, &sessions, &key);
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
            deregister(&sessions, &key, slot);
            report_own_presence(&presence, &decision_makers, &sessions, &key);
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
    // The highest cursor the relay has pushed to the client, per slot. Push only
    // on advance.
    let mut last_beacon_sent: HashMap<SlotId, u64> = HashMap::new();
    // Whether the inbound beacon reader task is still feeding cursors. Once it
    // ends (the client's beacon uni-stream closed or errored), `recv()` returns
    // `None` — an always-ready future that would spin the loop at 100% CPU.
    // Disabling this branch on the first `None` keeps the task asleep; the real
    // link failure surfaces via `link.recv()`.
    let mut beacon_alive = true;

    // Whether we've received from this client since we last sent it a packet. Every
    // packet we send folds in the latest acks, so a forwarded turn clears this too,
    // and the flush only needs to carry acks when no forward has.
    let mut acks_owed = false;
    // The next maintenance flush. Pushed out whenever a forwarded turn re-carries
    // unacked turns (recovery is riding the forward stream, so no flush is due); left
    // to fire when a forward carries no redundancy or the link is idle, so a turn the
    // fresh packets can't re-carry is still retransmitted.
    let mut flush_deadline = Instant::now() + FLUSH_INTERVAL;

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
                            // Only a *validated* turn's frame feeds the consensus
                            // coordinate — a rejected packet must not leave a
                            // trace in decision state. (And the coordinate is the
                            // minimum across slots, so even a validated turn's
                            // inflated claim can only mislead its own slot.)
                            if let Some(frame) = payload.game_frame_count {
                                consensus::observe_frame(
                                    &decision_makers,
                                    &key,
                                    slot,
                                    rally_point_proto::ids::GameFrameCount(frame),
                                );
                            }
                            crate::mesh::forward_turn(
                                &sessions,
                                &mesh_links,
                                &seen_registries,
                                &decision_makers,
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
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some(payload) => {
                        let fits = match link.payload_fits(&payload) {
                            Ok(fits) => fits,
                            Err(error) => {
                                log_link_closed(&key, slot, &error);
                                break 'serve;
                            }
                        };
                        if !fits {
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
                    // The post-loop Trigger-A `decide_leave` below still
                    // runs on the way out, but it dedups by slot and finds
                    // this one already decided, so it is a no-op there --
                    // deregistration, the presence report, and the
                    // decision-maker's per-slot cleanup all run exactly as
                    // they would for a dropped client. On a relay that
                    // isn't this session's authority `decide_leave` returns
                    // `None` here just as it does for a drop -- routing a
                    // peer relay's own client's intent to the authority over
                    // the mesh (`SlotDeparted`) is the same known gap as
                    // Trigger A, not yet wired.
                    Some(ControlInbound::LeaveIntent) => {
                        tracing::info!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            "client announced clean leave",
                        );
                        if let Some(leave) = crate::consensus::decide_leave(
                            &decision_makers,
                            &key,
                            slot,
                            LEAVE_REASON_LEFT,
                        ) {
                            fan_out_leave(&sessions, &key, slot, leave);
                        }
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
                                // coordinate, exactly as on the datagram path.
                                if let Some(frame) = payload.game_frame_count {
                                    consensus::observe_frame(
                                        &decision_makers,
                                        &key,
                                        slot,
                                        rally_point_proto::ids::GameFrameCount(frame),
                                    );
                                }
                                crate::mesh::forward_turn(
                                    &sessions,
                                    &mesh_links,
                                    &seen_registries,
                                    &decision_makers,
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

    deregister(&sessions, &key, slot);
    crate::mesh::unpublish_conditions(&conditions, &key, slot);
    // Trigger A (synced player-leave): this client's link ended, so it has left
    // the game. Schedule a coordinated leave for its slot on the session's
    // authority, so every remaining client drops it from lockstep at the same
    // frame (rather than stalling on a slot that will never send another turn).
    // A no-op unless this relay is the authority; a departed client homed on a
    // peer relay reaches the authority via the mesh instead (SlotDeparted — not
    // yet wired). Must run *before* `remove_slot` below, which clears the slot's
    // last observed frame that the apply frame is computed from. On a decision,
    // push the leave down every surviving client's reliable control stream (the
    // departing slot is already off the roster from `deregister` above, so
    // `fan_out_leave` targets only survivors) — the turn stream has stopped for
    // them, so the reliable stream is the only channel that unstalls them.
    if let Some(leave) =
        crate::consensus::decide_leave(&decision_makers, &key, slot, LEAVE_REASON_DROPPED)
    {
        fan_out_leave(&sessions, &key, slot, leave);
    }
    // Forget this slot's condition history in the decision-maker so a departed
    // client's stale stats don't outlive its connection. The maker itself lives
    // until the session ends (the coordinator drops the descriptor).
    if let Some(maker) = decision_makers.lock().get_mut(&key) {
        maker.remove_slot(slot);
    }
    // This client leaving may hand the session's buffer authority to the next
    // relay in the order — the presence-driven half of the handoff. The local
    // verdict moves here; the peers hear the emptied roster from the mesh
    // drivers' presence reconcile.
    report_own_presence(&presence, &decision_makers, &sessions, &key);
}

/// Reports the current roster count for `key` into the presence registry and
/// re-derives the session's authority verdict when the report flipped this
/// relay's liveness. A session with no presence entry (no descriptor set an
/// order — dev/loopback harnesses that inject a verdict by hand) is left
/// untouched.
fn report_own_presence(
    presence: &crate::presence::PresenceRegistry,
    decision_makers: &crate::consensus::DecisionMakers,
    sessions: &Sessions,
    key: &SessionKey,
) {
    let live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    if crate::presence::record_own(presence, key, live) {
        crate::presence::recompute(presence, decision_makers, key);
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
        let k = key();

        // This relay is not the session's authority: its own maker never has a
        // directive, so the forward step must leave an incoming stamp alone.
        consensus::sync_maker(
            &makers,
            &k,
            BufferBounds::new(0, 20).unwrap(),
            Authority::Peer,
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
            maker.sync(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay);
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
            &k,
            SlotId(0),
            duplicate,
        );
        assert!(
            inbox.forward_rx.try_recv().is_err(),
            "the topological duplicate is dropped",
        );
    }
}
