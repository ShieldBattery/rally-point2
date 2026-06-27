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
//! and re-send its turns forever, so when a link has gone a short idle stretch with
//! no turn to forward back, it flushes an ack-only packet instead. The idle timer
//! resets on every packet sent, so a normal two-way game — where a forwarded turn
//! carries the acks each turn — keeps pushing it out and never reaches it.
//!
//! On a received turn the owning task runs it through [`validate_turn`]: the slot
//! is rebound to the one the client is authorized for (never the slot on the
//! wire), commands are bounds-checked, and the controls a live turn may not carry
//! are stripped. A turn that fails validation is a misbehaving or hostile client,
//! so its connection is closed. The fanned-out payload keeps its source slot — a
//! client needs to know whose commands these are — and is handed to each peer's
//! link, which stamps its own transport sequence as it goes out; the sequence the
//! sender used is discarded at the seam.
//!
//! Each routing group's roster is scoped by tenant *and* session: session ids are
//! only unique within a tenant, so two tenants can be assigned the same number and
//! must never share a game. A connection is added before its client is told it's
//! authorized and removed when its task ends, so fan-out always sees exactly the
//! slots currently able to receive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::quinn::VarInt;
use rally_point_transport::{Link, LinkError};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep_until};

use crate::validation::validate_turn;

/// How many outbound payloads may queue for one slot before fan-out to it applies
/// backpressure. Turns are small and drained promptly; a slot this far behind is
/// effectively a dead client. A real capacity/backpressure model is future work,
/// so this is deliberately generous rather than tuned.
const FORWARD_CAPACITY: usize = 1024;

/// QUIC application close code for a connection dropped because its client sent a
/// turn that failed validation.
const INVALID_TURN_CLOSE: u32 = 0x01;

/// QUIC application close code for a connection the relay disconnects because its
/// link fell hopelessly behind (its forward queue filled), isolating it so it can't
/// back-pressure healthy peers.
const ISOLATED_CLOSE: u32 = 0x04;

/// How long a link will go without sending before it flushes an ack-only packet to
/// carry acks it owes. The deadline resets on every packet sent, so in a normal
/// two-way game the forwarded turns — one per turn, ~40ms apart — keep pushing it
/// out and it never fires; it triggers only when a client gets no turns back for
/// this long (a lone slot, a quiet session, a stalled peer). Set to roughly three
/// to four turns at the 24-per-second turn rate: clear of ordinary jitter, while
/// keeping a one-way sender's unacked backlog to a few small turns.
const IDLE_ACK_DELAY: Duration = Duration::from_millis(150);

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
    shutdown: Arc<Notify>,
}

/// The receiving end of a registered slot, handed to its link task: the queue of
/// turns to deliver to the client, and the signal to shut the link down.
pub struct SlotInbox {
    forward_rx: mpsc::Receiver<Payload>,
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
    let shutdown = Arc::new(Notify::new());
    {
        let mut roster = sessions.lock().expect("sessions roster lock poisoned");
        let slots = roster.entry(key.clone()).or_default();
        if slots.contains_key(&slot) {
            return None;
        }
        slots.insert(
            slot,
            SlotEntry {
                forward: tx,
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
        shutdown,
    };
    Some((registration, inbox))
}

/// Removes `slot` from the `key` routing group's roster, dropping the group entry
/// once its last slot leaves. Idempotent: removing an absent slot is a no-op, so a
/// guard and a link task can both run it without double-free hazard.
fn deregister(sessions: &Sessions, key: &SessionKey, slot: SlotId) {
    let mut roster = sessions.lock().expect("sessions roster lock poisoned");
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
fn fan_out(sessions: &Sessions, key: &SessionKey, source: SlotId, payload: Payload) {
    let targets: Vec<(SlotId, ForwardTx, Arc<Notify>)> = {
        let roster = sessions.lock().expect("sessions roster lock poisoned");
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
) {
    let SlotInbox {
        mut forward_rx,
        shutdown,
    } = inbox;

    // Whether we've received from this client since we last sent it a packet. Every
    // packet we send folds in the latest acks, so a forwarded turn clears this too,
    // and a standalone ack-only flush is only needed when no forward has.
    let mut acks_owed = false;
    // When to flush an ack-only packet if nothing has been sent by then. Reset on
    // every send — never on receive — so steady forwarded traffic keeps pushing it
    // out, while a client that only sends still gets acked on this cadence.
    let mut ack_deadline = Instant::now() + IDLE_ACK_DELAY;

    'serve: loop {
        tokio::select! {
            received = link.recv() => {
                let payloads = match received {
                    Ok(payloads) => payloads,
                    Err(error) => {
                        log_link_closed(&key, slot, &error);
                        break 'serve;
                    }
                };
                acks_owed = true;
                for payload in payloads {
                    match validate_turn(slot, &payload.commands) {
                        Ok(turn) => fan_out(&sessions, &key, slot, turn.payload),
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
            }
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some(payload) => {
                        if let Err(error) = link.send(Some(payload)) {
                            log_link_closed(&key, slot, &error);
                            break 'serve;
                        }
                        acks_owed = false;
                        ack_deadline = Instant::now() + IDLE_ACK_DELAY;
                    }
                    // The roster dropped our sender: we've been deregistered.
                    None => break 'serve,
                }
            }
            _ = sleep_until(ack_deadline) => {
                // A full idle stretch with no turn to forward back. If we owe acks,
                // carry them on an ack-only packet so a client with no return traffic
                // still retires the turns it has sent us.
                if acks_owed {
                    if let Err(error) = link.send(None) {
                        log_link_closed(&key, slot, &error);
                        break 'serve;
                    }
                    acks_owed = false;
                }
                ack_deadline = Instant::now() + IDLE_ACK_DELAY;
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
                link.connection()
                    .close(VarInt::from_u32(ISOLATED_CLOSE), b"forward queue full");
                break 'serve;
            }
        }
    }

    deregister(&sessions, &key, slot);
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
        let roster = sessions.lock().expect("lock");
        let slots = roster.get(&k).expect("group present");
        assert!(slots.contains_key(&SlotId(1)));
        assert!(slots.contains_key(&SlotId(2)));
    }
}
