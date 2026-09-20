//! Delivering one thing to many slots — or to one named slot: turns onto the
//! datagram forward queues, and leaves, session starts, region labels, phase
//! directives, connectivity changes and load-state probes onto each slot's
//! reliable control-stream push channel. Every function here clones the senders
//! out under the roster lock and drops the lock before it sends, so no slow
//! client can park the caller.

use super::*;

use super::forward::ForwardOutcome;
use crate::observability::events::{FlightEvent, FlightEvents};

/// Clones one push sender per registered slot out from under the roster lock,
/// so nothing is ever sent with the lock held. `select` names which of a slot's
/// push channels to take; `except` drops one slot from the result (the departing
/// slot on a leave), and `None` keeps every slot.
fn collect_slot_senders<T>(
    sessions: &Sessions,
    key: &SessionKey,
    except: Option<SlotId>,
    select: impl Fn(&SlotEntry) -> mpsc::Sender<T>,
) -> Vec<(SlotId, mpsc::Sender<T>)> {
    let roster = sessions.lock();
    match roster.get(key) {
        Some(slots) => slots
            .iter()
            .filter(|(slot, _)| Some(**slot) != except)
            .map(|(slot, entry)| (*slot, select(entry)))
            .collect(),
        None => Vec::new(),
    }
}

/// Offers each collected target its value without blocking, which is all any of
/// the control-stream fan-outs do once the roster lock is gone. `what` names the
/// frame in the log line, and `subject` is the slot a frame is *about* when that
/// differs from the slot receiving it.
fn push_to_slots<T>(
    key: &SessionKey,
    what: &str,
    subject: Option<SlotId>,
    targets: impl IntoIterator<Item = (SlotId, mpsc::Sender<T>, T)>,
) {
    for (slot, tx, value) in targets {
        match tx.try_send(value) {
            // A full push queue is unexpected — these frames are rare and each
            // slot's link drains its queue promptly — so say so rather than let
            // the push vanish silently. What a lost one costs varies by frame: a
            // missed leave can leave a survivor stalled, a missed label map only
            // costs a display name.
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                subject = subject.map(|subject| subject.0),
                "{what} queue full; the push may be delayed for this slot",
            ),
            // The slot's task already ended; it needs nothing pushed to it.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
            Ok(()) => {}
        }
    }
}

/// Clones one named slot's push sender out from under the roster lock — `None`
/// when that slot is not currently registered.
fn slot_sender<T>(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    select: impl Fn(&SlotEntry) -> mpsc::Sender<T>,
) -> Option<mpsc::Sender<T>> {
    let roster = sessions.lock();
    roster
        .get(key)
        .and_then(|slots| slots.get(&slot))
        .map(select)
}

/// Offers one value down one named slot's control-stream push channel. A slot
/// absent from the roster (already gone) is skipped, and a full queue is simply
/// dropped: every caller is a connect-time re-push of state that a later
/// session-wide push restates anyway.
fn deliver_to_slot<T>(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    select: impl Fn(&SlotEntry) -> mpsc::Sender<T>,
    value: T,
) {
    if let Some(tx) = slot_sender(sessions, key, slot, select) {
        let _ = tx.try_send(value);
    }
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
    let targets = collect_slot_senders(sessions, key, Some(departing), |entry| {
        entry.leave_push.clone()
    });
    push_to_slots(
        key,
        "leave-push",
        Some(departing),
        targets.into_iter().map(|(slot, tx)| (slot, tx, leave)),
    );
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
    let targets = collect_slot_senders(sessions, key, None, |entry| entry.start_push.clone());
    push_to_slots(
        key,
        "session-start",
        None,
        targets
            .into_iter()
            .map(|(slot, tx)| (slot, tx, initial_buffer_turns)),
    );
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
    deliver_to_slot(
        sessions,
        key,
        slot,
        |entry| entry.start_push.clone(),
        initial_buffer_turns,
    );
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
    let targets = collect_slot_senders(sessions, key, None, |entry| entry.region_push.clone());
    push_to_slots(
        key,
        "region-label",
        None,
        targets
            .into_iter()
            .map(|(slot, tx)| (slot, tx, labels.to_vec())),
    );
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
    deliver_to_slot(
        sessions,
        key,
        slot,
        |entry| entry.region_push.clone(),
        labels,
    );
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
    // Collected per correction rather than per roster entry: only the named
    // slots are being corrected, so the roster is queried, not walked.
    let targets: Vec<(SlotId, mpsc::Sender<PhaseDirective>, PhaseDirective)> = {
        let roster = sessions.lock();
        match roster.get(key) {
            Some(slots) => corrections
                .iter()
                .filter_map(|&(slot, delay_us)| {
                    slots.get(&slot).map(|entry| {
                        (
                            slot,
                            entry.phase_push.clone(),
                            PhaseDirective {
                                delay_us,
                                slew_us_per_s: crate::consensus::phase::SLEW_US_PER_S,
                            },
                        )
                    })
                })
                .collect(),
            None => Vec::new(),
        }
    };
    push_to_slots(key, "send-phase directive", None, targets);
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
    deliver_to_slot(
        sessions,
        key,
        slot,
        |entry| entry.phase_push.clone(),
        directive,
    );
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
    events: &impl FlightEvents,
) {
    // Snapshot each recipient's epoch with its sender so a concurrent reconnect
    // cannot attribute a full old queue to the replacement link.
    let targets: Vec<_> = {
        let roster = sessions.lock();
        roster.get(key).map_or_else(Vec::new, |slots| {
            slots
                .iter()
                .map(|(&recipient, entry)| {
                    (recipient, entry.connection_epoch, entry.conn_push.clone())
                })
                .collect()
        })
    };
    for (recipient, recipient_epoch, tx) in targets {
        if let Err(mpsc::error::TrySendError::Full(_)) =
            tx.try_send((slot, connected, connection_epoch))
        {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = recipient.0,
                subject = slot.0,
                "connectivity queue full; the push was dropped for this slot",
            );
            events.record(
                key,
                FlightEvent::ConnectivityQueueFull {
                    recipient: recipient.0,
                    connection_epoch: recipient_epoch,
                    slot: slot.0,
                    connected,
                    subject_connection_epoch: connection_epoch,
                },
            );
        }
    }
}

/// Pushes a load-state fence probe carrying `probe_id` down the control stream of
/// the link registered for `slot` on `connection_epoch`, returning whether it was
/// queued.
///
/// The epoch is what makes this target one *link* rather than one seat, and why it
/// does not go through the plain single-slot delivery above. A slot the caller read
/// from the roster can be replaced by a reconnect before this call runs, and the
/// replacement is a different client stream with its own queue of owed reports —
/// probing it would answer a question about a connection the caller never asked
/// about. So a registration whose epoch differs is treated exactly like an absent
/// one.
///
/// `false` means there is no fence for this link and the caller must read it as
/// unfenced: the slot is no longer registered, the registration is a different
/// connection's, or the push queue is full. Never blocks — the caller is the
/// relay's coordinator connection, which must not be parked by one slow client.
pub(crate) fn deliver_load_state_probe_to_slot(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    connection_epoch: u64,
    probe_id: u64,
) -> bool {
    let sender = {
        let roster = sessions.lock();
        roster
            .get(key)
            .and_then(|slots| slots.get(&slot))
            .filter(|entry| entry.connection_epoch == connection_epoch)
            .map(|entry| entry.probe_push.clone())
    };
    sender.is_some_and(|tx| tx.try_send(probe_id).is_ok())
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
    events: &impl FlightEvents,
) {
    fan_out_connectivity(sessions, key, slot, connected, connection_epoch, events);
    crate::mesh::fan_out_slot_connectivity(mesh_links, key, slot, connected, connection_epoch);
}
