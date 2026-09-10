//! Delivering one thing to many slots: turns onto the datagram forward queues,
//! and leaves, session starts, region labels, phase directives and connectivity
//! changes onto each slot's reliable control-stream push channel. Every function
//! here clones the senders out under the roster lock and drops the lock before it
//! sends, so no slow client can park the caller.

use super::*;

use super::forward::ForwardOutcome;

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
            slew_us_per_s: crate::consensus::phase::SLEW_US_PER_S,
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
