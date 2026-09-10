//! Session-scoped lifecycle steps a slot's arrival or a directive triggers:
//! delivering the session-start directive, announcing a fresh slot's presence,
//! signalling slots to close, and the two teardowns for admissions that were
//! refused or never claimed by a descriptor.

use super::*;

use crate::consensus;

use std::sync::atomic::Ordering;

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

/// Pushes a load-state fence probe carrying `probe_id` down the control stream of
/// the link registered for `slot` on `connection_epoch`, returning whether it was
/// queued.
///
/// The epoch is what makes this target one *link* rather than one seat. A slot the
/// caller read from the roster can be replaced by a reconnect before this call
/// runs, and the replacement is a different client stream with its own queue of
/// owed reports — probing it would answer a question about a connection the caller
/// never asked about. So a registration whose epoch differs is treated exactly like
/// an absent one.
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
    signal_close(
        sessions,
        key,
        slots,
        SlotCloseReason::Unspecified,
        "closing slot link after terminal directive",
    );
}

/// Closes the links of `slots` in the `key` routing group because their clients
/// stopped producing turns while the session advanced past them (see
/// [`crate::consensus::run_silence_watch`]). Identical to [`close_slots`] but for
/// the reason it stamps, which is what makes the closed connection carry
/// `SILENT_SLOT_CLOSE` instead of the generic close: a client whose game thread
/// hung has a perfectly healthy link, and its log should say so.
pub fn close_slots_for_silence(sessions: &Sessions, key: &SessionKey, slots: &[SlotId]) {
    signal_close(
        sessions,
        key,
        slots,
        SlotCloseReason::SilentSlot,
        "closing slot link after silent-slot eviction",
    );
}

/// Stamps `reason` on each named slot's roster entry and fires its shutdown
/// signal, logging `message`. The stamp lands before the signal, so the woken
/// link task always reads the reason for the wake it is answering.
fn signal_close(
    sessions: &Sessions,
    key: &SessionKey,
    slots: &[SlotId],
    reason: SlotCloseReason,
    message: &'static str,
) {
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
                "{message}",
            );
            entry.close_reason.store(reason as u8, Ordering::Release);
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
/// ([`SessionGates::discard_if`](crate::session::gate::SessionGates)), which
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
/// [`ProvisionalTurnPen::discard_if_empty`]: crate::session::provisional_turns::ProvisionalTurnPen::discard_if_empty
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
/// admitted session before its deadline (see [`crate::session::provisional`]). A
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
pub(super) fn record_leave_control_write(
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
        crate::observability::flight_recorder::FlightEvent::LeaveControlWrite {
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
