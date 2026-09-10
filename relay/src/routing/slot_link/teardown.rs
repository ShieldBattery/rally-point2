//! The single teardown path every way `run_slot_link` can end converges on.

use super::*;

use crate::consensus::LEAVE_REASON_DROPPED;

use crate::routing::registry::deregister;

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
pub(in crate::routing) fn end_slot_link(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    slot: SlotId,
    connection_epoch: u64,
    leave_announced: bool,
) {
    mesh.decision_makers.flight_recorder().record(
        key,
        crate::observability::flight_recorder::FlightEvent::SlotDisconnected { slot: slot.0 },
    );
    // Drop this member's lobby-push channel before the roster deregister below.
    // The roster refuses a duplicate slot, so a reconnecting slot cannot register
    // (and re-register its lobby member) until this deregister frees the roster
    // slot — doing the lobby deregister first keeps a fresh connection's
    // `register_member` from being clobbered by this one's cleanup.
    crate::session::lobby::deregister_member(&mesh.lobby, key, slot);
    // Same rationale for chat: deregister before the roster frees the slot, so
    // a reconnect can't clobber this connection's cleanup.
    crate::session::chat::deregister_member(&mesh.chat, key, slot);
    // Same for skins: deregister the member before the roster frees the slot. The
    // session's blob map is left intact (like the lobby log), so a remaining or
    // reconnecting member still replays it.
    crate::session::skin::deregister_member(&mesh.skins, key, slot);
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
