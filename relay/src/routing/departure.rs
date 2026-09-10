//! Deciding who has left and telling everyone: recording a home client's
//! departure, holding a drop until a human resolves it, deciding a clean leave
//! at once, and the presence/abandonment reconciliation that bounds how long an
//! empty session's held departures can stay undecided.

use super::*;

use super::close::maybe_close_emptied_session_for_abandon_expiry;
use crate::consensus;
use crate::consensus::LEAVE_REASON_DROPPED;

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
    drop_holds: &crate::session::drop_hold::DropHolds,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    sessions: &Sessions,
    mesh_links: &crate::mesh::MeshLinks,
    provisional_turns: &crate::session::provisional_turns::ProvisionalTurnPen,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
    final_turn_count: Option<u64>,
    connection_epoch: Option<u64>,
) -> bool {
    if provisional_turns.armed() {
        use crate::session::provisional_turns::{HoldOutcome, PennedIngress};
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
    drop_holds: &crate::session::drop_hold::DropHolds,
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
    drop_holds: &crate::session::drop_hold::DropHolds,
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
            crate::observability::flight_recorder::FlightEvent::DropHeld { slot: slot.0 },
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

/// Decides `slot`'s synced leave and broadcasts it session-wide — to local
/// survivors ([`fan_out_leave`]) and every peer relay
/// ([`crate::mesh::fan_out_leave_directive`]). `Some` only on the authority, and
/// only once per slot (`decide_leave` dedups), so a hold's expiry and a racing
/// clean decision cannot double-broadcast. The departing slot is already off the
/// roster, so `fan_out_leave` reaches only survivors.
pub(super) fn decide_and_broadcast_leave(
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
pub(super) fn report_own_presence(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    let live = {
        let roster = sessions.lock();
        roster.get(key).map_or(0, |slots| slots.len() as u32)
    };
    if crate::session::presence::record_own(&mesh.presence, key, live) {
        // Slots whose drop is still held on this relay must not be decided by the
        // promotion a re-derive may trigger: a held drop is decided only by an
        // honored manual request, never by a promotion.
        let held = mesh.drop_holds.pending_slots(key);
        let leaves =
            crate::session::presence::recompute(&mesh.presence, &mesh.decision_makers, key, &held);
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
/// A *started* session that is empty session-wide ([`crate::session::presence::all_empty`])
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
    let globally_empty = crate::session::presence::all_empty(&mesh.presence, key, own_live);
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
pub(super) fn decide_and_broadcast_abandoned(
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
    if own_live > 0 || !crate::session::presence::all_empty(&mesh.presence, key, own_live) {
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
