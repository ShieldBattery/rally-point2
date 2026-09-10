//! Synced-leave entry points: deciding a leave, observing a peer authority's,
//! and the homing and reconcile queries the mesh and routing layers ask.

use super::*;

/// The reachability ceiling for a leave's apply frame at `slot`'s departure —
/// the highest game frame every surviving slot has provably executed (see
/// `DecisionMaker`'s `reachable_frame`). Read on the departing slot's home relay,
/// *before* the departure is recorded (which retires the slot's live state), to
/// fill both the departure record and the `SlotDeparted` frame the peers
/// receive, so every relay clamps to the identical value. `None` when no maker
/// exists or no survivor has framed history yet.
pub fn reachable_frame(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> Option<u32> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.reachable_frame(slot))
}

/// Whether `slot`'s synced leave is already decided for `key`. Terminal for
/// the slot's participation: a decided leave refuses readmission, so no turn
/// the slot originates after this is part of the game — the home-ingress turn
/// fence keys on it. `false` when no maker exists.
pub fn slot_leave_decided(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.decided_leaves.contains_key(&slot))
}

/// Whether `slot`'s leave, if decided right now, would actually commit: a
/// framed scheduling basis exists (a session frame, or a last frame on the
/// slot's own departure record) — the same short-circuit `commit_leave`
/// applies. Read before releasing a drop hold whose decide must not silently
/// fail: a released hold with no committed leave strands the departure with
/// nothing left to retry against. Monotone-safe as a check-then-act — frames
/// only accumulate, so a `true` here never becomes `false` by decide time.
/// `false` with no maker (nothing to decide into).
pub fn leave_schedulable(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry.lock().get(key).is_some_and(|maker| {
        maker.session_frame().is_some()
            || maker
                .departures
                .get(&slot)
                .and_then(|d| d.last_frame)
                .is_some()
    })
}

/// Normalizes a leave directive observed from the wire: a **dropped**
/// directive's `final_turn_count` is accepted only with the finalization
/// proof (`finalized`), and only when `finalized_drops_enabled` — the
/// session's descriptor flag — says this session runs the handshake at all.
/// Anything else is stripped (proof flag included) before the directive is
/// compared, cached, recorded, or fanned any further: an unproven count means
/// the authoring relay ran code predating the clean-leaves-or-finalized rule,
/// and because a `LeaveDirective` can outrun its matching `SlotDeparted`
/// across peer links, this ingress must sanitize for itself rather than rely
/// on the departure-record sanitizers.
pub fn normalize_observed_leave(
    leave: &LeaveDirective,
    finalized_drops_enabled: bool,
) -> LeaveDirective {
    if leave.reason == LEAVE_REASON_DROPPED
        && (leave.final_turn_count.is_some() || leave.finalized)
        && !(leave.finalized && finalized_drops_enabled)
    {
        tracing::debug!(
            slot = leave.slot,
            leave_seq = leave.leave_seq,
            stripped_count = ?leave.final_turn_count,
            finalized = leave.finalized,
            "stripping an unproven dropped leave's final turn count at ingress",
        );
        return LeaveDirective {
            final_turn_count: None,
            finalized: false,
            ..*leave
        };
    }
    *leave
}

/// Caches a synced leave a peer relay's authority authored (received off the
/// mesh) into the session's decision-maker, if the relay has one, so a later
/// promotion re-broadcasts it verbatim. A no-op when no maker exists.
///
/// On a **first insert** for the slot — the leave newly entering this relay's
/// cache — fires one departure notice up the coordinator connection. A redundant
/// copy (for example a reconcile-on-join re-send) inserts nothing and
/// fires nothing, so the coordinator sees at most one notice per relay per slot.
///
/// Returns whether it was a first insert (mirroring
/// [`DecisionMaker::observe_leave`]'s own `#[must_use]`) — `#[must_use]` here
/// too, so a caller can't silently forward a directive this relay's own
/// consensus just rejected: `false` covers both an ordinary redundant copy
/// (harmless to skip re-forwarding — it was already fanned out on the first
/// insert) and a genuine conflicting duplicate for the slot (an authority
/// bug this relay's cache just caught), and a caller that fans out
/// regardless would hand clients a directive this relay's own state
/// disagrees with.
#[must_use]
pub fn observe_leave(registry: &DecisionMakers, key: &SessionKey, leave: &LeaveDirective) -> bool {
    // Normalize before the notice below, not just inside the maker's cache:
    // the departure notice must describe the sanitized directive, never an
    // unproven count the coordinator would retain and re-seed on a rehome.
    let leave = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return false;
        };
        let leave = normalize_observed_leave(leave, maker.finalized_drops_enabled);
        if !maker.observe_leave(&leave) {
            return false;
        }
        leave
    };
    registry.notify_departure(departure_notice(registry, key, &leave));
    true
}

/// Whether `slot` is admissible on this relay per `key`'s session descriptor
/// (see `DecisionMaker`'s `admits_slot`) — read at client admission (`server.rs`)
/// to refuse a token authorized for a slot the coordinator did not assign here.
///
/// `true` (admit) when no maker exists for the session: this is the same
/// permissive default `slot_departed`/`is_authority` use for a session this
/// relay knows nothing about yet, and it is what preserves today's
/// descriptor-arrival-race behavior — a client dialing before the relay has
/// received any descriptor for the session must be admitted exactly as before
/// this check existed, not stalled or refused waiting for one. Enforcement
/// only engages once a maker exists AND its homed set is non-empty (see the
/// field's doc on [`DecisionMaker`]); a legacy/dev descriptor (or one that
/// never arrived) leaves it permissive.
pub fn slot_homed(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(key)
        .is_none_or(|maker| maker.admits_slot(slot))
}

/// Whether a departure has been recorded for `slot` in `key`'s decision-maker (see
/// [`DecisionMaker::has_departure`]). `false` when no maker exists for the session.
/// Read at re-register time to tell a resumable reconnect (a departure held under a
/// live drop hold) from a decided one (a departure whose leave was already made).
pub fn slot_departed(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.has_departure(slot))
}

/// Discards `slot`'s departure record for `key` because the client re-registered
/// while its drop was still held (see [`DecisionMaker::reinstate_slot`]). A no-op
/// when no maker exists, the slot had no departure recorded, or the slot's leave
/// is already decided (see [`DecisionMaker::reinstate_slot`] for why that last case
/// matters: it is the abandoned-session force-decide race guard). Called alongside
/// the hold release at a re-register, so a subsequent authority promotion does not
/// re-derive a leave for a slot that has already come back.
pub fn reinstate_slot(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get_mut(key)
        .is_some_and(|maker| maker.reinstate_slot(slot))
}

/// The slots whose leave `key`'s decision-maker has already decided or cached (see
/// `DecisionMaker`'s `decided_slots`). Empty when no maker exists. Read at a
/// session-emptied teardown to filter the drop-hold sweep: a hold for a decided
/// slot is safe to discard, one for an undecided slot must survive (see
/// [`crate::session::drop_hold::DropHolds::end_session`]).
pub fn decided_slots(registry: &DecisionMakers, key: &SessionKey) -> HashSet<SlotId> {
    registry
        .lock()
        .get(key)
        .map(DecisionMaker::decided_slots)
        .unwrap_or_default()
}

/// Fires a session-closed notice up the coordinator connection: this relay has
/// torn down its last local state for `key`. A no-op on a standalone relay (no
/// notifier). Fire it *after* the session's departures have already been emitted
/// on the same channel, so the coordinator's in-order dispatch treats a delivered
/// close as proof no earlier notice for the session is still in flight.
pub fn session_closed(registry: &DecisionMakers, key: &SessionKey) {
    registry.notify_session_closed(key.tenant.clone(), key.session);
    // The session's local state is gone: seal the flight recording with the
    // close event and flush it (fire-and-forget — a flush must never delay a
    // teardown). This is the recording's ordinary end; the drain path's
    // wholesale flush covers sessions that never reach it.
    //
    // Sealing touches only a recording that already exists. A close evaluated
    // for a session this relay recorded nothing of — or one whose recording an
    // earlier close already flushed — must store nothing, rather than begin a
    // recording whose whole content is that the session ended.
    registry.flight.record_existing(
        key,
        crate::observability::flight_recorder::FlightEvent::SessionClosed,
    );
    // Whether the flush plants a close seal follows the session's lifecycle.
    // A maker means a descriptor named the session, so the descriptor
    // retirement that clears seals will come; a maker-less session (a
    // provisional admission no descriptor ever claimed) has no retirement in
    // its future — a seal planted for it would live for the relay's lifetime,
    // and there is nothing for it to guard anyway: no mesh ever joined the
    // session (membership is descriptor-driven), every local link is already
    // gone by this point, and a later dial for the id is a genuinely fresh
    // admission whose recording must not be silently dropped.
    let seal = registry.lock().contains_key(key);
    registry.flight.flush_session_detached(key, seal);
}

/// This relay's known leave state for `key` — every recorded departure and every
/// cached leave — for re-announcing to a freshly (re)joined mesh link. Empty when
/// no maker exists. See `DecisionMaker`'s `leave_reconcile`.
pub fn leave_reconcile(
    registry: &DecisionMakers,
    key: &SessionKey,
) -> (Vec<RecordedDeparture>, Vec<LeaveDirective>) {
    registry
        .lock()
        .get(key)
        .map(|maker| maker.leave_reconcile())
        .unwrap_or_default()
}

/// Removes a session's decision-maker (the session has ended). Idempotent.
/// Also forgets the session's correlation ids, so the refs map doesn't outlive
/// the sessions it describes.
pub fn deregister_maker(registry: &DecisionMakers, key: &SessionKey) {
    registry.lock().remove(key);
    registry.forget_session_refs(key);
}

/// Decides a synced player-leave for `slot` on the session's authority relay and
/// queues it for broadcast, logging it. Returns the queued [`LeaveDirective`], or
/// `None` when this relay isn't the authority / has no maker / can't schedule yet
/// (see [`DecisionMaker::decide_leave`]). Records the departure as a side effect
/// (merging the slot's own frame into its record and retiring its live state),
/// so the apply frame derives the same way no matter which relay decides.
pub fn decide_leave(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    reason: u32,
) -> Option<LeaveDirective> {
    let directive = registry.lock().get_mut(key)?.decide_leave(slot, reason)?;
    log_leave(key, &directive);
    record_leave_event(registry, key, &directive);
    // `decide_leave` returns `Some` only on the authority's first decision for
    // the slot (it dedups internally), so this is the one departure notice the
    // authoring relay sends for it.
    registry.notify_departure(departure_notice(registry, key, &directive));
    Some(directive)
}

/// Records a decided leave into the session's flight recording — the decision's
/// observability shadow, fired at the same once-per-slot points the departure
/// notice is (the maker's internal dedup guarantees the once).
pub(in crate::consensus) fn record_leave_event(
    registry: &DecisionMakers,
    key: &SessionKey,
    directive: &LeaveDirective,
) {
    registry.flight.record(
        key,
        crate::observability::flight_recorder::FlightEvent::LeaveDecided {
            slot: directive.slot as u8,
            kind: if directive.reason == LEAVE_REASON_DROPPED {
                DepartureKind::Dropped
            } else {
                DepartureKind::Left
            },
            reason: directive.reason,
            apply_frame: directive.apply_at_frame,
            leave_seq: directive.leave_seq,
            finalized: directive.finalized,
            final_turn_count: directive.final_turn_count,
        },
    );
}

/// Whether `key`'s decision-maker holds at least one recorded departure whose leave
/// has not been decided (see [`DecisionMaker::has_undecided_departure`]). `false`
/// when no maker exists. One half of the fully-abandoned-session condition: a
/// session with no undecided departure has nothing for the abandoned-session timer
/// to close out.
pub fn has_undecided_departure(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(DecisionMaker::has_undecided_departure)
}

/// Whether any departure still promises a reconnect on this relay (see
/// [`DecisionMaker::has_reconnectable_departure`]) — the condition that defers
/// the session-emptied close. `held` is the caller's current set of pending
/// drop holds. `false` when no maker exists: with no departure records there is
/// no reconnect promise to wait on.
pub fn has_reconnectable_departure(
    registry: &DecisionMakers,
    key: &SessionKey,
    held: &HashSet<SlotId>,
) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.has_reconnectable_departure(held))
}

/// [`claim_close_report`], but refusing (`false`) when no decision-maker exists
/// — in the same single registry acquisition, so a retirement cannot land
/// between an existence check and the claim. For the abandoned-session timer's
/// expiry: a maker is created when the session's descriptor is applied and
/// destroyed when it is removed, and the timer only ever arms while one exists
/// (its arming condition reads the maker's undecided departures), so finding
/// none at expiry proves the descriptor was retired mid-window — the close
/// already ran and reached the coordinator, and [`claim_close_report`]'s
/// no-maker default (`true`, meant for sessions that never had a maker at all)
/// must not be read as permission to report it again.
pub fn claim_close_report_with_maker(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get_mut(key)
        .is_some_and(DecisionMaker::claim_close_report)
}

/// Whether `key`'s session runs the home-side drop-finalization handshake —
/// the descriptor's immutable `finalized_drops` flag, latched at maker
/// creation. `false` when no maker exists.
pub fn finalized_drops_enabled(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.finalized_drops_enabled)
}

/// Whether the descriptor **strictly** homes `slot` on this relay: the homed
/// set is non-empty and names the slot. Unlike [`slot_homed`] (the admission
/// gate, which fails open on an empty/legacy set), this never fails open —
/// it selects the one relay that answers a `FinalizeDrop`, and an open
/// fallback would have every session relay finalize with its own (different)
/// cursor.
pub fn slot_strictly_homed(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.strictly_homes(slot))
}
