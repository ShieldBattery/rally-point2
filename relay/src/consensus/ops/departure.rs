//! Departure entry points: recording a departure against a connection epoch,
//! the reconnect admission path, end-of-game results, and the finalized-drop
//! seal.

use super::*;

/// Records a slot departure into the session's decision-maker, if the relay has
/// one, so a later authority promotion can re-derive the leave. Every relay calls
/// this on a departure it learns of (its own home client, or a peer's
/// `SlotDeparted`). A no-op when no maker exists.
pub fn record_departure(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    stamps: DepartureStamps,
    reason: u32,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.record_departure(slot, stamps, reason);
    }
}

/// Epoch-fenced form of [`record_departure`]. Returns `false` when the frame
/// belongs to a stale/legacy generation that cannot match the slot's current
/// fence; callers must then skip every associated hold and fan-out side effect.
/// A missing maker preserves [`record_departure`]'s historical no-op admission:
/// there is no local consensus state with which the frame could conflict.
#[must_use]
pub fn record_departure_for_epoch(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    stamps: DepartureStamps,
    reason: u32,
    connection_epoch: Option<u64>,
) -> bool {
    record_departure_for_epoch_outcome(registry, key, slot, stamps, reason, connection_epoch)
        != DepartureRecordOutcome::Rejected
}

/// Records the same epoch-fenced departure while distinguishing an undecided
/// drop from a terminal metadata merge. Callers use this distinction to install
/// a reconnect hold only for the former; a delayed `SlotDeparted` after the
/// final `LeaveDirective` may still enrich the retained record but must never
/// recreate a drop hold.
#[must_use]
pub(crate) fn record_departure_for_epoch_outcome(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    stamps: DepartureStamps,
    reason: u32,
    connection_epoch: Option<u64>,
) -> DepartureRecordOutcome {
    let mut makers = registry.lock();
    let Some(maker) = makers.get_mut(key) else {
        return DepartureRecordOutcome::Pending;
    };
    if maker.decided_leaves.contains_key(&slot) {
        // A final leave is stronger than the physical-link generation fence.
        // Its SlotDeparted may arrive afterward on a different reliable peer
        // stream, including after a newer generation was already marked down.
        // Merge only its terminal metadata; do not let that stale generation
        // mutate the current connection tombstone or recreate a drop hold.
        maker.note_departure(slot, stamps.clone(), reason, None);
        maker.delivery.forget_slot(slot);
        return DepartureRecordOutcome::Terminal;
    }
    if !maker.record_departure_for_epoch(slot, stamps, reason, connection_epoch) {
        return DepartureRecordOutcome::Rejected;
    }
    DepartureRecordOutcome::Pending
}

/// Activates an authenticated or reliably-announced connection generation.
/// Returns whether that generation is Up afterward. A duplicate Up(E) returns
/// true; the terminal Down(E), a pending departure, and a missing maker return
/// false.
#[must_use]
pub fn activate_connection_epoch(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    epoch: u64,
) -> bool {
    let now = Instant::now();
    registry
        .lock()
        .get_mut(key)
        .is_some_and(|maker| maker.activate_connection_epoch(slot, epoch, now))
}

/// Atomically resolves a reliable connection-up event against both the drop
/// hold and the decision-maker's departure/generation state. The hold map stays
/// locked while the maker is acquired, and reinstatement plus activation happen
/// under that single maker lock. Thus an old departure can linearize only wholly
/// before this operation (and be claimed here) or wholly after the new epoch is
/// active (and be rejected as stale).
pub(crate) fn admit_reconnect(
    registry: &DecisionMakers,
    drop_holds: &crate::session::drop_hold::DropHolds,
    key: &SessionKey,
    slot: SlotId,
    epoch: Option<u64>,
) -> ReconnectAdmission {
    admit_reconnect_with(registry, drop_holds, key, slot, epoch, || {})
}

pub(in crate::consensus) fn admit_reconnect_with(
    registry: &DecisionMakers,
    drop_holds: &crate::session::drop_hold::DropHolds,
    key: &SessionKey,
    slot: SlotId,
    epoch: Option<u64>,
    after_reinstate: impl FnOnce(),
) -> ReconnectAdmission {
    drop_holds.resolve_reconnect(key, slot, |hold_pending| {
        let transition = registry.lock().get_mut(key).map_or(
            ReconnectTransition {
                admission: ReconnectAdmission::Admitted { reinstated: false },
                consume_hold: hold_pending,
            },
            |maker| maker.resolve_reconnect_with(slot, epoch, hold_pending, after_reinstate),
        );
        (transition.admission, transition.consume_hold)
    })
}

/// Commits a reliable level=false frame. A duplicate Down(E) is idempotent;
/// stale generations and legacy downgrades are rejected.
#[must_use]
pub(crate) fn mark_connection_down(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    epoch: Option<u64>,
) -> bool {
    registry
        .lock()
        .get_mut(key)
        .is_none_or(|maker| maker.mark_connection_down(slot, epoch))
}

/// Checks a generation-bearing mesh/local teardown operation against the
/// current fence. A missing maker admits the informational frame, preserving
/// legacy behavior when the mesh session arrives ahead of its descriptor.
pub fn connection_epoch_matches(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    epoch: Option<u64>,
) -> bool {
    registry
        .lock()
        .get(key)
        .is_none_or(|maker| maker.connection_epoch_matches(slot, epoch))
}

/// Epoch-fenced live-state removal for a connection teardown.
#[must_use]
pub fn remove_slot_for_epoch(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    epoch: Option<u64>,
) -> bool {
    registry
        .lock()
        .get_mut(key)
        .is_some_and(|maker| maker.remove_slot_for_epoch(slot, epoch))
}

/// Records a client's end-of-game result report into the session's
/// decision-maker, firing exactly one result notice up the coordinator connection
/// on the first report from `slot`. A repeat from the same slot inserts nothing
/// and fires nothing; an empty or over-cap payload is rejected by
/// [`DecisionMaker::record_result`] the same way, so it also inserts and fires
/// nothing (the caller cannot tell a rejection from a duplicate, which is fine —
/// both mean the retained state didn't change). A no-op when no maker exists (a
/// session this relay does not serve). `slot` is the authenticated connection's
/// slot the report arrived on, never a value from the payload; `payload` is
/// forwarded opaque.
///
/// The retained result echo captures the relay's own view of *when* the report
/// landed — a wall-clock arrival stamp plus the session's consensus frame and the
/// reporting slot's newest observed frame at arrival, all read here while the
/// maker is locked (the report does not retire the slot, so its framed history is
/// still live). The same echo is retained on the maker so the slot's later
/// departure embeds it into the departure notice; the standalone notice fired
/// here is the early, redundant delivery.
pub fn record_result(registry: &DecisionMakers, key: &SessionKey, slot: SlotId, payload: Vec<u8>) {
    let echo = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return;
        };
        let echo = ResultEcho {
            payload,
            arrival_ms: now_ms(),
            session_frame: maker.session_frame().map(|f| f.0),
            slot_frame: maker.slot_frame(slot).map(|f| f.0),
        };
        if !maker.record_result(slot, echo.clone()) {
            return;
        }
        echo
    };
    registry.notify_result(result_notice(registry, key, slot, echo));
}

/// The end-of-game result `slot` reported for `key`, if the relay has a maker
/// that retained one. Read on the reporting slot's home relay when the slot
/// departs — *before* the departure is recorded — to seed both the departure
/// record and the `SlotDeparted` frame the peers receive with the retained
/// result. `None` when no maker exists or the slot never reported.
pub fn result_for(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> Option<ResultEcho> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.result_for(slot).cloned())
}

/// The home-side outcome of a drop finalization (see [`finalize_drop`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// The slot's generation is sealed terminal and `final_turn_count` is its
    /// gap-free forwarded count — the authority may decide the leave with it.
    Finalized {
        /// The sealed count.
        final_turn_count: u64,
    },
    /// The slot has a live (reconnected) generation — the drop must not be
    /// decided; the game continues with the slot present.
    RejectedLive,
    /// This relay holds no gap-free forwarded prefix for the slot (a
    /// collapsed sparse window, a post-rehome home with no cursor
    /// continuity, or no maker at all). The drop stays undecided — never a
    /// frame-scheduled fallback, which is exactly the unsoundness
    /// finalization exists to remove.
    RejectedNoCursor,
}

/// Home-side drop finalization: atomically (against admission) verifies the
/// slot has no live connection generation, seals future admission
/// terminally-in-progress, and only then snapshots the slot's gap-free
/// forwarded count through `read_cursor` (the caller passes this relay's
/// session-level forward-gate cursor read). On success the count is stamped
/// into the departure record with the finalization proof, so the leave the
/// authority then decides carries it (see `commit_leave`); on
/// [`RejectedNoCursor`](FinalizeOutcome::RejectedNoCursor) the seal is lifted
/// again so a later reconnect can still resume the slot.
///
/// Idempotent: a re-request after the leave was already decided returns the
/// decided directive's finalized count (or `RejectedLive` when the slot was
/// decided without one — nothing here may ever contradict a decided leave).
/// The snapshot is stable between the seal and the read because the slot has
/// no live link (checked under the same maker lock that admission uses) and
/// the seal refuses any new one; the slot's own home is the only ingress
/// that feeds its cursor.
///
/// `requested_epoch` is the departed connection generation the requester is
/// finalizing, checked against this relay's own departure record for the
/// slot: a mismatch means the request describes a generation this home has
/// moved past (the slot reconnected and dropped again since the request was
/// authored, or the record was seeded by a rehome), and sealing against it
/// would answer for the wrong departure — rejected as
/// [`RejectedLive`](FinalizeOutcome::RejectedLive) so the requester re-asks
/// with its current record.
pub fn finalize_drop(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    requested_epoch: Option<u64>,
    read_cursor: impl FnOnce() -> Option<u64>,
) -> FinalizeOutcome {
    {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return FinalizeOutcome::RejectedNoCursor;
        };
        if let Some(decided) = maker.decided_leaves.get(&slot) {
            return match (decided.finalized, decided.final_turn_count) {
                (true, Some(final_turn_count)) => FinalizeOutcome::Finalized { final_turn_count },
                _ => FinalizeOutcome::RejectedLive,
            };
        }
        if maker.connection_is_up(slot) {
            return FinalizeOutcome::RejectedLive;
        }
        let recorded_epoch = maker.departures.get(&slot).and_then(|d| d.connection_epoch);
        if recorded_epoch != requested_epoch {
            return FinalizeOutcome::RejectedLive;
        }
        // A home gained mid-session (rehome) has a cursor covering only what
        // it forwarded itself, not the slot's whole ingress history — a
        // non-`None` prefix can still stop short of turns other relays'
        // clients already consumed, so it must never be sealed as a count.
        if maker.rehomed_homes.contains(&slot) {
            return FinalizeOutcome::RejectedNoCursor;
        }
        // Pre-frame (no framed turn observed anywhere, and none on the
        // slot's own record): the game has not started, nothing is stalled,
        // and the leave the count would feed has no scheduling basis yet —
        // sealing admission here would only lock a lobby slot out of
        // rejoining while the decide side could never complete. Refuse
        // without sealing; the drop stays held and a later request, once
        // frames exist, finalizes normally.
        if maker.session_frame().is_none()
            && maker
                .departures
                .get(&slot)
                .and_then(|d| d.last_frame)
                .is_none()
        {
            return FinalizeOutcome::RejectedNoCursor;
        }
        maker.finalizing_drops.insert(slot);
    }
    let count = read_cursor();
    let mut makers = registry.lock();
    let Some(maker) = makers.get_mut(key) else {
        return FinalizeOutcome::RejectedNoCursor;
    };
    match count {
        Some(final_turn_count) => {
            maker.note_departure(
                slot,
                DepartureStamps {
                    final_turn_count: Some(final_turn_count),
                    finalized: true,
                    ..DepartureStamps::default()
                },
                LEAVE_REASON_DROPPED,
                None,
            );
            FinalizeOutcome::Finalized { final_turn_count }
        }
        None => {
            maker.finalizing_drops.remove(&slot);
            FinalizeOutcome::RejectedNoCursor
        }
    }
}

/// The connection generation recorded on `slot`'s departure, if any — echoed
/// into a `FinalizeDrop` so the home's answer is correlatable. `None` for a
/// legacy-mode departure (or no record/maker).
pub fn departure_epoch(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> Option<u64> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.departures.get(&slot))
        .and_then(|d| d.connection_epoch)
}

/// Whether a decision-maker exists for `key` — that is, whether a descriptor
/// has ever named the session on this relay (makers are created only by
/// descriptor application). Distinguishes a coordinator-managed session,
/// whose lifecycle ends in a descriptor retirement, from a provisionally
/// admitted one that has no coordinator lifecycle at all.
pub fn maker_exists(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry.lock().contains_key(key)
}

/// Claims the one session-closed report for `key` (see
/// [`DecisionMaker::claim_close_report`]): `true` means the caller runs the close,
/// `false` that an earlier evaluation already did. `true` when no maker exists —
/// with nowhere to latch, every emptying reports, which is also the only close
/// such a session (no descriptor, no decide paths) can ever reach.
pub fn claim_close_report(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get_mut(key)
        .is_none_or(DecisionMaker::claim_close_report)
}

/// Clears `key`'s session-closed latch because a slot link is serving the session
/// again (see [`DecisionMaker::reopen_close_report`]). A no-op when no maker
/// exists.
pub fn reopen_close_report(registry: &DecisionMakers, key: &SessionKey) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.reopen_close_report();
    }
}

/// Force-decides every undecided departure for a fully-abandoned session — one
/// with zero live slots session-wide — bypassing the authority gate, and returns
/// the freshly decided directives for the caller to broadcast. With every slot
/// disconnected, presence names no authority (the verdict is [`Authority::Peer`]
/// everywhere), so [`decide_leave`] would decide nothing; but there are no clients
/// left to desync, so the departures must simply be committed to funnel the session
/// into its normal close cascade (departure notices, coordinator lifecycle). Fires
/// exactly one departure notice per freshly decided slot, like [`decide_leave`],
/// and dedups by slot, so a duplicate call — or several relays' abandoned-session
/// timers firing at once — decides each slot at most once. A no-op (empty) when no
/// maker exists or every departure is already decided.
///
/// The read of every undecided departure and every one of the force-decides that
/// follow all run inside one acquisition of `registry`'s lock, so a concurrent
/// [`reinstate_slot`] for the same slot cannot interleave with this — it either
/// runs entirely before this call starts (nothing to decide is left out from under
/// it) or entirely after (it finds the slot's leave already decided and, per
/// [`DecisionMaker::reinstate_slot`]'s guard, no-ops instead of erasing a departure
/// this call already broadcast). The caller is responsible for releasing each
/// decided slot's drop hold (see [`crate::session::drop_hold::DropHolds::release`]) — this
/// function only touches the decision-maker.
pub fn decide_abandoned_departures(
    registry: &DecisionMakers,
    key: &SessionKey,
) -> Vec<LeaveDirective> {
    // Force-decide under the lock, collecting the fresh directives; release the lock
    // before firing notices (`departure_notice` re-locks the registry to read the
    // slot's retained result).
    let decided: Vec<LeaveDirective> = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return Vec::new();
        };
        maker
            .undecided_departures()
            .into_iter()
            .filter_map(|(slot, reason)| maker.force_decide_leave(slot, reason))
            .collect()
    };
    for directive in &decided {
        log_leave(key, directive);
        record_leave_event(registry, key, directive);
        registry.notify_departure(departure_notice(registry, key, directive));
    }
    decided
}
