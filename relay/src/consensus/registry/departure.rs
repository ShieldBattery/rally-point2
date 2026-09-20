//! Departure entry points: recording a departure against a connection epoch,
//! the reconnect admission path, end-of-game results, and the finalized-drop
//! seal.

use super::*;

impl DecisionMakers {
    /// Records a slot departure into the session's decision-maker, if the relay has
    /// one, so a later authority promotion can re-derive the leave. Every relay calls
    /// this on a departure it learns of (its own home client, or a peer's
    /// `SlotDeparted`). A no-op when no maker exists.
    pub fn record_departure(
        &self,
        key: &SessionKey,
        slot: SlotId,
        stamps: DepartureStamps,
        reason: u32,
    ) {
        if let Some(maker) = self.lock().get_mut(key) {
            maker.record_departure(slot, stamps, reason);
        }
    }

    /// Epoch-fenced form of [`record_departure`](Self::record_departure). Returns `false` when the frame
    /// belongs to a stale/legacy generation that cannot match the slot's current
    /// fence; callers must then skip every associated hold and fan-out side effect.
    /// A missing maker preserves [`record_departure`](Self::record_departure)'s historical no-op admission:
    /// there is no local consensus state with which the frame could conflict.
    #[must_use]
    pub fn record_departure_for_epoch(
        &self,
        key: &SessionKey,
        slot: SlotId,
        stamps: DepartureStamps,
        reason: u32,
        connection_epoch: Option<u64>,
    ) -> bool {
        self.record_departure_for_epoch_outcome(key, slot, stamps, reason, connection_epoch)
            != DepartureRecordOutcome::Rejected
    }

    /// Records the same epoch-fenced departure while distinguishing an undecided
    /// drop from a terminal metadata merge. Callers use this distinction to install
    /// a reconnect hold only for the former; a delayed `SlotDeparted` after the
    /// final `LeaveDirective` may still enrich the retained record but must never
    /// recreate a drop hold.
    #[must_use]
    pub(crate) fn record_departure_for_epoch_outcome(
        &self,
        key: &SessionKey,
        slot: SlotId,
        stamps: DepartureStamps,
        reason: u32,
        connection_epoch: Option<u64>,
    ) -> DepartureRecordOutcome {
        let mut makers = self.lock();
        let Some(maker) = makers.get_mut(key) else {
            return DepartureRecordOutcome::Pending;
        };
        if maker.leave_decided(slot) {
            maker.merge_terminal_departure(slot, stamps, reason);
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
    pub fn activate_connection_epoch(&self, key: &SessionKey, slot: SlotId, epoch: u64) -> bool {
        let now = Instant::now();
        self.lock()
            .get_mut(key)
            .is_some_and(|maker| maker.activate_connection_epoch(slot, epoch, now))
    }

    /// Resolves a reliable connection-up event against the decision-maker's
    /// departure and generation state, under one acquisition of the maker lock:
    /// whether the dial is admitted, and whether it claimed the caller's pending
    /// drop hold. `hold_pending` is whether a hold for the slot is currently
    /// installed, read by the caller under the hold map's own lock.
    ///
    /// The reinstatement and the new generation's activation both happen inside
    /// that one maker lock, so an old departure can linearize only wholly before
    /// this call (and be claimed here) or wholly after the new epoch is active
    /// (and be rejected as stale). The caller's hold map must stay locked across
    /// this call for the pairing to be atomic — see
    /// [`crate::session::state::SessionState::admit_reconnect`], which owns both
    /// registries and is the only production caller.
    ///
    /// A missing maker admits without reinstating: there is no local consensus
    /// state the dial could conflict with.
    pub(crate) fn resolve_reconnect(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
        hold_pending: bool,
        after_reinstate: impl FnOnce(),
    ) -> ReconnectTransition {
        self.lock().get_mut(key).map_or(
            ReconnectTransition {
                admission: ReconnectAdmission::Admitted { reinstated: false },
                consume_hold: hold_pending,
            },
            |maker| maker.resolve_reconnect_with(slot, epoch, hold_pending, after_reinstate),
        )
    }

    /// Commits a reliable level=false frame. A duplicate Down(E) is idempotent;
    /// stale generations and legacy downgrades are rejected.
    #[must_use]
    pub(crate) fn mark_connection_down(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
    ) -> bool {
        self.lock()
            .get_mut(key)
            .is_none_or(|maker| maker.mark_connection_down(slot, epoch))
    }

    /// Checks a generation-bearing mesh/local teardown operation against the
    /// current fence. A missing maker admits the informational frame, preserving
    /// legacy behavior when the mesh session arrives ahead of its descriptor.
    pub fn connection_epoch_matches(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
    ) -> bool {
        self.lock()
            .get(key)
            .is_none_or(|maker| maker.connection_epoch_matches(slot, epoch))
    }

    /// Epoch-fenced live-state removal for a connection teardown.
    #[must_use]
    pub fn remove_slot_for_epoch(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
    ) -> bool {
        self.lock()
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
    pub fn record_result(&self, key: &SessionKey, slot: SlotId, payload: Vec<u8>) {
        let echo = {
            let mut makers = self.lock();
            let Some(maker) = makers.get_mut(key) else {
                return;
            };
            let echo = ResultEcho {
                payload,
                arrival_ms: unix_millis(),
                session_frame: maker.session_frame().map(|f| f.0),
                slot_frame: maker.slot_frame(slot).map(|f| f.0),
            };
            if !maker.record_result(slot, echo.clone()) {
                return;
            }
            echo
        };
        self.emit_notice(RelayNotice::Result(result_notice(self, key, slot, echo)));
    }

    /// The end-of-game result `slot` reported for `key`, if the relay has a maker
    /// that retained one. Read on the reporting slot's home relay when the slot
    /// departs — *before* the departure is recorded — to seed both the departure
    /// record and the `SlotDeparted` frame the peers receive with the retained
    /// result. `None` when no maker exists or the slot never reported.
    pub fn result_for(&self, key: &SessionKey, slot: SlotId) -> Option<ResultEcho> {
        self.lock()
            .get(key)
            .and_then(|maker| maker.result_for(slot).cloned())
    }

    /// Home-side drop finalization: seals the slot's generation against admission
    /// and, only then, snapshots its gap-free forwarded count through
    /// `read_cursor` (the caller passes this relay's session-level forward-gate
    /// cursor read). The decisions are the maker's — see
    /// `DecisionMaker::seal_for_finalize` for what is refused and why, and
    /// `DecisionMaker::finish_finalize` for what a count does to the record.
    ///
    /// The cursor read runs between two acquisitions of the registry lock, never
    /// under one: it is the caller's own I/O-free but foreign read, and the seal
    /// is what makes the gap safe.
    pub fn finalize_drop(
        &self,
        key: &SessionKey,
        slot: SlotId,
        requested_epoch: Option<u64>,
        read_cursor: impl FnOnce() -> Option<u64>,
    ) -> FinalizeOutcome {
        {
            let mut makers = self.lock();
            let Some(maker) = makers.get_mut(key) else {
                return FinalizeOutcome::RejectedNoCursor;
            };
            if let Err(outcome) = maker.seal_for_finalize(slot, requested_epoch) {
                return outcome;
            }
        }
        let count = read_cursor();
        let mut makers = self.lock();
        match makers.get_mut(key) {
            Some(maker) => maker.finish_finalize(slot, count),
            None => FinalizeOutcome::RejectedNoCursor,
        }
    }

    /// The connection generation recorded on `slot`'s departure, if any — echoed
    /// into a `FinalizeDrop` so the home's answer is correlatable. `None` for a
    /// legacy-mode departure (or no record/maker).
    pub fn departure_epoch(&self, key: &SessionKey, slot: SlotId) -> Option<u64> {
        self.lock()
            .get(key)
            .and_then(|maker| maker.departures.get(&slot))
            .and_then(|d| d.connection_epoch)
    }

    /// Whether a decision-maker exists for `key` — that is, whether a descriptor
    /// has ever named the session on this relay (makers are created only by
    /// descriptor application). Distinguishes a coordinator-managed session,
    /// whose lifecycle ends in a descriptor retirement, from a provisionally
    /// admitted one that has no coordinator lifecycle at all.
    pub fn maker_exists(&self, key: &SessionKey) -> bool {
        self.lock().contains_key(key)
    }

    /// Claims the one session-closed report for `key` (see
    /// [`DecisionMaker::claim_close_report`]). `Some(true)` means the caller runs
    /// the close, `Some(false)` that an earlier evaluation already did, and `None`
    /// that the session has no decision-maker to latch on.
    ///
    /// What `None` means is the caller's to decide — it reads one way for a session
    /// that never had a descriptor and the opposite way for one whose descriptor was
    /// retired, so neither can be the default here. It comes back from the same
    /// registry acquisition as the claim rather than from a separate existence
    /// check, so a retirement cannot land between the two.
    pub fn claim_close_report(&self, key: &SessionKey) -> Option<bool> {
        self.lock()
            .get_mut(key)
            .map(DecisionMaker::claim_close_report)
    }

    /// Clears `key`'s session-closed latch because a slot link is serving the session
    /// again (see [`DecisionMaker::reopen_close_report`]). A no-op when no maker
    /// exists.
    pub fn reopen_close_report(&self, key: &SessionKey) {
        if let Some(maker) = self.lock().get_mut(key) {
            maker.reopen_close_report();
        }
    }

    /// Force-decides every undecided departure for a fully-abandoned session — one
    /// with zero live slots session-wide — bypassing the authority gate, and returns
    /// the freshly decided directives for the caller to broadcast. With every slot
    /// disconnected, presence names no authority (the verdict is [`Authority::Peer`]
    /// everywhere), so [`DecisionMakers::decide_leave`] would decide nothing; but there are no clients
    /// left to desync, so the departures must simply be committed to funnel the session
    /// into its normal close cascade (departure notices, coordinator lifecycle). Fires
    /// exactly one departure notice per freshly decided slot, like [`DecisionMakers::decide_leave`],
    /// and dedups by slot, so a duplicate call — or several relays' abandoned-session
    /// timers firing at once — decides each slot at most once. A no-op (empty) when no
    /// maker exists or every departure is already decided.
    ///
    /// The read of every undecided departure and every one of the force-decides that
    /// follow all run inside one acquisition of the registry lock, so a concurrent
    /// [`DecisionMakers::reinstate_slot`] for the same slot cannot interleave with this — it either
    /// runs entirely before this call starts (nothing to decide is left out from under
    /// it) or entirely after (it finds the slot's leave already decided and, per
    /// [`DecisionMaker::reinstate_slot`]'s guard, no-ops instead of erasing a departure
    /// this call already broadcast). The caller is responsible for releasing each
    /// decided slot's drop hold (see [`crate::session::drop_hold::DropHolds::release`]) — this
    /// function only touches the decision-maker.
    pub fn decide_abandoned_departures(&self, key: &SessionKey) -> Vec<LeaveDirective> {
        // Force-decide under the lock, collecting the fresh directives; release the lock
        // before firing notices (`departure_notice` re-locks the self to read the
        // slot's retained result).
        let decided: Vec<LeaveDirective> = {
            let mut makers = self.lock();
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
            self.record_leave_event(key, directive);
            self.emit_notice(RelayNotice::Departure(departure_notice(
                self, key, directive,
            )));
        }
        decided
    }
}
