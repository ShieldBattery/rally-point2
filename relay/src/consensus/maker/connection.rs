//! Condition ingest and the per-slot connection epoch: folding local and
//! mesh-forwarded conditions into slot state, and the reconnect lifecycle
//! that decides which generation of a slot's link a sidecar or departure
//! belongs to.

use super::*;

impl DecisionMaker {
    /// Ingests this relay's own home-client `LinkConditions` (conditions the
    /// relay observed directly on its local clients).
    ///
    /// Local slots have `mesh_rtt = 0` (no mesh hop -- this relay). RTT
    /// samples are pushed into the per-slot ring buffer for jitter-aware
    /// sizing. Monotonic cumulative loss endpoints advance or refine the
    /// accepted baseline so the next decision can difference them.
    ///
    /// Returns a [`Decision`] if the control law fires a change, `None` if it
    /// holds (target unchanged, or min-dwell suppressing a lower, or no framed
    /// turn observed yet, or this relay is not the authority). The caller
    /// translates a returned decision into a broadcast.
    pub fn ingest_local(&mut self, conditions: &LinkConditions) -> Option<Decision> {
        self.activate_local_epochs(&conditions.slots);
        self.ingest_slots(&conditions.slots, 0)
    }

    /// Ingests one home-client conditions sample without requiring a
    /// one-element [`LinkConditions`] allocation. This is the slot-link hot
    /// path; it shares the same slice-based state update and decision step as
    /// [`ingest_local`](Self::ingest_local).
    pub fn ingest_local_condition(&mut self, conditions: &SlotConditions) -> Option<Decision> {
        self.activate_local_epochs(std::slice::from_ref(conditions));
        self.ingest_slots(std::slice::from_ref(conditions), 0)
    }

    /// Ingests a peer relay's `LinkConditions` sidecar (conditions the peer
    /// relay observed on its own home clients, forwarded across the mesh).
    ///
    /// `mesh_rtt_us` is the relay-pair RTT from the authority to the peer
    /// relay -- sampled from the `MeshLink`'s QUIC connection stats. It's added
    /// to each remote slot's effective RTT so cross-relay paths include the
    /// mesh hop. The transport doesn't carry mesh RTT in the sidecar because
    /// it's a property of the relay-pair, not of any individual client's link.
    ///
    /// Returns a [`Decision`] if the control law fires a change, `None` if it
    /// holds.
    pub fn ingest_remote(
        &mut self,
        conditions: &LinkConditions,
        mesh_rtt_us: u32,
    ) -> Option<Decision> {
        self.ingest_slots(&conditions.slots, mesh_rtt_us)
    }

    /// Shared ingestion: admits current sender RTT observations, advances only
    /// monotonic cumulative loss counters, sets the receiver-local mesh hop,
    /// then runs `decide` if this relay is the authority.
    pub(in crate::consensus) fn ingest_slots(
        &mut self,
        conditions: &[SlotConditions],
        mesh_rtt_us: u32,
    ) -> Option<Decision> {
        let snapshot_interval = self.law.loss_snapshot_interval();
        let run_bucket_span = self.law.blackout_run_bucket_span();
        // One acceptance instant for the whole batch: the receive-gap clock
        // the outage detection reads. Remote sidecars are stamped at authority
        // arrival, and a mesh sidecar re-carries a *cached* snapshot of every
        // co-homed slot's conditions on any sibling's traffic -- so arrival
        // alone proves nothing about a given slot's freshness. That is why
        // `update_counters` advances the gap clock only on samples whose
        // counters moved: a cached re-send is bit-identical and leaves the
        // clock (and so the measured gap) untouched.
        let now = Instant::now();
        for slot in conditions {
            // A truncating cast would alias an out-of-range wire slot onto a
            // different, valid slot's tracked RTT/loss state, corrupting that
            // slot's decision inputs instead of merely dropping the malformed
            // sample. Skip it (defensive — wire values are validated upstream).
            let Ok(id) = u8::try_from(slot.slot).map(SlotId) else {
                continue;
            };
            // A departed slot's stale sample can still be in flight (a mesh
            // datagram raced the departure); re-creating its entry would
            // resurrect state its departure deliberately retired — the same
            // guard `observe_frame` applies.
            if self.departures.contains_key(&id) {
                continue;
            }
            // An epoch-bearing remote sidecar is admitted only after the
            // reliable connectivity stream established that exact generation.
            // Datagrams and streams have no cross-channel order, so allowing an
            // unknown sidecar to establish state could let E2 arrive first and
            // then let a delayed reliable E1 switch the slot backward. Local
            // samples are activated just above this method by the authenticated
            // slot-link path.
            match (
                self.connection_states.get(&id).copied(),
                slot.connection_epoch,
            ) {
                (Some(ConnectionState::Up(current)), Some(observed)) if current == observed => {}
                (None, None) => {}
                _ => continue,
            }
            let state = self.slots.entry(id).or_default();
            let counter_update = state.update_counters(
                slot.lost_packets,
                slot.sent_packets,
                snapshot_interval,
                run_bucket_span,
                now,
            );
            if counter_update == CounterUpdate::OutageRebaselined {
                tracing::debug!(
                    tenant = self.key.tenant.as_ref(),
                    session = self.key.session.0,
                    slot = id.0,
                    "counter sample spanned a stall-length receive gap; \
                     outage interval excluded from the loss windows",
                );
            }

            // Sender RTT is instantaneous rather than cumulative, but a
            // counter-regressing sidecar is known to be stale as a whole and
            // must not advance the sample-count-based window. Equal counters
            // may still carry a changed RTT (Noq updates smoothed RTT without
            // necessarily sending another packet), but an exact duplicate must
            // not age the window. A `0` (no measurement) is skipped by `push`.
            // Clamp peer-reported values on ingress so an unclamped
            // near-u32::MAX claim cannot saturate every effective-RTT sum.
            let rtt_us = slot.rtt_us.min(MAX_INGEST_RTT_US);
            let admit_sender_rtt = match counter_update {
                CounterUpdate::Baseline
                | CounterUpdate::Advanced
                | CounterUpdate::OutageRebaselined
                | CounterUpdate::LossAdvanced => true,
                CounterUpdate::NonAdvancing => state.last_sender_rtt_us != Some(rtt_us),
                CounterUpdate::Stale => false,
            };
            if admit_sender_rtt {
                state.rtt_window.push(rtt_us);
                state.last_sender_rtt_us = Some(rtt_us);
            }

            // The mesh hop is sampled locally by this receiving relay at
            // ingestion time, so sender counter order does not make it stale.
            // Refresh it for every sidecar, including one whose client counters
            // are equal or backward (local ingestion supplies zero).
            state.mesh_rtt_us = mesh_rtt_us;
        }

        if !self.is_authority() {
            return None;
        }

        self.decide()
    }

    /// Trusts epochs carried by samples measured on this relay's authenticated
    /// home-client link. Unlike a mesh datagram, a local sample is an
    /// authoritative activation barrier for a replacement connection.
    pub(in crate::consensus) fn activate_local_epochs(&mut self, conditions: &[SlotConditions]) {
        // One instant for the batch, for the same reason `ingest_slots` takes
        // one: these samples all arrived together.
        let now = Instant::now();
        for condition in conditions {
            let (Ok(slot), Some(epoch)) = (
                u8::try_from(condition.slot).map(SlotId),
                condition.connection_epoch,
            ) else {
                continue;
            };
            if !self.departures.contains_key(&slot) && !self.decided_leaves.contains_key(&slot) {
                let _ = self.activate_connection_epoch(slot, epoch, now);
            }
        }
    }

    /// Classifies a reliable level=true frame without mutating state. This is
    /// intentionally separate from activation so callers can reject a terminal
    /// same-generation replay before it consumes a reconnect hold.
    pub(crate) fn connection_activation(
        &self,
        slot: SlotId,
        observed: Option<u64>,
    ) -> ConnectionActivation {
        if self.decided_leaves.contains_key(&slot) {
            return ConnectionActivation::Rejected;
        }
        if observed.is_some_and(|epoch| {
            self.retired_connection_epochs
                .get(&slot)
                .is_some_and(|retired| retired.contains(&epoch))
        }) {
            return ConnectionActivation::Rejected;
        }
        if self.departures.contains_key(&slot)
            && !self.connection_states.contains_key(&slot)
            && observed.is_none()
        {
            return ConnectionActivation::Replacement;
        }
        match (self.connection_states.get(&slot).copied(), observed) {
            (None, None) => ConnectionActivation::Current,
            (None, Some(_)) => ConnectionActivation::Replacement,
            (Some(ConnectionState::Up(current)), Some(epoch)) if current == epoch => {
                ConnectionActivation::Current
            }
            (Some(ConnectionState::Down(current)), Some(epoch)) if current == epoch => {
                ConnectionActivation::Rejected
            }
            (Some(_), Some(_)) => ConnectionActivation::Replacement,
            (Some(_), None) => ConnectionActivation::Rejected,
        }
    }

    /// Admits a reliable level=true frame after any departure/hold transition
    /// has completed. A down generation is terminal: only a distinct epoch can
    /// reopen it. Returns true when the requested generation is up afterward.
    pub(crate) fn admit_connection_up(
        &mut self,
        slot: SlotId,
        observed: Option<u64>,
        now: Instant,
    ) -> bool {
        if self.departures.contains_key(&slot) || self.decided_leaves.contains_key(&slot) {
            return false;
        }
        match observed {
            Some(epoch) => self.activate_connection_epoch(slot, epoch, now),
            None => !self.connection_states.contains_key(&slot),
        }
    }

    /// Activates one authenticated/reliably-announced epoch-aware generation.
    /// A duplicate Up(E) is idempotent. Down(E) and every superseded epoch reject
    /// that epoch forever; a previously unseen distinct epoch may replace the
    /// current one once the departure record is gone.
    ///
    /// `now` records how long this slot's link has been up, which is what the
    /// silence watch owes a freshly connected slot a window against (see
    /// [`silent_slot`](Self::silent_slot)); it deliberately does not touch the
    /// slot's stop time. The idempotent same-epoch return records nothing — a
    /// client could otherwise renew that window forever by re-announcing the
    /// generation it already holds.
    #[must_use]
    pub fn activate_connection_epoch(&mut self, slot: SlotId, epoch: u64, now: Instant) -> bool {
        if self.departures.contains_key(&slot) || self.decided_leaves.contains_key(&slot) {
            return false;
        }
        if self
            .retired_connection_epochs
            .get(&slot)
            .is_some_and(|retired| retired.contains(&epoch))
        {
            return false;
        }
        match self.connection_states.get(&slot).copied() {
            Some(ConnectionState::Up(current)) if current == epoch => return true,
            Some(ConnectionState::Down(current)) if current == epoch => return false,
            _ => {}
        }
        if let Some(superseded) = self.connection_states.get(&slot).copied() {
            self.retired_connection_epochs
                .entry(slot)
                .or_default()
                .insert(superseded.epoch());
        }
        self.connection_states
            .insert(slot, ConnectionState::Up(epoch));
        if let Some(state) = self.slots.get_mut(&slot) {
            state.reset_link_conditions();
            state.connection_up_at = Some(now);
        }
        true
    }

    /// Resolves a reliable connection-up event in one decision-maker critical
    /// section. If an undecided departure has a matching drop hold, its complete
    /// slot state is restored and the new generation is activated without a gap
    /// in which the old generation can record another departure.
    #[cfg(test)]
    pub(in crate::consensus) fn resolve_reconnect(
        &mut self,
        slot: SlotId,
        observed: Option<u64>,
        hold_pending: bool,
    ) -> ReconnectTransition {
        self.resolve_reconnect_with(slot, observed, hold_pending, || {})
    }

    pub(in crate::consensus) fn resolve_reconnect_with(
        &mut self,
        slot: SlotId,
        observed: Option<u64>,
        hold_pending: bool,
        after_reinstate: impl FnOnce(),
    ) -> ReconnectTransition {
        if self.decided_leaves.contains_key(&slot) {
            return ReconnectTransition {
                admission: ReconnectAdmission::Rejected,
                consume_hold: hold_pending,
            };
        }
        // This slot's link was closed because its simulation stopped stepping
        // while the session ran on past it, and reconnecting cannot restart a
        // dead simulation. Admitting it would clear the survivors' drop hold and
        // restart their countdown on every redial, leaving them stalled forever
        // — so refuse, and deliberately do NOT consume the hold, which is what
        // lets them decide the drop.
        if self.silence_evicted.contains(&slot) {
            return ReconnectTransition {
                admission: ReconnectAdmission::Rejected,
                consume_hold: false,
            };
        }
        // A drop mid-finalization is terminal-in-progress: the home has
        // sealed the generation and is snapshotting (or has snapshotted) the
        // count, and an admission here would push turns past it. Refuse
        // without consuming the hold — if the finalization fails to produce a
        // count, the mark is lifted and a later reconnect resumes normally.
        if self.finalizing_drops.contains(&slot) {
            return ReconnectTransition {
                admission: ReconnectAdmission::Rejected,
                consume_hold: false,
            };
        }
        if self.connection_activation(slot, observed) == ConnectionActivation::Rejected {
            return ReconnectTransition {
                admission: ReconnectAdmission::Rejected,
                consume_hold: false,
            };
        }

        let reinstated = self.departures.contains_key(&slot);
        if reinstated && !hold_pending {
            // A departure without a hold is a clean/final leave (or legacy
            // inconsistent state), never authority to resurrect the slot.
            return ReconnectTransition {
                admission: ReconnectAdmission::Rejected,
                consume_hold: false,
            };
        }
        if reinstated {
            let restored = self.reinstate_slot(slot);
            debug_assert!(restored, "the undecided departure was checked above");
            if !restored {
                return ReconnectTransition {
                    admission: ReconnectAdmission::Rejected,
                    consume_hold: hold_pending,
                };
            }
            after_reinstate();
        }

        let admitted = self.admit_connection_up(slot, observed, Instant::now());
        debug_assert!(
            admitted,
            "a preclassified generation with no departure must be admissible"
        );
        ReconnectTransition {
            admission: if admitted {
                ReconnectAdmission::Admitted { reinstated }
            } else {
                ReconnectAdmission::Rejected
            },
            // A hold with no departure is stale bookkeeping. Once a generation
            // is admitted it must not remain available for a later drop request.
            consume_hold: hold_pending,
        }
    }

    /// Moves the matching active generation to its terminal down state. A
    /// duplicate Down(E) is idempotent; a stale generation and any legacy frame
    /// after upgrade are rejected.
    pub(in crate::consensus) fn mark_connection_down(
        &mut self,
        slot: SlotId,
        observed: Option<u64>,
    ) -> bool {
        match (self.connection_states.get(&slot).copied(), observed) {
            (None, None) => true,
            (None, Some(epoch)) => {
                self.connection_states
                    .insert(slot, ConnectionState::Down(epoch));
                true
            }
            (Some(ConnectionState::Up(current)), Some(epoch)) if current == epoch => {
                self.connection_states
                    .insert(slot, ConnectionState::Down(epoch));
                true
            }
            (Some(ConnectionState::Down(current)), Some(epoch)) if current == epoch => true,
            _ => false,
        }
    }

    /// Whether a generation-bearing operation belongs to the active physical
    /// connection. `None` is accepted only while this slot remains in legacy,
    /// unfenced mode; seeing an epoch is a one-way upgrade for the session.
    pub fn connection_epoch_matches(&self, slot: SlotId, epoch: Option<u64>) -> bool {
        match (self.connection_states.get(&slot).copied(), epoch) {
            (Some(current), Some(observed)) => current.epoch() == observed,
            (None, None) => true,
            _ => false,
        }
    }
}
