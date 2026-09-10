//! Relay-side bookkeeping: the control-connection epochs that let a stale
//! connection's messages be rejected, heartbeat ingestion (load-state
//! restatements, presence, and the complete-roster emptiness evidence), the
//! small helpers that invalidate that evidence, and the metrics census.

use super::*;

impl Lifecycle {
    /// Commits a registry enrollment and its lifecycle epoch as one serialized
    /// operation. The callback performs the registry mutation and returns the new
    /// generation; no stale close or heartbeat can land between that mutation and
    /// the invalidation below.
    pub fn enroll_relay_epoch<E>(
        &self,
        relay: RelayId,
        enroll: impl FnOnce() -> Result<u64, E>,
    ) -> Result<u64, E> {
        let mut epochs = self.inner.relay_epochs.lock();
        let generation = enroll()?;
        self.apply_relay_enrolled(&mut epochs, relay, generation);
        Ok(generation)
    }

    /// Test seam for lifecycle-only tests whose registry is intentionally absent.
    #[cfg(test)]
    pub(crate) fn on_relay_enrolled(&self, relay: RelayId, generation: u64) {
        let mut epochs = self.inner.relay_epochs.lock();
        self.apply_relay_enrolled(&mut epochs, relay, generation);
    }

    fn apply_relay_enrolled(
        &self,
        epochs: &mut HashMap<RelayId, RelayEpoch>,
        relay: RelayId,
        generation: u64,
    ) {
        // Generations are process-global and strictly increasing. A delayed
        // callback for an older (or duplicate) connection cannot roll the epoch
        // backward or reopen evidence from the connection that replaced it.
        if epochs
            .get(&relay)
            .is_some_and(|epoch| epoch.generation >= generation)
        {
            return;
        }
        epochs.insert(
            relay,
            RelayEpoch {
                generation,
                connected: true,
            },
        );

        // Enrollment is rare, so scan all lifecycle states. This deliberately
        // clears a close left by an earlier assignment even when this relay is not
        // currently in its descriptor set; the id may be selected for that
        // session again by a later re-home.
        let now = Instant::now();
        let mut sessions = self.inner.sessions.lock();
        for ((tenant, session), state) in sessions.iter_mut() {
            let invalidated = state
                .empty_relays
                .get(&relay)
                .is_some_and(|evidence| evidence.generation < generation);
            let reopened = state.closed_relays.remove(&relay).is_some();
            if invalidated || reopened {
                state.empty_relays.remove(&relay);
                self.invalidate_empty_timer(state);
                self.reevaluate_empty_reap(tenant, *session, state, now);
            }
        }
    }

    /// Commits removal of the current registry entry and invalidates its
    /// heartbeat omission under the same epoch gate. A `SessionClosed` accepted
    /// before the removal remains terminal; only a later enrollment reopens it.
    pub fn disconnect_relay_epoch(
        &self,
        relay: RelayId,
        generation: u64,
        remove: impl FnOnce() -> bool,
    ) -> bool {
        let mut epochs = self.inner.relay_epochs.lock();
        if !remove() {
            return false;
        }
        self.apply_relay_disconnected(&mut epochs, relay, generation);
        true
    }

    /// Test seam matching [`Self::on_relay_enrolled`].
    #[cfg(test)]
    pub(crate) fn on_relay_disconnected(&self, relay: RelayId, generation: u64) {
        let mut epochs = self.inner.relay_epochs.lock();
        self.apply_relay_disconnected(&mut epochs, relay, generation);
    }

    fn apply_relay_disconnected(
        &self,
        epochs: &mut HashMap<RelayId, RelayEpoch>,
        relay: RelayId,
        generation: u64,
    ) {
        let Some(epoch) = epochs.get(&relay) else {
            return;
        };
        if epoch.generation != generation || !epoch.connected {
            return;
        }
        // Provisioned relay ids are not reused after retirement. Drop disconnected
        // epochs so fleet churn cannot grow this map forever; terminal close
        // evidence carries its own generation and the next enrollment scans all
        // session states before accepting new frames.
        epochs.remove(&relay);

        let now = Instant::now();
        let mut sessions = self.inner.sessions.lock();
        for ((tenant, session), state) in sessions.iter_mut() {
            let invalidated = state
                .empty_relays
                .get(&relay)
                .is_some_and(|evidence| evidence.generation == generation);
            if invalidated {
                state.empty_relays.remove(&relay);
                self.invalidate_empty_timer(state);
                self.reevaluate_empty_reap(tenant, *session, state, now);
            }
        }
    }

    /// Applies one relay's sanitized heartbeat roster to the stale-session
    /// safeguard. Listed sessions with connected slots are positive evidence and
    /// always cancel an empty proof. Only a `complete` roster may use omission as
    /// evidence that an assigned session is empty; legacy, truncated, or otherwise
    /// partial rosters turn omissions into unknown instead.
    ///
    /// `now` is injected so the continuity/freshness boundary can be tested without
    /// wall-clock sleeps. The API calls this only after fencing the heartbeat to the
    /// relay's current control-connection generation.
    pub fn on_relay_heartbeat(
        &self,
        relay: RelayId,
        generation: u64,
        roster: &[SessionPresence],
        complete: bool,
        now: Instant,
    ) {
        let epochs = self.inner.relay_epochs.lock();
        if !epochs
            .get(&relay)
            .is_some_and(|epoch| epoch.connected && epoch.generation == generation)
        {
            return;
        }
        // The descriptor outbox is the coordinator's declarative per-relay
        // assignment index. Snapshot only its lightweight keys so each heartbeat
        // is O(sessions served by this relay), not O(all active sessions).
        let assigned = self.inner.setup.descriptors().current_keys_for(relay);
        let occupied: HashSet<SessionRef> = roster
            .iter()
            .filter(|session| !session.slots.is_empty())
            .map(|session| (session.tenant.clone(), session.session))
            .collect();
        let freshness = self.inner.empty_roster_freshness;
        let mut sessions = self.inner.sessions.lock();
        for descriptor in assigned {
            let key = (descriptor.tenant, descriptor.session);
            let Some(state) = sessions.get_mut(&key) else {
                continue;
            };
            if !state.serving_relays.contains(&relay) {
                continue;
            }
            let is_occupied = occupied.contains(&key);
            let mut continuity_reset = false;
            if is_occupied {
                let was_empty = state.empty_relays.remove(&relay).is_some();
                let was_closed = state.closed_relays.remove(&relay).is_some();
                continuity_reset = was_empty || was_closed;
                self.mark_started(state);
            } else if complete {
                match state.empty_relays.get_mut(&relay) {
                    Some(evidence)
                        if evidence.generation == generation
                            && now.saturating_duration_since(evidence.last_seen) <= freshness =>
                    {
                        evidence.last_seen = now;
                    }
                    _ => {
                        state.empty_relays.insert(
                            relay,
                            EmptyRosterEvidence {
                                generation,
                                last_seen: now,
                            },
                        );
                        continuity_reset = true;
                    }
                }
            } else {
                // A partial snapshot cannot carry prior omission evidence forward.
                // Positive entries above still prove their named sessions occupied.
                continuity_reset = state.empty_relays.remove(&relay).is_some();
            }

            if continuity_reset {
                self.invalidate_empty_timer(state);
            }
            self.reevaluate_empty_reap(&key.0, key.1, state, now);
        }
    }

    /// Marks `state` as started and cancels its never-started reap timer, if
    /// one is armed. Idempotent — called from every path that proves a real
    /// client has been present.
    pub(super) fn mark_started(&self, state: &mut SessionState) {
        state.started = true;
        if let Some(timer) = state.never_started_timer.take() {
            timer.abort();
        }
    }

    /// Drops all globally-empty evidence and its timer after an assignment-level
    /// change (registration/re-home). The replacement must establish a fresh set of
    /// complete post-change rosters before it can become a reap candidate.
    pub(super) fn reset_empty_evidence(&self, state: &mut SessionState) {
        state.empty_relays.clear();
        self.invalidate_empty_timer(state);
    }

    /// Cancels the current globally-empty timer. Removing its identity from the
    /// slot is the part that remains effective if the task already woke and can no
    /// longer be stopped by aborting its handle.
    pub(super) fn invalidate_empty_timer(&self, state: &mut SessionState) {
        if let Some(timer) = state.empty_timer.take() {
            timer.abort.abort();
        }
    }

    /// A scrape-time census of the lifecycle map for metrics: per tenant, how
    /// many sessions have an assigned serving relay (split by whether a client
    /// has been seen), and the total depth of that tenant's pending webhook
    /// queues. The epoch gate makes the empty-grace slice agree with reconnects.
    pub(crate) fn metrics_census(&self) -> LifecycleMetrics {
        let epochs = self.inner.relay_epochs.lock();
        let sessions = self.inner.sessions.lock();
        let now = Instant::now();
        let mut out = LifecycleMetrics::default();
        for ((tenant, _session), state) in sessions.iter() {
            // Only sessions with an assigned serving-relay set count toward the
            // active gauge; a webhook-only state (empty serving set) is not a live
            // session but still contributes its queue depth below.
            if !state.serving_relays.is_empty() {
                let census = out.sessions.entry(tenant.clone()).or_default();
                if state.empty_timer.is_some()
                    && state.all_relays_confirmed_empty(now, self.inner.empty_roster_freshness)
                    && state.empty_evidence_matches_epochs(&epochs)
                {
                    census.empty_grace += 1;
                } else if state.started {
                    census.started += 1;
                } else {
                    census.loading += 1;
                }
            }
            // Pending queue depth: how many sends the queue has taken that have not
            // yet drained (its configured capacity minus its currently free slots).
            let depth = state
                .queue
                .max_capacity()
                .saturating_sub(state.queue.capacity()) as u64;
            *out.notices_pending.entry(tenant.clone()).or_default() += depth;
        }
        out
    }
}
