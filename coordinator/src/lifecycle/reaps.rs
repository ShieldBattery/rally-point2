//! The reap timers and the policy that arms and disarms them: holdout,
//! linger, never-started, globally-empty, and the webhook-only idle reap, each
//! an arm/fire pair, plus the shared re-evaluation entry points and the fan-out
//! that sends `CloseSlot` directives to a session's serving relays.

use super::*;

impl Lifecycle {
    /// Arms (or re-arms) a webhook-only state's idle reap, but only while it is
    /// webhook-only — a state with a serving relay has the normal all-relays-closed
    /// removal path and needs no idle reap. Called after every webhook enqueued, so
    /// the grace measures idle time since the last one and a game's tail notices
    /// keep the entry alive until they stop arriving.
    pub(super) fn arm_webhook_reap_if_orphan(
        &self,
        tenant: &TenantId,
        session: SessionId,
        state: &mut SessionState,
    ) {
        if !state.serving_relays.is_empty() {
            return;
        }
        if let Some(timer) = state.webhook_timer.take() {
            timer.abort();
        }
        let this = self.clone();
        let tenant = tenant.clone();
        let grace = self.inner.webhook_grace;
        state.webhook_timer = Some(
            tokio::spawn(async move {
                tokio::time::sleep(grace).await;
                this.fire_webhook_reap(tenant, session);
            })
            .abort_handle(),
        );
    }

    /// The webhook-only reap timer firing: if the state is still webhook-only (no
    /// serving relay was recorded during the grace), remove it. Removing it drops
    /// the ordered queue's sender, so its detached drain task delivers whatever is
    /// still queued and then exits — no parked task is left behind — and its dedup
    /// entries are pruned.
    fn fire_webhook_reap(&self, tenant: TenantId, session: SessionId) {
        let key = (tenant.clone(), session);
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get(&key) else {
            return;
        };
        if !state.serving_relays.is_empty() {
            return; // it gained a serving set: the normal close path owns it now
        }
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        abort_timers(&state);
        // Dropping `state` drops the queue sender; the drain task finishes any
        // buffered job, then exits.
        drop(state);
        self.prune_dedup(&tenant, session);
        // Retire any pending reap directives for the removed session (a webhook-only
        // state normally has none, but this keeps the pending set bounded either way).
        self.inner.setup.reaps().retire(&tenant, session);
        // A webhook-only state has no relay membership (this coordinator lifetime
        // never created the session), so the take returns an empty serving set, the
        // removal loop is empty, and forget_rehomes a harmless no-op. The steps run
        // anyway in the same take-first order as `on_session_closed` above, so the two
        // close paths stay uniform (see that path for why the take must come first).
        let serving = self.inner.setup.take_session_membership(&tenant, session);
        for relay_id in serving {
            self.inner
                .setup
                .descriptors()
                .remove(relay_id, &tenant, session);
        }
        self.inner.setup.forget_rehomes(&tenant, session);
        self.inner.setup.rehome_limiter().forget(&tenant, session);
        tracing::debug!(
            tenant = tenant.as_ref(),
            session = session.0,
            "webhook-only session state reaped after its idle grace",
        );
    }

    /// Drops the notice dedup entries for `(tenant, session)`, if a dedup set was
    /// wired in. A no-op for a lifecycle built without one.
    pub(super) fn prune_dedup(&self, tenant: &TenantId, session: SessionId) {
        if let Some(dedup) = self.inner.dedup.get() {
            dedup.prune_session(tenant, session);
        }
    }

    /// Whether a lifecycle state currently exists for `(tenant, session)` — a test
    /// hook for asserting a state was reaped (its map entry removed), or created
    /// (including webhook-only, unlike [`is_alive`](Self::is_alive)).
    #[cfg(test)]
    pub(crate) fn contains_state(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.inner
            .sessions
            .lock()
            .contains_key(&(tenant.clone(), session))
    }

    /// Re-arms or disarms the two reap timers for `state` after its accounting
    /// changed. Arming is idempotent — an already-armed timer is left running
    /// rather than reset, so the grace measures from when the condition first held.
    pub(super) fn reevaluate_reaps(
        &self,
        tenant: &TenantId,
        session: SessionId,
        state: &mut SessionState,
    ) {
        let unaccounted = state.unaccounted_players();

        // Holdout: all-but-one player accounted, the last one silent on a live
        // link. Only meaningful for a real multi-player session.
        if state.player_slots.len() >= 2 && unaccounted.len() == 1 {
            let holdout = unaccounted[0];
            if state.holdout_timer.is_none() {
                state.holdout_timer = Some(self.arm_holdout(
                    tenant.clone(),
                    session,
                    holdout,
                    self.inner.holdout_grace,
                ));
            }
        } else if let Some(timer) = state.holdout_timer.take() {
            timer.abort();
        }

        // Linger: every player accounted but links remain (sessionClosed not yet
        // fired). Protects the defeated spectator — not all accounted, no reap.
        if !state.player_slots.is_empty() && unaccounted.is_empty() && !state.all_relays_closed() {
            if state.linger_timer.is_none() {
                state.linger_timer =
                    Some(self.arm_linger(tenant.clone(), session, self.inner.linger_grace));
            }
        } else if let Some(timer) = state.linger_timer.take() {
            timer.abort();
        }
    }

    /// Arms or cancels the started-session globally-empty backstop. The timer is
    /// left running while the condition remains continuously true, so its grace is
    /// measured from the last assigned relay first becoming confirmed empty rather
    /// than being pushed out by every 10-second refresh.
    pub(super) fn reevaluate_empty_reap(
        &self,
        tenant: &TenantId,
        session: SessionId,
        state: &mut SessionState,
        now: Instant,
    ) {
        let confirmed_empty = state.started
            && !state.all_relays_closed()
            && state.all_relays_confirmed_empty(now, self.inner.empty_roster_freshness);
        if confirmed_empty {
            if state.empty_timer.is_none() {
                let token = self
                    .inner
                    .next_empty_timer_token
                    .fetch_add(1, Ordering::Relaxed);
                state.empty_timer = Some(EmptyTimer {
                    token,
                    abort: self.arm_empty_session(
                        tenant.clone(),
                        session,
                        token,
                        self.inner.empty_session_grace,
                    ),
                });
            }
        } else if state.empty_timer.is_some() {
            self.invalidate_empty_timer(state);
        }
    }

    /// Spawns the holdout-reap timer: after `grace`, if the holdout is still
    /// unaccounted, close its link on every serving relay.
    fn arm_holdout(
        &self,
        tenant: TenantId,
        session: SessionId,
        holdout: SlotId,
        grace: Duration,
    ) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_holdout(tenant, session, holdout);
        })
        .abort_handle()
    }

    /// The holdout timer firing: re-check the condition (accounting can have moved
    /// during the grace), then close the holdout's link on every serving relay.
    fn fire_holdout(&self, tenant: TenantId, session: SessionId, holdout: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        state.holdout_timer = None;
        if state.accounted.contains(&holdout) {
            return; // the holdout reported/departed during the grace — resolved
        }
        let relays = state.serving_relays.clone();
        drop(sessions);
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            slot = holdout.0,
            "holdout reap: closing the silent slot's link",
        );
        self.close_slots(&tenant, session, vec![holdout], &relays);
    }

    /// Spawns the linger-reap timer: after `grace`, if all players are still
    /// accounted and links remain, close every slot with no departure record.
    fn arm_linger(&self, tenant: TenantId, session: SessionId, grace: Duration) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_linger(tenant, session);
        })
        .abort_handle()
    }

    /// The linger timer firing: re-check the condition, then close every player or
    /// observer slot that has no departure record (reported-but-still-linked
    /// stragglers and observers).
    fn fire_linger(&self, tenant: TenantId, session: SessionId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        state.linger_timer = None;
        if !state.unaccounted_players().is_empty() || state.all_relays_closed() {
            return; // condition resolved during the grace
        }
        let targets: Vec<SlotId> = state
            .player_slots
            .iter()
            .chain(state.observer_slots.iter())
            .filter(|s| !state.departures.contains_key(s))
            .copied()
            .collect();
        let relays = state.serving_relays.clone();
        drop(sessions);
        if targets.is_empty() {
            return;
        }
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            slots = ?targets,
            "linger reap: closing the non-departed stragglers",
        );
        self.close_slots(&tenant, session, targets, &relays);
    }

    /// Spawns the never-started reap timer: after `grace`, if the session is
    /// still unstarted, retire it exactly as a normal close would.
    pub(super) fn arm_never_started(
        &self,
        tenant: TenantId,
        session: SessionId,
        grace: Duration,
    ) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_never_started(tenant, session);
        })
        .abort_handle()
    }

    /// The never-started timer firing: re-check `started` under the lock
    /// (the session could have started, or already have been closed some
    /// other way, at any point during the grace — including in a race with
    /// this very timer's own abort, which cannot retroactively stop a task
    /// already past its sleep), then retire the session exactly like a
    /// normal close, firing its `sessionClosed` webhook so the tenant learns
    /// the session died unborn rather than simply vanishing.
    fn fire_never_started(&self, tenant: TenantId, session: SessionId) {
        let key = (tenant.clone(), session);
        // Serialize the terminal retirement against re-home's membership and
        // descriptor commit. Whichever takes the assignment lock first completes;
        // the other then evaluates only the fully committed before/after state.
        let _assignment = self.inner.setup.lock_assignment();
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&key) else {
            return; // already retired some other way
        };
        state.never_started_timer = None;
        if state.started {
            return; // started (or was marked so) during the grace
        }
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        self.close_and_retire(tenant.clone(), session, state);
        crate::metrics::session_reaped(&tenant, "never_started");
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            "session reaped: created but never started within its grace window",
        );
    }

    /// Spawns the globally-empty backstop timer. The firing path rechecks both
    /// continuous complete-roster evidence and freshness under the lifecycle lock.
    fn arm_empty_session(
        &self,
        tenant: TenantId,
        session: SessionId,
        token: u64,
        grace: Duration,
    ) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_empty_session(tenant, session, token);
        })
        .abort_handle()
    }

    /// Retires a started session only if every assigned relay still has fresh,
    /// complete empty-roster evidence (or already reported `SessionClosed`) when
    /// the grace expires. Any reconnect, partial snapshot, occupancy, re-home, or
    /// heartbeat gap makes the check fail closed and leaves the session alive.
    pub(super) fn fire_empty_session(&self, tenant: TenantId, session: SessionId, token: u64) {
        let key = (tenant.clone(), session);
        // Serialize retirement against re-home, then final epoch validation
        // against registry enrollment and disconnect. An older timer/connection
        // cannot cross either external mutation and consume newer evidence.
        let _assignment = self.inner.setup.lock_assignment();
        let epochs = self.inner.relay_epochs.lock();
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&key) else {
            return;
        };
        if !state
            .empty_timer
            .as_ref()
            .is_some_and(|timer| timer.token == token)
        {
            return;
        }
        state.empty_timer = None;
        if !state.started
            || state.all_relays_closed()
            || !state.all_relays_confirmed_empty(Instant::now(), self.inner.empty_roster_freshness)
            || !state.empty_evidence_matches_epochs(&epochs)
        {
            return;
        }
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        self.close_and_retire(tenant.clone(), session, state);
        crate::metrics::session_reaped(&tenant, "heartbeat_empty");
        tracing::warn!(
            tenant = tenant.as_ref(),
            session = session.0,
            "session reaped after every serving relay continuously reported an empty roster",
        );
    }

    /// Fans a `CloseSlot` directive out to every serving relay. A relay that does
    /// not hold a named slot ignores it, so naming every serving relay is safe.
    fn close_slots(
        &self,
        tenant: &TenantId,
        session: SessionId,
        slots: Vec<SlotId>,
        relays: &[RelayId],
    ) {
        let close = SlotClose {
            tenant: tenant.clone(),
            session,
            slots,
        };
        for relay in relays {
            self.inner.setup.reaps().send(*relay, close.clone());
        }
    }
}
