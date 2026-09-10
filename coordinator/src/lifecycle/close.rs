//! The end of a session: a relay's `SessionClosed`, the all-relays-closed
//! condition that enqueues the terminal `sessionClosed` webhook, retirement of
//! the session's state, and the ordered dispatch queue itself — the two kinds
//! of push (ordinary, droppable; terminal, never dropped) and state creation.

use super::*;

impl Lifecycle {
    /// Records a relay's `SessionClosed`. When every assigned serving relay has
    /// closed, enqueues the final `sessionClosed` webhook (behind every prior
    /// notice in queue order) and reaps the session's state. Until that global
    /// close, positive presence or a replacement enrollment may reopen one
    /// relay's mark because relays deliberately permit a quick reconnect.
    pub fn on_session_closed(
        &self,
        tenant: TenantId,
        session: SessionId,
        relay_id: RelayId,
        generation: u64,
    ) {
        // Re-home holds this same assignment lock across its authoritative
        // membership mutation. Thus an old assignment's close is checked wholly
        // before that mutation (and cleared by prepare/on_rehome), or wholly after
        // it (and rejected); it cannot straddle the boundary.
        let _assignment = self.inner.setup.lock_assignment();
        let epochs = self.inner.relay_epochs.lock();
        if !epochs
            .get(&relay_id)
            .is_some_and(|epoch| epoch.connected && epoch.generation == generation)
        {
            return;
        }
        let authoritative = self.inner.setup.serving_relays(&tenant, session);
        if !authoritative.contains(&relay_id) {
            return;
        }
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return; // an unknown session (restart amnesia): no serving set to close
        };
        if !state.serving_relays.contains(&relay_id) {
            // Production re-home installs lifecycle membership under the same
            // assignment lock before publishing descriptors. A mismatch here is
            // therefore stale or unassigned evidence, never a future member.
            return;
        }
        state.closed_relays.insert(relay_id, generation);
        state.empty_relays.remove(&relay_id);
        self.invalidate_empty_timer(state);
        self.reevaluate_empty_reap(&tenant, session, state, Instant::now());
        self.finish_if_all_closed(sessions, tenant, session);
    }

    /// If every serving relay has now reported closed — and the terminal webhook
    /// has not already been enqueued — declares the session over: sets the
    /// enqueued guard, enqueues `sessionClosed` behind everything already in the
    /// queue, and retires the session's state. A no-op otherwise: some relay is
    /// still open, the terminal webhook already fired, or the state was already
    /// removed by an earlier close.
    ///
    /// Every mutation that can newly satisfy the all-relays-closed condition
    /// funnels through here so the evaluation is never dropped on the floor: a
    /// relay reporting closed ([`on_session_closed`](Self::on_session_closed))
    /// and a re-home swapping the cached serving set
    /// ([`on_rehome`](Self::on_rehome)).
    ///
    /// Takes the held `sessions` guard by value rather than a `&mut` to it so it
    /// can enforce the retire discipline [`close_and_retire`](Self::close_and_retire)
    /// depends on: the state is removed from the map and the session lock is
    /// fully dropped BEFORE `close_and_retire` runs, because that path acquires
    /// the relay-membership, descriptor, and rehome locks and must never hold
    /// the session lock while doing so.
    fn finish_if_all_closed(
        &self,
        mut sessions: MutexGuard<'_, HashMap<SessionRef, SessionState>>,
        tenant: TenantId,
        session: SessionId,
    ) {
        let key = (tenant.clone(), session);
        let Some(state) = sessions.get_mut(&key) else {
            return; // already retired by an earlier close, or never tracked
        };
        if !state.all_relays_closed() || state.session_closed_enqueued {
            return;
        }
        state.session_closed_enqueued = true;
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        self.close_and_retire(tenant.clone(), session, state);
        crate::metrics::session_closed(&tenant);
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            "session fully closed; sessionClosed enqueued",
        );
    }

    /// Enqueues the final `sessionClosed` webhook (if the tenant has notify
    /// config) behind whatever is already in `state`'s queue, then retires
    /// every piece of this session's coordinator-side state — its reap
    /// timers, dedup entries, pending reap directives, relay membership and
    /// descriptors, and the rehome idempotency record.
    ///
    /// Shared by every path that declares a session over: all serving relays
    /// reporting closed (`on_session_closed`), a session whose never-started
    /// grace elapsed (`fire_never_started`), or a started session whose complete
    /// heartbeat rosters remained globally empty (`fire_empty_session`). The
    /// tenant learns about every case through the same terminal notice. The
    /// caller has already removed `state` from the session map and taken
    /// responsibility for the policy gate; this only performs the retirement.
    pub(super) fn close_and_retire(
        &self,
        tenant: TenantId,
        session: SessionId,
        state: SessionState,
    ) {
        // Build the sessionClosed job and enqueue it behind everything already in
        // the queue: the queue's own sender lives on in the detached drain task,
        // which delivers the final job and then exits.
        if let Some((config, body)) =
            notify::session_closed_dispatch(&self.inner.setup, &tenant, session)
        {
            self.push_terminal(
                &tenant,
                session,
                state.queue.clone(),
                WebhookJob {
                    tenant: tenant.clone(),
                    config,
                    body,
                    kind: "sessionClosed",
                },
            );
        }
        abort_timers(&state);
        // The session is done: drop its dedup entries so they don't accumulate for
        // the process lifetime, and retire any pending reap directives so they are
        // not replayed to a relay that reconnects after this.
        self.prune_dedup(&tenant, session);
        self.inner.setup.reaps().retire(&tenant, session);
        // Take (remove-and-return) the session's relay membership FIRST, atomically
        // with the serving-set snapshot, then drop each serving relay's descriptor
        // and only afterward clear the recorded rehomes. Ordering matters against a
        // concurrent `session::rehome`, which re-validates membership under the same
        // `session_relays` lock this take acquires:
        //
        // - Once the membership is gone (after this take), any racing rehome fails
        //   its under-lock re-validation: it can neither push a descriptor nor record
        //   a rehome, so there is nothing of its left to clean up.
        // - A rehome that completed BEFORE this take had already added its target
        //   relay to the membership, so that relay is in `serving` here — the
        //   descriptor removal below therefore covers the resumed descriptor it
        //   pushed, and `forget_rehomes` (run after the take) clears the idempotency
        //   entry it recorded.
        //
        // Every interleaving is thus covered. Removing the descriptor also stops a
        // relay reconnecting after the close from being re-synced the dead session's
        // stale descriptor and re-applying it — the relay-side reconciler only ends
        // sessions ABSENT from the pushed set, so a present-but-dead descriptor would
        // otherwise resurrect the session on that relay. Retiring the membership is
        // also what makes every subsequent re-home ask honestly answer `Unavailable`
        // (the empty serving set trips `session::rehome`'s guard), and dropping the
        // rate-limit bucket keeps that map bounded by live sessions.
        let serving = self.inner.setup.take_session_membership(&tenant, session);
        for relay_id in serving {
            self.inner
                .setup
                .descriptors()
                .remove(relay_id, &tenant, session);
        }
        self.inner.setup.forget_rehomes(&tenant, session);
        self.inner.setup.rehome_limiter().forget(&tenant, session);
    }

    /// Enqueues a webhook onto the session's ordered dispatch queue, creating a
    /// webhook-only queue on the fly for a session this coordinator lifetime never
    /// created (restart amnesia — the departure still delivers, serialized).
    ///
    /// This is the non-terminal (departure/desync/result) path: it may drop
    /// the notice instead of enqueueing it — see `push_ordinary`.
    /// The terminal `sessionClosed` job is never routed through here; it has
    /// its own push (`push_terminal`) that may not drop.
    pub fn enqueue_webhook(
        &self,
        tenant: TenantId,
        session: SessionId,
        config: NotifyConfig,
        body: Bytes,
        kind: &'static str,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        self.push_ordinary(
            &tenant,
            session,
            state,
            WebhookJob {
                tenant: tenant.clone(),
                config,
                body,
                kind,
            },
        );
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Ensures a lazily-created webhook-only lifecycle state exists for
    /// `(tenant, session)` and its idle reap is armed, without enqueuing any
    /// webhook — the minimal half of [`enqueue_webhook`](Self::enqueue_webhook)'s lazy creation, for
    /// a caller that must remember it saw something for this session
    /// regardless of whether that something is ultimately deliverable.
    ///
    /// A notice-dedup set (e.g. desync ordinals) that records `(tenant,
    /// session, ...)` on first sight, before knowing whether the notice will
    /// resolve to an actual webhook, needs exactly this: without a session
    /// state, the dedup entry has no retirement path at all (this
    /// coordinator lifetime's normal all-relays-closed removal, and
    /// `prune_dedup` alongside it, both require an existing
    /// `SessionState`) — a notice this coordinator can never resolve a
    /// notify config or a `gameId` ref for (a tenant with no webhook
    /// configured, or a session outside this coordinator's session store)
    /// would otherwise leak that dedup entry for the life of the process.
    /// Calling this unconditionally on first sight closes that gap
    /// regardless of how the notice is later resolved.
    pub fn ensure_orphan_tracked(&self, tenant: TenantId, session: SessionId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Pushes a non-terminal notice onto `state`'s queue, reserving its last
    /// slot for the session's eventual terminal `sessionClosed` job: an
    /// ordinary notice is sent only while the queue has room to spare beyond
    /// that one slot, so `sessionClosed` can never itself be the notice an
    /// overflow drops (see [`push_terminal`](Self::push_terminal)).
    ///
    /// On overflow, the notice being pushed — the newest one for the session
    /// — is the one dropped, loudly (a `warn!` plus [`DROPPED_NOTICE_COUNT`]).
    /// Everything already queued keeps its place: the queue never reorders,
    /// and nothing already accepted is evicted to make room. Given
    /// [`NOTICE_QUEUE_CAPACITY`]'s headroom over any honest session's real
    /// notice volume, this should only ever fire under a bug or abuse.
    fn push_ordinary(
        &self,
        tenant: &TenantId,
        session: SessionId,
        state: &SessionState,
        job: WebhookJob,
    ) {
        // `capacity()` is the number of additional sends the channel can
        // currently accept; requiring more than 1 before sending is what
        // keeps the last slot free for the terminal push. Every push onto one
        // session's queue runs under `self.inner.sessions`'s lock (there is no
        // other producer that could race this check against the send), so
        // this is effectively atomic in practice, not just in the common case.
        if state.queue.capacity() <= 1 {
            DROPPED_NOTICE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                tenant = tenant.as_ref(),
                session = session.0,
                kind = job.kind,
                capacity = self.inner.queue_capacity,
                "notice queue full; dropping the newest notice",
            );
            return;
        }
        let _ = state.queue.try_send(job);
    }

    /// Pushes the session's terminal `sessionClosed` job onto `queue`. Must
    /// never be dropped: its delivery is the proof (see the module doc) that
    /// no earlier notice for the session is still in flight, so silently
    /// dropping it would break that guarantee for whatever the queue's
    /// ordering exists to prove in the first place.
    ///
    /// [`push_ordinary`](Self::push_ordinary) always leaves this job exactly
    /// one reserved slot, so the immediate `try_send` below should always
    /// succeed. The `Full` arm is a last-resort fallback against a bug that
    /// let something else consume the reserved slot: it awaits capacity on a
    /// detached task instead of dropping, which still preserves ordering —
    /// the fallback sends on the very same channel handle, and tokio's mpsc
    /// serves sends against one channel in the order they were made, however
    /// long any individual one waits for room.
    fn push_terminal(
        &self,
        tenant: &TenantId,
        session: SessionId,
        queue: mpsc::Sender<WebhookJob>,
        job: WebhookJob,
    ) {
        match queue.try_send(job) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(job)) => {
                tracing::error!(
                    tenant = tenant.as_ref(),
                    session = session.0,
                    "sessionClosed found its reserved queue slot occupied; \
                     awaiting capacity instead of dropping it",
                );
                tokio::spawn(async move {
                    let _ = queue.send(job).await;
                });
            }
            // The drain task already exited (its receiver dropped) — nothing
            // left to deliver to. Only reachable if this queue's sender
            // somehow outlived its own drain task, which the drain loop's own
            // "exit when every sender is dropped" contract should prevent.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Whether the coordinator currently holds live state for `session` — it was
    /// created this coordinator lifetime and has not fully closed. The batch
    /// liveness endpoint reports exactly this; a session unknown, closed, or
    /// created only as a webhook-only queue (restart amnesia) reads as not alive,
    /// so the caller force-reconciles it.
    pub fn is_alive(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .is_some_and(|state| !state.serving_relays.is_empty() && !state.all_relays_closed())
    }

    /// Builds a fresh `SessionState` with an ordered dispatch queue whose detached
    /// drain task delivers jobs one at a time (each retry blocking the next).
    pub(super) fn new_state(&self, serving_relays: Vec<RelayId>) -> SessionState {
        let (tx, rx) = mpsc::channel::<WebhookJob>(self.inner.queue_capacity);
        let tenants = self.inner.setup.tenants().clone();
        tokio::spawn(drain_queue(rx, tenants));
        SessionState {
            serving_relays,
            created_here: false,
            player_slots: HashSet::new(),
            observer_slots: HashSet::new(),
            accounted: HashSet::new(),
            connected_slots: HashSet::new(),
            started_slots: HashSet::new(),
            // A state built anywhere but `register_session` covers only what
            // arrived after it appeared, so it can vouch for nothing about the
            // session's beginning until a registration says otherwise.
            attestable: false,
            started_at_ms: None,
            departures: HashMap::new(),
            closed_relays: HashMap::new(),
            session_closed_enqueued: false,
            queue: tx,
            holdout_timer: None,
            linger_timer: None,
            webhook_timer: None,
            started: false,
            never_started_timer: None,
            empty_relays: HashMap::new(),
            empty_timer: None,
        }
    }
}
