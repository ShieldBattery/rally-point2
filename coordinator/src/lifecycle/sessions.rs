//! Per-session facts arriving from the relay control connections: session
//! registration, re-home bookkeeping, departures and results, the connected /
//! started slot records behind a load-state read, and the presence signal that
//! marks a session as actually begun. Everything here mutates one session's
//! entry in the lifecycle map and then re-evaluates that session's reaps.

use super::*;

impl Lifecycle {
    /// Records a freshly created session's serving relays and its player/observer
    /// slot split, spawning its ordered dispatch queue, and arms the
    /// never-started reap for it (see `fire_never_started`). Called from
    /// `create_session`. A repeat call (a session id collision, or a re-create)
    /// replaces the accounting inputs while keeping the existing queue.
    pub fn register_session(
        &self,
        tenant: TenantId,
        session: SessionId,
        serving_relays: Vec<RelayId>,
        player_slots: HashSet<SlotId>,
        observer_slots: HashSet<SlotId>,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.serving_relays = serving_relays;
        // This coordinator has held the session since its creation, so what it
        // accumulates for it is complete rather than whatever notices happened to
        // find it. Only the load-state read cares (see `load_state`).
        state.created_here = true;
        state.player_slots = player_slots;
        state.observer_slots = observer_slots;
        state.closed_relays.clear();
        // The session starts here, on relays that hold it from this instant: their
        // memory covers its whole life until something breaks that chain.
        state.attestable = true;
        // If this state existed only as a webhook-only entry (a departure/result
        // arrived before its registration), it now has the normal all-relays-
        // closed removal path, so its idle reap no longer applies.
        if !state.serving_relays.is_empty()
            && let Some(timer) = state.webhook_timer.take()
        {
            timer.abort();
        }
        // A repeat registration re-arms the never-started clock fresh (a
        // re-create is, from this session's perspective, starting over) --
        // unless the session is already known to have started, in which case
        // there is nothing left for this reap to protect against.
        if let Some(timer) = state.never_started_timer.take() {
            timer.abort();
        }
        if !state.started {
            state.never_started_timer =
                Some(self.arm_never_started(tenant, session, self.inner.never_started_grace));
        }
        self.reset_empty_evidence(state);
    }

    /// Invalidates heartbeat-empty evidence before attempting a re-home. This is
    /// deliberately separate from [`Self::on_rehome`]: the session registry is
    /// mutated outside the lifecycle lock, so cancelling the old assignment's
    /// timer first prevents it from firing in the gap between that mutation and
    /// the lifecycle's cached serving-relay update.
    ///
    /// A failed or no-op re-home conservatively requires fresh complete rosters
    /// before the empty grace may begin again.
    pub fn prepare_rehome(&self, tenant: &TenantId, session: SessionId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        // `dead` is retained here because the re-home may return Stay or
        // Unavailable, in which case no assignment boundary exists and its close
        // remains legitimate. A successful under-lock `on_rehome` clears both
        // endpoints before resumed descriptors are published.
        self.reset_empty_evidence(state);
    }

    /// Swaps `dead` for `r_new` in the session's cached serving-relay set, so a
    /// later `SessionClosed` from the replacement (or from any other surviving
    /// relay) can still satisfy the all-relays-closed condition — without this, a
    /// re-home leaves the cached set naming a relay that will never report
    /// closed, and the session's final `sessionClosed` webhook, state, and drain
    /// queue task never retire.
    ///
    /// A same-id swap (`dead == r_new`, a relay that restarted in place under a
    /// new cert) leaves the serving set unchanged but still clears old assignment
    /// evidence. Otherwise, if `r_new` is already present, `dead` is simply dropped
    /// from the set rather than producing a duplicate entry. A
    /// session with no cached state, or one whose cached set no longer names
    /// `dead` (an already-applied swap, or an id unrelated to this session), is
    /// left untouched — the call is idempotent, so a caller need not track
    /// whether it already applied a given swap.
    ///
    /// Both endpoints' close evidence is cleared as part of a different-id swap:
    /// the dead relay's notice belongs to the removed assignment, while the
    /// target's resumed descriptor may now admit a different homed group. The API
    /// invokes this under the assignment lock before publishing those descriptors,
    /// so subsequent terminal notices are unambiguously scoped to the new set.
    ///
    /// A re-home also ends the session's completeness claim for good. The departing
    /// relay's retained load state dies with its assignment and the replacement
    /// starts from an empty maker, so nothing that comes after can speak for what
    /// the old relay saw and never restated. A same-id swap is the same loss: a
    /// relay that restarted in place came back with an empty memory too.
    pub fn on_rehome(&self, tenant: &TenantId, session: SessionId, dead: RelayId, r_new: RelayId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        if dead == r_new {
            // Membership is unchanged, but the resumed descriptor is still a new
            // assignment boundary. Clear any close/empty evidence that landed
            // after `prepare_rehome` and before the assignment lock was acquired.
            self.reset_empty_evidence(state);
            state.closed_relays.remove(&dead);
            state.attestable = false;
            return;
        }
        let Some(pos) = state.serving_relays.iter().position(|&id| id == dead) else {
            return;
        };
        // Keep this reset as defense in depth for direct callers and tests. The
        // API cancels the timer before mutating membership via `prepare_rehome`.
        self.reset_empty_evidence(state);
        // Assignment-scoped evidence leaves with the relay.
        state.closed_relays.remove(&dead);
        state.attestable = false;
        // A resumed descriptor changes what the target may serve, even when it was
        // already a member. Drop its prior close evidence before the new descriptor
        // is published; a later close then belongs to the resumed assignment.
        state.closed_relays.remove(&r_new);
        if state.serving_relays.contains(&r_new) {
            state.serving_relays.remove(pos);
        } else {
            state.serving_relays[pos] = r_new;
        }
    }

    /// Records a slot's departure: accounts the slot (if a player), notes it
    /// departed with its left-vs-dropped classification and the leave's exact
    /// turn count, and re-evaluates the reap timers. Both retained values are
    /// what a coordinator-mediated re-home seeds into a fresh relay
    /// ([`departed_slots`](Self::departed_slots)).
    pub fn on_departure(
        &self,
        tenant: TenantId,
        session: SessionId,
        slot: SlotId,
        kind: DepartureKind,
        final_turn_count: Option<u64>,
        finalized: bool,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        // A dropped count is retained only with the home-finalization proof;
        // anything else is discarded here rather than trusted from the wire
        // (the reporting relay may run code that predates the
        // clean-leaves-or-finalized rule), so a rehome descriptor never
        // re-seeds an unsound drop count into a relay that would trust it.
        let finalized = matches!(kind, DepartureKind::Dropped) && finalized;
        let final_turn_count = match kind {
            DepartureKind::Dropped if !finalized => None,
            _ => final_turn_count,
        };
        // First record for a slot wins — a slot never departs twice, and every
        // relay's copy of the same decided leave carries the same substance.
        state.departures.entry(slot).or_insert(DepartureSeed {
            kind,
            final_turn_count,
            finalized,
        });
        if state.player_slots.contains(&slot) {
            state.accounted.insert(slot);
        }
        // A departure is only possible once a real client has been there —
        // proof enough to cancel the never-started reap even without a
        // heartbeat ever having reported this slot connected.
        self.mark_started(state);
        self.reevaluate_reaps(&tenant, session, state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
        // Fold a departure recorded after a rehome's descriptor build into the
        // staged resumed descriptors (a no-op for a never-rehomed session).
        // The sessions lock must be released first: the refresh takes the
        // assignment lock and then re-reads the accounting through
        // `departed_slots`, and every other path orders assignment before
        // sessions.
        drop(sessions);
        crate::session::refresh_resumed_descriptors(&self.inner.setup, &tenant, session, || {
            self.departed_slots(&tenant, session)
        });
    }

    /// The slots this coordinator has recorded as departed for `session`, each
    /// with its left-vs-dropped classification and the leave's exact turn count
    /// — the seed a coordinator-mediated re-home carries in the rebuilt
    /// descriptors so a fresh relay's consensus treats the departures as
    /// already decided (and schedules them at the count the original directive
    /// carried). Empty for a session with no recorded departures (or one this
    /// coordinator lifetime never registered).
    pub fn departed_slots(&self, tenant: &TenantId, session: SessionId) -> Vec<DepartedSlot> {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| {
                state
                    .departures
                    .iter()
                    .map(|(&slot, seed)| DepartedSlot {
                        finalized: seed.finalized,
                        slot,
                        kind: seed.kind,
                        final_turn_count: seed.final_turn_count,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records a slot's result: accounts the slot (if a player) and re-evaluates
    /// the reap timers. A result does not mark the slot departed — a reported
    /// player may still be watching live.
    pub fn on_result(&self, tenant: TenantId, session: SessionId, slot: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        if state.player_slots.contains(&slot) {
            state.accounted.insert(slot);
        }
        // A result is only possible once a real client has played -- see the
        // matching note on `on_departure`.
        self.mark_started(state);
        self.reevaluate_reaps(&tenant, session, state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Records that a slot's link activated on a serving relay: adds the slot to
    /// the ever-connected set and marks the session started.
    ///
    /// Stronger evidence of the same fact `on_presence_seen` records — a relay
    /// only reports this when a client's link is actually serving — so it
    /// disarms the never-started reap the same way. Unlike a heartbeat this
    /// arrives once per activation rather than every ~10s, so it lazily creates a
    /// webhook-only state (as `on_result` does) instead of ignoring an untracked
    /// session: the tenant's load-state pull should still find the arrival after
    /// a coordinator restart forgot the session.
    pub fn on_slot_connected(&self, tenant: TenantId, session: SessionId, slot: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.connected_slots.insert(slot);
        self.mark_started(state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Records the session's start instant — from the authority relay's
    /// session-started notice, or from any relay restating one on its heartbeat —
    /// and marks the session started. The first instant wins: a re-send, a second
    /// authority after a promotion, or a peer reporting when it adopted the
    /// directive must not move a value the tenant may already have recorded.
    pub fn on_session_started(&self, tenant: TenantId, session: SessionId, started_at_ms: u64) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.started_at_ms.get_or_insert(started_at_ms);
        self.mark_started(state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Records that a slot reported its game loop running: adds the slot to the
    /// ever-started set and marks the session started. Lazily creates a
    /// webhook-only state for the same reason [`on_slot_connected`](Self::on_slot_connected)
    /// does.
    pub fn on_slot_started(&self, tenant: TenantId, session: SessionId, slot: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.started_slots.insert(slot);
        self.mark_started(state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// The session's load progress as the coordinator currently knows it: when it
    /// started, which slots ever connected, which ever reported their game loop
    /// running, plus the two facts a completeness claim rests on — whether this
    /// coordinator created the session and whether relay memory covering it is
    /// unbroken — and the relays that would have to attest for such a claim. Both
    /// slot lists are sorted ascending.
    ///
    /// `Some` for every session the coordinator holds any state for, whatever built
    /// that state: the facts it has accumulated are positive evidence and worth
    /// answering with regardless. `None` only when it holds nothing at all — the
    /// session was never created here and no notice or beat has arrived for it, or
    /// it has already been reaped.
    ///
    /// Nothing here decides whether a slot's *absence* may be read as proof it
    /// never arrived. That also requires the serving relays to have just answered
    /// for themselves, which only the caller that asked them can know.
    pub fn load_state(&self, tenant: &TenantId, session: SessionId) -> Option<SessionLoadState> {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| SessionLoadState {
                created_here: state.created_here,
                attestable: state.attestable,
                serving_relays: state.serving_relays.clone(),
                started_at_ms: state.started_at_ms,
                connected_slots: sorted_slots(&state.connected_slots),
                started_slots: sorted_slots(&state.started_slots),
            })
    }

    /// Folds the load state a relay reported for each named session into the
    /// coordinator's records: the ever-connected and ever-started slot sets union
    /// in, and the first start instant seen wins.
    ///
    /// Fed by both sources that carry the shape — every heartbeat, which restates
    /// each session's whole retained state, and the on-demand snapshot a relay
    /// answers a load-state request with. They merge identically because the claim
    /// is identical: only positive facts, always safe to fold in, never a statement
    /// that something did *not* happen. The heartbeat is the durable repair path (a
    /// notice is dropped once its send succeeds, so a coordinator that died before
    /// committing one — or restarted — recovers within a beat); the snapshot is
    /// what a caller with a deadline asks for.
    ///
    /// Deliberately fires no webhook: these are re-statements of facts already
    /// notified, and the tenant's feed must not repeat them every ten seconds.
    ///
    /// An entry's *currently connected* slots union in as ever-connected too: a
    /// slot connected now necessarily connected at some point, which recovers a
    /// slot-connected notice lost before the relay had a maker to retain it in the
    /// set the entry restates.
    ///
    /// The caller applies the same fences as the rest of the beat — a stale control
    /// connection's roster is dropped whole, and an entry for a session the relay
    /// does not serve is rejected — before anything reaches here.
    pub fn merge_load_state(&self, sessions: &[SessionPresence]) {
        for session in sessions {
            for &slot in session.slots.iter().chain(&session.ever_connected) {
                self.on_slot_connected(session.tenant.clone(), session.session, slot);
            }
            for &slot in &session.started {
                self.on_slot_started(session.tenant.clone(), session.session, slot);
            }
            if let Some(started_at_ms) = session.started_at_ms {
                self.on_session_started(session.tenant.clone(), session.session, started_at_ms);
            }
        }
    }

    /// Records that `relay`'s process memory is discontinuous with whatever it held
    /// before — it re-enrolled under a different process identity, or under none at
    /// all — so every session it serves loses its completeness claim permanently.
    ///
    /// A relay's retained load state lives in that process's memory. Once the
    /// process is gone, whatever it observed and had not yet restated is
    /// unrecoverable, and a snapshot from its successor covers only the interval
    /// since. The sessions keep every fact already folded in; what they lose is the
    /// right to read an absent slot as one that never arrived.
    pub fn on_relay_lineage_break(&self, relay: RelayId) {
        let mut sessions = self.inner.sessions.lock();
        for state in sessions.values_mut() {
            if state.serving_relays.contains(&relay) {
                state.attestable = false;
            }
        }
    }

    /// Records that some relay's heartbeat reported at least one connected
    /// slot for `session` — the coordinator's own "a real client is here"
    /// signal, distinct from any accounting event (a client can stay
    /// connected a long time before it ever departs or reports a result).
    /// Cancels the never-started reap timer if one is armed.
    ///
    /// Deliberately does NOT lazily create a webhook-only state the way
    /// `on_departure`/`on_result`/`enqueue_webhook` do: a session this
    /// coordinator lifetime never registered has no never-started timer to
    /// cancel in the first place, and heartbeats arrive constantly (every
    /// live session, every ~10s, from every relay serving it) — spinning up
    /// a whole state (with its own drain task) just to immediately do
    /// nothing with it would itself leak one per pre-existing session across
    /// every coordinator restart until its own idle grace caught up.
    pub fn on_presence_seen(&self, tenant: TenantId, session: SessionId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant, session)) else {
            return; // untracked: never registered this lifetime, or already closed
        };
        self.mark_started(state);
    }
}
