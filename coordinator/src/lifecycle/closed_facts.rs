//! The load facts a retired session leaves behind: what a session's lifecycle
//! state had accumulated about its load progress, kept for a retention window
//! after the state itself is removed so the load-state read can still answer
//! with them.
//!
//! A tenant reads load state when its own load deadline expires. A short game can
//! start, end, and close before that, and without these records the read would
//! find nothing and answer every set empty, losing the very facts (a slot whose
//! game loop ran) the read exists to recover.
//!
//! Lock order: the `sessions` map, then the closed-facts map. A record is written
//! while the `sessions` guard that removed its state is still held, and a read
//! takes both in the same order, so no reader can observe a state already gone
//! from `sessions` whose facts are not yet recorded. Nothing takes the
//! closed-facts lock first, and nothing is locked while it is held.

use super::*;

/// The positive load facts one session had accumulated when its lifecycle state
/// was retired: the start instant and the four ever-sets. The load-state read
/// answers from it until it expires, after which it is treated as absent.
///
/// Connection observations are deliberately not kept. Their absence makes no
/// claim about a connection, so a post-close answer simply carries none.
///
/// Held in memory only, never in `LifecycleFacts`: a coordinator restart forgets
/// every record. That is a deliberate limit: persistence restores only sessions
/// that were still live, so a read after a restart finds nothing for a session
/// that closed before it and answers with no information, exactly as it does for
/// any session the restarted process never knew.
#[derive(Debug, Clone)]
pub(super) struct ClosedSessionLoadFacts {
    /// Relay wall-clock (unix epoch ms) of the session's start, as its state held
    /// it. Once set, a later retirement for the same session never moves it, for
    /// the same reason the live state's first report wins.
    started_at_ms: Option<u64>,
    /// Slots whose links ever activated.
    connected_slots: HashSet<SlotId>,
    /// Slots that ever reported their game loop running.
    started_slots: HashSet<SlotId>,
    /// Slots whose home relay ever forwarded one of their turns.
    forwarded_slots: HashSet<SlotId>,
    /// Slots whose home relay observed a pre-game lobby policy violation.
    lobby_violation_slots: HashSet<SlotId>,
    /// When the most recent retirement that contributed to this record happened;
    /// the retention window is measured from here.
    retired_at: Instant,
}

impl ClosedSessionLoadFacts {
    /// The facts `state` holds as of its retirement at `retired_at`, or `None`
    /// when it holds no positive fact at all (every set empty, no start instant),
    /// so retiring an empty state neither creates nor disturbs a record.
    fn from_retired(state: &SessionState, retired_at: Instant) -> Option<Self> {
        let facts = Self {
            started_at_ms: state.started_at_ms,
            connected_slots: state.connected_slots.clone(),
            started_slots: state.started_slots.clone(),
            forwarded_slots: state.forwarded_slots.clone(),
            lobby_violation_slots: state.lobby_violation_slots.clone(),
            retired_at,
        };
        let has_positive_fact = facts.started_at_ms.is_some()
            || !facts.connected_slots.is_empty()
            || !facts.started_slots.is_empty()
            || !facts.forwarded_slots.is_empty()
            || !facts.lobby_violation_slots.is_empty();
        has_positive_fact.then_some(facts)
    }

    /// Folds a later retirement's facts for the same session into this record:
    /// every set unions, the start instant already recorded is kept (the later
    /// one fills it only when this record has none), and the retention window
    /// restarts from the later retirement.
    fn absorb(&mut self, later: Self) {
        self.started_at_ms = self.started_at_ms.or(later.started_at_ms);
        self.connected_slots.extend(later.connected_slots);
        self.started_slots.extend(later.started_slots);
        self.forwarded_slots.extend(later.forwarded_slots);
        self.lobby_violation_slots
            .extend(later.lobby_violation_slots);
        self.retired_at = self.retired_at.max(later.retired_at);
    }

    /// Whether `retention` has fully elapsed since this record's last retirement
    /// at `now`. A zero retention expires every record the moment it is written.
    fn is_expired(&self, now: Instant, retention: Duration) -> bool {
        now.saturating_duration_since(self.retired_at) >= retention
    }

    /// The load-state answer for a session with no live state: these facts, with
    /// nothing a completeness claim could rest on. The coordinator no longer holds
    /// the session, so it was not created here as far as this answer can vouch,
    /// relay memory covering it is not attestable, and there is no relay left to
    /// ask.
    fn load_state(&self) -> SessionLoadState {
        SessionLoadState {
            evidence: Vec::new(),
            created_here: false,
            attestable: false,
            serving_relays: Vec::new(),
            started_at_ms: self.started_at_ms,
            connected_slots: sorted_slots(&self.connected_slots),
            started_slots: sorted_slots(&self.started_slots),
            forwarded_slots: sorted_slots(&self.forwarded_slots),
            lobby_violation_slots: sorted_slots(&self.lobby_violation_slots),
        }
    }

    /// Unions these facts into `live`, the answer built from a state that exists
    /// beside this record (one created for the session after it closed). The
    /// record's start instant wins because it was recorded first; every
    /// completeness input stays the live state's.
    fn overlay(&self, live: &mut SessionLoadState) {
        live.started_at_ms = self.started_at_ms.or(live.started_at_ms);
        union_sorted(&mut live.connected_slots, &self.connected_slots);
        union_sorted(&mut live.started_slots, &self.started_slots);
        union_sorted(&mut live.forwarded_slots, &self.forwarded_slots);
        union_sorted(&mut live.lobby_violation_slots, &self.lobby_violation_slots);
    }
}

/// Unions `extra` into the ascending, duplicate-free `slots`, keeping it so.
fn union_sorted(slots: &mut Vec<SlotId>, extra: &HashSet<SlotId>) {
    slots.extend(extra);
    slots.sort_unstable();
    slots.dedup();
}

impl Lifecycle {
    /// Removes `key`'s state from `sessions` to retire it, recording its load
    /// facts before returning. Every path that retires a state goes through here,
    /// so none can leave a reader a window where the state is gone and its facts
    /// are not yet kept.
    ///
    /// Taking the map by `&mut` means the caller holds the `sessions` guard for
    /// the whole call, which is what puts the record's write inside the same hold
    /// as the removal. The caller still drops that guard before
    /// [`close_and_retire`](Self::close_and_retire), as that path requires.
    pub(super) fn remove_for_retirement(
        &self,
        sessions: &mut HashMap<SessionRef, SessionState>,
        key: &SessionRef,
    ) -> Option<SessionState> {
        let state = sessions.remove(key)?;
        self.record_closed_load_facts(key, &state, Instant::now());
        Some(state)
    }

    /// Records `state`'s load facts for `key` as retired at `now`, first dropping
    /// every record already expired at `now`, so the map holds only the sessions
    /// that closed within the retention window without needing a timer. A record
    /// already kept for `key` absorbs the new facts rather than being replaced by
    /// a poorer one. A state with no positive fact touches no record at all.
    ///
    /// Must be called with the `sessions` guard held (see the module's lock order).
    pub(super) fn record_closed_load_facts(
        &self,
        key: &SessionRef,
        state: &SessionState,
        now: Instant,
    ) {
        let Some(facts) = ClosedSessionLoadFacts::from_retired(state, now) else {
            return;
        };
        let retention = self.inner.tunables.closed_load_facts_retention;
        let mut closed = self.inner.closed_load_facts.lock();
        closed.retain(|_, record| !record.is_expired(now, retention));
        match closed.get_mut(key) {
            Some(record) => record.absorb(facts),
            None => {
                closed.insert(key.clone(), facts);
            }
        }
    }

    /// The load-state answer for `key`, given the live answer `live` built from
    /// its state (if any): `live` unchanged when no unexpired record is kept,
    /// the record's own answer when there is no live state, and the two combined
    /// when both exist. An expired record found here is removed and treated as
    /// absent.
    ///
    /// Must be called with the `sessions` guard held, so the live answer and the
    /// record are read as one consistent picture.
    pub(super) fn with_closed_load_facts(
        &self,
        key: &SessionRef,
        live: Option<SessionLoadState>,
        now: Instant,
    ) -> Option<SessionLoadState> {
        let retention = self.inner.tunables.closed_load_facts_retention;
        let mut closed = self.inner.closed_load_facts.lock();
        let record = match closed.get(key) {
            Some(record) if record.is_expired(now, retention) => {
                closed.remove(key);
                return live;
            }
            Some(record) => record,
            None => return live,
        };
        match live {
            Some(mut live) => {
                record.overlay(&mut live);
                Some(live)
            }
            None => Some(record.load_state()),
        }
    }

    /// How many closed-session records are currently kept, expired or not — a
    /// test hook for asserting pruning.
    #[cfg(test)]
    pub(crate) fn closed_load_facts_count(&self) -> usize {
        self.inner.closed_load_facts.lock().len()
    }
}
