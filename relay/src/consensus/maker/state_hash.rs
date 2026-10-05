//! A rollback session's state hash reports (see `sync::hashes`).

use super::*;

use std::sync::atomic::Ordering;

impl DecisionMaker {
    /// Records `slot`'s report that its state after `step` hashed to `hash`, and returns whatever
    /// verdicts the report completes. Nothing happens outside a rollback session, or for an
    /// observer, which reports nothing.
    pub fn observe_state_hash(
        &mut self,
        slot: SlotId,
        step: u64,
        hash: u64,
        now: Instant,
    ) -> Vec<SyncDivergence> {
        if !self.rollback_enabled || self.observers.contains(&slot) {
            return Vec::new();
        }
        self.hashes.record(&self.key, slot, step, hash);
        self.judge_state_hashes(now)
    }

    /// Notes that this relay has forwarded `count` of `slot`'s turns without a gap, which starts
    /// the report deadlines of the steps that became confirmable, updates
    /// [`turns_complete`](Self::turns_complete_handle) and, on the authority, moves the session
    /// clock on, returning any change to it. Nothing outside a rollback session.
    pub fn note_forwarded_turns(
        &mut self,
        slot: SlotId,
        count: u64,
        now: Instant,
    ) -> Option<ClockUpdate> {
        if !self.rollback_enabled {
            return None;
        }
        let observers = &self.observers;
        let departures = &self.departures;
        let required = self
            .expected_slots
            .iter()
            .copied()
            .filter(|slot| !observers.contains(slot) && !departures.contains_key(slot));
        let before = self.hashes.confirmable_until();
        self.hashes
            .note_forwarded(&self.key, slot, count, now, required);
        // Unlike what is confirmable, an observer's turns count: a client's simulation waits on
        // every slot's turn, an observer's too.
        let complete = self
            .expected_slots
            .iter()
            .filter(|slot| !departures.contains_key(slot))
            .map(|&slot| self.hashes.forwarded_count(slot))
            .min()
            .unwrap_or(0);
        self.turns_complete.store(complete, Ordering::Release);
        self.advance_clock(before, self.hashes.confirmable_until(), now)
    }

    /// The count of every in-game slot's turns this relay has forwarded without a gap, as the
    /// packets to its own clients carry it (zero outside a rollback session, or until every slot
    /// has forwarded a turn), shared so a link can read it on every packet without a lock.
    pub fn turns_complete_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.turns_complete)
    }

    /// Judges every step whose reports are all in or whose deadline has passed by `now`, if this
    /// relay is the session's authority. Every relay keeps the reports; only the authority judges.
    /// Every slot a verdict names, or every player for a verdict with no majority, is also queued
    /// for eviction (see [`claim_desync_evictions`](Self::claim_desync_evictions)): a rollback
    /// client runs no native sync, so nothing but the relay takes a diverged player out of the
    /// game.
    pub fn judge_state_hashes(&mut self, now: Instant) -> Vec<SyncDivergence> {
        if !self.rollback_enabled || self.authority != Authority::SelfRelay || self.hashes.dormant {
            return Vec::new();
        }
        let observers = &self.observers;
        let departures = &self.departures;
        let mut required: Vec<SlotId> = self
            .expected_slots
            .iter()
            .copied()
            .filter(|slot| !observers.contains(slot) && !departures.contains_key(slot))
            .collect();
        required.sort_unstable();
        let verdicts = self.hashes.judge_ready(now, required.iter().copied());
        self.queue_desync_evictions(&verdicts, &required);
        verdicts
    }
}
