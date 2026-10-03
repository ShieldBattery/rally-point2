//! A rollback session's state hash reports (see `sync::hashes`).

use super::*;

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
    /// the report deadlines of the steps that became confirmable. Nothing outside a rollback
    /// session.
    pub fn note_forwarded_turns(&mut self, slot: SlotId, count: u64, now: Instant) {
        if !self.rollback_enabled {
            return;
        }
        let observers = &self.observers;
        let departures = &self.departures;
        let required = self
            .expected_slots
            .iter()
            .copied()
            .filter(|slot| !observers.contains(slot) && !departures.contains_key(slot));
        self.hashes
            .note_forwarded(&self.key, slot, count, now, required);
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
