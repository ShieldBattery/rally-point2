//! A rollback session's state hash reports: fed from the forward gate, judged there and by a
//! periodic sweep that catches deadlines passing while no report arrives.

use super::*;

impl DecisionMakers {
    /// Records the state hash report a forwarded turn of `slot`'s carried, and publishes whatever
    /// verdicts it completes. Called from the forward gate for every fresh turn that carries one.
    pub fn observe_state_hash(&self, key: &SessionKey, slot: SlotId, step: u64, hash: u64) {
        let now = Instant::now();
        let verdicts = match self.lock().get_mut(key) {
            Some(maker) => maker.observe_state_hash(slot, step, hash, now),
            None => return,
        };
        for verdict in &verdicts {
            self.publish_desync(key, verdict);
        }
    }

    /// Judges every rollback session's steps whose report deadlines have passed by `now`, and
    /// publishes the verdicts. Run periodically: a deadline passes whether or not any report
    /// arrives to trigger a judgement.
    pub fn judge_overdue_state_hashes(&self, now: Instant) {
        let verdicts: Vec<(SessionKey, SyncDivergence)> = self
            .lock()
            .iter_mut()
            .flat_map(|(key, maker)| {
                maker
                    .judge_state_hashes(now)
                    .into_iter()
                    .map(|verdict| (key.clone(), verdict))
            })
            .collect();
        for (key, verdict) in &verdicts {
            self.publish_desync(key, verdict);
        }
    }

    /// Every slot a rollback verdict named since the last claim, across every session, each one
    /// this relay strictly homes already marked evicted (see
    /// [`DecisionMaker::claim_desync_evictions`]). What a caller does with them — closing the
    /// link of a slot this relay homes and telling every other relay serving the session —
    /// belongs to the layer that owns links and the mesh, which is why this hands the slots back
    /// rather than acting on them.
    ///
    /// The whole sweep runs under one acquisition of the registry lock, and the mark is taken
    /// inside it, so a dial arriving while the caller acts is already refused.
    pub fn claim_desync_evictions(&self) -> Vec<(SessionKey, DesyncEviction)> {
        let mut claimed = Vec::new();
        for (key, maker) in self.lock().iter_mut() {
            claimed.extend(
                maker
                    .claim_desync_evictions()
                    .into_iter()
                    .map(|eviction| (key.clone(), eviction)),
            );
        }
        claimed
    }

    /// Marks `slot` evicted for desync in `key`'s session if this relay strictly homes it, and
    /// returns whether it does (see [`DecisionMaker::mark_desync_evicted`]). For a verdict another
    /// relay produced; `false` when no maker exists.
    pub fn mark_desync_evicted(&self, key: &SessionKey, slot: SlotId) -> bool {
        self.lock()
            .get_mut(key)
            .is_some_and(|maker| maker.mark_desync_evicted(slot))
    }

    /// Why this relay evicted `slot` from `key`'s session, if it did (see
    /// [`DecisionMaker::eviction`]).
    pub fn eviction(&self, key: &SessionKey, slot: SlotId) -> Option<EvictionCause> {
        self.lock().get(key).and_then(|maker| maker.eviction(slot))
    }
}
