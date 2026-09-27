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
}
