//! The relay-wide sweep that judges rollback sessions' state hash reports once their deadlines
//! pass. Reports arriving on turns trigger most judgements, but a slot that withholds its report
//! produces nothing to trigger one, so a timer has to.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::consensus::DecisionMakers;

/// How often the sweep checks every rollback session for overdue reports. Short next to the
/// report deadline, so a verdict follows within a second of the deadline passing.
pub const STATE_HASH_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Every `interval`, judges each rollback session's steps whose report deadlines have passed and
/// publishes the verdicts. One task per relay, spawned by the binary; never returns.
pub async fn run_state_hash_watch(makers: Arc<DecisionMakers>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; nothing can be overdue yet.
    tick.tick().await;
    loop {
        tick.tick().await;
        makers.judge_overdue_state_hashes(Instant::now());
    }
}
