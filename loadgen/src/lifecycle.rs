//! Session-wide phase coordination for synthetic players.
//!
//! A relay's `SessionStart` reaches each physical client independently. The
//! harness must not turn that delivery skew into different game windows and
//! staggered leaves, so every player rendezvous here before turn production.
//! The same coordinator holds every link open after the exact send workload is
//! complete until all expected deliveries arrive or one shared drain deadline
//! expires.

use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::watch;
use tokio::time::{Duration, Instant, sleep_until};

/// Small lead between the last ready player and the common first turn. This
/// lets every released task arm its ticker before the instant arrives.
const START_LEAD: Duration = Duration::from_millis(25);
/// How long a fully-sent session remains live while final payloads and their
/// redundancy/ack flushes drain. The transport maintenance cadence is 150 ms,
/// so five seconds leaves ample recovery time without allowing a broken run to
/// hang indefinitely.
pub const DELIVERY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The terminal result of the shared delivery-drain phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResolution {
    /// Every player observed every expected peer frame.
    Complete,
    /// The shared drain deadline expired before the session became complete.
    TimedOut,
    /// A player failed before the normal drain result could be reached.
    Aborted,
}

/// Session-level lifecycle state consumed after all player tasks finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleOutcome {
    pub complete: bool,
    pub timed_out: bool,
    pub aborted: bool,
}

/// A cloneable handle shared by every player in one synthetic session.
#[derive(Clone)]
pub struct SessionLifecycle {
    inner: Arc<Inner>,
}

struct Inner {
    expected_players: usize,
    start_lead: Duration,
    drain_timeout: Duration,
    state: Mutex<State>,
    /// A monotonically-changing wake signal. State remains authoritative; the
    /// watch value only makes check-then-wait race-free for every waiter.
    changed: watch::Sender<u64>,
}

#[derive(Debug, Default)]
struct State {
    ready_players: usize,
    senders_done: usize,
    receivers_done: usize,
    start_at: Option<Instant>,
    drain_deadline: Option<Instant>,
    leave_released: bool,
    timed_out: bool,
    aborted: bool,
}

impl SessionLifecycle {
    pub fn new(expected_players: usize) -> Self {
        Self::with_timing(expected_players, START_LEAD, DELIVERY_DRAIN_TIMEOUT)
    }

    fn with_timing(expected_players: usize, start_lead: Duration, drain_timeout: Duration) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                expected_players,
                start_lead,
                drain_timeout,
                state: Mutex::new(State::default()),
                changed,
            }),
        }
    }

    /// Marks this player ready and waits for the one common start instant. A
    /// failure in any participant aborts the rendezvous and returns `None`.
    pub async fn ready_and_wait_for_start(&self) -> Option<Instant> {
        let mut changed = self.inner.changed.subscribe();
        let should_wake = {
            let mut state = self.state();
            if state.aborted {
                return None;
            }
            state.ready_players += 1;
            debug_assert!(state.ready_players <= self.inner.expected_players);
            if state.ready_players == self.inner.expected_players {
                state.start_at = Some(Instant::now() + self.inner.start_lead);
                true
            } else {
                false
            }
        };
        if should_wake {
            self.bump();
        }

        loop {
            {
                let state = self.state();
                if state.aborted {
                    return None;
                }
                if let Some(start_at) = state.start_at {
                    return Some(start_at);
                }
            }
            // The sender lives as long as the lifecycle, so closure is
            // unreachable; treat it like an abort if that invariant changes.
            if changed.changed().await.is_err() {
                return None;
            }
        }
    }

    /// Resolves only if another participant aborts the session. Used beside the
    /// send ticker so a failed peer does not leave survivors pumping for the
    /// entire configured game duration.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }

    pub async fn wait_for_abort(&self, changed: &mut watch::Receiver<u64>) {
        loop {
            if self.state().aborted {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }

    /// Records that this player emitted its exact configured frame count. The
    /// last sender starts the one shared delivery-drain deadline.
    pub fn sender_done(&self) {
        let should_wake = {
            let mut state = self.state();
            if state.aborted {
                return;
            }
            state.senders_done += 1;
            debug_assert!(state.senders_done <= self.inner.expected_players);
            if state.senders_done == self.inner.expected_players {
                state.drain_deadline = Some(Instant::now() + self.inner.drain_timeout);
            }
            true
        };
        if should_wake {
            self.bump();
        }
    }

    /// Records that this player has every expected peer frame. The last receiver
    /// releases every participant to send its leave intent together.
    pub fn receiver_done(&self) {
        let should_wake = {
            let mut state = self.state();
            if state.aborted || state.leave_released {
                return;
            }
            state.receivers_done += 1;
            debug_assert!(state.receivers_done <= self.inner.expected_players);
            if state.receivers_done == self.inner.expected_players {
                state.leave_released = true;
            }
            true
        };
        if should_wake {
            self.bump();
        }
    }

    /// Waits for complete delivery, the common deadline, or a participant
    /// failure. Multiple players may race the deadline; the state transition is
    /// idempotent and every waiter observes the same result.
    pub async fn wait_for_drain_resolution(
        &self,
        changed: &mut watch::Receiver<u64>,
    ) -> DrainResolution {
        loop {
            let deadline = {
                let state = self.state();
                if state.aborted {
                    return DrainResolution::Aborted;
                }
                if state.timed_out {
                    return DrainResolution::TimedOut;
                }
                if state.leave_released {
                    return DrainResolution::Complete;
                }
                state.drain_deadline
            };

            if let Some(deadline) = deadline {
                tokio::select! {
                    changed_result = changed.changed() => {
                        if changed_result.is_err() {
                            return DrainResolution::Aborted;
                        }
                    }
                    _ = sleep_until(deadline) => self.expire_drain(),
                }
            } else if changed.changed().await.is_err() {
                return DrainResolution::Aborted;
            }
        }
    }

    /// Aborts every phase and releases all waiters. Safe to call repeatedly.
    pub fn abort(&self) {
        let changed = {
            let mut state = self.state();
            if state.aborted || state.leave_released {
                false
            } else {
                state.aborted = true;
                state.leave_released = true;
                true
            }
        };
        if changed {
            self.bump();
        }
    }

    pub fn outcome(&self) -> LifecycleOutcome {
        let state = self.state();
        LifecycleOutcome {
            complete: state.leave_released
                && state.receivers_done == self.inner.expected_players
                && !state.timed_out
                && !state.aborted,
            timed_out: state.timed_out,
            aborted: state.aborted,
        }
    }

    fn expire_drain(&self) {
        let changed = {
            let mut state = self.state();
            if state.leave_released || state.aborted {
                false
            } else {
                state.timed_out = true;
                state.leave_released = true;
                true
            }
        };
        if changed {
            self.bump();
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn bump(&self) {
        self.inner
            .changed
            .send_modify(|version| *version = version.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn staggered_readiness_releases_one_common_start_instant() {
        let lifecycle =
            SessionLifecycle::with_timing(2, Duration::from_millis(1), Duration::from_secs(1));
        let first_lifecycle = lifecycle.clone();
        let first =
            tokio::spawn(async move { first_lifecycle.ready_and_wait_for_start().await.unwrap() });

        tokio::task::yield_now().await;
        assert!(
            !first.is_finished(),
            "the first player started before the staggered peer was ready"
        );

        let second_start = lifecycle.ready_and_wait_for_start().await.unwrap();
        let first_start = first.await.unwrap();
        assert_eq!(first_start, second_start);
    }

    #[tokio::test]
    async fn delayed_final_delivery_holds_the_common_leave() {
        let lifecycle = SessionLifecycle::with_timing(2, Duration::ZERO, Duration::from_secs(30));
        let first_lifecycle = lifecycle.clone();
        let first_ready =
            tokio::spawn(async move { first_lifecycle.ready_and_wait_for_start().await });
        lifecycle.ready_and_wait_for_start().await.unwrap();
        first_ready.await.unwrap().unwrap();

        lifecycle.sender_done();
        lifecycle.sender_done();
        lifecycle.receiver_done();

        let wait_lifecycle = lifecycle.clone();
        let mut wait_changes = wait_lifecycle.subscribe();
        let waiter = tokio::spawn(async move {
            wait_lifecycle
                .wait_for_drain_resolution(&mut wait_changes)
                .await
        });
        tokio::task::yield_now().await;
        assert!(!lifecycle.outcome().complete);
        assert!(
            !waiter.is_finished(),
            "one receiver's delayed final frame must hold every leave"
        );

        lifecycle.receiver_done();
        assert_eq!(waiter.await.unwrap(), DrainResolution::Complete);
        assert_eq!(
            lifecycle.outcome(),
            LifecycleOutcome {
                complete: true,
                timed_out: false,
                aborted: false,
            }
        );
    }

    #[tokio::test]
    async fn participant_failure_releases_ready_and_drain_waiters() {
        let lifecycle = SessionLifecycle::new(2);
        let ready_lifecycle = lifecycle.clone();
        let ready = tokio::spawn(async move { ready_lifecycle.ready_and_wait_for_start().await });
        tokio::task::yield_now().await;
        lifecycle.abort();
        assert_eq!(ready.await.unwrap(), None);
        let mut changed = lifecycle.subscribe();
        assert_eq!(
            lifecycle.wait_for_drain_resolution(&mut changed).await,
            DrainResolution::Aborted
        );
    }

    #[tokio::test]
    async fn one_shared_deadline_marks_an_incomplete_session_timed_out() {
        let lifecycle = SessionLifecycle::with_timing(1, Duration::ZERO, Duration::ZERO);
        lifecycle.ready_and_wait_for_start().await.unwrap();
        lifecycle.sender_done();
        let mut changed = lifecycle.subscribe();

        assert_eq!(
            lifecycle.wait_for_drain_resolution(&mut changed).await,
            DrainResolution::TimedOut
        );
        assert_eq!(
            lifecycle.outcome(),
            LifecycleOutcome {
                complete: false,
                timed_out: true,
                aborted: false,
            }
        );
    }
}
