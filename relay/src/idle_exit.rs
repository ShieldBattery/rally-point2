//! Relay self-reap when it goes idle with no coordinator control connection.
//!
//! A relay whose coordinator vanished — died or restarted with ledger loss, or
//! left this task orphaned — otherwise runs forever as an idle task, serving
//! nobody and enrolled nowhere. This module watches for exactly that state and
//! exits the process cleanly so the task platform can reclaim it: when the relay
//! holds **zero live sessions** ([`crate::routing::holds_any_slots`]) *and* has
//! **no established control connection** (see
//! [`crate::coordinator_client::run_descriptor_subscriber`]'s `control_connected`)
//! continuously for a threshold, [`run`] resolves and the caller returns from
//! `main` with a success exit code. On Fargate the platform then stops the task,
//! the coordinator's vanished-task sweep tombstones it, and provisioning replaces
//! it on demand.
//!
//! Both halves of the condition are load-bearing. Zero sessions alone would reap a
//! relay that is still enrolled but momentarily empty — a healthy scale target the
//! coordinator would immediately re-fill. No control connection alone would reap a
//! relay mid-game during a coordinator restart, stranding its players. Only their
//! *continuous* conjunction past the threshold marks a relay that has genuinely
//! lost its coordinator with nothing to lose by exiting.
//!
//! Two configurations never self-reap: a relay with **no coordinator configured**
//! (a standalone/dev relay — there is no enrollment to lose, and it must serve for
//! as long as it runs) and an explicit **zero threshold** (the disable switch).
//! Both make [`run`] pend forever instead of ever resolving.

use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::routing::{self, Sessions};

/// How often [`run`] samples the roster and control-connection state. Coarse
/// because a self-reap is not latency-critical — the relay has already been idle
/// and unenrolled for the whole threshold by the time it fires — so a fine poll
/// would only add wakeups for nothing.
const IDLE_EXIT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Tracks how long a boolean condition has held **continuously**. Each
/// [`observe`](Self::observe) records the condition at an instant and answers
/// whether it has now held unbroken for at least `threshold`; any false
/// observation clears the accumulator, so a momentary break restarts the count
/// from zero rather than resuming it.
struct IdleExitTracker {
    /// How long the condition must hold continuously before [`observe`](Self::observe)
    /// reports it satisfied.
    threshold: Duration,
    /// When the current unbroken run of true observations began, or `None` while
    /// the condition is not currently held.
    since: Option<Instant>,
}

impl IdleExitTracker {
    /// A tracker that reports satisfied once its condition has held continuously
    /// for `threshold`.
    fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            since: None,
        }
    }

    /// Records the condition's value at `now`, returning whether it has now held
    /// continuously for at least `threshold`. A `false` observation clears the
    /// accumulated run (the count is continuous, not cumulative); a `true` one
    /// either starts a fresh run or extends the current one.
    fn observe(&mut self, now: Instant, condition: bool) -> bool {
        if !condition {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        now.duration_since(since) >= self.threshold
    }

    /// How long the current unbroken run has held as of `now`, or zero when the
    /// condition is not currently held.
    fn held_for(&self, now: Instant) -> Duration {
        match self.since {
            Some(since) => now.duration_since(since),
            None => Duration::ZERO,
        }
    }
}

/// What the relay observed at the moment it decided to self-reap: how long it had
/// continuously held zero sessions and no control connection. Carried out of
/// [`run`] so the caller can log the idle span on the exit line that distinguishes
/// a self-reap from a crash.
pub struct IdleExitReport {
    /// The continuous idle-and-unenrolled duration that reached the threshold.
    pub idle_for: Duration,
}

/// Resolves only when the relay should exit on its own: it has continuously held
/// zero live sessions AND no established coordinator control connection for at
/// least `threshold_secs`. Spawned as one of `main`'s `select!` branches; when it
/// resolves, the caller logs the exit and returns cleanly.
///
/// Never resolves — pends forever — when the relay must not self-reap:
/// `control_connected` is `None` (no coordinator configured; a standalone/dev
/// relay serves for as long as it runs) or `threshold_secs` is 0 (the explicit
/// disable). This entry injects the production poll cadence; [`run_with`] takes it
/// explicitly so a test need not wait the production interval.
pub async fn run(
    sessions: Sessions,
    control_connected: Option<watch::Receiver<bool>>,
    threshold_secs: u64,
) -> IdleExitReport {
    run_with(
        sessions,
        control_connected,
        Duration::from_secs(threshold_secs),
        IDLE_EXIT_POLL_INTERVAL,
    )
    .await
}

/// [`run`] with the exit threshold and poll cadence injected, so a test can drive
/// the accumulation with tiny real durations rather than the production ones.
///
/// A `None` `control_connected` (no coordinator configured) or a zero `threshold`
/// (the disable switch) pends forever — the relay never self-reaps in either case.
/// Otherwise each poll folds the current condition into the tracker; when it fires,
/// both signals are re-read once more before returning. An unenrolled relay still
/// admits token-valid clients provisionally, so a slot can register between the
/// poll that fired and this decision — if the re-read shows a held slot or a live
/// connection, the tracker resets and the relay keeps serving instead of exiting.
pub async fn run_with(
    sessions: Sessions,
    control_connected: Option<watch::Receiver<bool>>,
    threshold: Duration,
    poll_interval: Duration,
) -> IdleExitReport {
    let Some(control_connected) = control_connected else {
        return std::future::pending().await;
    };
    if threshold.is_zero() {
        return std::future::pending().await;
    }

    let mut tracker = IdleExitTracker::new(threshold);
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let now = Instant::now();
        if tracker.observe(now, idle_and_unenrolled(&sessions, &control_connected)) {
            // The condition just reached the threshold. Re-read both signals: a
            // slot can register (an unenrolled relay still admits token-valid
            // clients provisionally) or the control connection can re-establish
            // between the poll above and here. Exit only if the relay is still idle
            // and unenrolled; otherwise clear the run and keep serving.
            if idle_and_unenrolled(&sessions, &control_connected) {
                return IdleExitReport {
                    idle_for: tracker.held_for(now),
                };
            }
            tracker.observe(now, false);
        }
    }
}

/// Whether the relay currently holds no session AND has no established coordinator
/// control connection — the instantaneous form of the self-reap condition, folded
/// over time by [`IdleExitTracker`].
fn idle_and_unenrolled(sessions: &Sessions, control_connected: &watch::Receiver<bool>) -> bool {
    !routing::holds_any_slots(sessions) && !*control_connected.borrow()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::{SessionId, SlotId};

    use super::*;
    use crate::routing::SessionKey;

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(session),
        }
    }

    #[test]
    fn the_condition_must_hold_continuously_to_fire_at_the_threshold() {
        let threshold = Duration::from_secs(900);
        let mut tracker = IdleExitTracker::new(threshold);
        let t0 = Instant::now();

        // The first idle observation starts the clock but does not fire.
        assert!(!tracker.observe(t0, true));
        // Partway through the window, still not fired.
        assert!(!tracker.observe(t0 + Duration::from_secs(600), true));
        // Exactly at the threshold boundary, it fires.
        assert!(tracker.observe(t0 + threshold, true));
        // And stays fired as the unbroken run continues past it.
        assert!(tracker.observe(t0 + threshold + Duration::from_secs(1), true));
    }

    #[test]
    fn a_break_in_the_condition_clears_the_accumulated_idle_time() {
        let threshold = Duration::from_secs(900);
        let mut tracker = IdleExitTracker::new(threshold);
        let t0 = Instant::now();

        assert!(!tracker.observe(t0, true));
        assert!(!tracker.observe(t0 + Duration::from_secs(800), true));

        // A single non-idle observation clears the accumulated run.
        assert!(!tracker.observe(t0 + Duration::from_secs(801), false));
        assert_eq!(
            tracker.held_for(t0 + Duration::from_secs(801)),
            Duration::ZERO
        );

        // Re-accumulation starts from zero at the next true observation, discarding
        // the pre-break run: 800s past the restart — which, added to the discarded
        // 800s, would long since have crossed the threshold — still does not fire...
        let restart = t0 + Duration::from_secs(802);
        assert!(!tracker.observe(restart, true));
        assert!(!tracker.observe(restart + Duration::from_secs(800), true));
        // ...only a full threshold past the restart fires.
        assert!(tracker.observe(restart + threshold, true));
    }

    #[tokio::test]
    async fn it_exits_once_the_roster_empties_and_stays_unenrolled_past_the_threshold() {
        let threshold = Duration::from_millis(120);
        let poll = Duration::from_millis(10);
        let sessions: Sessions = Arc::default();

        // Populated: a held slot means the relay is serving, so it must not exit
        // even though it is unenrolled.
        let (guard, _inbox) =
            routing::register(&sessions, &key(1), SlotId(0)).expect("slot 0 registers");

        // Unenrolled throughout: the sender is kept alive so the receiver reads a
        // steady `false`.
        let (_connected_tx, connected_rx) = watch::channel(false);
        let handle = tokio::spawn(run_with(
            sessions.clone(),
            Some(connected_rx),
            threshold,
            poll,
        ));

        // While the slot is held, the relay never exits — well past the threshold.
        tokio::time::sleep(threshold * 2).await;
        assert!(
            !handle.is_finished(),
            "a serving relay does not self-reap even while unenrolled",
        );

        // Empty the roster: dropping the (armed) registration deregisters the slot,
        // so the relay is now both idle and unenrolled.
        drop(guard);

        let report = tokio::time::timeout(threshold * 8, handle)
            .await
            .expect("the relay self-reaps once idle and unenrolled past the threshold")
            .expect("the idle-exit task completes without panicking");
        assert!(
            report.idle_for >= threshold,
            "the reported idle span is at least the threshold (observed {:?})",
            report.idle_for,
        );
    }

    #[tokio::test]
    async fn enrolling_mid_countdown_resets_the_idle_timer() {
        let threshold = Duration::from_millis(150);
        let poll = Duration::from_millis(10);
        // Idle roster throughout; only the enrollment state changes.
        let sessions: Sessions = Arc::default();
        let (connected_tx, connected_rx) = watch::channel(false);

        let handle = tokio::spawn(run_with(sessions, Some(connected_rx), threshold, poll));

        // Partway into the countdown, the control connection (re)establishes: the
        // condition breaks and the accumulated idle time is cleared.
        tokio::time::sleep(threshold / 2).await;
        connected_tx.send(true).unwrap();

        // Well past the original threshold-from-start, the relay has not exited —
        // the enroll reset the countdown and the relay is now enrolled.
        tokio::time::sleep(threshold * 2).await;
        assert!(
            !handle.is_finished(),
            "an enroll mid-countdown resets the self-reap timer",
        );

        // Losing the connection again starts a fresh countdown that does fire.
        connected_tx.send(false).unwrap();
        tokio::time::timeout(threshold * 8, handle)
            .await
            .expect("a fresh idle-and-unenrolled span past the threshold self-reaps")
            .expect("the idle-exit task completes without panicking");
    }

    #[tokio::test]
    async fn a_zero_threshold_disables_self_reap() {
        // Idle and unenrolled, but a zero threshold is the explicit disable.
        let sessions: Sessions = Arc::default();
        let (_connected_tx, connected_rx) = watch::channel(false);
        let never = run_with(
            sessions,
            Some(connected_rx),
            Duration::ZERO,
            Duration::from_millis(10),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), never)
                .await
                .is_err(),
            "a zero threshold never self-reaps even while idle and unenrolled",
        );
    }

    #[tokio::test]
    async fn a_relay_with_no_coordinator_never_self_reaps() {
        // Idle roster, but no control-connection watch: a standalone/dev relay must
        // serve for as long as it runs.
        let sessions: Sessions = Arc::default();
        let never = run_with(
            sessions,
            None,
            Duration::from_millis(50),
            Duration::from_millis(10),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), never)
                .await
                .is_err(),
            "a relay with no coordinator configured never self-reaps",
        );
    }
}
