//! The level-triggered reconcile loop: every tick it re-derives each region's
//! desired relay count from scratch and takes the actions that close the gap.
//!
//! Nothing is edge-triggered. A tick reads the current world — the region config,
//! the registry, session membership, the ledger, warm demand, and the backbone-RTT
//! pair table — and acts on the difference, so a failed action is simply retried by
//! the next tick re-deriving the same gap. Each action is independently guarded: a
//! provisioner or ledger error logs and the tick continues, so no single failure
//! kills the loop.
//!
//! Per configured region a tick derives a desired relay count — the greater of the
//! region's warm demand and its coverage-bootstrap demand — then:
//!
//! - **scales up** while the live-plus-launching count is under the target —
//!   minting an id, launching a task, and recording its addresses once the task
//!   reports running;
//! - **scales down** while the live count is over the target — draining the
//!   longest-idle session-free relay past a grace period, marked draining and
//!   re-checked against the placement race before its task is stopped and its id
//!   retired.
//!
//! Coverage-bootstrap demand asks for one relay while some configured pair
//! involving the region has no measured backbone RTT, so a fresh fleet fills its
//! own pair table instead of waiting for games to happen everywhere. It is
//! self-clearing (the demand vanishes once the pairs arrive, and the relay drains
//! by the normal idle path) and self-limiting (a region whose measurements never
//! arrive backs off exponentially rather than relaunching forever); see
//! [`ProvisionLoop::coverage_demand`].
//!
//! Then, fleet-wide, it sweeps: launches whose token expired before enrolling,
//! bound ids whose relay vanished, and tasks the ledger no longer references.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;

use super::{LaunchSpec, Provisioner, TaskId, TaskState, WarmTargets};
use crate::ledger::RelayLedger;
use crate::pair_rtts::PairRttStore;
use crate::registry::{self, EnrolledRelay, RelayRegistry};
use crate::session::SessionSetup;

/// Static configuration for a [`ProvisionLoop`].
#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// The regions the loop reconciles, in no particular order. A region absent
    /// here is never scaled — its relays (if any enrolled) are left alone.
    pub regions: Vec<RegionId>,
    /// How often the loop ticks.
    pub tick_interval: Duration,
    /// The lifetime of a minted enroll token — the deadline by which a launched
    /// relay must enroll. A launch that has not enrolled by the time its token
    /// expires is swept: its task stopped, its id retired.
    pub launch_deadline: Duration,
    /// How long an enrolled relay must be continuously session-free before a
    /// scale-down may drain it.
    pub idle_grace: Duration,
}

/// A launched task whose addresses have not been recorded yet — the loop polls it
/// each tick until it reports running.
struct PendingLaunch {
    /// The id the task runs as.
    relay_id: RelayId,
    /// The provisioner handle for the task.
    task: TaskId,
}

/// How long a region may demand a bootstrap relay without any of its pairs gaining
/// a value before the loop counts the attempt failed and starts backing off. Kept
/// generous against the launch → enroll → sweep → heartbeat path (about a minute),
/// so a working bootstrap clears its coverage well within the window and only a
/// genuinely broken measurement path ever trips the backoff.
const COVERAGE_HOLD_SECS: u64 = 300;

/// The backoff after the first failed bootstrap attempt. Each further consecutive
/// failure doubles it, up to [`COVERAGE_BACKOFF_CAP_SECS`].
const COVERAGE_BACKOFF_BASE_SECS: u64 = 600;

/// The ceiling on the exponential bootstrap backoff: a permanently broken region
/// (dead beacon, unreachable) re-probes at most this often instead of churning
/// tasks forever.
const COVERAGE_BACKOFF_CAP_SECS: u64 = 6 * 3_600;

/// The backoff, in seconds, after `attempts` consecutive failed bootstrap
/// attempts: `BASE * 2^(attempts - 1)`, clamped to the cap. `attempts` is always
/// at least 1 here — it is read only after a failure has incremented it.
fn coverage_backoff_secs(attempts: u32) -> u64 {
    // Cap the shift far below `u64`'s width so it cannot overflow; the value cap
    // clamps the result long before the shift grows large anyway.
    let doublings = attempts.saturating_sub(1).min(32);
    COVERAGE_BACKOFF_BASE_SECS
        .saturating_mul(1u64 << doublings)
        .min(COVERAGE_BACKOFF_CAP_SECS)
}

/// Per-region bootstrap tracking for the coverage input: how many of the region's
/// pairs were covered when last observed, and where the region sits in its
/// try/back-off cycle.
///
/// Invariants:
/// - An entry exists only while the region has at least one uncovered configured
///   pair. The tick drops it the moment the region is fully covered, so a covered
///   region carries no state and contributes no demand.
/// - Stored pair values are never evicted, so `covered_pairs` only ever rises. A
///   rise between ticks is therefore unambiguous progress — the measurement path
///   works — and resets `attempts` to 0 and the phase to a fresh `Trying` window.
/// - `attempts` counts *failed* attempts (hold windows that elapsed with the
///   region still uncovered). It is 0 until the first window lapses, grows only
///   while the region stays broken, and returns to 0 on any progress.
struct CoverageState {
    /// Count of the region's configured pairs that held a value at the last
    /// observation. A rise is progress and resets the cycle.
    covered_pairs: usize,
    /// Consecutive failed bootstrap attempts, driving the backoff schedule.
    attempts: u32,
    /// Whether the region is currently demanding a relay or waiting out a backoff.
    phase: CoveragePhase,
}

/// Where a still-uncovered region sits in its bootstrap cycle.
#[derive(Clone, Copy)]
enum CoveragePhase {
    /// Demanding a bootstrap relay; the current hold window began at `since` (Unix
    /// seconds). Contributes a desired count of 1. If the window elapses while the
    /// region is still uncovered, the attempt has failed and the region moves to
    /// `BackingOff`.
    Trying {
        /// When the current hold window started.
        since: u64,
    },
    /// Waiting out a backoff after a failed attempt, until `until` (Unix seconds).
    /// Contributes no demand, so any relay launched for the region idle-drains by
    /// the normal path. When `until` passes the region returns to `Trying`.
    BackingOff {
        /// When the backoff expires and demand may resume.
        until: u64,
    },
}

/// The reconcile loop. Owns the coordinator handles it reconciles over — the
/// registry, session membership, the ledger, warm demand, and a provisioner —
/// plus the loop-local memory a level-triggered pass needs across ticks: per-relay
/// idle timers and the set of launched-but-not-yet-recorded tasks.
///
/// Generic over the [`Provisioner`] so it dispatches statically to whichever
/// substrate it was built with; it never names a concrete one.
pub struct ProvisionLoop<P> {
    config: ProvisionConfig,
    registry: RelayRegistry,
    setup: SessionSetup,
    ledger: Arc<RelayLedger>,
    warm: WarmTargets,
    /// The backbone-RTT pair table, read each tick to derive coverage-bootstrap
    /// demand: a region with any unmeasured configured pair is asked for a relay so
    /// the fleet fills its own table.
    pair_rtts: PairRttStore,
    provisioner: P,
    /// Per-relay Unix-second instant of the first tick that observed the relay
    /// session-free. Reset when it picks up a session or leaves the fleet. Purely
    /// loop-local: a restart resets it, which only delays a scale-down by one grace
    /// period.
    idle_since: HashMap<RelayId, u64>,
    /// Tasks launched this loop's lifetime whose addresses are not yet recorded.
    /// Polled every tick until running. Also spares them from the orphan sweep —
    /// they are accounted for even though the ledger does not reference them yet.
    pending: Vec<PendingLaunch>,
    /// Per-region bootstrap tracking for coverage demand — attempt counts and
    /// backoff windows. Purely loop-local: a restart resets it, at worst re-probing
    /// a region one extra time.
    coverage: HashMap<RegionId, CoverageState>,
}

impl<P: Provisioner> ProvisionLoop<P> {
    /// Builds a loop over the given coordinator handles and provisioner.
    pub fn new(
        config: ProvisionConfig,
        registry: RelayRegistry,
        setup: SessionSetup,
        ledger: Arc<RelayLedger>,
        warm: WarmTargets,
        pair_rtts: PairRttStore,
        provisioner: P,
    ) -> Self {
        Self {
            config,
            registry,
            setup,
            ledger,
            warm,
            pair_rtts,
            provisioner,
            idle_since: HashMap::new(),
            pending: Vec::new(),
            coverage: HashMap::new(),
        }
    }

    /// Runs the loop forever, ticking on the configured interval. A tick is skipped
    /// only when the system clock is unusable — a token expiry derived from it
    /// could not be trusted, so it is safer to wait for the next tick than to sweep
    /// against a broken clock.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.config.tick_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let now = now_unix_secs();
            if now == u64::MAX {
                tracing::warn!("system clock is unusable; skipping this provisioning tick");
                continue;
            }
            self.tick(now).await;
        }
    }

    /// One reconcile pass at `now` (Unix seconds). Public so a test — or the e2e —
    /// can drive ticks deterministically rather than sleeping through real time.
    pub async fn tick(&mut self, now: u64) {
        let enrolled = registry::enrolled_relays(&self.registry);
        self.refresh_idle(&enrolled, now);

        // The pairs that currently hold a value, snapshotted once so each region's
        // coverage check is a set lookup rather than a fresh lock per pair.
        let covered = self.pair_rtts.covered_pairs();

        let regions = self.config.regions.clone();
        for region in &regions {
            // A region's target is the greater of its warm demand and its
            // coverage-bootstrap demand — never their sum: a region already warm for
            // serving needs no extra relay merely to fill the pair table, and one
            // relay satisfies both. Coverage demand is transient and self-clearing
            // (see `coverage_demand`).
            let warm_target = self.warm.target_at(region, now);
            let coverage_target = self.coverage_demand(region, &covered, now);
            let target = warm_target.max(coverage_target);
            let live = enrolled
                .iter()
                .filter(|r| r.region.as_ref() == Some(region))
                .count() as u32;
            self.scale_up(region, live, target, now).await;
            self.scale_down(region, &enrolled, live, target, now).await;
        }

        self.resolve_pending().await;
        self.launch_deadline_sweep(now).await;
        self.vanished_task_sweep().await;
        self.orphan_sweep().await;
    }

    /// Updates each relay's idle timer: a session-free relay's timer starts at its
    /// first session-free observation and holds; a relay serving a session, or one
    /// that left the fleet, loses its timer. Only relays with a live timer are ever
    /// scale-down candidates, so a candidate has been session-free at least since
    /// that first observation.
    fn refresh_idle(&mut self, enrolled: &[EnrolledRelay], now: u64) {
        let present: HashSet<RelayId> = enrolled.iter().map(|r| r.relay_id).collect();
        self.idle_since.retain(|id, _| present.contains(id));
        for relay in enrolled {
            if self.setup.session_count_for_relay(relay.relay_id) == 0 {
                self.idle_since.entry(relay.relay_id).or_insert(now);
            } else {
                self.idle_since.remove(&relay.relay_id);
            }
        }
    }

    /// How many of `region`'s configured pairs currently hold a value, and how many
    /// pairs it has. A pair is `(region, other)` for every *other* configured
    /// region, so a single-region config yields `(0, 0)` — no pairs, and thus never
    /// any coverage demand.
    fn region_pair_coverage(
        &self,
        region: &RegionId,
        covered: &HashSet<(RegionId, RegionId)>,
    ) -> (usize, usize) {
        let mut have = 0usize;
        let mut total = 0usize;
        for other in &self.config.regions {
            if other == region {
                continue;
            }
            total += 1;
            let (a, b) = crate::pair_rtts::canonical_pair(region, other);
            if covered.contains(&(a.clone(), b.clone())) {
                have += 1;
            }
        }
        (have, total)
    }

    /// The transient desired relay count region coverage contributes for `region`
    /// this tick, advancing its bootstrap state machine.
    ///
    /// A region "needs bootstrap" while some configured pair involving it has no
    /// stored value — the coordinator has no measurement for that backbone link, so
    /// a relay is asked for to run one. The demand is level-triggered and
    /// self-limiting:
    ///
    /// - Fully covered (including a single-region config, which has no pairs):
    ///   demand 0, and any tracking state is dropped.
    /// - A pair value arriving (coverage rising) resets the cycle: the path works,
    ///   so the failure count clears and a fresh hold window starts.
    /// - Uncovered and within the hold window: demand 1.
    /// - Uncovered and the hold window elapsed: the attempt has failed — count it,
    ///   log it, and back off for an exponentially growing interval during which the
    ///   region demands nothing, so a dead beacon cannot relaunch-churn tasks.
    /// - Backoff elapsed: demand 1 again for a fresh window.
    fn coverage_demand(
        &mut self,
        region: &RegionId,
        covered: &HashSet<(RegionId, RegionId)>,
        now: u64,
    ) -> u32 {
        let (have, total) = self.region_pair_coverage(region, covered);
        if have >= total {
            // Every pair covered (or no pairs at all): nothing to bootstrap.
            self.coverage.remove(region);
            return 0;
        }
        let state = self
            .coverage
            .entry(region.clone())
            .or_insert_with(|| CoverageState {
                covered_pairs: have,
                attempts: 0,
                phase: CoveragePhase::Trying { since: now },
            });
        if have > state.covered_pairs {
            // Progress since the last observation: the measurement path is live, so
            // clear the failure count and give the region a fresh hold window.
            state.covered_pairs = have;
            state.attempts = 0;
            state.phase = CoveragePhase::Trying { since: now };
        }
        match state.phase {
            CoveragePhase::Trying { since } => {
                if now.saturating_sub(since) < COVERAGE_HOLD_SECS {
                    // Still within the window: keep asking for a relay.
                    1
                } else {
                    // The window elapsed with the region still uncovered: a failed
                    // attempt. Count it, back off, and demand nothing until the
                    // backoff expires.
                    state.attempts += 1;
                    let backoff = coverage_backoff_secs(state.attempts);
                    state.phase = CoveragePhase::BackingOff {
                        until: now.saturating_add(backoff),
                    };
                    tracing::warn!(
                        region = region.as_ref(),
                        attempt = state.attempts,
                        backoff_secs = backoff,
                        "region bootstrap produced no backbone-RTT measurement within the \
                         hold window; backing off before retrying",
                    );
                    0
                }
            }
            CoveragePhase::BackingOff { until } => {
                if now < until {
                    // Still serving out the backoff: no demand.
                    0
                } else {
                    // Backoff over: demand a relay again for a fresh window.
                    state.phase = CoveragePhase::Trying { since: now };
                    1
                }
            }
        }
    }

    /// Launches relays while `region` is under its target, crediting in-flight
    /// launches so a task still coming up is not double-launched. A mint or launch
    /// failure logs and ends this region's scale-up for the tick; the next tick
    /// re-derives the same gap and retries with a fresh mint.
    async fn scale_up(&mut self, region: &RegionId, live: u32, target: u32, now: u64) {
        let mut launching = match self.ledger.count_launching(Some(region), now) {
            Ok(count) => count as u32,
            Err(error) => {
                tracing::warn!(
                    region = region.as_ref(),
                    %error,
                    "counting launching relays failed; skipping scale-up for this region",
                );
                return;
            }
        };
        while live + launching < target {
            let minted = match self
                .ledger
                .mint_at(now, Some(region), self.config.launch_deadline)
            {
                Ok(minted) => minted,
                Err(error) => {
                    tracing::warn!(
                        region = region.as_ref(),
                        %error,
                        "minting a relay id failed; retrying next tick",
                    );
                    return;
                }
            };
            let spec = LaunchSpec {
                relay_id: minted.relay_id,
                enroll_token: minted.token,
                region: Some(region.clone()),
            };
            match self.provisioner.launch(&spec).await {
                Ok(task) => {
                    tracing::info!(
                        region = region.as_ref(),
                        relay_id = minted.relay_id.0,
                        task = %task,
                        "launched a relay task",
                    );
                    self.pending.push(PendingLaunch {
                        relay_id: minted.relay_id,
                        task,
                    });
                    launching += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        region = region.as_ref(),
                        relay_id = minted.relay_id.0,
                        %error,
                        "launching a relay task failed; retiring the minted id",
                    );
                    if let Err(error) = self.ledger.retire(minted.relay_id) {
                        tracing::warn!(
                            relay_id = minted.relay_id.0,
                            %error,
                            "retiring a failed launch's id failed",
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Drains relays while `region` is over its target: the longest-idle
    /// session-free relays past the grace, each through the placement-race-safe
    /// drain sequence, until the live count meets the target or candidates run out.
    async fn scale_down(
        &mut self,
        region: &RegionId,
        enrolled: &[EnrolledRelay],
        live: u32,
        target: u32,
        now: u64,
    ) {
        if live <= target {
            return;
        }
        let grace = self.config.idle_grace.as_secs();
        let mut candidates: Vec<(RelayId, u64, u64)> = enrolled
            .iter()
            .filter(|r| !r.draining && r.region.as_ref() == Some(region))
            .filter_map(|r| {
                let idle = now.saturating_sub(*self.idle_since.get(&r.relay_id)?);
                (idle >= grace).then_some((r.relay_id, r.generation, idle))
            })
            .collect();
        // Longest-idle first.
        candidates.sort_by_key(|(_, _, idle)| std::cmp::Reverse(*idle));

        let mut live = live;
        for (relay_id, generation, _) in candidates {
            if live <= target {
                break;
            }
            if self.try_drain_one(relay_id, generation).await {
                live -= 1;
            }
        }
    }

    /// Drains one relay, closing the placement race. Marks it draining and
    /// re-checks its session count under the assignment lock, so the mark and the
    /// check are mutually exclusive with any session-create commit: a session that
    /// raced the mark is either seen here (the relay is spared and un-marked) or was
    /// blocked until the mark was visible (so it never placed on the relay). Only
    /// then, with the relay already ineligible for new placement and confirmed
    /// session-free, does it stop the task and retire the id — outside the lock,
    /// since stopping awaits the task's death. Returns whether the relay was
    /// drained.
    async fn try_drain_one(&mut self, relay_id: RelayId, generation: u64) -> bool {
        let proceed = {
            let _assignment = self.setup.lock_assignment();
            if !registry::mark_draining(&self.registry, relay_id, generation) {
                // The relay reconnected or left between selection and the mark.
                false
            } else if self.setup.session_count_for_relay(relay_id) != 0 {
                // A session landed in the placement race: spare the relay.
                registry::clear_draining(&self.registry, relay_id, generation);
                false
            } else {
                true
            }
        };
        if !proceed {
            return false;
        }
        match self.ledger.task_arn(relay_id) {
            Ok(Some(arn)) => {
                if let Err(error) = self.provisioner.stop(&TaskId(arn)).await {
                    tracing::warn!(
                        relay_id = relay_id.0,
                        %error,
                        "stopping a drained relay's task failed; retiring the id anyway",
                    );
                }
            }
            Ok(None) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    "draining a relay with no recorded task; retiring the id only",
                );
            }
            Err(error) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    %error,
                    "reading a drained relay's task failed; retiring the id anyway",
                );
            }
        }
        if let Err(error) = self.ledger.retire(relay_id) {
            tracing::warn!(relay_id = relay_id.0, %error, "retiring a drained relay failed");
        }
        self.idle_since.remove(&relay_id);
        true
    }

    /// Polls each pending launch. A task that reports running has its addresses
    /// recorded and leaves the pending set; one still starting stays; one that
    /// stopped before enrolling is a failed launch — its id is retired so it can
    /// never enroll, and the next tick re-mints. A record or poll error keeps the
    /// task pending for a later tick.
    async fn resolve_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        let mut still = Vec::with_capacity(pending.len());
        for launch in pending {
            match self.provisioner.state(&launch.task).await {
                Ok(TaskState::Running {
                    expected_ips,
                    addrs,
                }) => {
                    if let Err(error) = self.ledger.record_task(
                        launch.relay_id,
                        &launch.task.0,
                        &expected_ips,
                        &addrs,
                    ) {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            %error,
                            "recording a launched task failed; retrying next tick",
                        );
                        still.push(launch);
                    }
                }
                Ok(TaskState::Starting) => still.push(launch),
                Ok(TaskState::Stopped) => {
                    tracing::warn!(
                        relay_id = launch.relay_id.0,
                        task = %launch.task,
                        "a launched task stopped before enrolling; retiring the id",
                    );
                    if let Err(error) = self.ledger.retire(launch.relay_id) {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            %error,
                            "retiring a stopped launch failed",
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        relay_id = launch.relay_id.0,
                        %error,
                        "polling a launched task failed; retrying next tick",
                    );
                    still.push(launch);
                }
            }
        }
        self.pending = still;
    }

    /// Stops and retires every launch whose token expired before it enrolled — the
    /// relay never bound its id, and its token can no longer authorize a first
    /// enroll, so the id is dead.
    async fn launch_deadline_sweep(&mut self, now: u64) {
        let expired = match self.ledger.expired_launching(now) {
            Ok(expired) => expired,
            Err(error) => {
                tracing::warn!(%error, "listing expired launches failed; skipping the launch-deadline sweep");
                return;
            }
        };
        for relay in expired {
            if let Some(arn) = relay.task_arn
                && let Err(error) = self.provisioner.stop(&TaskId(arn)).await
            {
                tracing::warn!(
                    relay_id = relay.relay_id.0,
                    %error,
                    "stopping an expired launch's task failed",
                );
            }
            if let Err(error) = self.ledger.retire(relay.relay_id) {
                tracing::warn!(
                    relay_id = relay.relay_id.0,
                    %error,
                    "retiring an expired launch failed",
                );
            }
            self.pending.retain(|p| p.relay_id != relay.relay_id);
            self.idle_since.remove(&relay.relay_id);
        }
    }

    /// Retires every bound id whose relay is no longer enrolled and whose task has
    /// stopped — the relay died. Retiring tombstones the id so the dead relay's
    /// certificate can never reclaim it. A bound id whose relay is still enrolled,
    /// or whose task is still up, is left alone (a reconnect may yet resume it).
    async fn vanished_task_sweep(&mut self) {
        let bound = match self.ledger.bound_unretired() {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, "listing bound relays failed; skipping the vanished-task sweep");
                return;
            }
        };
        for relay in bound {
            if registry::is_enrolled(&self.registry, relay.relay_id) {
                continue;
            }
            let Some(arn) = relay.task_arn else {
                continue;
            };
            match self.provisioner.state(&TaskId(arn)).await {
                Ok(TaskState::Stopped) => {
                    tracing::info!(
                        relay_id = relay.relay_id.0,
                        "retiring a bound relay whose task has stopped and is not enrolled",
                    );
                    if let Err(error) = self.ledger.retire(relay.relay_id) {
                        tracing::warn!(
                            relay_id = relay.relay_id.0,
                            %error,
                            "retiring a vanished relay failed",
                        );
                    }
                    self.idle_since.remove(&relay.relay_id);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        relay_id = relay.relay_id.0,
                        %error,
                        "probing a bound relay's task failed; leaving it for next tick",
                    );
                }
            }
        }
    }

    /// Stops every task the provisioner still runs that no unretired ledger row
    /// references and that this loop is not itself tracking as a pending launch — a
    /// task the ledger lost track of (e.g. one that outlived a coordinator restart
    /// that cleared the pending set) must not keep running unaccounted. A task the
    /// loop just launched but has not recorded yet is spared: it is accounted for
    /// even though the ledger does not reference it yet.
    async fn orphan_sweep(&mut self) {
        let tasks = match self.provisioner.list().await {
            Ok(tasks) => tasks,
            Err(error) => {
                tracing::warn!(%error, "listing provisioner tasks failed; skipping the orphan sweep");
                return;
            }
        };
        let mut accounted: HashSet<String> = match self.ledger.referenced_task_arns() {
            Ok(arns) => arns.into_iter().collect(),
            Err(error) => {
                tracing::warn!(%error, "listing referenced tasks failed; skipping the orphan sweep");
                return;
            }
        };
        for launch in &self.pending {
            accounted.insert(launch.task.0.clone());
        }
        for task in tasks {
            if !accounted.contains(&task.0) {
                tracing::info!(task = %task, "stopping an orphaned task no live ledger row references");
                if let Err(error) = self.provisioner.stop(&task).await {
                    tracing::warn!(task = %task, %error, "stopping an orphaned task failed");
                }
            }
        }
    }
}

/// The current Unix time in seconds, `u64::MAX` on a pre-epoch or errored clock —
/// the sentinel [`ProvisionLoop::run`] treats as "skip this tick", since a token
/// expiry compared against an untrustworthy clock cannot be relied on.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;

    use parking_lot::Mutex;
    use rally_point_proto::control::{
        BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::SlotId;
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
    use rally_point_proto::version::ProtocolVersion;

    use super::*;
    use crate::provision::ProvisionError;
    use crate::session::create_session;
    use crate::tenant;

    const TENANT: &str = "sb-test";

    /// A scripted, inspectable [`Provisioner`]: it records launches and stops,
    /// hands each launch a scripted initial [`TaskState`], and can be told to fail
    /// any of its calls, so the loop's resilience is exercisable.
    struct FakeProvisioner {
        state: Mutex<FakeState>,
    }

    struct FakeState {
        next: u64,
        /// The state a freshly launched task takes.
        launch_state: TaskState,
        /// Every launch's spec, in call order.
        launches: Vec<LaunchSpec>,
        /// Each known task's current state.
        tasks: HashMap<String, TaskState>,
        /// Every stopped task id, in call order.
        stops: Vec<String>,
        fail_launch: bool,
        fail_state: bool,
        fail_stop: bool,
        fail_list: bool,
    }

    /// A running-task state at a fixed loopback address — the usual scripted
    /// "the launch came up" outcome.
    fn running() -> TaskState {
        TaskState::Running {
            expected_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 15_000))],
        }
    }

    impl FakeProvisioner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(FakeState {
                    next: 0,
                    launch_state: running(),
                    launches: Vec::new(),
                    tasks: HashMap::new(),
                    stops: Vec::new(),
                    fail_launch: false,
                    fail_state: false,
                    fail_stop: false,
                    fail_list: false,
                }),
            })
        }

        fn set_launch_state(&self, state: TaskState) {
            self.state.lock().launch_state = state;
        }

        /// Scripts (or injects) a task's state — used both to advance a launched
        /// task and to plant a task the ledger never minted (an orphan).
        fn set_task_state(&self, task: &str, state: TaskState) {
            self.state.lock().tasks.insert(task.to_owned(), state);
        }

        fn set_fail_launch(&self, fail: bool) {
            self.state.lock().fail_launch = fail;
        }

        fn set_fail_state(&self, fail: bool) {
            self.state.lock().fail_state = fail;
        }

        fn set_fail_stop(&self, fail: bool) {
            self.state.lock().fail_stop = fail;
        }

        fn set_fail_list(&self, fail: bool) {
            self.state.lock().fail_list = fail;
        }

        fn launches(&self) -> Vec<LaunchSpec> {
            self.state.lock().launches.clone()
        }

        fn stops(&self) -> Vec<String> {
            self.state.lock().stops.clone()
        }
    }

    impl Provisioner for FakeProvisioner {
        async fn launch(&self, spec: &LaunchSpec) -> Result<TaskId, ProvisionError> {
            let mut state = self.state.lock();
            if state.fail_launch {
                return Err(ProvisionError::Backend("launch failed".into()));
            }
            let id = format!("task-{}", state.next);
            state.next += 1;
            state.launches.push(spec.clone());
            let launch_state = state.launch_state.clone();
            state.tasks.insert(id.clone(), launch_state);
            Ok(TaskId(id))
        }

        async fn state(&self, task: &TaskId) -> Result<TaskState, ProvisionError> {
            let state = self.state.lock();
            if state.fail_state {
                return Err(ProvisionError::Backend("state failed".into()));
            }
            Ok(state
                .tasks
                .get(&task.0)
                .cloned()
                .unwrap_or(TaskState::Stopped))
        }

        async fn stop(&self, task: &TaskId) -> Result<(), ProvisionError> {
            let mut state = self.state.lock();
            if state.fail_stop {
                return Err(ProvisionError::Backend("stop failed".into()));
            }
            state.stops.push(task.0.clone());
            state.tasks.insert(task.0.clone(), TaskState::Stopped);
            Ok(())
        }

        async fn list(&self) -> Result<Vec<TaskId>, ProvisionError> {
            let state = self.state.lock();
            if state.fail_list {
                return Err(ProvisionError::Backend("list failed".into()));
            }
            Ok(state
                .tasks
                .iter()
                .filter(|(_, s)| **s != TaskState::Stopped)
                .map(|(id, _)| TaskId(id.clone()))
                .collect())
        }
    }

    fn region(name: &str) -> RegionId {
        RegionId(name.to_owned())
    }

    /// How many launches the fake provisioner has recorded for `region` so far —
    /// the coverage tests' demand signal (paired with a launch state that stops
    /// before enrolling, one demanding tick equals one launch for the region).
    fn launches_for(h: &Harness, region: &RegionId) -> usize {
        h.fake
            .launches()
            .into_iter()
            .filter(|spec| spec.region.as_ref() == Some(region))
            .count()
    }

    /// A hello for `id`, tagged with `region`, on a per-id loopback port.
    fn hello_in_region(id: u64, region: &RegionId) -> RelayHello {
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14_900 + id as u16)),
            ProtocolVersion::CURRENT,
            vec![id as u8; 4],
        )
        .with_region(region.clone())
    }

    /// A two-player, region-blind session request — its slots home on whatever
    /// relay is available.
    fn two_player_request() -> SessionRequest {
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        }
    }

    /// A test rig: shared registry, ledger, session setup (with one enrolled
    /// tenant), warm demand, a fake provisioner, and the loop built over them.
    struct Harness {
        reg: RelayRegistry,
        ledger: Arc<RelayLedger>,
        setup: SessionSetup,
        warm: WarmTargets,
        pair_rtts: PairRttStore,
        fake: Arc<FakeProvisioner>,
        provision: ProvisionLoop<Arc<FakeProvisioner>>,
    }

    impl Harness {
        fn new(regions: Vec<RegionId>, idle_grace: Duration, launch_deadline: Duration) -> Self {
            let reg = registry::new_registry();
            let tenants = tenant::new_store();
            tenant::enroll(
                &tenants,
                KeyId("test-key-1".to_owned()),
                TenantId(TENANT.to_owned()),
                BufferBounds::new(1, 6).unwrap(),
            )
            .unwrap();
            let setup = SessionSetup::new(reg.clone(), tenants);
            let ledger =
                Arc::new(RelayLedger::open(Path::new(":memory:")).expect("in-memory ledger opens"));
            let warm = WarmTargets::new();
            let pair_rtts = crate::pair_rtts::new_store();
            let fake = FakeProvisioner::new();
            let config = ProvisionConfig {
                regions,
                tick_interval: Duration::from_secs(5),
                launch_deadline,
                idle_grace,
            };
            let provision = ProvisionLoop::new(
                config,
                setup.registry().clone(),
                setup.clone(),
                ledger.clone(),
                warm.clone(),
                pair_rtts.clone(),
                fake.clone(),
            );
            Self {
                reg,
                ledger,
                setup,
                warm,
                pair_rtts,
                fake,
                provision,
            }
        }

        /// Mints, binds, records a task for, and enrolls a live relay in `region`
        /// at `now`, as if it had come up and enrolled. Returns its id and enroll
        /// generation.
        fn seed_live_relay(&self, region: &RegionId, now: u64) -> (RelayId, u64) {
            let minted = self
                .ledger
                .mint_at(now, Some(region), Duration::from_secs(3_600))
                .unwrap();
            self.ledger
                .authorize_enroll_at(now, minted.relay_id, [0x11; 32], Some(&minted.token), None)
                .unwrap();
            self.ledger
                .record_task(
                    minted.relay_id,
                    &format!("task-live-{}", minted.relay_id.0),
                    &[],
                    &[],
                )
                .unwrap();
            let generation =
                registry::enroll(&self.reg, hello_in_region(minted.relay_id.0, region));
            (minted.relay_id, generation)
        }
    }

    #[tokio::test]
    async fn scale_up_mints_launches_and_records_once_running() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);

        h.provision.tick(1_000).await;

        // Exactly one launch, tagged for the region.
        let launches = h.fake.launches();
        assert_eq!(launches.len(), 1);
        assert_eq!(launches[0].region.as_ref(), Some(&east));

        // The running task's address was recorded against the minted id.
        let minted_id = launches[0].relay_id;
        assert_eq!(
            h.ledger.task_arn(minted_id).unwrap(),
            Some("task-0".to_owned()),
            "the launched task is recorded once it reports running",
        );
        // Still launching (unbound) — one in-flight launch credited against target.
        assert_eq!(h.ledger.count_launching(Some(&east), 1_000).unwrap(), 1);
    }

    #[tokio::test]
    async fn launching_counts_against_target_so_no_double_launch() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        // A launch that stays Starting (its task never comes up this test).
        h.fake.set_launch_state(TaskState::Starting);
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);

        h.provision.tick(1_000).await;
        assert_eq!(h.fake.launches().len(), 1, "the first tick launches one");

        // A second tick, the task still Starting: the in-flight launch counts
        // against the target, so no second task is launched.
        h.provision.tick(1_001).await;
        assert_eq!(
            h.fake.launches().len(),
            1,
            "a still-launching task is not double-launched",
        );
        // And the still-pending launch is spared the orphan sweep.
        assert_eq!(h.fake.stops(), Vec::<String>::new());
        assert_eq!(h.provision.pending.len(), 1);
    }

    #[tokio::test]
    async fn a_starting_task_is_recorded_once_it_reports_running() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        h.fake.set_launch_state(TaskState::Starting);
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);

        h.provision.tick(1_000).await;
        let minted_id = h.fake.launches()[0].relay_id;
        assert_eq!(
            h.ledger.task_arn(minted_id).unwrap(),
            None,
            "a still-starting task is not yet recorded",
        );

        // The task comes up; the next tick records it and clears it from pending.
        h.fake.set_task_state("task-0", running());
        h.provision.tick(1_005).await;
        assert_eq!(
            h.ledger.task_arn(minted_id).unwrap(),
            Some("task-0".to_owned()),
        );
        assert!(
            h.provision.pending.is_empty(),
            "a recorded task leaves pending"
        );
    }

    #[tokio::test]
    async fn a_lapsed_warm_target_scales_back_to_zero() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(5),
            Duration::from_secs(300),
        );
        // Warm for 5s, then let it lapse.
        h.warm.warm_at(east.clone(), Duration::from_secs(5), 1_000);
        h.provision.tick(1_000).await;
        assert_eq!(h.fake.launches().len(), 1, "warm demand launched one");

        // Past the warm deadline (and no live relay ever enrolled): the target is 0,
        // so nothing new launches, and the never-enrolled launch stays launching
        // until its own deadline sweep — no runaway launching.
        h.provision.tick(1_010).await;
        assert_eq!(
            h.fake.launches().len(),
            1,
            "a lapsed warm target launches nothing more",
        );
    }

    #[tokio::test]
    async fn scale_down_drains_only_idle_zero_session_relays_past_the_grace() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(5),
            Duration::from_secs(300),
        );
        // No warm demand: target is 0, so the single live relay is over target.
        let (id, _gen) = h.seed_live_relay(&east, 1_000);

        // First tick starts the idle timer; the relay is not yet idle past the grace.
        h.provision.tick(1_000).await;
        assert!(
            registry::is_available(&h.reg, id),
            "a relay under the idle grace is not drained",
        );
        assert!(h.fake.stops().is_empty());

        // Past the grace: the relay is drained — its task stopped and its id retired.
        h.provision.tick(1_010).await;
        assert_eq!(
            h.fake.stops(),
            vec![format!("task-live-{}", id.0)],
            "the idle relay's task is stopped",
        );
        assert!(
            !registry::is_available(&h.reg, id),
            "the drained relay is marked draining",
        );
        assert!(
            h.ledger.bound_unretired().unwrap().is_empty(),
            "the drained relay's id is retired",
        );
    }

    #[tokio::test]
    async fn scale_down_spares_a_relay_that_gained_a_session_in_the_race() {
        let east = region("us-east");
        let h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(5),
            Duration::from_secs(300),
        );
        let (id, generation) = h.seed_live_relay(&east, 1_000);

        // A session lands on the relay (the only enrolled one).
        create_session(&h.setup, two_player_request(), ExpiresAt(u64::MAX)).unwrap();
        assert_eq!(h.setup.session_count_for_relay(id), 1);

        // The drain sequence marks it, re-checks, sees the session, and spares it.
        let mut h = h;
        let drained = h.provision.try_drain_one(id, generation).await;
        assert!(!drained, "a relay that gained a session is spared");
        assert!(
            registry::is_available(&h.reg, id),
            "the spared relay is un-marked (draining cleared)",
        );
        assert!(
            h.fake.stops().is_empty(),
            "a spared relay's task is never stopped"
        );
        assert_eq!(
            h.ledger.bound_unretired().unwrap().len(),
            1,
            "the spared relay's id is not retired",
        );
    }

    #[tokio::test]
    async fn a_stale_generation_drain_is_a_no_op() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(5),
            Duration::from_secs(300),
        );
        let (id, stale_generation) = h.seed_live_relay(&east, 1_000);
        // The relay reconnects: a newer generation supersedes the one selected.
        registry::enroll(&h.reg, hello_in_region(id.0, &east));

        let drained = h.provision.try_drain_one(id, stale_generation).await;
        assert!(!drained, "a stale-generation drain does not apply");
        assert!(
            registry::is_available(&h.reg, id),
            "the reconnected relay stays available",
        );
        assert!(h.fake.stops().is_empty());
    }

    #[tokio::test]
    async fn the_launch_deadline_sweep_stops_and_retires_a_never_enrolled_task() {
        let east = region("us-east");
        // A short launch deadline: the token expires quickly.
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(10),
        );
        h.fake.set_launch_state(TaskState::Starting);
        // Warm briefly, so a launch happens but the region is cold by the sweep.
        h.warm.warm_at(east.clone(), Duration::from_secs(5), 1_000);
        h.provision.tick(1_000).await;
        assert_eq!(h.fake.launches().len(), 1);
        let minted_id = h.fake.launches()[0].relay_id;

        // Past the token deadline (1_000 + 10) and the warm deadline: the launch is
        // swept — its task stopped, its id retired, its pending entry dropped.
        h.provision.tick(2_000).await;
        assert_eq!(
            h.fake.stops(),
            vec!["task-0".to_owned()],
            "the never-enrolled task is stopped",
        );
        assert_eq!(
            h.ledger.count_launching(Some(&east), 2_000).unwrap(),
            0,
            "the expired launch no longer counts as launching",
        );
        assert_eq!(
            h.ledger.expired_launching(2_000).unwrap().len(),
            0,
            "the expired launch was retired, so it is gone from the launching set",
        );
        assert!(
            h.provision.pending.is_empty(),
            "the swept launch left pending"
        );
        // A fresh mint after the retire gets a new id (the retired one is tombstoned).
        assert_ne!(
            h.ledger
                .mint_at(2_000, Some(&east), Duration::from_secs(10))
                .unwrap()
                .relay_id,
            minted_id,
        );
    }

    #[tokio::test]
    async fn the_vanished_task_sweep_retires_a_bound_relay_whose_task_stopped() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        // A bound id, recorded task, but never enrolled in the registry and whose
        // task the provisioner reports stopped.
        let minted = h
            .ledger
            .mint_at(1_000, Some(&east), Duration::from_secs(3_600))
            .unwrap();
        h.ledger
            .authorize_enroll_at(
                1_000,
                minted.relay_id,
                [0x22; 32],
                Some(&minted.token),
                None,
            )
            .unwrap();
        h.ledger
            .record_task(minted.relay_id, "task-vanished", &[], &[])
            .unwrap();
        h.fake.set_task_state("task-vanished", TaskState::Stopped);

        h.provision.tick(2_000).await;
        assert!(
            h.ledger.bound_unretired().unwrap().is_empty(),
            "a bound relay whose task stopped and is not enrolled is retired",
        );
    }

    #[tokio::test]
    async fn the_vanished_task_sweep_leaves_an_enrolled_relay_alone() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        let (id, _gen) = h.seed_live_relay(&east, 1_000);
        // Its task reports stopped, but it is still enrolled — a false alarm.
        h.fake
            .set_task_state(&format!("task-live-{}", id.0), TaskState::Stopped);

        h.provision.tick(1_001).await;
        assert_eq!(
            h.ledger.bound_unretired().unwrap().len(),
            1,
            "an enrolled relay is never vanished-swept, whatever its task reports",
        );
    }

    #[tokio::test]
    async fn the_orphan_sweep_stops_an_unreferenced_task_and_spares_a_referenced_one() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );

        // A referenced task: a live relay's recorded task.
        let (id, _gen) = h.seed_live_relay(&east, 1_000);
        let referenced = format!("task-live-{}", id.0);
        h.fake.set_task_state(&referenced, running());

        // An orphan: a running task no ledger row references.
        h.fake.set_task_state("task-orphan", running());

        h.provision.tick(1_001).await;
        assert!(
            h.fake.stops().contains(&"task-orphan".to_owned()),
            "an unreferenced task is stopped",
        );
        assert!(
            !h.fake.stops().contains(&referenced),
            "a referenced task is spared",
        );
    }

    #[tokio::test]
    async fn a_provisioner_launch_error_does_not_kill_the_loop_and_next_tick_retries() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);

        // First tick: launching fails. The tick completes (does not panic), and the
        // failed launch's minted id is retired, so nothing is left launching.
        h.fake.set_fail_launch(true);
        h.provision.tick(1_000).await;
        assert!(
            h.fake.launches().is_empty(),
            "the failed launch recorded no spec"
        );
        assert_eq!(
            h.ledger.count_launching(Some(&east), 1_000).unwrap(),
            0,
            "a failed launch's minted id is retired, not left launching",
        );

        // Next tick: launching succeeds — the loop retries the still-open gap.
        h.fake.set_fail_launch(false);
        h.provision.tick(1_001).await;
        assert_eq!(
            h.fake.launches().len(),
            1,
            "the next tick retries the launch"
        );
    }

    #[tokio::test]
    async fn provisioner_state_and_list_errors_do_not_kill_the_loop() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);

        // Poll and list both fail this tick; the launch still records its spec, and
        // the tick completes without panicking.
        h.fake.set_fail_state(true);
        h.fake.set_fail_list(true);
        h.provision.tick(1_000).await;
        assert_eq!(h.fake.launches().len(), 1);
        // The task could not be polled, so it stays pending for a later tick.
        assert_eq!(h.provision.pending.len(), 1);

        // With polling restored, the next tick records the task.
        h.fake.set_fail_state(false);
        h.fake.set_fail_list(false);
        let minted_id = h.fake.launches()[0].relay_id;
        h.provision.tick(1_001).await;
        assert_eq!(
            h.ledger.task_arn(minted_id).unwrap(),
            Some("task-0".to_owned()),
            "the recovered poll records the task",
        );
    }

    #[tokio::test]
    async fn a_stop_error_during_drain_still_retires_the_id() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(5),
            Duration::from_secs(300),
        );
        let (id, _gen) = h.seed_live_relay(&east, 1_000);
        h.fake.set_fail_stop(true);

        h.provision.tick(1_000).await; // start idle timer
        h.provision.tick(1_010).await; // past grace: drain
        assert!(
            h.ledger.bound_unretired().unwrap().is_empty(),
            "a stop failure does not stop the id from being retired",
        );
        assert!(
            !registry::is_available(&h.reg, id),
            "the relay is still marked draining despite the stop error",
        );
    }

    #[tokio::test]
    async fn an_empty_pair_table_bootstraps_every_configured_region() {
        let east = region("us-east");
        let west = region("us-west");
        let central = region("us-central");
        let mut h = Harness::new(
            vec![east.clone(), west.clone(), central.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );

        // No warm demand and an empty pair table: every region has an uncovered pair,
        // so every region bootstraps exactly one relay.
        h.provision.tick(1_000).await;

        assert_eq!(h.fake.launches().len(), 3, "one launch per region, no more");
        let bootstrapped: HashSet<RegionId> = h
            .fake
            .launches()
            .into_iter()
            .filter_map(|s| s.region)
            .collect();
        assert_eq!(
            bootstrapped,
            HashSet::from([east, west, central]),
            "each configured region gets a bootstrap launch",
        );
    }

    #[tokio::test]
    async fn warm_and_coverage_demand_merge_by_max_not_sum() {
        let east = region("us-east");
        let west = region("us-west");
        let mut h = Harness::new(
            vec![east.clone(), west.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );

        // East is warm (target 1) and also lacks coverage (empty pair table). The two
        // demands merge by max, not sum: exactly one relay, not two.
        h.warm
            .warm_at(east.clone(), Duration::from_secs(600), 1_000);
        h.provision.tick(1_000).await;

        assert_eq!(
            launches_for(&h, &east),
            1,
            "a warm region that also needs coverage bootstraps just once",
        );
    }

    #[tokio::test]
    async fn coverage_demand_clears_when_a_regions_pairs_arrive() {
        let east = region("us-east");
        let west = region("us-west");
        // A short idle grace so the drain is reachable in a couple of ticks; a long
        // launch deadline so the seeded relay is not swept as an expired launch.
        let mut h = Harness::new(
            vec![east.clone(), west.clone()],
            Duration::from_secs(5),
            Duration::from_secs(3_600),
        );
        // A live relay in east, no warm demand. The empty pair table leaves east's one
        // pair uncovered, so coverage demand holds its target at 1.
        let (east_id, _gen) = h.seed_live_relay(&east, 1_000);

        // First tick starts the relay's idle timer; coverage keeps the target at 1, so
        // the relay is not yet a scale-down candidate.
        h.provision.tick(1_000).await;
        assert!(
            registry::is_available(&h.reg, east_id),
            "an uncovered region's relay is held up by coverage demand",
        );

        // Past the idle grace but still uncovered: coverage demand still shields the
        // idle relay from the scale-down.
        h.provision.tick(1_010).await;
        assert!(
            registry::is_available(&h.reg, east_id),
            "coverage demand keeps the relay from idle-draining while a pair is missing",
        );
        assert!(h.fake.stops().is_empty());

        // The relay's measurement lands: east's only pair now has a value, so coverage
        // demand clears. With no warm demand the target falls to 0 and the idle relay
        // drains by the normal path (whose mechanics are covered by other tests).
        h.pair_rtts.record(&east, &west, 87, 1_010);
        h.provision.tick(1_011).await;
        assert!(
            !registry::is_available(&h.reg, east_id),
            "once covered, the relay drops to the normal idle-drain path",
        );
        assert_eq!(
            h.fake.stops(),
            vec![format!("task-live-{}", east_id.0)],
            "the released relay's task is stopped",
        );
    }

    #[tokio::test]
    async fn a_region_that_never_reports_backs_off_and_escalates() {
        let east = region("us-east");
        let west = region("us-west");
        let mut h = Harness::new(
            vec![east.clone(), west.clone()],
            Duration::from_secs(600),
            Duration::from_secs(3_600),
        );
        // Every bootstrap launch stops before enrolling, so nothing lingers as
        // "launching": each tick with live coverage demand produces exactly one launch
        // per region, giving a clean per-tick demand signal.
        h.fake.set_launch_state(TaskState::Stopped);

        // A fresh, uncovered region demands a bootstrap relay within the hold window.
        h.provision.tick(1_000).await;
        assert_eq!(launches_for(&h, &east), 1, "an uncovered region bootstraps");

        // The hold window elapses with no measurement: the region counts a failed
        // attempt and backs off, so this tick demands nothing more for it.
        let failed_at = 1_000 + COVERAGE_HOLD_SECS + 1;
        h.provision.tick(failed_at).await;
        assert_eq!(
            launches_for(&h, &east),
            1,
            "past the hold window with no report, the region backs off (no demand)",
        );

        // Deep into the first backoff (BASE seconds), still no demand.
        h.provision
            .tick(failed_at + COVERAGE_BACKOFF_BASE_SECS - 1)
            .await;
        assert_eq!(
            launches_for(&h, &east),
            1,
            "the region demands nothing while backing off",
        );

        // The first backoff expires: one fresh demanding tick.
        let second_try_at = failed_at + COVERAGE_BACKOFF_BASE_SECS;
        h.provision.tick(second_try_at).await;
        assert_eq!(
            launches_for(&h, &east),
            2,
            "when the backoff expires the region tries once more",
        );

        // That attempt's hold window elapses too: a second failure. The backoff has
        // doubled past BASE, so even BASE seconds after this failure it is still
        // backing off — proof the interval escalated.
        let second_failed_at = second_try_at + COVERAGE_HOLD_SECS + 1;
        h.provision.tick(second_failed_at).await;
        assert_eq!(
            launches_for(&h, &east),
            2,
            "the second failure backs off again"
        );
        h.provision
            .tick(second_failed_at + COVERAGE_BACKOFF_BASE_SECS + 1)
            .await;
        assert_eq!(
            launches_for(&h, &east),
            2,
            "the escalated backoff is longer than the first, so no retry yet",
        );
    }

    #[tokio::test]
    async fn a_pair_value_resets_the_bootstrap_backoff() {
        let east = region("us-east");
        let west = region("us-west");
        let central = region("us-central");
        // Three regions so east has two pairs and a single value is partial progress.
        let mut h = Harness::new(
            vec![east.clone(), west.clone(), central.clone()],
            Duration::from_secs(600),
            Duration::from_secs(3_600),
        );
        h.fake.set_launch_state(TaskState::Stopped);

        // Drive east into a backoff: one attempt, then a failed hold window.
        h.provision.tick(1_000).await;
        let failed_at = 1_000 + COVERAGE_HOLD_SECS + 1;
        h.provision.tick(failed_at).await;
        assert_eq!(
            launches_for(&h, &east),
            1,
            "east backed off after its hold window elapsed with no report",
        );
        // Confirm it is genuinely backing off: a tick within the backoff demands
        // nothing.
        h.provision.tick(failed_at + 10).await;
        assert_eq!(
            launches_for(&h, &east),
            1,
            "east demands nothing while backing off",
        );

        // A value arrives for one of east's two pairs — partial coverage, but proof the
        // measurement path works. It resets the backoff: east demands a relay again on
        // the very next tick, without waiting out the backoff.
        h.pair_rtts.record(&east, &west, 87, failed_at + 20);
        h.provision.tick(failed_at + 20).await;
        assert_eq!(
            launches_for(&h, &east),
            2,
            "a pair value resets the backoff and east resumes demanding immediately",
        );

        // The reset also returned the attempt count to zero: the next failure backs
        // off by BASE again (not the escalated interval), so a retry lands exactly one
        // BASE window after this fresh failure.
        let refailed_at = failed_at + 20 + COVERAGE_HOLD_SECS + 1;
        h.provision.tick(refailed_at).await;
        assert_eq!(
            launches_for(&h, &east),
            2,
            "the fresh attempt fails and backs off",
        );
        h.provision
            .tick(refailed_at + COVERAGE_BACKOFF_BASE_SECS)
            .await;
        assert_eq!(
            launches_for(&h, &east),
            3,
            "the backoff is BASE again, confirming the attempt count reset",
        );
    }

    #[tokio::test]
    async fn a_single_region_config_never_bootstraps() {
        let east = region("us-east");
        let mut h = Harness::new(
            vec![east.clone()],
            Duration::from_secs(600),
            Duration::from_secs(300),
        );

        // A lone region has no pairs, so coverage never demands anything.
        h.provision.tick(1_000).await;
        assert!(
            h.fake.launches().is_empty(),
            "a single-region config has no pairs to bootstrap",
        );
    }
}
