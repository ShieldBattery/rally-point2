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
//!
//! # File map
//!
//! - `mod.rs` (this file) — config, loop state, `new`/`run`/`tick`.
//! - `scaling` — the second `impl<P: Provisioner> ProvisionLoop<P>` block:
//!   idle tracking, coverage demand, and scale up/down.
//! - `sweeps` — the fleet-wide sweeps `tick` runs after scaling: expired
//!   launches, vanished tasks, and ledger orphans.

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
/// each tick until it reports running. `expects_public_ipv4` and `launched_at`
/// gate that recording against a substrate whose task can report running with an
/// address set that is still missing an address family it will carry once fully
/// up (see [`PUBLIC_IPV4_WAIT_SECS`]).
struct PendingLaunch {
    /// The id the task runs as.
    relay_id: RelayId,
    /// The provisioner handle for the task.
    task: TaskId,
    /// Whether this launch's substrate is expected to eventually attach a public
    /// IPv4 address to the task. When true, an address set reporting running
    /// without one is treated as still incomplete rather than final.
    expects_public_ipv4: bool,
    /// When the task was launched (Unix seconds) — what
    /// [`PUBLIC_IPV4_WAIT_SECS`] is measured from when deciding whether a
    /// still-v4-less address set has waited long enough to record as-is.
    launched_at: u64,
}

/// How long an address set missing an expected public IPv4 is treated as still
/// incomplete after its task's launch. Some substrates attach a task's network
/// interface with other addresses first and its public-IPv4 association only
/// afterward, so an early poll can observe an address set missing the v4 the
/// launch expects; recording that set as final would leave the relay reachable
/// over only its other address family for the rest of its life. Past this many
/// seconds since launch the set is recorded as-is regardless, so a deployment
/// that legitimately never gets a public IPv4 is not blocked forever — the
/// launch-deadline sweep remains the backstop for a task that never truly comes
/// up.
const PUBLIC_IPV4_WAIT_SECS: u64 = 90;

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
            // Draining relays are excluded: placement can no longer land a session on
            // one (`registry::is_available` already refuses it), so counting it toward
            // `live` would hide a real gap behind a relay that is on its way out —
            // scale-up would stay suppressed for as long as the drain takes to finish
            // (up to a full game's remaining length) even though nothing placeable
            // covers the target.
            let live = enrolled
                .iter()
                .filter(|r| !r.draining && r.region.as_ref() == Some(region))
                .count() as u32;
            self.scale_up(region, live, target, now).await;
            self.scale_down(region, &enrolled, live, target, now).await;
        }

        self.resolve_pending(now).await;
        self.launch_deadline_sweep(now).await;
        self.vanished_task_sweep().await;
        self.orphan_sweep().await;
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

mod scaling;
mod sweeps;

#[cfg(test)]
mod tests;
