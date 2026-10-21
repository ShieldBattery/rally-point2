# AGENTS.md — `provision/`

## File map
- `mod.rs` — substrate contract only (`Provisioner`, `LaunchSpec`, `TaskId`,
  `TaskState`, `ProvisionError`, the `Arc<P>` blanket impl). No policy.
- `reconcile/` — the loop, split across four `impl<P: Provisioner>
  ProvisionLoop<P>` blocks: `mod.rs` (`new`/`run`/`tick`), `scaling.rs` (idle
  tracking, coverage-bootstrap demand, scale up/down), `retirement.rs`
  (max-age replacement), `sweeps.rs` (the fleet-wide cleanups).
- `warm.rs` — `WarmTargets`: per-region warm demand with a TTL deadline.
  Independent of `reconcile`.
- `coverage.rs` — `CoverageStatus`: the coverage phase the loop publishes out,
  so a scrape can read state that is otherwise loop-local. Independent of
  `reconcile`, and the mirror of `warm.rs` — demand travels in through the
  provision gate, phase travels out through it.
- `ecs/` — the Fargate `Provisioner`. `mod.rs` holds config, errors, and the
  substrate-independent `EcsCore` mapping; `api.rs` holds the `EcsApi` trait
  + its real (SDK) impl, split so the mapping is testable against a fake.
- `process.rs` — the local child-process `Provisioner`, for dev/tests.

## Tick order (why)
`refresh_idle` → `aged_relays` → per-region `scale_up` → `retire_aged` →
`scale_down` (target = `max(warm, coverage)`, never their sum) → `resolve_pending` →
`finish_drains` → `launch_deadline_sweep` → `vanished_task_sweep` →
`orphan_sweep`. A launch is written to the ledger (`record_launch`) the moment
it returns, so the orphan sweep never mistakes it for a stray, whatever the
order. The sweeps' relative order doesn't matter — each is an independent full
re-derivation from the ledger/registry.

## Max-age retirement
Two relay counts per region, and mixing them up breaks make-before-break.
`scale_up` counts only *fresh* (non-draining, not aged) relays, so an aged
relay's replacement launches while it still serves. `scale_down` counts every
non-draining relay *after* `retire_aged` has run. `retire_aged` flips
`draining` in the tick's `enrolled` snapshot for each relay it marks, so an
aged relay with no enrolled replacement still counts as live there and drains
by the idle path when its region has no demand. A busy aged relay stays marked;
never route it through `try_drain_one`, which un-marks a relay it finds busy.

## Snapshots go stale within a tick
Scaling awaits provisioner calls between decisions, so the tick's `enrolled`
snapshot can be wrong by the time a relay is drained: another relay in the
region may have disconnected or begun its own drain. Every decision that removes
a placeable relay re-checks the live registry under the assignment lock first.
`retire_aged` requires a still-available replacement, `try_drain_one`
requires the region to still be over target, and `finish_drains` requires the
relay to still be draining under the snapshot's generation (a reconnect installs
an undrained enrollment) with no sessions. A new drain path must do the same.

## Coverage backoff
A region demands one relay per uncovered pair for `COVERAGE_HOLD_SECS`; still
uncovered when that lapses is a failed attempt, doubling the backoff
(`coverage_backoff_secs`, capped). Any rise in covered-pair count resets
`attempts` to 0. State (`ProvisionLoop.coverage`) is loop-local, dropped once
a region is fully covered; the loop republishes the resulting phase into the
gate's `CoverageStatus` every tick it derives one, so the published bit is
level-triggered and never has to be cleared by hand.

## Loop liveness
Nothing outside the loop notices it stopping: creates keep being held and
answered, and only scaling ceases. So every substrate call must be bounded (the
ECS clients carry SDK operation timeouts; a new substrate needs the same), a
panicking tick is caught and logged in `run` rather than ending the task, and a
tick past `SLOW_TICK_WARN` is logged while still stuck. Completed ticks stamp
`rp2_provision_last_tick_seconds`; a value falling behind the clock is the
stall signal.

Continuing after a panic is only sound because a tick can stop at any await
without stranding anything: every piece of work is re-derived from the ledger
and registry on the next tick (launches still coming up from
`unrecorded_launches`, interrupted drains from `finish_drains`). Loop-local
state (`idle_since`, `coverage`) may only hold what is safe to lose. A new step
that half-applies a change across an await must leave behind something the next
tick finds and finishes; test it by panicking the provisioner mid-step.

## `Provisioner` contract
Every method must be safe to retry, with no memory of a prior failure — the
ledger/registry, not the provisioner, is the source of truth for whether a
relay should exist. ECS ENIs carry an address as soon as they attach, before
task status reaches RUNNING, so `state` reports `Running` off the ENI alone;
a v6-only set stays `Starting` until a v4 attaches or `PUBLIC_IPV4_WAIT_SECS`
elapses (the launch-deadline sweep is the real backstop).

## Testing
`reconcile` shares a `FakeProvisioner` + `Harness` (`reconcile/tests/mod.rs`)
over an in-memory registry/ledger/session; every clock read takes an
explicit `now: u64`. `ecs` uses a `FakeEcsApi` scripted with per-call maps —
no live AWS. Run: `cargo test -p rally-point-coordinator --lib provision::`.
