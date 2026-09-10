# AGENTS.md — `provision/`

## File map
- `mod.rs` — substrate contract only (`Provisioner`, `LaunchSpec`, `TaskId`,
  `TaskState`, `ProvisionError`, the `Arc<P>` blanket impl). No policy.
- `reconcile/` — the loop, split across three `impl<P: Provisioner>
  ProvisionLoop<P>` blocks: `mod.rs` (`new`/`run`/`tick`), `scaling.rs` (idle
  tracking, coverage-bootstrap demand, scale up/down), `sweeps.rs` (the
  fleet-wide cleanups).
- `warm.rs` — `WarmTargets`: per-region warm demand with a TTL deadline.
  Independent of `reconcile`.
- `ecs/` — the Fargate `Provisioner`. `mod.rs` holds config, errors, and the
  substrate-independent `EcsCore` mapping; `api.rs` holds the `EcsApi` trait
  + its real (SDK) impl, split so the mapping is testable against a fake.
- `process.rs` — the local child-process `Provisioner`, for dev/tests.

## Tick order (why)
`refresh_idle` → per-region `scale_up`/`scale_down` (target =
`max(warm, coverage)`, never their sum) → `resolve_pending` →
`launch_deadline_sweep` → `vanished_task_sweep` → `orphan_sweep`. Scaling runs
first so a launch made this tick is never swept as an orphan (`pending`
entries are exempt). The sweeps' relative order doesn't matter — each is an
independent full re-derivation from the ledger/registry.

## Coverage backoff
A region demands one relay per uncovered pair for `COVERAGE_HOLD_SECS`; still
uncovered when that lapses is a failed attempt, doubling the backoff
(`coverage_backoff_secs`, capped). Any rise in covered-pair count resets
`attempts` to 0. State (`ProvisionLoop.coverage`) is loop-local, dropped once
a region is fully covered.

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
