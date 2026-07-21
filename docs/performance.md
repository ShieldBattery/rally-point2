# Relay performance workflow

This repository has two complementary performance harnesses:

- Criterion microbenchmarks isolate transport and relay hot paths. They are fast
  enough to run while changing an implementation and report statistical
  before/after deltas.
- `rally-point-loadgen` drives real coordinator, relay, QUIC, validation, mesh,
  and client code. The relay's task-stats line pairs VM/container CPU with actual
  validated-turn and local-delivery rates, while the loadgen reports latency,
  stalls, delivery counts, and a self-describing JSON workload.

Neither harness changes the transport model. In particular, benchmark results
must never be used to justify ordered delivery, timeout retransmission, or
relay-side turn reordering; those would measure a different protocol.

## Microbenchmarks

The suites live in `transport/benches/hot_paths.rs` and
`relay/benches/hot_paths.rs`.

Run them normally:

```sh
cargo bench -p rally-point-transport --bench hot_paths
cargo bench -p rally-point-relay --bench hot_paths
```

For an optimization, save the unchanged implementation as a named baseline,
then compare the candidate against it on the same machine:

```sh
# Unchanged implementation (usually main, with the same benchmark harness).
cargo bench -p rally-point-transport --bench hot_paths -- --save-baseline main
cargo bench -p rally-point-relay --bench hot_paths -- --save-baseline main

# Candidate implementation.
cargo bench -p rally-point-transport --bench hot_paths -- --baseline main
cargo bench -p rally-point-relay --bench hot_paths -- --baseline main
```

The benchmark source itself must be identical on both revisions. The easiest
workflow is to land the harness before the optimization; for an older revision,
use a temporary worktree and apply only the harness (plus the smallest API
adapter needed to express the same operation). Comparing two different benchmark
bodies is not a before/after measurement.

A positional Criterion filter shortens the loop while working on one area:

```sh
cargo bench -p rally-point-transport --bench hot_paths -- ack_manager/build_ack_history
cargo bench -p rally-point-relay --bench hot_paths -- validation/clean
```

Criterion stores local samples under `target/criterion`; they are machine-local
artifacts and are not committed. Use the same host, build profile, power mode,
and background-load conditions for both sides. Treat changes whose confidence
intervals overlap as inconclusive and repeat them before keeping extra
complexity.

The current cases cover:

- redundancy packing when the unacked window fits and when the datagram budget
  is constrained;
- reliable-cursor retirement with unrelated slots present (also a regression
  guard: a repeated range-search/remove implementation measured no better than
  the single-pass retain and was not kept);
- receive ack-history construction;
- clean and sanitizing command validation;
- in-order mesh dedup, the warm per-session registry path, and turn-ring writes.
- consensus target calculation at realistic roster sizes and single-slot versus
  one-element-batch condition ingestion.

## End-to-end relay runs

Build optimized binaries and start relays with task stats enabled. On Fargate,
the reporter automatically reads the task-local ECS metadata endpoint; outside
ECS it is a no-op.

```sh
cargo build --release -p rally-point-relay -p rally-point-coordinator -p rally-point-loadgen

# Add this to each relay invocation/environment.
--task-stats-interval-secs 5
```

Run the load generator long enough to leave a steady-state window after the
arrival ramp. The tenant key and region names are deployment-specific:

```sh
target/release/rally-point-loadgen \
  --coordinator-url https://COORDINATOR \
  --tenant TENANT \
  --client-key ED25519_SEED_HEX \
  --sessions 200 \
  --arrival-rate 10 \
  --players 4 \
  --game-secs 180 \
  --turn-rate 24 \
  --turn-bytes 16 \
  --slot-regions us-west,us-east \
  --json-out run.json
```

The JSON includes the complete workload, wall time, actual sent/delivered rates,
latency distributions, stalls, and connection outcomes. A relay task-stats line
reports CPU and network rates plus actual validated-turn, distinct mesh-ingress,
and local-delivery rates. Local validation and delivery totals reuse the flight
recorder's existing per-slot atomics and are summed only at the task-stats poll.
Distinct mesh ingress is counted immediately after session-level dedup, while
the turn ring already holds its record lock. Measurement therefore adds neither
a second per-turn atomic update nor a new lock acquisition. Its CPU-per-work
fields are deliberately reported against three denominators:

- CPU ns / validated turn is useful for identical client-ingress and topology
  runs;
- CPU ns / ingress turn divides by locally validated plus distinct mesh-origin
  turns, making it the all-ingress denominator for split-relay topologies;
- CPU ns / local delivery captures fan-out work, but does not include mesh sends
  as a separate unit.

`mesh_ingress_turns_per_sec` counts only the first mesh copy of each
`(slot, seq)` that wins session dedup. Redundant or replayed copies rejected by
that gate do not inflate it. `ingress_turns_per_sec` is the sum of that rate and
`validated_turns_per_sec`. The corresponding `validated_turns_total`,
`mesh_ingress_turns_total`, and `ingress_turns_total` fields expose the sampled
cumulative counters, making a relay restart or counter reset visible when
filtering steady-state plateaus.

Keep topology identical when comparing any value. A split two-relay game does
different work from a single-relay game even if both validate the same number of
client turns.

For the one-hop relay invariant, also compare aggregate relay `net_tx_mibps`.
With `R` relays serving one session, one locally originated turn should enter
exactly `R - 1` mesh links. Any build that re-forwards the first mesh copy at
each receiver instead performs `R * (R - 1)` mesh sends before session-level
dedup catches the echoes, so the waste grows linearly with relay count even when
client delivery totals look identical.

Use this minimum matrix to reveal where a change helps:

| Axis | Runs | What it separates |
| --- | --- | --- |
| Topology | one relay; two relays with alternating slot regions | client-edge cost from mesh cost |
| Players/session | 2, 4, 8 | fixed per-turn work from local fan-out slope |
| Turn size | 16, 256, 1024 bytes | fixed bookkeeping from encode/copy/bandwidth cost |
| Concurrency | increase sessions to roughly 50%, 70%, then 90% CPU | low-load latency from saturation behavior |

For each point, run at least three repetitions. Compare the median steady-state
task samples after the ramp and before teardown; also require that p99 fan-out
latency, stalls, clean endings, and delivery counts do not regress. CPU is not a
win if the change merely drops or delays work.

## Profiling a remaining hotspot

Use the microbench result to decide whether a small function is worth inspecting.
Use the real load run to find cross-module costs that a microbenchmark cannot
represent. On a Linux relay host, sampling `perf` against an optimized binary is
the most direct CPU flame graph/input; hardware counters from `perf stat` help
separate fewer instructions from fewer cache misses. Allocation profilers such
as heaptrack are useful when the CPU profile points into allocator paths.

Profile the same steady workload used for the comparison, and record the exact
git revision, relay arguments, workload JSON, VM/task size, and topology beside
the profile. Without those, two profiles are not meaningfully comparable.
