# Staging relay load baseline — July 2026

This sweep answers a capacity-planning question: how many simulated players can
one ARM64 Fargate relay serve before CPU saturation visibly harms delivery? It
also measures the extra work when every game spans two relays instead of keeping
all players on one relay.

These are measured operating points, not hard limits or an SLA. Most points had
one repetition; the two-relay 72-client-per-relay boundary had three. Repeat the
matrix before changing production sizing or after a material hot-path, runtime,
Fargate platform, or workload change.

## Workload and interpretation

- 120-second games, 24 turns/second/player, 16-byte turn payloads, IPv4.
- Players arrived at 10 clients/second. A single-relay game placed every slot in
  `us-east`; a split game alternated slots between `us-east` and `us-west`.
- Relay tasks were Linux/ARM64. The 0.5-vCPU sweep used 1 GiB; the 1-vCPU sweep
  used 2 GiB.
- Relay builds ranged from `d223940` through `bcdfc6f`; the complete 1-vCPU and
  matched-topology runs used exactly `bcdfc6f`. Later commits add measurement and
  hot-path improvements, so this is deliberately a conservative historical
  baseline rather than a claim about an unmeasured build.
- CPU is median steady-state container CPU time divided by monotonic wall time.
  `1.0` means one fully occupied core; utilization of a 0.5-vCPU task is
  `cpu_cores / 0.5`.
- The historical sweep called a point "clean" when every client connected and
  ended cleanly and no stalls were reported. Its loadgen independently timed each
  player's leave and did not retain exact per-frame delivery coordinates, so the
  old artifacts cannot prove terminal delivery completeness. Re-establish exact
  completeness with the synchronized/draining harness before treating these
  points as correctness baselines. A sharp p99 latency rise is still treated as
  the saturation knee even if all games eventually finish.

## Current-platform rerun (`da47bc7`)

AWS replaced the Fargate platform revision used by newly launched tasks between
the historical sweep and this rerun. These results therefore describe the
current platform plus relay commit `da47bc7`; differences from the historical
tables cannot be attributed to the code change alone. Each point below is one
120-second repetition on a 0.5-vCPU/1-GiB ARM64 task.

The running image's ten-second CPU reporter aliased with the ECS stats cache at
some points, producing compensating zero/catch-up samples. CPU here is the
arithmetic mean of every evenly spaced steady-state sample, including both
halves of those pairs. The updated reporter records provider timestamps and raw
cumulative CPU so future sweeps can use first-to-last deltas directly.

| Players/game | Topology | Conservative planning point | Highest zero-stall point | Observed boundary |
| --- | --- | ---: | ---: | --- |
| 2 | one relay | 96 clients | 108 clients, 0.378 cores, 4.63 ms p99 | 120 clients had 17 stalls; 144 had 90 stalls and 10.49 ms p99 |
| 2 | two relays | 48 clients/relay (96 total) | 48/relay, 0.381 east / 0.371 west, 69.06 ms p99 | 60/relay had no stalls under the old lifecycle accounting; 72/relay had 11 stalls |
| 4 | one relay | 80 clients (headroom below the sampled point) | 96 clients, 0.479 cores, 5.72 ms p99 | 112 clients used 0.526 cores, had 317 stalls, and reached 17.34 ms p99 |
| 8 | one relay | 56 clients (headroom below the sampled point) | 64 clients, 0.467 cores, 4.06 ms p99 | 72 clients used 0.510 cores, had 274 stalls, and reached 20.98 ms p99 |

The 80- and 56-client planning values are conservative interpolations, not
separately sampled points. They keep useful CPU margin below clean measurements
that already consumed 96% and 93% of the nominal half-core allocation.

The final two-relay 96-client run used the synchronized exact-accounting
harness: all 48 sessions completed, with 276,480 expected and distinct
deliveries, zero missing, zero duplicate, and zero stalls. At the same total
client count, the one-relay run used 0.346 cores; the split run used 0.752 cores
in aggregate, about 2.17 times as much. The inter-region mesh hop also raised
p99 fan-out from 2.32 ms to 69.06 ms.

After the final session ended at 04:44:27 UTC, the coordinator retired both
relay tasks at 04:55:12/04:55:23 UTC with reason `coordinator scale-down` and
container exit code 0. All three regional clusters then had zero running tasks;
no manual stop was required.

## Promoted-image validation (`4455b99`)

The first run after promoting the mesh-Join rendezvous fix and zstd-compressed
relay image repeated the exact 96-client comparison on 2026-07-22. Both relay
tasks were 0.5-vCPU/1-GiB Linux/ARM64 Fargate tasks. The split run began with
the east and west clusters at zero; the single-relay control reused the warm
east task immediately afterward. Both used 48 two-player sessions, a five
session/second arrival rate, 120-second games, 24 turns/second/player, and
16-byte turn payloads.

The running tasks both reported image index digest
`sha256:5898bea6785e1114c84f0ab6b3a234a3dc49f385712a169dcc07039c61afd005`.
All 19 layers of its ARM64 child were zstd-compressed and totaled 25,834,666
bytes, 9.80% smaller than the previous image's 28,642,250 compressed layer
bytes.

| Topology | Clients/relay | CPU cores/relay | Aggregate relay cores | Fan-out p99 | Players seeing `SessionStart` | Exact delivery | Stalls |
| --- | ---: | --- | ---: | ---: | ---: | --- | ---: |
| one warm relay | 96 east | 0.312 east | 0.312 | 0.973 ms | 96/96 | 276,480/276,480, 0 missing/duplicate | 0 |
| two cold relays | 48 east / 48 west | 0.348 east / 0.346 west | 0.694 | 72.201 ms | 96/96 | 276,480/276,480, 0 missing/duplicate | 0 |

CPU is the first-to-last cumulative CPU/provider-time delta across each full
steady-state plateau. Split topology consumed 2.22 times the aggregate relay
CPU of the same-total-client single-relay control. That is consistent with the
earlier topology result: each split relay handles client ingress plus mesh
ingress even though it homes only half the clients.

The preceding cold split had stranded one whole session at 94/96 clients
observing `SessionStart`. This first cold run with the rendezvous fix reached
96/96 and completed every delivery exactly once, directly exercising the race
that motivated the fix. The split and single CPU results were respectively
7.7% and 9.8% below the preceding current-platform measurements, but each is
only one repetition on fresh Fargate placements; treat that as encouraging
variance, not a demonstrated CPU improvement.

Cold launch timing remained dominated by Fargate work before image pull:

| Region | create -> connectivity | create -> pull start | image pull | create -> task started | task started -> control connected |
| --- | ---: | ---: | ---: | ---: | ---: |
| us-east-1 | 5.984 s | 14.109 s | 9.458 s | 24.204 s | 0.096 s |
| us-west-2 | 5.598 s | 14.221 s | 2.205 s | 16.965 s | 0.488 s |

The west pull was faster than the earlier 3--7-second examples, while the east
pull was slower. One launch pair cannot isolate compression from regional
cache and placement noise. It does show that the smaller zstd image is accepted
by Fargate, while the roughly 14 seconds before either pull began remains the
larger cold-start floor. The load generator observed 626 provisioning holds,
30.287 seconds p99 create latency, and 314 milliseconds p99 from successful
create to `SessionStart` in the cold split.

Scale-down also completed without operator intervention. West began stopping at
07:46:43 UTC, about ten minutes after the split run ended; east began stopping
at 07:50:53 UTC, exactly ten minutes after the later single-relay run ended.
Both ECS tasks stopped with reason `coordinator scale-down` and container exit
code 0, all three staging clusters returned to zero running and pending tasks,
and the load-generator instance was stopped immediately after its artifacts
were copied.

## Historical 0.5-vCPU results

| Players/game | Topology | Practical planning point | Highest clean point sampled | Observed boundary |
| --- | --- | ---: | ---: | --- |
| 2 | one relay | 144 clients | 168 clients, 0.468 cores, 2.36 ms p99 | 192 clients used 0.497 cores and p99 rose to 22.65 ms |
| 2 | two relays | 60 clients/relay (120 total) | 72/relay was borderline: 0, 0, and 1 stalls over three runs, 71–73 ms p99 | 96/relay was overloaded: 80–1,303 stalls and >790 ms p99 |
| 4 | one relay | 112 clients | 128 clients, 0.450 cores, 1.47 ms p99 | No higher point sampled |
| 8 | one relay | 72 clients | 80 clients, 0.426 cores, 1.50 ms p99 | No higher point sampled |

The planning points intentionally leave room for workload variance, platform
noise, larger turns, and operational telemetry. Larger games reach a lower
client count because each incoming turn fans out to more local destinations.

## 1-vCPU, two-player games on one relay

| Clients | Sessions | Median CPU cores | Fan-out p99 | Stalls |
| ---: | ---: | ---: | ---: | ---: |
| 288 | 144 | 0.474 | 1.524 ms | 0 |
| 336 | 168 | 0.558 | 1.706 ms | 0 |
| 384 | 192 | 0.613 | 1.891 ms | 0 |
| 480 | 240 | 0.713 | 2.214 ms | 0 |
| 600 | 300 | 0.895 | 2.501 ms | 0 |

There was no observed latency knee through 600 clients. For planning, 480
clients per 1-vCPU relay is the defensible point from this sweep: it retains
about 29% CPU headroom. Six hundred clients is a demonstrated clean near-ceiling
point, not the recommended steady allocation.

## Historical matched one-relay versus two-relay topology

The fair comparison holds total clients constant. It compares 288 clients on
one relay with 288 clients split as 144 on each of two relays.

| Topology | Clients/relay | Median CPU cores/relay | Aggregate relay cores | Fan-out p99 | Stalls |
| --- | ---: | --- | ---: | ---: | ---: |
| one relay | 288 | 0.474 | 0.474 | 1.524 ms | 0 |
| two relays | 144 | 0.542 east / 0.540 west | 1.082 | 68.882 ms | 0 |

The split topology consumed about 2.28 times the aggregate relay CPU. That is
real work: both relays ingest their local clients, exchange every distinct turn
over the mesh, and deliver all turns to their local clients. Its latency also
includes the inter-region hop, so the p99 values are not a pure CPU comparison.

The authority-balancing coordinator change was tested before and after against
the same already-running relay tasks and the same 288-client split workload.
Median CPU moved from roughly 0.543/0.543 cores to 0.542/0.540 cores. That is
measurement noise, so the change should be credited as a fairness/correctness
improvement, not a demonstrated two-player CPU optimization. Its CPU value may
be more visible for larger rosters, where authority work grows with the number
of slot pairs; that remains to be measured.

## Repeating the baseline

Use the workflow and acceptance rules in [`performance.md`](performance.md).
Keep the workload, topology, task size, architecture, arrival ramp, and relay
image digest fixed; run at least three repetitions per point; and compare
first-to-last cumulative CPU/provider-time deltas alongside p99 latency, stalls,
exact delivery totals, and clean endings. Preserve each load generator JSON
result and the corresponding relay task-stat window so a later comparison is
auditable.
