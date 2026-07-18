# rally-point-loadgen

Synthetic load harness for the netcode v2 stack: drives many concurrent sessions through a real
coordinator and real relays without running any actual game clients. One process plays every role a
fleet of ShieldBattery app servers + game DLLs would — it creates sessions over the signed tenant
API, dials relays over QUIC with real minted tokens, answers the connection-binding challenge, and
pumps validator-clean turn streams at game cadence — so a single load box can stand in for hundreds
of simultaneous games.

## Why synthetic clients are honest here

The harness links the same `rally-point-client` crate the game DLL links, so everything below the
game simulation is the real production path, not a mock:

- **Session create** — signed `POST /session/create` exactly as the app server sends it
  (`rp2-request-v1` Ed25519 request signature, per-player ephemeral pubkeys, optional per-slot
  regions, `external_id` idempotency).
- **Relay connect** — real QUIC dial with the response's pinned relay cert, token presentation,
  and challenge response (`Identity`), one `LinkDriver` per player.
- **Turn traffic** — datagram turns at the live turn rate through the relay's full ingress path:
  command validation, slot rebinding, dedup, mesh forwarding (for cross-region sessions), and the
  authority's buffer/leave/desync consensus engines all see exactly what they'd see from a game.
- **Sync comparator** — every turn carries a well-formed `0x37` sync command (ring nibble, hash
  kind, `hash16`), derived from a per-session seed so all players agree — the comparator runs hot
  but observes no divergence. A `--desync-fraction` knob perturbs one player's hashes to exercise
  the desync verdict + webhook path deliberately.
- **Session end** — leave intents drain through the relay's coordinated-leave machinery and close
  sessions cleanly, so lifecycle accounting, reaping, and (on a provisioning coordinator)
  idle-relay scale-down run for real.

What is *not* simulated: the BW simulation itself (turn payloads are minimal valid command
streams, not real orders), reconnect/re-home storms (the driver runs without the reconnect layer
in v1), and results reporting. Those don't affect transport-plane load; add them as scenarios only
if a test needs them.

## What a run measures

Per session: create latency (and provisioning holds), time from create to the relay's
`SessionStart` directive (all slots connected), clean-close success. Per turn stream: fan-out
latency (send→receive across players, measured against the process's own clock, correlated by the
turn's frame coordinate), inbound inter-arrival gaps, stall counts. Global: session success/failure
counts by cause, error log. Summary percentiles (p50/p90/p99/max) print at the end; `--json-out`
writes the raw aggregates for comparison across runs.

Relay/coordinator-side numbers (CPU, memory, packets, per-session state) come from the target
processes themselves — Prometheus metrics on the coordinator, OS accounting on the relays — not
from the harness; a load run should record both sides.

## Usage

```
rally-point-loadgen \
  --coordinator-url http://[::1]:14910 \
  --tenant sb-dev \
  --client-key <64-hex Ed25519 seed>       # the tenant's request-signing seed
  --sessions 100                            # total sessions to run
  --arrival-rate 5                          # session creates per second (ramp)
  --players 2                               # players per session
  --game-secs 120                           # how long each session pumps turns
  --turn-rate 24                            # turns per second per player (TR24)
  --turn-bytes 16                           # approximate command payload per turn
  [--slot-regions us-east,us-west]          # per-slot region tags, round-robin → cross-relay mesh
  [--desync-fraction 0.05]                  # fraction of sessions that deliberately diverge
  [--json-out results.json]
```

The client key must be one the coordinator holds the public half of — for a loopback coordinator,
the `--dev-tenant-client-key` seed. Sessions are created with `external_id` values namespaced by a
run id, so a rerun never collides with a live run's idempotency entries.

**Scope guard: this is a dev/loopback/staging tool.** Do not point it at a production coordinator;
staging runs are coordinated with the fleet owner first (they cost real relay-hours and can
scale the fleet up).

## Turn stream shape

Each player's turn is a valid SC:R command stream the relay's validator accepts:

- one 7-byte `0x37` sync command per turn: `[0x37, (ring << 4) | kind, hash_lo, hash_hi, 0, 0, 0]`
  where `ring` starts at 1 and advances `+1 mod 16` per turn, `kind` is 1 on even rings and 2 on
  odd rings, and `hash16` is derived from `(session_seed, ordinal)` so every player in a session
  emits identical hashes (the comparator's happy path). Bytes `[4..7)` are per-sender fog/vision
  data the comparator never reads.
- `0x05` (keepalive) padding to reach `--turn-bytes`, since real turns are mostly small command
  runs and byte size shapes datagram/bundle behavior.
- the turn's `game_frame_count` advances by one per turn — it is the consensus coordinate the
  buffer/leave engines key on and the harness's latency-correlation key.

## Load-testing playbook (the runs that matter)

1. **Single-relay saturation (loopback or one cloud relay):** ramp sessions on one relay until
   turn fan-out p99 degrades; that knee is the per-relay session capacity. Sweep `--players` and
   `--turn-bytes` to see how roster size and payload shift it.
2. **Coordinator create-path throughput:** high `--arrival-rate` with short `--game-secs` — create
   signing/verification, placement, token minting, and lifecycle accounting are the hot path;
   watch create-latency percentiles and the session ceiling / 503 behavior at the configured cap.
3. **Cross-relay mesh:** `--slot-regions` across two+ relays; mesh forwarding, `MeshSeen` dedup,
   and presence now carry the traffic. Compare same-relay vs cross-relay fan-out latency.
4. **Provisioning churn (cloud, coordinated):** arrival ramp against a scale-to-zero fleet —
   measures cold-start holds (`202 provisioning` rates), enroll latency under pressure, and
   scale-down correctness as sessions drain.
5. **Desync/webhook pressure:** `--desync-fraction` at scale proves the comparator + webhook
   pipeline under load, not just in isolation.
6. **Cost:** a sustained cloud run at target concurrency, priced from the fleet's actual
   relay-hours + egress. (Relay egress ≈ players × (players−1) × turn_rate × bytes-on-wire; the
   harness's own numbers give the achieved rates to multiply.)
