# AGENTS.md — `relay/src/consensus`

## Map

- `mod.rs` — its `//!` header is the real design write-up (target formula, authority,
  apply horizon). Holds the public constants and the re-exports keeping every public
  path at `consensus::X`. Submodules are private; the `use law::*` / `use ops::*` …
  glob block is what lets each child's `use super::*` keep resolving bare names.
- `law.rs` tuning + `ControlLaw` + RTT/loss/outage windows; `slot.rs` per-slot state
  and connection-epoch types; `sync/` the desync comparator; `registry.rs` the locked
  map, notices, `log_*`. `phase/`, `delivery.rs`, `buffer_law_sim.rs` are elsewhere.
- `maker/` is one `impl DecisionMaker` block per concern — `authority` frames +
  handoff, `connection` ingest + epochs, `buffer` the control law, `leave`,
  `departure`, `start` (roster/shape/region labels/phase), `silence`, `sync`. `ops/`
  mirrors those names with the `&DecisionMakers` free functions.

## Reads like a bug, is deliberate

- **Authority is an injected input**, never derived here — the caller re-injects it
  via `sync`/`set_authority`. A non-authority still ingests everything so promotion
  is instant; it just decides nothing.
- **Decisions apply at a future turn**, horizon scaling with the buffer span. The
  directive is re-stamped on every forwarded turn until the session passes its apply
  frame — that repetition *is* the broadcast, not a retransmit. Ties break by
  `decision_seq` then relay id, matching the client.
- **Loss/outage rebaselining**: counters accumulated across a receive gap are
  excluded, not differenced in, and an outage banks absorption credit expiring on
  wall clock. Tests that "lose" loss are exercising this.
- **Desync needs corroboration** (`SYNC_CORROBORATION_MIN` reporters, a majority)
  and an ordinal waits until the frontier clears a bounds-scaled margin; anomalies
  are rate-limited, so one odd report firing nothing is correct.
- **Synced leaves** schedule from the *departing* slot's last frame, clamped to a
  reachable ceiling so an inflated claim cannot stall survivors. A promoted relay
  re-broadcasts a cached directive verbatim, re-derives the rest.
- **Finalized drops are off** unless the session enables them; finalize seals the
  stamps and fails closed without a cursor.
- **Silence eviction** names the slot that stopped *strictly* earliest, and blocks
  entirely while any required slot is unaccounted for.

**Visibility + tests.** Items private to the old single file are `pub(in crate::consensus)` — exactly their old
reach; use that form when `pub(super)` is too narrow. `tests/mod.rs` holds every shared
fixture and the topic files just `use super::*`; makers run on fixed `Instant`s so the
region-label delay and outage deadlines are stepped, never slept. Run these alone with
`cargo test -p rally-point-relay --lib consensus::tests::`.
