# AGENTS.md — `relay/src/consensus`

## Map

- `mod.rs` — its `//!` header is the real design write-up (target formula, authority,
  apply horizon). Holds the public constants and the re-exports keeping every public
  path at `consensus::X`. Submodules are private; the `use law::*` / `use registry::*`
  … glob block is what lets each child's `use super::*` keep resolving bare names.
- `law.rs` tuning + `ControlLaw` + RTT/loss/outage windows; `slot.rs` per-slot state
  and connection-epoch types; `sync/` the desync comparator. `phase/`, `delivery.rs`,
  and `buffer_law_sim/` also live here.
- **Two layers, one vocabulary.** `maker/` is one `impl DecisionMaker` block per
  concern — the pure core. `registry/` is one `impl DecisionMakers` block per the
  *same* concerns — the locked map every caller holds, adding the lock, the log, the
  coordinator notice and the flight event. A registry method carries the maker
  method's name; where they once differed (`slot_homed`/`admits_slot`,
  `slot_departed`/`has_departure`, `session_started`/`is_started`, `record_*`/`note_*`)
  the maker's spelling won, so one grep finds a concept everywhere.
  Files by concern: `authority` (descriptor sync + frames + the desync hook),
  `buffer`, `departure`, `homing`, `leave`, `phase`, `session_start`, `silence`,
  `sync_coverage`; `registry/mod.rs` holds the type itself, the notice builders and
  the `log_*` helpers.
- Policy lives on the maker, not the registry: the registry sequences lock, record
  and notify, and every decision it sequences is a `DecisionMaker` method
  (`seal_for_finalize`/`finish_finalize`, `seed_resumed`, `rehome_homed_slots`,
  `leave_schedulable`, …). A registry method reaching into `maker.<field>` is the
  smell this split exists to remove.

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
- **Desync needs ordered history**: checksum metadata follows each origin's complete
  sequence prefix and retains absolute sync ordinals across promotion. An ordinal
  waits until the frontier clears a bounds-scaled margin; uncertain history excludes
  only that origin, and checksum bookkeeping never gates gameplay forwarding.
- **Synced leaves** schedule from the *departing* slot's last frame, clamped to a
  reachable ceiling so an inflated claim cannot stall survivors. A promoted relay
  re-broadcasts a cached directive verbatim, re-derives the rest.
- **Finalized drops are off** unless the session enables them; finalize seals the
  stamps and fails closed without a cursor.
- **Silence eviction** names the slot that stopped *strictly* earliest, and blocks
  entirely while any required slot is unaccounted for. Only the *verdict* is here
  (`claim_silent_slots`, which also marks what it names); the watch that closes the
  named link is `routing::run_silence_watch`.

## Easy to break

- **This module depends outward on nothing.** It names
  `observability::events` — plain record shapes plus the `FlightEvents` sink trait,
  itself a leaf — and never the recorder, which reaches back into mesh and session.
  Recording goes through `DecisionMakers::record_event`, statically dispatched
  because an event can be emitted from a rare branch of the turn path. Don't
  reintroduce a `crate::routing` / `crate::session` / `crate::mesh` import here:
  actuation belongs to the layer that owns the thing being acted on (the silence
  watch is the worked example), and an operation locking this registry *and*
  another belongs to `session::SessionState`, which owns both (`admit_reconnect`).
- The lock is never held across an `await`, and a notice or flight event is never
  emitted under it — capture under the lock, publish outside.
- The turn path (`observe_turn_frame`, `observe_sync*`, `active_directive`,
  `ingest_*`) must stay allocation-free and single-lock on its common path.
  Returning events or `Vec`s from those to let a caller record them would cost
  exactly what this layer exists to avoid.

**Visibility + tests.** Items private to the old single file are `pub(in crate::consensus)` —
exactly their old reach; use that form when `pub(super)` is too narrow. `tests/mod.rs` holds every
shared fixture and the topic files just `use super::*`; makers run on fixed `Instant`s so the
region-label delay and outage deadlines are stepped, never slept. Run these alone with
`cargo test -p rally-point-relay --lib consensus::tests::`.
