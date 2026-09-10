# session

## Files

- `mod.rs` — public surface + shared types (`SessionRefs`, `CreatedSession`,
  `CreateOutcome`, `RehomeOutcome`, `MAX_SLOT`). Everything else is a private
  submodule re-exported here, so `crate::session::X` paths never move.
- `setup.rs` — `SessionSetup`: the registries, the per-session maps, and the
  locking discipline every other file relies on.
- `gate.rs` — create fingerprinting + the provisioning gate (warm store, hold cap).
- `create.rs` / `placement.rs` — the create body and where each slot homes.
- `rehome.rs` — failover off a relay, and the resumed-descriptor refresh.
- `descriptor.rs` — building a relay's `SessionDescriptor` from recorded state.

## Easy to break

- `assignment_lock` is the **outermost** lock: create, rehome, drain marks, and
  terminal close all take it, and every fine lock (`session_relays`, registry,
  descriptor outbox, `rehomes`) nests under it. Never take it while holding one
  of those, and never hold it across an await.
- `rehome_inner` re-validates membership *under the `session_relays` lock* after
  picking a replacement. Drop that re-read and a close racing mid-rehome leaves a
  recorded rehome or a resumed descriptor for a dead session.
- A create *peeks* its session id (`candidate_session_id`) for tie-rotation and
  consumes it only after placement succeeds — a failed placement must leave the
  id for the next create. `create_body`'s `debug_assert_eq!` guards that.
- Idempotent replay is keyed `(tenant, external_id)` but gated on a matching
  `CreateFingerprint`: same id + different roster is a conflict, never a replay.
  A new request field that shapes the session must join the fingerprint.
- Re-home compares the relay's **cert fingerprint**, not its enroll generation:
  a generation bump also happens on a benign reconnect, where `Stay` is correct.
- A session's relays must stay inside one finalized-drop capability cohort even
  when the feature switch is off — `capable_cohort` (build class) and
  `finalized_drops` (feature on) are deliberately separate flags.

## Tests

`cargo test -p rally-point-coordinator --lib session::` (89). Fixtures live in
`tests/mod.rs` and reach every topic child through `use super::*;` — add new ones
there instead of duplicating an enroll helper. Hold-cap tests drive the clock
explicitly via `create_or_provision_session_at`, so nothing here sleeps.
