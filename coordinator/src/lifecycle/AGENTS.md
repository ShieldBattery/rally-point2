# lifecycle/

Split by concern, not visibility: the public API is one flat `impl Lifecycle`
spread across these files, so grep by method name, not by file.

- `mod.rs` — module docs, reap graces, `SessionState`/`Inner`/`Lifecycle`, the
  constructor family, and the `abort_timers` / `drain_queue` free helpers.
- `sessions.rs` — one session's facts: register, re-home, departure/result,
  connected/started slots, load state, presence.
- `relays.rs` — control-connection epochs, the empty-roster evidence a beat's
  roster leaves behind, its invalidation, and the metrics census.
- `heartbeat.rs` — `RelayHeartbeat` + `ingest_heartbeat`: the single owner of
  what a relay's beat means (the per-beat wire-shape ceilings, the generation
  fence, the serving-relay filter, and the fan-out to presence / empty-roster
  evidence / load state / backbone RTTs), plus the `RegionRttIngest` view the
  RTT half folds through.
- `close.rs` — `SessionClosed` handling, retirement, both queue pushes.
- `notices.rs` — `SessionNotice` + `ingest_notice`: the single owner of "a relay
  reported X" (authorize the reporter, record the fact, enqueue the webhook),
  and the notice dedup sets the lifecycle holds.
- `reaps.rs` — every arm/fire timer pair plus the re-evaluation entry points.
- `persist.rs` — restart survival: `LifecycleFacts` export/restore for
  `crate::persist`, and the shutdown's bounded webhook drain.
- `tests/mod.rs` — shared fixtures; topic modules beside it.

## Invariants that are easy to break

- `ingest_heartbeat` is the only way a beat enters: it bounds the wire shape,
  fences on the connection's generation, drops the roster entries for sessions
  the relay does not serve, and only then fans out — so a superseded
  connection's beat has no effect at all and a forged entry costs only itself.
  A second ingest path (a replay, a batch endpoint) would re-decide all four.
  Truncating a roster also clears its completeness flag: a suffix the
  coordinator dropped must never read as a session the relay said was absent.
- `ingest_notice` is the only way a reported notice enters: it authorizes the
  reporter against the session's serving set, records the fact, then enqueues the
  webhook, in that order. A new notice kind is a `SessionNotice` variant and an
  arm there — never a second path, which would skip the authorization.
- `sessionClosed` is enqueued only once **every** relay the coordinator assigned
  to serve the session has reported `SessionClosed`. A webhook-only state (no
  serving set) therefore never fires one — deliberate, not a gap.
- The notice queue reserves one slot for the terminal job: an ordinary notice may
  be dropped on overflow (counted in `DROPPED_NOTICE_COUNT`), the terminal one
  never is. Don't let `push_ordinary` fill the last slot.
- Every heartbeat-derived fact is scoped to a relay's control-connection
  generation; a superseded connection must not restore close or empty evidence.
  Enrollment/disconnect/heartbeat serialize on the `relay_epochs` mutex so no
  check can straddle a reconnect.
- Emptiness proof needs *complete, fresh, same-epoch* rosters from all serving
  relays. Silence is unknown, never proof — a stale roster resets the timer.
- Timers: **holdout** (last unaccounted player), **linger** (all accounted, links
  still open), **never-started** (registered, no client ever seen — disarmed when
  `started` flips), **empty-session** (continuous global emptiness, token-guarded
  so a stale task can't consume a re-armed timer's evidence), **webhook-only**
  (idle orphan state, re-armed by each webhook enqueued). A fired timer re-checks
  its condition under the lock; the abort alone is not trusted to win the race.
- A restart restores only what `LifecycleFacts` carries. A new *accumulated*
  fact on `SessionState` (something a relay will not restate on its next beat)
  must join it, with a `serde(default)` reading for records written before it;
  timers and heartbeat evidence stay out — restore re-derives them.
- Close removes the lifecycle state *before* `retire_session` takes membership,
  and create registers *inside* its commit (the `on_commit` hook, under the
  assignment lock, before the replayable idempotency entry). `crate::persist`
  writes only sessions live in both halves and relies on exactly that ordering;
  registering after the create returns lets a concurrent replay hand out tokens
  for a session no capture includes.
- Enrollment records a relay's boot id and runs `on_relay_lineage_break` inside
  one hold of the assignment lock, and persistence captures facts and boot ids
  under one hold too. Split either and a restart can restore an `attestable`
  claim beside the boot id that should have cleared it.
- `pending_webhooks` counts a job up before its push and down after its
  dispatch (or a failed push); a new push path must do the same or a shutdown's
  drain exits early.

## Tests

`cargo test -p rally-point-coordinator --lib lifecycle::`. Graces are injected —
`Lifecycle::with_tunables(setup, LifecycleTunables { .. })`, overriding only the
fields a test cares about and letting `..Default::default()` fill the rest — so
no test sleeps a production window.
