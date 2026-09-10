# session/ — per-session relay state

Each store is keyed by `SessionKey` (tenant + session), local to this relay,
and lives only as long as it locally serves the session (see each module's
teardown).

## File map

- `presence.rs` — own + peer live-player counts and the buffer-authority
  verdict (first still-live relay in the coordinator's priority order).
- `lobby.rs` — pre-game `LobbyCommand` fan-out **plus an ordered replay log**
  (setup can predate a late dial). Caps: `LOBBY_LOG_MAX_COMMANDS`/`_BYTES` +
  `TokenBucket`.
- `chat.rs` — mid-game `GameChat` fan-out, **no log** (a missed message is
  simply missed). Caps: `CHAT_TEXT_MAX_BYTES` + `TokenBucket`.
- `skin.rs` — cosmetic `PlayerSkin` fan-out via a **latest-blob-per-slot map**
  (one-shot state; a re-send replaces, a late joiner gets only the newest).
  Caps: `SKIN_BLOB_MAX_BYTES` + `TokenBucket`.
- `gate.rs` — `SessionGates`, the terminal ingress boundary every
  session-scoped path (dial, turn funnel, mesh dispatch, flight-recorder
  create-on-first-touch) runs through: `with_ingress` refuses once `retire`
  marks the session, and `retire` drains in-flight ingress first, closing
  check-then-mutate races. Lock order: gate then registry, never reversed.
- `provisional.rs` — admit-first bookkeeping for a client dial that beat its
  descriptor; deadline on the mark, reaped by `run_sweep` if no descriptor
  claims the session. Sweep arms only on a coordinator-driven relay with a
  live control connection.
- `provisional_turns/` — pre-descriptor ingress **journal** (turns +
  departures) for a session with no maker yet: Gathering → Draining →
  Resolved. Nothing is deleted while undrained; only descriptor retirement
  discards it. Fail-closed ceilings: per-session, aggregate byte, session count.
- `drop_hold/` — indefinite holds on a *dropped* (not cleanly left) slot's
  removal, the `RequestBucket` cap on manual `RequestDrop`s, and the
  abandoned-session force-decide timer. A hold is a marker, not a timer.
- `turn_ring/` — bounded per-session record of forwarded turns for reconnect
  replay: count bound (sized to the drop-unlock window at live slot count)
  and byte bound (oversize-turn spray backstop), drop-oldest on either.
  **Local and ephemeral** — a resume replay only needs what this relay
  delivered.

## Tests

`cargo test -p rally-point-relay --lib session::` — each split module's tests
live in a sibling `tests.rs` or `tests/`.
