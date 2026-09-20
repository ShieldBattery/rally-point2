# session/ — per-session relay state

Each store is keyed by `crate::key::SessionKey` (tenant + session), local to
this relay, and lives only as long as it locally serves the session (see each
module's teardown).

## File map

- `state/` — `SessionState`, the bundle of every store below plus the
  decision-makers and the load fence, and `Tunables`, the windows and ceilings
  it is built with (`Default` = production). The per-session tasks carry one
  bundle rather than a dozen registries. It also owns the three teardown
  phases — `remove_slot` (one slot's link ended), `close_emptied` (the last
  local slot went) and `retire` (the descriptor was retired) — so a new store
  is added to the bundle and to its sweep in one place, not at three call
  sites. `retire` is terminal and sweeps everything, side channels included:
  a session retired with members still connected never reaches
  `close_emptied` (its gate refuses the later teardowns), so nothing else
  would.
- `presence.rs` — own + peer live-player counts and the buffer-authority
  verdict (first still-live relay in the coordinator's priority order).
- `side_channel/` — the reliable non-turn traffic members exchange over their
  control streams. **One registry with three replay policies**, not three
  modules: `SideChannel<R>` owns the per-member push channels, the
  register/deregister/end-session lifecycle, the `admit` gate (size cap +
  `TokenBucket`) and the author-skipping `deliver`; `R: ReplayPolicy` is the
  only axis the three differ on, and `SideChannels` is the bundle
  `SessionState` holds, because all three are always used in lockstep. The
  three configured rows — every cap, with its reasoning — are `LOBBY`, `CHAT`
  and `SKIN` in `side_channel/channels.rs`; a fourth kind of side traffic is a
  row there plus a field on `SideChannels`, not a new module. The policies
  live in `side_channel/replay.rs`:
  - `OrderedLog` (**lobby**) — every command in arrival order, replayed whole
    to a late joiner, because setup can predate a member's dial and a missed
    setup command leaves its pre-game state permanently incomplete. Bounded by
    message count *and* payload bytes; past either, the overflow latch refuses
    so a late joiner replays a truncated but consistent prefix.
  - `NoReplay` (**chat**) — nothing is retained; a member whose stream comes
    up late simply missed what was said. Also the one policy that never
    creates per-session state on delivery alone.
  - `LatestPerSlot` (**skins**) — one-shot state, not events: a slot's re-send
    *replaces* its entry, and a late joiner replays only the newest message per
    slot, unordered. Bounded by distinct authoring slots; a slot already in the
    map is always admitted.
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
  removal, the `TokenBucket` cap on manual `RequestDrop`s, and the
  abandoned-session force-decide timer. A hold is a marker, not a timer.
- `turn_ring/` — bounded per-session record of forwarded turns for reconnect
  replay: count bound (sized to the drop-unlock window at live slot count)
  and byte bound (oversize-turn spray backstop), drop-oldest on either.
  **Local and ephemeral** — a resume replay only needs what this relay
  delivered.

## Easy to break

- **Both `close_emptied` and `retire` sweep the side channels.** The emptied
  close is the ordinary path, but a session retired while local slots are
  still connected never reaches it (each slot's later teardown is refused by
  the gate retirement just shut), so retirement is their only remaining
  sweep. Dropping either call leaks that session's lobby log, chat state and
  skin map for the relay's lifetime.
- **A side channel's `register_member` and `deliver` share one lock on
  purpose.** That is the whole exactly-once guarantee across the replay/live
  boundary. Snapshotting the retained state outside the lock that inserts the
  member's sender would let a concurrent delivery be both replayed and fanned
  live, or neither.
- **The fan-out is `try_send` and must stay non-blocking.** A full receiver is
  dropped with a warning, never awaited: one hopelessly behind member must not
  stall the fan-out to every other member, and the registry lock is held
  across it.
- **`admit` belongs to the client edge alone.** A mesh-received message has
  already passed its origin relay's `admit`; re-checking it here would
  re-penalize it against a second, independent bucket keyed on the same slot.
- **`deliver`'s bool is the mesh-forward cue.** A message the local policy
  refused was never retained or fanned to local members, so forwarding a copy
  across the mesh anyway would leave peers holding state this relay's own
  members never will.

## Tests

`cargo test -p rally-point-relay --lib session::` — each split module's tests
live in a sibling `tests.rs` or `tests/`.

`side_channel/tests/` is split the way the type is: `shared.rs` holds the
bodies every channel owes — author exclusion, the member lifecycle, the size
and rate caps — written once, generic over a `Probe`, and instantiated for
every row the guarantee applies to; `ordered_log.rs`, `no_replay.rs` and
`latest_per_slot.rs` hold what belongs to exactly one policy. A guarantee all
three owe goes in `shared.rs`, never three times.
