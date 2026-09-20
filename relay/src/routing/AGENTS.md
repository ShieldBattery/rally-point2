# routing/

## Map

- `mod.rs` — every capacity constant, `Sessions`, and `SlotEntry`/`SlotInbox`:
  their fields stay private *here* so every submodule can touch them without
  widening. Also the re-exports keeping `routing::X` paths stable. The session
  identity itself is `crate::key::SessionKey` — every per-session store in the
  relay is keyed by it, so it belongs to none of them.
- `forward.rs` one slot's queue + its resident-byte count; `registry.rs`
  register/deregister and roster snapshots; `fan_out.rs` one thing to many
  slots; `lifecycle.rs` session start, presence announce, close signals,
  refused/provisional teardown.
- `slot_link/` — `run_slot_link`: `mod.rs` has the setup, `SlotLinkCtx` and the
  `select!` skeleton; `setup.rs`/`inbound.rs`/`control.rs`/`pushes.rs`/
  `maintenance.rs`/`teardown.rs` one arm or phase each.
- `departure.rs`, `drops.rs`, `close.rs` — who left, who decides it, and what
  this relay tears down once its last local slot is gone.
- `silence.rs` — the relay-wide silent-slot watch: a timer that takes each
  session's verdict from the decision-makers (`claim_silent_slots`) and closes
  the named slot's link. The verdict is consensus's and stays there; the
  actuation is here, behind a `SilenceCloser` the roster implements, so the
  loop is testable with a fake closer.

## Easy to break

- Fan-out delivers the instant a turn validates. Never buffer, reorder, or wait.
- A slot's queue is bounded by payload *count* and by resident *bytes*.
  Crossing either does not drop the turn: it signals that slot to disconnect and
  leaves it on the roster until its own task exits. Nothing may pull a roster
  entry from under a live task, or a reconnect seats a second sender for a slot.
- Close codes are meaningful diagnostics — a client's only account of why its
  link died. The whole table, both directions, lives in
  `rally_point_proto::close_codes` with a doc comment per cause; add new ones
  there rather than defining a number here. Don't collapse two causes onto one
  code, and don't reuse a retired number.
- A resume anchor is an unvalidated client value about to become window state:
  over `MAX_SANE_RESUME_ANCHOR` it is refused; merely past this relay's
  forwarded prefix it is only logged (a lagging re-home is legitimate).
- The control stream is the only path for `RequestDrop` and a clean leave, so
  its reader ending closes the connection rather than limping on.
- A *drop* is only ever held; an honored `RequestDrop` (or the abandon timer)
  decides it, and in finalized-drop sessions only the slot's home may seal the
  count. A *clean leave* decides immediately, at the home.
- A slot the silence watch named is already marked evicted by the claim that
  named it, so the close is owed exactly once — don't re-derive the verdict
  here, and don't let a failed close silently un-name it.

## Slot-link context

`SlotLinkCtx` holds the session identity, the registries, both send streams and
the loop's small state (`acks_owed`, deadlines, `leave_announced`). `link` and
every receiver stay outside it — the `select!` futures borrow those while an arm
holds `&mut` on the context. Arms return `ControlFlow`; `Break` means
`break 'serve`. Keep arm order and the `, if …_alive` guards as they are.

## Tests

`cargo test -p rally-point-relay --lib routing::`. Fixtures and the drop-hold /
abandoned-session harnesses live in `tests/mod.rs`; `TINY_ABANDON`,
`IMMEDIATE_UNLOCK` and `UNREACHABLE_UNLOCK` make those windows drivable without
real waits, and a test that still has to outlast one runs under
`#[tokio::test(start_paused = true)]`, where a sleep past the deadline costs
no real time. Read a registered slot through `SlotInbox`'s accessors rather
than its private fields, so the in-module tests and the cross-module ones
share one path. `relay/tests/client_edge/` drives `run_slot_link` end to end.
