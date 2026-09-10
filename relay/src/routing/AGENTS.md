# routing/

## Map

- `mod.rs` — every capacity/close-code constant, `SessionKey`, `Sessions`, and
  `SlotEntry`/`SlotInbox`: their fields stay private *here* so every submodule
  can touch them without widening. Also the re-exports keeping `routing::X`
  paths stable.
- `forward.rs` one slot's queue + its resident-byte count; `registry.rs`
  register/deregister and roster snapshots; `fan_out.rs` one thing to many
  slots; `lifecycle.rs` session start, presence announce, close signals,
  refused/provisional teardown.
- `slot_link/` — `run_slot_link`: `mod.rs` has the setup, `SlotLinkCtx` and the
  `select!` skeleton; `setup.rs`/`inbound.rs`/`control.rs`/`pushes.rs`/
  `maintenance.rs`/`teardown.rs` one arm or phase each.
- `departure.rs`, `drops.rs`, `close.rs` — who left, who decides it, and what
  this relay tears down once its last local slot is gone.

## Easy to break

- Fan-out delivers the instant a turn validates. Never buffer, reorder, or wait.
- A slot's queue is bounded by payload *count* and by resident *bytes*.
  Crossing either does not drop the turn: it signals that slot to disconnect and
  leaves it on the roster until its own task exits. Nothing may pull a roster
  entry from under a live task, or a reconnect seats a second sender for a slot.
- Close codes are meaningful diagnostics: `0x01` invalid turn, `0x04` isolated
  (queue or unacked window), `0x05` leave processed, `0x07` control stream lost,
  `0x09` insane resume anchor, `0x0A` provisional window expired, `0x0D` silent
  slot. Don't collapse them.
- A resume anchor is an unvalidated client value about to become window state:
  over `MAX_SANE_RESUME_ANCHOR` it is refused; merely past this relay's
  forwarded prefix it is only logged (a lagging re-home is legitimate).
- The control stream is the only path for `RequestDrop` and a clean leave, so
  its reader ending closes the connection rather than limping on.
- A *drop* is only ever held; an honored `RequestDrop` (or the abandon timer)
  decides it, and in finalized-drop sessions only the slot's home may seal the
  count. A *clean leave* decides immediately, at the home.

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
real waits. `relay/tests/client_edge/` drives `run_slot_link` end to end.
