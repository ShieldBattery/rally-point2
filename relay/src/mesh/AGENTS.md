# mesh/

## Who owns what

- `mod.rs` — `MeshState` (the registry bundle every task carries) plus the
  re-exports: everything outside reaches mesh items through `crate::mesh::X`.
- `seen.rs` forward-once gate · `links.rs` link registry, provenance lease, RTT
  cache · `conditions.rs` outgoing sidecar samples · `frames.rs` frame builders ·
  `fan_out.rs` what leaves this relay · `forward.rs` turn delivery both ways ·
  `dispatch.rs` + `dispatch_finalize.rs` what arrives on the peer control stream
  · `join.rs` the Join-time reconcile re-sends.
- `link_run.rs` — `run_mesh_link`'s setup and `select!` skeleton; `link_arms.rs`
  / `link_commands.rs` hold the arm bodies as methods on `LinkDriver` (only that
  loop's locals bundled up), returning `ControlFlow::Break(exit)` where the loop
  used to `break exit`.
- `control/` Join source (coordinator descriptors → Join/Leave) · `edge/` the
  relay↔relay QUIC connection half · `dialer.rs` which peers to dial.

## Easy to break

- One QUIC connection per relay pair, lower id dials. Both directions admit via
  `claim_verified_mesh_link`: verify the datagram floor **before** claiming, or a
  refused connection kills the healthy link on its way out.
- A lease that loses provenance stops mutating shared state mid-frame: ingress
  runs inside `with_current`, awaits inside `await_while_current`.
- Dedup is per session, not per link, and sits above validation — only fanned-out
  turns advance it. `forwarded_count` refuses a sparse-cap-collapsed prefix.
- A Join anchors receive windows from the forward-gate cursors and asks the peer
  to replay from them. `resuming` separates a first join (ask for nothing) from a
  recovery whose slots are all gapped (ask for everything) — both send an empty
  cursor list.
- Every inline reliable-stream write is deadline-bounded; a peer that stops
  reading would otherwise suspend the loop for every session on the pair. The
  unacked-window cap and a full forward queue both reset the link on purpose:
  the redial's reconcile plus resume replay is the recovery.
- The idle timer arms only after a link has served a session; a never-joined link
  must stay parked or the pair never comes back. A cross-tenant session-id
  collision is refused at Join; `Leave` matches the whole `SessionKey`.

## `control/` and `edge/`

- `control/`'s `desired` (coordinator intent) and `joined` (delivered state) maps
  are deliberately separate; every send is re-derived from their diff, so a lost
  command self-heals on the next reconcile instead of needing a retry path.
- `control/apply.rs` is one long method on purpose: authority verdict, maker sync,
  region labels, provisional-turn drain, roster reconcile — reordering changes
  correctness (`gates.reopen` before `sync_maker`; drain after leave-seeding so a
  seeded-departed slot's journaled turns die at the fence).
- `edge/` only establishes the QUIC connection and hands `(peer_id, sender)` to the
  Join source; it never sends `Join`/`Leave` itself. The accept-side handshake
  permit is a process-wide `static Semaphore` held only across the handshake, so
  tests that exercise it must live in a single test function.
- `verify_mesh_peer_identity` is a no-op until the coordinator pushes a fleet map
  unless `require_peer_auth` is set, which fails closed from boot.

## Tests

`cargo test -p rally-point-relay --lib mesh::tests::`. Fixtures in `tests/mod.rs`
(`control_key`, `register_link_channels`, `test_mesh_state`, `joined_state`); real
connections come from `connected_mesh_link[_pair]` in `tests/link_state.rs`. Shrink
a production timing window with a `new_mesh_state_with_*` constructor, don't sleep.
