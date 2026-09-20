# transport/src

The `//!` header of `lib.rs` is the design write-up (why this is deliberately not a
reliable-ordered protocol). Read it before touching `ack_manager/` or `link/`.

## File map

- `ack_manager/` — `mod.rs` the struct + anchors and the re-exports; `send.rs` packing
  and re-carry (`build_outgoing`, `record_sent`, `reinject_unacked`); `recv.rs` ack
  intake and retirement; `policy.rs` `RecarryPolicy`/`CarrySpacing`; `history.rs` the
  received-packet ack bitfield; `sent.rs` sent-packet bookkeeping, the datagram budget
  and `AckError`.
- `link/` — `mod.rs` the `Link` over a QUIC connection; `dedup.rs` per-slot dedup and
  the fresh-payload filter.
- `mesh_link/` — `mod.rs` the per-pair mesh link and its sizing; `session_link.rs` the
  per-session view; `error.rs`, `sizing.rs`.
- `recarry_sim/` — test-only simulator (`model.rs` network + loss models,
  `scenarios.rs` the fade/burst/blackout cases). Its comparison-table dump is
  `#[ignore]`d: `cargo test -p rally-point-transport recarry_sim -- --ignored --nocapture`.
- `quic/`, `control.rs`, `mesh_control_stream.rs`, `control_framing.rs` (the length-prefix
  frame reader both control streams share), `beacon.rs`, `sequence_buffer.rs` — single files.

## Rules

- Every `pub` item keeps its original path (`rally_point_transport::ack_manager::X`
  etc.) via `pub use` from each `mod.rs`; submodules stay private. `client`, `relay`,
  `loadgen` and the benches depend on those paths and must be updated together with
  any move. The game DLL reaches only `Link` and the `rustls` re-export, so those two
  are the paths that cannot move at all.
- A `Packet` seq is an ack handle, not an ordering key; `recv` returns one packet's
  new payloads in arrival order. Anything that looks like reordering, retransmit on
  timeout, or head-of-line blocking is a regression, not a fix.
- `GUARANTEED_DATAGRAM_BUDGET` is the outer datagram floor every link type derives
  its admission number from; a payload that cannot fit is diverted to the reliable
  control stream by the layer above, never fragmented here.

## Tests

`cargo test -p rally-point-transport` (84 + 1 ignored). Module tests sit in
`<module>/tests/` with shared fixtures in `tests/mod.rs`. The self-signed
certificate, the loopback QUIC pair on either ALPN, and the turn builder come
from `test_util` — never re-rolled per module; extend it instead.
