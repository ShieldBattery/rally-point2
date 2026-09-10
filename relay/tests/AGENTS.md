# AGENTS.md — relay integration tests

The three big suites are directory targets (`<name>/main.rs`, auto-discovered).

- `client_edge` — one relay, hand-driven clients. This suite *is* the executable
  spec for the handshake wire shape (`u16`-LE token, 32-byte challenge, 64-byte
  response, resume-cursor frame, one ack byte); change it only with `proto`.
- `mesh_edge` — what flows once two relays are meshed. Most tests feed a raw
  `MeshLink` pair straight into `run_mesh_link`, skipping the hello dance.
- `mesh_edge_connection` — the connection half: who dials, redial, retarget,
  peer-certificate enforcement on accept.

## Shared fixtures

`common/mod.rs` is *not* a test target — a `tests/common/` holding only `mod.rs`
is never auto-discovered — so each suite pulls it in with
`#[path = "../common/mod.rs"] mod common;`. It is `#![allow(dead_code)]` on
purpose: every binary uses a different subset of it.

Per-suite `helpers.rs` holds the rest and re-exports what it needs from
`common`, so topic modules only ever `use crate::helpers::*;`. Both mesh suites
wrap `common::handshake`/`make_tenant`/`registry_for` in shorter signatures, and
each has its own `Relay` (the mesh-accept channel field differs) — deliberately
not shared. `wait_until` differs between `client_edge` (deadline + panic
message) and `mesh_edge_connection` (bounded poll returning `bool`): same name,
different helper.

## Timing

Real loopback QUIC, self-signed certs, real time — no `tokio::time::pause`.
Poll with `wait_until` rather than sleeping, and read control frames through
`recv_meaningful` / `next_non_connectivity`, which skip the `SlotConnectivity`
frames every register and disconnect fans (asserting on the next frame directly
is the usual flake). `spawn_mesh_link` uses the production 60s
`mesh::IDLE_TIMEOUT`; only the idle-teardown test overrides it via
`spawn_mesh_link_timed`. Tests that must observe a drop first synchronize on
`wait_for_connectivity(.., false)`.

Run one suite with `cargo test -p rally-point-relay --test client_edge`; append
a test name (module-qualified now, e.g. `leaves::`) to run one test.
