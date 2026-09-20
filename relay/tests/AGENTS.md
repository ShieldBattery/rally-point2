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
is never auto-discovered — so every target pulls it in by path
(`#[path = "../common/mod.rs"] mod common;`, or `"common/mod.rs"` from a
single-file test). It is `#![allow(dead_code)]` on purpose: every binary uses a
different subset of it.

`common` owns anything more than one target wants: the tenant/token/handshake
fixtures, `Relay` (a serving relay plus the mesh-accept channel its ALPN
dispatch feeds, taken once via `mesh_accept_rx()`), `connect_client`,
`seed_authority` (the decision-maker seeding a lone relay needs before it
decides anything), `descriptor` (struct-update base for a `SessionDescriptor`),
`build_turn`, `recv_meaningful`, and the polling waits. Per-suite `helpers.rs`
holds only what that suite alone uses and re-exports `common`, so topic modules
only ever `use crate::helpers::*;` — `client_edge` keeps `TestRelay` (one client
endpoint dialing many slots, plus resume cursors), `mesh_edge` the raw-link
spawners and lobby/chat/skin readers, `mesh_edge_connection` the production dial
and accept wiring (`dial_to`/`spawn_dial`/`dial_a_to_b`, `accept_on`).

## Timing

Real loopback QUIC, self-signed certs, real time — no `tokio::time::pause`.
Never sleep a guess: poll the observable instead — `wait_until(what, cond)` for
anything else, `wait_for_mesh_link` once a driver's Join must have landed,
`wait_for_slots` once a client must be routable, `wait_for_connectivity(..,
false)` to observe a drop. `wait_for` in `mesh_edge_connection` is the same
shape returning a `Result` for the `?` tests. Read control frames through
`recv_meaningful`, which skips the `SlotConnectivity` frames every register and
disconnect fans (asserting on the next frame directly is the usual flake).

A *negative* claim is the one thing a poll cannot make, so those keep a short
fixed window (~100ms on loopback) and say in a comment why that is long enough.
`spawn_mesh_link` uses the production 60s `mesh::IDLE_TIMEOUT`; only the
idle-teardown tests override it via `spawn_mesh_link_timed`.

Run one suite with `cargo test -p rally-point-relay --test client_edge`; append
a test name (module-qualified, e.g. `leaves::`) to run one test.
