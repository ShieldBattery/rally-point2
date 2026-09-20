# api/

`mod.rs` owns the shared state, the timeouts and `router()`; siblings are private.
Public paths (`api::CoordinatorState`, `router`, `ControlAuth`,
`resolve_control_auth`, `HELLO_TIMEOUT`, `LIVENESS_TIMEOUT`) are used by
`main.rs`, `coordinator/tests/` and `relay/tests/` — keep them at `api::`.

## Which file owns what

- `sessions.rs` create / rehome / alive · `load_state.rs` the attested load read
- `queries.rs` presence, flight blob reads, warm, pubkey, regions
- `request_auth.rs` bearer check + tenant request signatures
- `control.rs` the endpoint, the socket loop that drives the enroll handshake,
  and the socket/channel types both halves share (`ControlRead`,
  `ControlWrite`, `DrainSend`)
- `control_enroll.rs` the enroll sequence itself as a typed state machine
  (`EnrollHandshake` / `EnrollStep`), plus the pending-Hello gate's size and the
  close code a saturated gate sends
- `control_hello.rs` the socket reads the sequence is fed from: the opening
  `Hello`, then every later frame · `control_writer.rs` send half, and the
  `WriterSources` it draws from
- `control_inbound.rs` read half + frame dispatch, the `ControlInbound` inputs
  they run over, and the drain mark · `control_flight.rs` upload grants and
  load-state snapshots (reader work done off the read loop)

What an inbound frame *means* belongs to the module that owns the state it
lands in: a heartbeat is decoded here and handed to
`Lifecycle::ingest_heartbeat` (the per-beat ceilings, the generation fence, the
serving-relay filter and the five-way fan-out), and a per-session notice to
`Lifecycle::ingest_notice` (the reporter authorization, the accounting, the
webhook). This layer decodes and calls once; it decides none of it.

## Easy to break

- Enroll order is load-bearing: pending-Hello permit → Hello → version negotiate
  → region check → proof-of-possession → **drop the permit** → ledger → registry.
  The permit covers only the unauthenticated window; moving the drop changes what
  the gate actually bounds. `EnrollHandshake` is that order — its stage picks
  which step a frame drives, every refusal is decided (and logged) there, and
  `control.rs` only sends what it returns. It names no axum/tungstenite type and
  never awaits, so `tests/control_enroll.rs` walks the whole sequence, and each
  refusal point, without a socket; assert where the permit is still held.
- `peer_ip` arrives only when the server was built with
  `into_make_service_with_connect_info`. In-process TLS keeps the real peer
  visible; behind an L7 proxy a ledger's expected-address check would compare
  garbage. `OptionalPeerAddr` never rejects, so `oneshot` tests read `None`.
- Every send lives on the writer. A `Draining` frame marks the registry on the
  reader, then hands the *set-then-ack* to the writer over a channel — that
  ordering is the contract. Reap nudges coalesce per `(tenant, session)` keeping
  the **last** (each carries the merged-so-far union).
- Flight uploads are request → grant (presigned, spawned off the read loop) →
  `done`. Grants are reader-local and swept opportunistically, never by a timer.
- A tenant request signature covers `rp2-request-v1:<ts>:<METHOD>:<path>:<body>`,
  ±5 min, no nonce. `verify_tenant_request` takes a required `TenantAccess` so a
  new endpoint cannot skip the suspended/revoked gate.

## Tests

`cargo test -p rally-point-coordinator --lib api::`; fixtures in `tests/mod.rs`
(`state_with_relay_and_tenant`, `signed_post`, `note_inbound_frame`).
`tests/notices.rs` is the reporter-authorization boundary suite: a new notice
kind joins its table. Build a
state from `CoordinatorState::new(setup, auth)` and override only what the test
configures — never a full literal, so a new field lands in one place. Shorten
`hello_timeout`/`liveness_timeout`/`attest_timeout` on the state rather than
sleeping.
