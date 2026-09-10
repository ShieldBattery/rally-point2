# api/

`mod.rs` owns the shared state, the timeouts and `router()`; siblings are private.
Public paths (`api::CoordinatorState`, `router`, `ControlAuth`,
`resolve_control_auth`, `HELLO_TIMEOUT`, `LIVENESS_TIMEOUT`) are used by
`main.rs`, `coordinator/tests/` and `relay/tests/` — keep them at `api::`.

## Which file owns what

- `sessions.rs` create / rehome / alive · `load_state.rs` the attested load read
- `queries.rs` presence, flight blob reads, warm, pubkey, regions
- `request_auth.rs` bearer check + tenant request signatures
- `control.rs` the endpoint, the enroll handshake, and the per-connection types
  (`ControlInbound`, `WriterSources`) both halves are driven from
- `control_hello.rs` pre-enroll reads · `control_writer.rs` send half
- `control_inbound.rs` read half + frame dispatch · `control_flight.rs` upload
  grants and load-state snapshots (reader work done off the read loop)

## Easy to break

- Enroll order is load-bearing: pending-Hello permit → Hello → version negotiate
  → region check → proof-of-possession → **drop the permit** → ledger → registry.
  The permit covers only the unauthenticated window; moving the drop changes what
  the gate actually bounds.
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
(`state_with_relay_and_tenant`, `signed_post`, `note_inbound_frame`). Shorten
`hello_timeout`/`liveness_timeout` on the state rather than sleeping.
