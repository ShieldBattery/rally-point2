# server/ — the client-facing edge

The `C–S–C` path: accept QUIC connections, dispatch mesh peers by ALPN,
authorize each client, and hand an admitted one to `routing::run_slot_link`.

## File map

- `mod.rs` — the endpoint binds (the primary port, plus any extra ports such
  as 443; only the primary's bind is fatal), one accept loop per endpoint
  sharing a single admission semaphore (acquired **before** the TLS
  handshake, so the cap bounds in-flight handshakes including TLS, relay-wide
  however many ports there are), the ALPN dispatch, `ConnError`, and
  `serve_connection`: the ordered gate list, written top to bottom.
- `admission.rs` — the refusal pipeline: the `Refusal` table (each row pairs a
  close code, a reason phrase, a `ConnError` kind and the rollback it owes),
  the pre-register gate predicates, and the `Admission` guard that owns the
  connection, the roster seat and the rollback rule.

## Easy to break

- **The gate order is load-bearing.** `PRE_REGISTER_GATES` runs in list order
  and `serve_connection` runs the rest in written order. Two in particular are
  not free to move: the handshake ack is written *before* any hold or
  departure state is touched (a client that reads `HANDSHAKE_OK` treats the
  link as up, and `admit_reconnect` mutates state a refused connection must
  never have changed), and the journal seal is re-checked *after* registration
  succeeds (registration succeeding is what proves the old link's seal was
  already installed).
- **A refused admission leaves no per-session scaffolding.** That is the whole
  reason refusals go through `Admission::refuse` instead of being written out
  at each gate. Adding a gate means picking its `Rollback`, not remembering to
  copy a cleanup block.
- **`Rollback::RetirementOwnsIt` is not an oversight.** A refusal caused by the
  session's retirement deliberately skips `abandon_refused_admission`:
  retirement's own sweep owns that state, and the gate tombstone already makes
  the rollback a no-op (`SessionGates::discard_if` refuses a retired gate
  without running its ownership check).
- **Managed admission requires a descriptor.** Startup enables descriptor waiting
  before accepting clients. Both client protocols share the same authorization
  deadline and handshake permit while waiting; standalone relays keep
  descriptor-less admission. Required evidence is checked before registration
  or handshake acknowledgement. Cached descriptors proceed immediately; a
  missing descriptor waits only within the remaining authorization deadline.
  Retirement wakes that wait promptly. Production leaves provisional admission
  disarmed; library callers can explicitly opt into it.
- **Close codes are a wire contract.** They live in `proto::close_codes`, one
  table for the whole 0x01–0x11 space, and a client reads them as its only
  diagnosis. Never reuse a retired number, and never collapse two causes onto
  one code.

## Tests

`cargo test -p rally-point-relay --lib server::` for the gate and rollback
tables in `admission/tests.rs`; the end-to-end close codes over real QUIC are
`relay/tests/client_edge/auth.rs`.
