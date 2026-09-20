# coordinator/tests

Integration suites: a real coordinator (`axum::serve` on an ephemeral loopback
port) driven over real WebSocket control connections — no direct handler calls.

- `descriptor_transport/` (directory test target: `main.rs` + topic modules +
  `helpers.rs`) — enroll, hello version/region negotiation, liveness,
  descriptor push (full sets vs. deltas), drain, mesh-peer distribution,
  tenant keys, region beacons/RTTs, split reader/writer concurrency.
- `enroll_identity.rs` — proof-of-possession, duplicate-id/downgrade refusal,
  same-cert reconnect; no ledger (the tokenless dev/loopback path).
- `ledger_enroll.rs` — minted tokens, advertise-set override, cert binding,
  tokenless bound-cert reconnect, retirement.
- `load_state_lineage.rs` — a session's load-record completeness claim turns
  on every serving relay reconnecting under the same `boot_id`.

## common/

`common/mod.rs` (`#![allow(dead_code)]`) holds everything more than one suite
needs:

- `CoordinatorBuilder` — the single coordinator stand-up (`axum::serve` on an
  ephemeral loopback port). Defaults are the dev/loopback posture; a test names
  only what it configures (`with_regions`/`with_ledger`/`with_liveness`/
  `with_hello_timeout`/`with_relays`/`with_relay_hello`/`with_tenant`/
  `with_control_auth`/`with_connect_info`/`with_pending_hello_limit`). Never
  hand-roll a `CoordinatorState` literal or a listener here — a new state field
  should land in one place.
- `with_connect_info` serves the way `main.rs` does, so the handler reads a real
  transport peer; without it `peer_ip` is `None` and a ledger's expected-address
  gate fails closed. `with_pending_hello_limit` shrinks the pending-Hello gate,
  which is otherwise sized for a whole fleet reconnecting.
- the per-relay-id self-signed cert+key cache (`relay_cert`/`relay_key`,
  byte-stable — duplicate-id enroll compares fingerprints), the challenge/proof
  round trip (`prove_identity`), the connect-time-lead readers
  (`expect_tenant_keys`, `expect_region_beacons`, `read_to_descriptors`), the
  registry polls (`wait_for_enrollment`/`wait_for_deregistration`) and the
  refusal readers (`expect_close`, `expect_closed_unserved`).

`descriptor_transport/helpers.rs` is that suite's own fixtures (relay-client
stand-ins, descriptor builders, frame readers), not generic enough for
`common/`; it re-exports the shared `TENANT`/`LIVENESS`/wait helpers so a topic
module's `use crate::helpers::*` still reaches them.

## Timing, flake, running

Enroll/deregister are asserted by polling (~2s bound), not by awaiting a
specific frame, and never by sleeping a guessed interval. Short
`liveness_timeout`/`hello_timeout` are passed per test — don't raise defaults
for convenience. Two tests pin `flavor = "current_thread"`, both because their
argument is that the writer task cannot run between two synchronous calls made
without an await — a property only a single-worker runtime gives. Run one
suite/test with
`cargo test -p rally-point-coordinator --test <suite> [<test_name> -- --exact]`.
