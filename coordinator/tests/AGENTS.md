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

`common/mod.rs` (`#![allow(dead_code)]`): a per-relay-id self-signed cert+key
cache (`relay_cert`/`relay_key`, byte-stable — duplicate-id enroll compares
fingerprints), the challenge/proof round trip (`prove_identity`), and readers
for the connect-time lead (`expect_tenant_keys`, `expect_region_beacons`,
`read_to_descriptors`). `descriptor_transport/helpers.rs` is that suite's own
fixtures, not generic enough for `common/`.

## Timing, flake, running

Enroll/deregister are asserted by polling (~2s bound), not by awaiting a
specific frame. Short `liveness_timeout`/`hello_timeout` are passed per test —
don't raise defaults for convenience. One test pins `flavor = "current_thread"`
for a no-await-between-sends coalescing check. Run one suite/test with
`cargo test -p rally-point-coordinator --test <suite> [<test_name> -- --exact]`.
