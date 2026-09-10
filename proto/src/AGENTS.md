# AGENTS.md — proto/src

`rally-point-proto` is the frozen contract layer: every `pub` path under
`rally_point_proto::{control, token, control_stream, handshake, mesh, ids,
version, commands, beacon, messages}` is consumed by `transport`, `client`,
`relay`, `coordinator`, the fuzz crate, loadgen, and the external ShieldBattery
game DLL. **No public path may change without updating every consumer.**

## Directory-module convention

`control/`, `token/`, and `control_stream/` are directory modules (`mod.rs` +
siblings), split purely to keep files a readable size — this changed nothing
about the public API. Every submodule is declared private (`mod relay;`, not
`pub mod relay;`) and re-exported with `pub use relay::*;` from `mod.rs`, so
`control::RelayHello` still resolves even though it's physically defined in
`control/relay.rs`. Never make a submodule itself `pub` — that adds a second,
redundant public path that then also can't be broken. A new type goes in the
file that already owns its concern (below), not in `mod.rs`.

## Where things live after the `control/` split

- `relay.rs` — the relay registry: `RelayHello` (phone-home), `RelayEntry`
  (registry record), `RelayEndpoint`/`RelayPeer` (client/mesh-facing views).
- `session.rs` — session setup (`SessionRequest`/`SessionResponse`/
  `SessionDescriptor`) plus the fleet registry data pushed alongside
  descriptors (`MeshPeerIdentity`, `TenantVerifyingKey`, `RegionBeaconTarget`,
  `RegionRttReport`) — config/state, grouped here rather than with the
  message envelopes in `messages.rs`.
- `messages.rs` — the control-connection wire enums, `CoordinatorToRelay` and
  `RelayToCoordinator`, plus `SessionPresence`.
- `notices.rs` — relay-authored per-session event reports (departure, desync,
  result, connect/start) sent as `RelayToCoordinator` payloads.
- `mod.rs` — `TenantId`/`RegionId` (shared by all four) and the local
  `serde_bytes` helper (shared raw-byte serde helper — reference as
  `super::serde_bytes`, don't duplicate it).

`token/` and `control_stream/` are plain `mod.rs` + `tests.rs`, too small to
need further internal splitting.

## Doc links across the split

A bare rustdoc link (`` [`Foo`] ``) only resolves if `Foo` is in scope in that
file. Cross-file references use a path form (`` [`super::Foo`] ``) instead of
an unused `use` added just to satisfy a doc comment — `clippy -D warnings`
flags a dead import.
