# CLAUDE.md

`rally-point2` is the all-Rust netcode v2 platform for ShieldBattery: the portable
client, the shared per-link transport layer, the validating relay + mesh, and the
multi-tenant coordinator. It replaces the Node.js `rally-point`.

## Where the design lives

The authoritative design — sequenced phases plus the load-bearing decisions
`D1`–`D11` — is `../shieldbattery/netcode-v2-build-plan.md`; the game-seam detail
is `../shieldbattery/scr-netcode-replacement-guide.md`. If code and those docs
disagree, the docs win unless you're deliberately changing a decision (then update
the plan in the same change). SC:R glue and UI live in `../shieldbattery/`
(`game/`, `server/`, `app/`), not here.

## Crates

- `proto` — the frozen contracts: wire framing, control-plane messages, tokens,
  protocol version + negotiation, SC:R command table. Anything that crosses a
  component boundary is defined here *first*.
- `transport` — per-link reliable delivery over unreliable QUIC datagrams (ack +
  redundancy + sequence buffer), shared by `client` and `relay` (one per link).
  Ported from `shieldbattery/game/src/netcode/`.
- `client` — portable client endpoint linked into `shieldbattery/game/`; runs
  `transport` for its home-relay link.
- `relay`, `coordinator` — `lib.rs` (logic) + thin `main.rs` (arg parsing + wiring).
- `infra/` — Fargate / region-beacon IaC (Phase 5). Not a crate; excluded from the workspace.

## Commands

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings   # CI enforces; keep it clean
cargo fmt --all
cargo run -p rally-point-relay -- --help                # relay/coordinator are runnable skeletons
```

## Conventions

- **Errors:** `thiserror` for library error types; `color-eyre` for binary `main`s.
- **Logging/metrics:** `tracing`, correlated by `tenant / session / slot / turn` (`D8`).
- **Deps:** declare once in `[workspace.dependencies]`, reference `{ workspace = true }`.
- **Code comments stand alone:** don't cite the build plan, phases, decision IDs
  (`D1`–`D11`), or doc sections (`§N`) in code or doc comments. State the *what*
  and *why* directly so the comment is self-contained for a reader who has never
  seen the plan. Such cross-references belong in the plan, not the source.

## Gotchas (will bite you)

- QUIC is **quinn + rustls + ring**, not the default aws-lc-rs — pinned to avoid a
  C/NASM toolchain on the 32-bit Windows build. Don't revert the backend.
- `client` must build for `i686-pc-windows-msvc` (linked into the 32-bit game DLL),
  so keep it portable and `unsafe`-free. CI has a dedicated job for it.
- `unsafe` is denied workspace-wide; the hot-path FFI and the BW-thread ⇄
  Tokio-thread handoff (`D1`) live in `shieldbattery/game/`, not here.
- `Cargo.lock` is committed and CI builds `--locked` — commit it when deps change.
- The datagram wire format is **protobuf**, generated from `proto/proto/wire.proto`
  by `protox` (pure-Rust, no `protoc` needed) in `proto/build.rs`. Edit the
  `.proto` and rebuild; never edit generated code. Protobuf is only the envelope
  — the SC:R command bytes inside a payload are still hand-validated (`D10`).

## Architectural invariants (not visible from the types)

Full detail in build plan §0 + §4. The ones easy to break by accident:

- Consensus runs on the relay/mesh, not the coordinator (`D9`), keyed on
  `game_frame_count`. Nothing on the per-turn path blocks on the coordinator —
  running games survive a coordinator outage.
- The relay validates turns and strips client-originated control commands (`D10`);
  its command parser is attacker-facing and gets fuzzed.
- Forward recovery is app-level, not QUIC's (§4): redundancy + ack bitfield over
  unreliable datagrams, one QUIC connection per relay-pair, no 0-RTT.
- Failover / partition / coordinator-outage responses are coordinated, never
  per-client (`D11`).
- We **replace** Storm's UDP transport, we don't tunnel it. The game hooks at the
  turn/command layer (`send_turn_message` / `storm_receive_turns`), so Storm's
  12-byte UDP header (Seq1/Seq2/CLS/PlayerID/resend/checksum) sits *below* our seam
  and is removed — `Packet` + QUIC own sequencing, acks, integrity, and recovery.
  Don't reintroduce Storm framing on the wire (that was the old double-reliability
  overhead). Transport identity is a per-link `seq` (Storm's own model), not a game
  frame; the D9 consensus coordinate is a separate, later concern.
