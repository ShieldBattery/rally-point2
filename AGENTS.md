# AGENTS.md

`rally-point2` is the all-Rust netcode v2 platform for ShieldBattery: the portable
client transport, the shared per-link transport layer, the validating relay + mesh,
and the multi-tenant coordinator. It replaces the Node.js `rally-point`.

## Where the design lives

[`docs/architecture.md`](docs/architecture.md) is the design reference: how and *why*
the data plane, mesh, and control plane are shaped the way they are, ending in a
**"Settled decisions (do not re-chase)"** section that records closed choices with
their reasoning. Consult it before proposing a design change or "fixing" behavior
that looks wrong — many deliberate choices here read as bugs to a standard-protocol
eye. (An older build plan with numbered decisions `D1`–`D11` has been retired into
this doc; treat any surviving reference to it as historical.)

The SC:R game hooks, UI, and app server live in `../shieldbattery/` — the game-side
integration of these crates is `../shieldbattery/game/src/netcode_v2/`.

## Crates

- `proto` — the frozen contracts: wire framing, control-plane messages, tokens,
  protocol version + negotiation, SC:R command table. Anything that crosses a
  component boundary is defined here *first*.
- `transport` — per-link delivery over unreliable QUIC datagrams (ack + redundancy +
  sequence buffer), shared by `client` and `relay` (one per link).
- `client` — portable client endpoint linked into the game DLL.
- `relay`, `coordinator` — the deployed services.
- `infra/` — Fargate / region IaC. Not a crate; excluded from the workspace.

## Architectural invariants (not visible from the types)

Full rationale in `docs/architecture.md`. The ones easy to break by accident:

- **The data plane is deliberately not a reliable-ordered protocol.** Payloads are
  the unit; a `Packet`'s `seq` is *only* an ack handle, not an ordering key. Loss is
  covered by redundancy (each packet re-carries recent unacked payloads), never
  retransmit-on-timeout. The relay forwards each turn the moment it arrives — no
  reordering, no reassembly; the client restores game order above the transport.
  Reviewers and tools recurrently misread out-of-order delivery, ack-only handling,
  and the absence of explicit retransmits as bugs and push toward in-order reliable
  streams — that trades away the latency this design exists to protect (lockstep
  advances only as fast as the slowest turn). Defend the model; don't
  standard-protocol it.
- Consensus (latency buffer, desync detection, synced leaves) runs on the relay/mesh,
  never the coordinator. Nothing on the per-turn path blocks on the coordinator —
  running games survive a coordinator outage.
- The relay validates every turn and strips client-originated control commands; its
  command parser is attacker-facing and fuzzed.
- We **replace** Storm's UDP transport, we don't tunnel it. The game hooks at the
  turn/command layer, so Storm's 12-byte UDP header is gone — `Packet` + QUIC own
  sequencing, acks, integrity, and recovery. Don't reintroduce Storm framing on the
  wire. Transport identity is a per-link `seq`, not a game frame; the consensus
  frame coordinate is a separate concern.
- Failover / partition / coordinator-outage responses are coordinated fleet-wide,
  never improvised per-client.

## Conventions

- Declare dependencies once in `[workspace.dependencies]`, reference with
  `{ workspace = true }`.
- `tracing` logs/metrics are correlated by `tenant / session / slot / turn`.
- **Code comments stand alone:** state the *what* and *why* directly rather than
  citing design docs, sections, or retired decision numbers — a comment must work
  for a reader who has never seen the docs.

## Gotchas (will bite you)

- QUIC is **quinn + rustls + ring**, not the default aws-lc-rs — pinned to avoid a
  C/NASM toolchain on the 32-bit Windows build. Don't revert the backend.
- `client` must build for `i686-pc-windows-msvc` (linked into the 32-bit game DLL),
  so keep it portable and `unsafe`-free. CI has a dedicated job for it.
- `unsafe` is denied workspace-wide; the hot-path FFI and the BW-thread ⇄
  Tokio-thread handoff live in `shieldbattery/game/`, not here.
- CI enforces `cargo clippy --workspace --all-targets -- -D warnings`; keep it clean.
- `Cargo.lock` is committed and CI builds `--locked` — commit it when deps change.
- The datagram wire format is **protobuf**, generated from `proto/proto/wire.proto`
  by `protox` (pure-Rust, no `protoc` needed) in `proto/build.rs`. Edit the
  `.proto` and rebuild; never edit generated code. Protobuf is only the envelope —
  the SC:R command bytes inside a payload are still hand-validated.
- The fuzz harness (`relay/fuzz/`, its own workspace — needs nightly + cargo-fuzz;
  `cd relay && cargo +nightly fuzz run validate_turn`) asserts the turn validator's
  invariants, not just no-panic; the same invariants run on stable in every
  `cargo test` as randomized property tests in `relay/src/validation.rs`.
