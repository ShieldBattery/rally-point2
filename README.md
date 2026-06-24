# rally-point2

All-Rust netcode v2 platform for [ShieldBattery](https://shieldbattery.net): a
portable client transport, a validating relay + mesh, and a multi-tenant
coordinator. Replaces the Node.js `rally-point`, which is decommissioned at the
end of the v2 cutover.

The full design and the load-bearing decisions (`D1`–`D11`) live in
`../shieldbattery/netcode-v2-build-plan.md`. Conventions for working in this
repo are in [`CLAUDE.md`](CLAUDE.md).

## Workspace

| Crate         | Role                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `proto`       | Shared wire framing, control-plane messages, tokens, protocol versioning, and the SC:R command table. Source of truth for every cross-component interface. |
| `client`      | Portable QUIC client transport, consumed by the ShieldBattery game DLL. Builds for `i686-pc-windows-msvc`.                       |
| `relay`       | Validating relay: command validation, mesh + dedup, per-turn consensus, replicated turn log, flight recorder.                   |
| `coordinator` | Multi-tenant control plane: relay registry, session setup, per-tenant tokens/quotas, consensus policy.                          |
| `infra/`      | Fargate / region-beacon IaC (Phase 5; not a Cargo crate — see [`infra/README.md`](infra/README.md)).                            |

## Development

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

`relay` and `coordinator` are runnable skeletons today:

```sh
cargo run -p rally-point-relay -- --help
cargo run -p rally-point-coordinator -- --help
```

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in the work by
you, as defined in the Apache-2.0 license, shall be dual-licensed as above,
without any additional terms or conditions.
