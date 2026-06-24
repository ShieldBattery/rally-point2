# infra

Infrastructure-as-code for the netcode v2 relay fleet and region beacons
(build plan WS-G, Phase 5). **No Global Accelerator** (decision **D3**) — GA
custom routing is IPv4-only and EC2-only, so relays use direct dual-stack
public IPs instead.

Scope (Phase 5):

- Fargate task definition: dual-stack ENI (IPv6-primary client ingress is viable
  now that GA is gone; IPv4 egress for ECR image pulls via NAT/IGW).
- Scratch relay image.
- Lobby-time provisioning + scale-to-zero, with a **warm-pool fallback** for the
  cold-start tail.
- Per-game relay IP rotation as a DDoS lever.

Two coordinator deployments share this IaC as **separate stacks + keys** (D2):
an isolated **prod** fleet, and a shared **staging + developer** fleet.

> The IaC tooling (CDK vs Terraform vs Pulumi) is undecided and is **not** a Rust
> crate, so this directory is intentionally excluded from the Cargo workspace
> until Phase 5.
