# infra

Infrastructure-as-code for the relay fleet: the AWS substrate the coordinator's
ECS provisioner launches relay tasks into.

- [`terraform/`](terraform/README.md) — the Terraform stacks: a once-per-account
  stack (the ECR registry + cross-region replication, the CI publishing role,
  ECS dual-stack account settings) and a per-environment fleet stack
  (dual-stack VPCs, clusters, the relay task definition, and the coordinator's
  narrowly-scoped IAM user) across us-east-1, us-west-2, and eu-central-1. The
  README there is the apply runbook.

The shape in brief: relays are ephemeral Fargate tasks with public dual-stack
addresses — no NAT, no load balancer, no proxy, because the coordinator
verifies each enrolling relay's source address against its task's network
interface, and anything in between would replace that address with its own.
The coordinator mints a relay's identity at launch and injects it through
container env overrides; the task definition supplies everything static, with
the bootstrap secret pulled from SSM Parameter Store. Scale-to-zero per region
is the resting posture; warm demand raised by app servers brings regions up on
demand. Staging and production are separate stacks with separate credentials —
an isolated production fleet, and a staging fleet shared with trusted
developers.

Region latency beacons need no infrastructure here: the region registry points
clients at AWS's public GameLift ping endpoints
(`gamelift-ping.<aws-region>.api.aws`), which answer whether or not any relay
task is running.

The relay image is built by CI (`.github/workflows/publish-relay.yml`) into the
account's ECR registry and replicated to every fleet region, so cold-start
pulls stay region-local. Promoting the `stable` tag the task definitions pull
is a manual retag workflow (`promote-relay.yml`), mirroring the coordinator
image's flow.

This directory is not a Rust crate and is deliberately excluded from the Cargo
workspace.
