# terraform

The AWS substrate the coordinator's ECS provisioner launches relay tasks into,
as two independent Terraform root stacks plus one shared module, all driven by a
single region catalog.

- **`account/`** — applied once per AWS account, shared by every environment. The
  relay ECR repository in each region, push-time cross-region replication, the
  GitHub Actions publisher role, and the `dualStackIPv6` ECS account settings.
- **`fleet/`** — applied once per environment (`staging`, `prod`). A dual-stack
  VPC + cluster + relay task definition in each region the environment runs (via
  `modules/region/`), plus the environment's execution role and the coordinator's
  narrowly-scoped IAM user. Emits the coordinator's `config/ecs.json`,
  `config/regions.json`, and access-key credentials as outputs.

Terraform `>= 1.10`, AWS provider `~> 6.0`. Multi-region placement is the AWS
provider 6.x per-resource `region` argument — every regional resource sets its
own region, so there are no provider aliases anywhere. State is in S3; each
stack's backend is configured at init from a sample file.

The repo owner runs Terraform with their own AWS credentials. Nothing here is run
by CI or by agents.

## Regions

Regions are declared once, in `region-catalog.json`, read by both stacks. It has
two sections:

```json
{
  "regions": {
    "us-east": { "aws_region": "us-east-1", "display_name": "US East" }
  },
  "environments": {
    "staging": { "us-east": "10.80.0.0/22" }
  }
}
```

- **`regions`** — per-region facts, keyed by the coordinator region id (the
  opaque label a relay enrolls with and a session slot requests). Each holds its
  `aws_region` and the client-facing `display_name`, plus OPTIONAL `beacon` and
  `fallback` latency-measurement endpoints. When those are omitted they default
  formulaically from the AWS region: beacon `gamelift-ping.<aws_region>.api.aws:7770`
  (the port GameLift's UDP ping beacons echo on),
  fallback `dynamodb.<aws_region>.amazonaws.com:443`. Set them explicitly only to
  override.

  Not every AWS region has a GameLift ping beacon (`mx` / mx-central-1 lacks one —
  the formulaic hostname doesn't resolve). Such a region still works end to end,
  by design, with no override: game clients catch the failed beacon measurement
  and rank the region by TCP-connect time to the fallback endpoint instead, and
  the backbone table fills from that region's relays measuring *outbound* to
  other regions' beacons (pairs serve from whichever directions are present, and
  coverage counts a pair covered with one). The deliberately-formulaic dead
  hostname is also the upgrade path: if AWS ships the beacon later, clients and
  relays start using UDP with no config change.
- **`environments`** — for each environment, the regions it runs mapped to that
  environment's VPC IPv4 CIDR. A region's presence under an environment is what
  enables it there, so environments can run different region sets (staging is
  expected to stay smaller than prod). CIDRs are per (environment, region) and
  must be distinct across environments so nothing is ambiguous when reading
  state; IPv6 is auto-assigned by AWS.

The account stack works from the union of every environment's regions (plus the
home region CI pushes to), so a region only reaches the fleet once its
environment entry exists. JSON carries no comments, which is why the shape lives
here.

Tenants are declared once too, but on the coordinator box rather than here: its
`config/tenants.json` holds each tenant's state, verifying keys, and webhook URL.
The relay tasks carry no tenant material — a relay receives the verifying keys it
checks player tokens against over the coordinator's control connection. See the
coordinator deployment README (`deployment/coordinator/` in the shieldbattery
repo) for the tenant flow.

## One-time setup

1. Create the S3 state bucket (versioning + default encryption on; keep it
   private — access-key material lands in fleet state). One bucket serves both
   stacks and both environments; the `key` differs per stack/env.

2. Fill in the bucket name in the backend samples (`account/account.s3.tfbackend`,
   `fleet/environments/staging.s3.tfbackend`,
   `fleet/environments/prod.s3.tfbackend`), replacing `CHANGEME-rp2-tfstate`.

3. Init each stack against its backend:

   ```sh
   cd account
   terraform init -backend-config=account.s3.tfbackend

   cd ../fleet
   terraform init -backend-config=environments/staging.s3.tfbackend
   # re-init with prod.s3.tfbackend when switching this directory to prod
   ```

   The two fleet environments use the same `fleet/` code with different backend
   keys and `-var-file`s. Keep their state separate (distinct `key`) and re-run
   `init` when switching which environment this working directory points at.

## 1. Apply the account stack

```sh
cd account
terraform plan
terraform apply
```

Then:

- Set the GitHub repository variable `RELAY_ECR_ROLE_ARN` to the
  `publisher_role_arn` output. The publish and promote workflows assume this role
  via OIDC; without the variable they skip.
- If the account already federates GitHub Actions, apply with
  `-var create_github_oidc_provider=false -var github_oidc_provider_arn=<arn>` so
  the existing provider is reused (only one provider per URL may exist).
- Run the "Publish relay image" workflow once (push to main or manual dispatch)
  so a `:latest` image exists. Promote a tested SHA to `:stable` with the
  "Promote relay image" workflow before expecting prod launches to succeed —
  the prod task definitions pull `:stable`, and a task launch fails while the
  tag doesn't exist (the apply itself doesn't care).
- **Rolling a relay image across a live fleet:** `MeshHello` carries the relay's
  CURRENT protocol version, and mixed-version relays do not mesh-pair until the
  fleet converges — each still serves its own single-relay sessions, but new
  cross-relay sessions can't form across the version split. Bounce every
  region's tasks promptly (rather than letting old and new coexist for long)
  when the image rolls. Connection-epoch compatibility is one-way: once a live
  session observes an epoch-enabled relay, it rejects later epoch-less lifecycle
  frames. Drain/bounce the fleet at this release boundary; do not let such a
  session rehome onto an older relay image.

## 2. Apply a fleet environment

The bootstrap secret is never written to a tfvars file; pass it through the
environment so it does not land on disk:

```sh
cd fleet
terraform init -backend-config=environments/staging.s3.tfbackend
export TF_VAR_coordinator_bootstrap_secret=... # the tenant's relay bootstrap secret
terraform plan  -var-file=environments/staging.tfvars
terraform apply -var-file=environments/staging.tfvars
```

Staging's tfvars needs no edits. For prod, fill in `coordinator_url` first (the
one `CHANGEME` in `prod.tfvars`). Regions and their CIDRs come from the catalog,
not the tfvars.

## 3. Wire the coordinator box

From the applied fleet environment:

```sh
terraform output -raw ecs_json     > /path/to/coordinator/config/ecs.json
terraform output -raw regions_json > /path/to/coordinator/config/regions.json
terraform output -raw coordinator_access_key_id       # -> AWS_ACCESS_KEY_ID
terraform output -raw coordinator_secret_access_key   # -> AWS_SECRET_ACCESS_KEY
```

`ecs.json` is the per-region Fargate launch config; `regions.json` is the region
registry the coordinator serves to clients (id, display name, and ping targets),
both generated for this environment from the catalog. Put the access-key pair in
the coordinator's `.env`, then uncomment `COORDINATOR_RELAY_LEDGER` and
`COORDINATOR_PROVISION_ECS_CONFIG` in that `.env`. They turn on together: the
provisioner needs the ledger to track the tasks it launches. Restart the
coordinator.

## 4. Verify

Warm one region and watch a task launch and enroll. The RunTask-to-enrolled
timing is recorded in the coordinator's ledger timestamps; use its distribution
to calibrate `COORDINATOR_PROVISION_CREATE_HOLD_SECS` (how long a session
create is worth holding for a cold region before falling back to a lit one)
and to sanity-check `COORDINATOR_PROVISION_LAUNCH_DEADLINE_SECS` (the point at
which an un-enrolled launch is abandoned and its task stopped) against the
tail.

## Review gates

Before applying, the review gates are:

```sh
terraform fmt -check -recursive
terraform validate
terraform plan -var-file=environments/<env>.tfvars   # fleet; plain plan for account
```

## Adding a region

Adding a region is a catalog edit — no provider aliases, no module blocks, no
tfvars churn, and no workflow edits (the promote workflow reads the account's
replication configuration to learn its regions):

1. Edit `region-catalog.json`: add the region's facts to `regions` once (its
   `aws_region` and `display_name`, plus `beacon`/`fallback` if the formulaic
   defaults don't fit), and add an entry under each environment in
   `environments` that should run it, with a distinct VPC CIDR.
2. Apply the `account` stack: it adds the region's ECR repository, lifecycle
   policy, `dualStackIPv6` setting, and a replication destination.
3. Apply each fleet environment that gained the region: it builds the region's
   VPC, cluster, and task definition and scopes the IAM policies to include it.
4. Regenerate both coordinator outputs onto the coordinator box
   (`terraform output -raw ecs_json` and `-raw regions_json`) and restart the
   coordinator.

## AWS caveats

- **`dualStackIPv6` is an account setting, not a fleet one.** It lives in the
  account stack and is set once per region. Without it, Fargate task ENIs never
  receive an IPv6 address, and the coordinator's IPv6 source-address gate can
  never be satisfied — relays would fail to enroll over v6.
- **ECR cross-region replication is an account-level singleton.** Exactly one
  replication configuration may exist per account. If the account already has one
  (for another project), merge the `rp2-` rule into it rather than applying a
  second `aws_ecr_replication_configuration`.
- **Replication is push-time and asynchronous.** A freshly published SHA takes a
  short while to appear in the replica regions; the promote workflow fails loudly
  if it cannot find the SHA tag in a region yet, which usually means replication
  has not caught up.
