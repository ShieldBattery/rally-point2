locals {
  # Environment-scoped names. Every resource that the coordinator addresses by
  # name derives from var.environment so staging and prod never collide.
  cluster_name       = "rp2-relays-${var.environment}"
  family             = "rp2-relay-${var.environment}"
  started_by         = "rp2-coordinator-${var.environment}"
  ssm_parameter_name = "/rp2/${var.environment}/relay/coordinator-secret"
  log_group_name     = "/rp2/${var.environment}/relay"

  # The one place regions are declared, shared verbatim with the account stack.
  # `regions` holds each region's facts (aws_region, display_name, optional
  # beacon/fallback ping targets); `environments` maps each environment to the
  # regions it runs and their per-environment VPC CIDRs.
  catalog = jsondecode(file("${path.module}/../region-catalog.json"))

  # The regions this environment runs, keyed by coordinator region id. A region
  # is enabled for an environment purely by appearing under that environment in
  # the catalog, so environments can run different region sets. Each entry pairs
  # the region's catalog facts with this environment's CIDR and its resolved
  # beacon/fallback targets: an explicit override in the catalog when present,
  # otherwise the formulaic AWS endpoints.
  regions = {
    for id, cidr in local.catalog.environments[var.environment] :
    id => merge(local.catalog.regions[id], {
      ipv4_cidr = cidr
      beacon    = try(local.catalog.regions[id].beacon, "gamelift-ping.${local.catalog.regions[id].aws_region}.api.aws:443")
      fallback  = try(local.catalog.regions[id].fallback, "dynamodb.${local.catalog.regions[id].aws_region}.amazonaws.com:443")
    })
  }

  # The AWS region strings this environment runs in. IAM is global, so the
  # coordinator user's and execution role's policies are scoped by spelling out
  # the per-region ARNs of the resources the region module creates; this list
  # must cover exactly the enabled regions.
  aws_regions = [for r in local.regions : r.aws_region]
}
