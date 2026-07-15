# The coordinator's ECS provisioner config, ready to write to config/ecs.json:
#   terraform output -raw ecs_json > config/ecs.json
# The keys and shape match the EcsConfig / EcsRegionConfig the coordinator
# deserializes, so this is consumed verbatim. `container` and `relay_port` come
# from the same variables the region modules build their task definitions and
# security groups from, so the coordinator's view cannot drift from what the
# tasks actually run.
output "ecs_json" {
  description = "Coordinator ECS provisioner config (config/ecs.json). Emit with: terraform output -raw ecs_json"
  value = jsonencode({
    started_by = local.started_by
    container  = var.container_name
    relay_port = var.relay_port
    regions = {
      for id, m in module.region : id => m.ecs_region_config
    }
  })
}

# The coordinator's region registry, ready to write to config/regions.json:
#   terraform output -raw regions_json > config/regions.json
# The shape matches the coordinator's RegionsConfig: a `regions` array of
# {id, display_name, beacon, fallback}, all generated from the catalog for this
# environment. beacon/fallback are the resolved ping targets — the catalog's
# override when present, otherwise the formulaic AWS endpoints.
#
# Entries come out id-sorted: a for expression over local.regions (a map) walks
# it in key order. The coordinator keeps this file's array order as its registry
# order, and clients show regions in registry order, so the region list a client
# sees is id-sorted.
output "regions_json" {
  description = "Coordinator region registry (config/regions.json). Emit with: terraform output -raw regions_json"
  value = jsonencode({
    regions = [
      for id, r in local.regions : {
        id           = id
        display_name = r.display_name
        beacon       = r.beacon
        fallback     = r.fallback
      }
    ]
  })
}

output "coordinator_access_key_id" {
  description = "Access key id for the coordinator user (the .env AWS_ACCESS_KEY_ID). Null when create_coordinator_access_key is false."
  value       = var.create_coordinator_access_key ? aws_iam_access_key.coordinator[0].id : null
  sensitive   = true
}

output "coordinator_secret_access_key" {
  description = "Secret access key for the coordinator user (the .env AWS_SECRET_ACCESS_KEY). Null when create_coordinator_access_key is false."
  value       = var.create_coordinator_access_key ? aws_iam_access_key.coordinator[0].secret : null
  sensitive   = true
}

output "execution_role_arn" {
  description = "ARN of the relay task execution role."
  value       = aws_iam_role.execution.arn
}

output "cluster_arns" {
  description = "Per-region ECS cluster ARNs, keyed by coordinator region id, for operational reference."
  value = {
    for id, m in module.region : id => m.cluster_arn
  }
}
