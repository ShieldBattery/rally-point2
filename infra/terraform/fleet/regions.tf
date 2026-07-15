# One instance of the region module per region this environment runs, keyed by
# coordinator region id. The set comes entirely from region-catalog.json (via
# local.regions), so adding a region is a catalog edit — nothing in this file
# changes. Each instance stamps its resources with the catalog's aws_region (the
# AWS provider 6.x per-resource region argument), so no provider aliases are
# involved.

module "region" {
  source   = "./modules/region"
  for_each = local.regions

  environment           = var.environment
  coordinator_region_id = each.key
  aws_region            = each.value.aws_region
  ipv4_cidr             = each.value.ipv4_cidr

  cluster_name       = local.cluster_name
  family             = local.family
  ssm_parameter_name = local.ssm_parameter_name
  log_group_name     = local.log_group_name

  repo_name        = var.repo_name
  relay_image_tag  = var.relay_image_tag
  cpu_architecture = var.cpu_architecture
  task_cpu         = var.task_cpu
  task_memory      = var.task_memory
  relay_port       = var.relay_port
  container_name   = var.container_name

  coordinator_url              = var.coordinator_url
  coordinator_bootstrap_secret = var.coordinator_bootstrap_secret

  execution_role_arn = aws_iam_role.execution.arn
  log_retention_days = var.log_retention_days
}
