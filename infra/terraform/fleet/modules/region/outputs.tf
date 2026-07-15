output "subnet_ids" {
  description = "Public subnet ids tasks launch into."
  value       = aws_subnet.public[*].id
}

output "security_group_id" {
  description = "Security group id applied to task ENIs."
  value       = aws_security_group.relay.id
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "cluster_arn" {
  description = "ECS cluster ARN."
  value       = aws_ecs_cluster.this.arn
}

output "family" {
  description = "ECS task definition family."
  value       = aws_ecs_task_definition.relay.family
}

output "ssm_parameter_arn" {
  description = "ARN of the relay bootstrap secret parameter."
  value       = aws_ssm_parameter.coordinator_secret.arn
}

output "log_group_name" {
  description = "Relay log group name."
  value       = aws_cloudwatch_log_group.relay.name
}

output "log_group_arn" {
  description = "Relay log group ARN."
  value       = aws_cloudwatch_log_group.relay.arn
}

# Pre-shaped entry for the coordinator's ecs.json. The keys match the
# EcsRegionConfig the coordinator deserializes: aws_region, cluster,
# task_definition, subnets, security_groups, assign_public_ip. assign_public_ip
# is always true — tasks need a public IPv4 for the coordinator to resolve and
# gate on their source address.
output "ecs_region_config" {
  description = "EcsRegionConfig entry for this region, consumed verbatim by the fleet stack's ecs_json output."
  value = {
    aws_region       = var.aws_region
    cluster          = aws_ecs_cluster.this.name
    task_definition  = aws_ecs_task_definition.relay.family
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.relay.id]
    assign_public_ip = true
  }
}
