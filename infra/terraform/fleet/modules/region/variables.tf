variable "environment" {
  type        = string
  description = "Deployment environment this region belongs to. Used only for resource Name tags."
}

variable "coordinator_region_id" {
  type        = string
  description = "Coordinator region id (us-east, us-west, eu-central). Used for Name tags and as the ecs_json key."
}

variable "aws_region" {
  type        = string
  description = "AWS region this module's provider targets (e.g. us-east-1). Used in the image URL, log config, and ecs_region_config."
}

variable "ipv4_cidr" {
  type        = string
  description = "VPC IPv4 CIDR. Subnets are carved from this; IPv6 is auto-assigned by AWS."
}

variable "cluster_name" {
  type        = string
  description = "ECS cluster name (shared across regions within an environment)."
}

variable "family" {
  type        = string
  description = "ECS task definition family."
}

variable "ssm_parameter_name" {
  type        = string
  description = "SSM parameter name holding the relay bootstrap secret."
}

variable "log_group_name" {
  type        = string
  description = "CloudWatch log group name for relay container logs."
}

variable "repo_name" {
  type        = string
  description = "ECR repository name for the relay image."
}

variable "relay_image_tag" {
  type        = string
  description = "Image tag the task definition pulls."
}

variable "cpu_architecture" {
  type        = string
  description = "Task CPU architecture (X86_64 or ARM64)."
}

variable "task_cpu" {
  type        = number
  description = "Fargate task CPU units."
}

variable "task_memory" {
  type        = number
  description = "Fargate task memory in MiB."
}

variable "coordinator_url" {
  type        = string
  description = "Base URL of the coordinator (RELAY_COORDINATOR_URL)."
}

variable "coordinator_bootstrap_secret" {
  type        = string
  description = "Relay bootstrap secret (RELAY_COORDINATOR_SECRET), stored in SSM."
  sensitive   = true
}

variable "execution_role_arn" {
  type        = string
  description = "ARN of the task execution role passed to the task definition."
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch retention for the relay log group, in days."
}

variable "relay_port" {
  type        = number
  description = "UDP port the relay listens on for QUIC (game clients and peer relays)."
  default     = 14900
}

variable "container_name" {
  type        = string
  description = "Relay container name in the task definition. The coordinator targets this name when injecting per-launch environment overrides."
  default     = "relay"
}
