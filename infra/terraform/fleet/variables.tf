variable "environment" {
  type        = string
  description = "Isolated deployment environment. Drives every environment-scoped name (cluster, task family, IAM user, SSM path, log group)."

  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be either \"staging\" or \"prod\"."
  }
}

variable "repo_name" {
  type        = string
  description = "ECR repository name for the relay image. Must match the account stack's repo_name."
  default     = "rp2-relay"
}

variable "relay_image_tag" {
  type        = string
  description = "Image tag the task definitions pull. Prod tracks the promoted `stable` tag; staging tracks `latest`."
  default     = "stable"
}

variable "cpu_architecture" {
  type        = string
  description = "Task CPU architecture. Flip to ARM64 only once the relay image is published multi-arch; a mismatch fails the task at launch."
  default     = "X86_64"
}

variable "task_cpu" {
  type        = number
  description = "Fargate task CPU units."
  default     = 256
}

variable "task_memory" {
  type        = number
  description = "Fargate task memory in MiB."
  default     = 512
}

variable "coordinator_url" {
  type        = string
  description = "Base URL of the coordinator the relays enroll with (RELAY_COORDINATOR_URL)."
}

variable "coordinator_bootstrap_secret" {
  type        = string
  description = "Relay bootstrap secret (RELAY_COORDINATOR_SECRET), stored in SSM. Pass via TF_VAR_coordinator_bootstrap_secret; keep it out of the tfvars files."
  sensitive   = true
}

variable "relay_port" {
  type        = number
  description = "UDP port the relay listens on for QUIC (game clients and peer relays). Must match the relay binary's default listen port; it feeds the security groups, the task definitions, and the coordinator config output alike."
  default     = 14900
}

variable "container_name" {
  type        = string
  description = "Relay container name in the task definitions. The coordinator targets this name when injecting per-launch environment overrides, so the task definitions and the coordinator config output must agree on it."
  default     = "relay"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch retention for the relay log group, in days."
  default     = 30
}

variable "create_coordinator_access_key" {
  type        = bool
  description = <<-EOT
    Whether to mint an access key for the coordinator IAM user. The key material
    lands in Terraform state, which is acceptable here because state is kept in a
    private, encrypted S3 bucket. Set false to create the key manually in the
    console instead and leave it out of state.
  EOT
  default     = true
}
