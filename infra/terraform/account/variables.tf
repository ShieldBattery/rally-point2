variable "repo_name" {
  type        = string
  description = "ECR repository name for the relay image, created in every fleet region. Must match the fleet stack's repo_name."
  default     = "rp2-relay"
}

variable "home_region" {
  type        = string
  description = "The region CI pushes the relay image to and ECR replication fans out from. Also the account stack's default provider region. Included in the account-wide region set even if no environment runs a relay there."
  default     = "us-east-1"
}

variable "github_repository" {
  type        = string
  description = "owner/name of the GitHub repository whose Actions runs may assume the publisher role."
  default     = "ShieldBattery/rally-point2"
}

variable "allowed_refs" {
  type        = list(string)
  description = "Git refs within github_repository allowed to assume the publisher role. Publishing runs only from main."
  default     = ["refs/heads/main"]
}

variable "create_github_oidc_provider" {
  type        = bool
  description = <<-EOT
    Whether to create the GitHub Actions OIDC provider in this account. An
    account that already federates GitHub Actions has exactly one such provider
    (only one per URL is allowed), so set this false and pass the existing
    provider's ARN via github_oidc_provider_arn to reuse it.
  EOT
  default     = true
}

variable "github_oidc_provider_arn" {
  type        = string
  description = "ARN of an existing GitHub Actions OIDC provider to reuse when create_github_oidc_provider is false."
  default     = ""
}
