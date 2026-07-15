output "publisher_role_arn" {
  description = "ARN of the CI publisher role. Set this as the GitHub repository variable RELAY_ECR_ROLE_ARN so the publish and promote workflows can assume it."
  value       = aws_iam_role.publisher.arn
}

output "registry_hostnames" {
  description = "Per-region ECR registry hostnames (the docker login / image-URL host for each region), keyed by AWS region across the account-wide region set."
  value = {
    for r in local.account_aws_regions :
    r => "${data.aws_caller_identity.current.account_id}.dkr.ecr.${r}.amazonaws.com"
  }
}

output "repo_name" {
  description = "ECR repository name shared by all regions. The fleet stack's repo_name must match this."
  value       = var.repo_name
}
