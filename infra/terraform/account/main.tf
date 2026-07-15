data "aws_caller_identity" "current" {}

locals {
  # Which OIDC provider the publisher role trusts: the one this stack creates, or
  # a pre-existing account provider passed in by ARN.
  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.github_oidc_provider_arn

  # The one place regions are declared, shared verbatim with the fleet stack.
  # Only the AWS region strings matter here; the account stack is environment-
  # agnostic, so it works from the union across environments, not any single
  # environment's region set.
  catalog = jsondecode(file("${path.module}/../region-catalog.json"))

  # Every coordinator region id any environment runs.
  enabled_region_ids = toset(flatten([
    for regions in values(local.catalog.environments) : keys(regions)
  ]))

  # AWS region strings every environment runs in, before adding the home region.
  environment_aws_regions = [for id in local.enabled_region_ids : local.catalog.regions[id].aws_region]

  # The account-wide AWS region set: every region any environment runs, plus the
  # home region CI pushes to. Every ECR repository, lifecycle policy, and
  # dualStackIPv6 setting is created across this set, so a region added to any
  # environment's catalog entry is provisioned account-wide in one apply.
  account_aws_regions = toset(concat(local.environment_aws_regions, [var.home_region]))

  # The replication destinations: every region in the set except the home region
  # the image is pushed to, since a registry does not replicate to itself.
  replica_aws_regions = setsubtract(local.account_aws_regions, [var.home_region])

  # Expire untagged images 7 days after they are pushed. Nothing tag-based: the
  # publish flow leaves a `latest`/`stable`/per-sha tag on every image worth
  # keeping, and an age- or count-based rule could evict whatever `stable`
  # currently points at. Relay images are small, so the storage saved by a more
  # aggressive policy is pennies and not worth the risk of dropping a promoted
  # image.
  untagged_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images 7 days after push"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# The relay image repository, created explicitly in each region rather than left
# to replication so every region can carry its own lifecycle policy — lifecycle
# policies are not replicated, only image pushes are. image_tag_mutability is
# MUTABLE because the publish/promote flow moves the `latest` and `stable` tags
# onto new images in place. One repository per region in the account-wide set.
resource "aws_ecr_repository" "relay" {
  for_each = local.account_aws_regions

  region               = each.value
  name                 = var.repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "relay" {
  for_each = local.account_aws_regions

  region     = each.value
  repository = aws_ecr_repository.relay[each.key].name
  policy     = local.untagged_lifecycle_policy
}

# Push-time replication from the home registry to every other region in the set,
# so a Fargate cold start pulls the relay image from its own region. This is an
# account-level singleton: an account may hold exactly one replication
# configuration, so this resource must be the only one in the account. The
# repository_filter keeps replication to the rp2- image repositories.
resource "aws_ecr_replication_configuration" "relay" {
  region = var.home_region

  replication_configuration {
    rule {
      dynamic "destination" {
        for_each = local.replica_aws_regions

        content {
          region      = destination.value
          registry_id = data.aws_caller_identity.current.account_id
        }
      }

      repository_filter {
        filter      = "rp2-"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}

# GitHub Actions authenticates to AWS by federating through this OIDC provider
# and assuming the publisher role — there is no long-lived AWS key stored in the
# repository. Only one provider per URL may exist in an account; if the account
# already federates GitHub Actions, set create_github_oidc_provider = false and
# supply the existing provider via github_oidc_provider_arn.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

# Trust policy: only GitHub Actions runs from the configured repository and refs,
# presenting an `sts.amazonaws.com` audience, may assume the publisher role.
data "aws_iam_policy_document" "publisher_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for ref in var.allowed_refs : "repo:${var.github_repository}:ref:${ref}"]
    }
  }
}

# Permissions the CI publish/promote workflows need: an ECR auth token, push+pull
# on the relay repository in every region, and a read of the account's
# replication configuration. Promotion retags an already-published image in every
# replica, so every repository is in scope, not just the home region, and the
# promote workflow reads the replication configuration to learn which regions
# those are rather than carrying a hardcoded list.
data "aws_iam_policy_document" "publisher" {
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "EcrPushPull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:DescribeImages",
    ]
    resources = [for repo in aws_ecr_repository.relay : repo.arn]
  }

  # DescribeRegistry is a registry-level action with no resource to scope to, so
  # it authorizes on *. The promote workflow calls it to read the replication
  # configuration and derive its region list from there.
  statement {
    sid       = "EcrDescribeRegistry"
    effect    = "Allow"
    actions   = ["ecr:DescribeRegistry"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "publisher" {
  name               = "rp2-relay-publisher"
  assume_role_policy = data.aws_iam_policy_document.publisher_trust.json
}

resource "aws_iam_role_policy" "publisher" {
  name   = "rp2-relay-publisher"
  role   = aws_iam_role.publisher.id
  policy = data.aws_iam_policy_document.publisher.json
}

# Fargate task ENIs only receive a public IPv6 address when the dualStackIPv6
# account setting is enabled, and the coordinator resolves and gates on each
# task's public IPv6. It is an account-level setting (one value per region), so
# it lives here rather than in the fleet stack — otherwise the staging and
# production fleets would each try to own the same account-wide setting. Set in
# every region in the account-wide set.
resource "aws_ecs_account_setting_default" "dual_stack_ipv6" {
  for_each = local.account_aws_regions

  region = each.value
  name   = "dualStackIPv6"
  value  = "enabled"
}
