data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # local.aws_regions (in locals.tf) is this environment's AWS region strings.
  # IAM is global, so the coordinator user's and execution role's policies are
  # scoped by spelling out the per-region ARNs of the resources the region module
  # creates. The repositories live in the account stack, so their ARNs are
  # constructed rather than referenced.
  repo_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:ecr:${region}:${local.account_id}:repository/${var.repo_name}"
  ]

  log_group_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:logs:${region}:${local.account_id}:log-group:${local.log_group_name}:*"
  ]

  ssm_parameter_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:ssm:${region}:${local.account_id}:parameter${local.ssm_parameter_name}"
  ]

  task_definition_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:ecs:${region}:${local.account_id}:task-definition/${local.family}:*"
  ]

  cluster_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:ecs:${region}:${local.account_id}:cluster/${local.cluster_name}"
  ]

  task_arns = [
    for region in local.aws_regions :
    "arn:${local.partition}:ecs:${region}:${local.account_id}:task/${local.cluster_name}/*"
  ]
}

# Execution role: used by the ECS agent (not the relay process) to pull the
# image, write container logs, and read the bootstrap secret. Created once for
# the environment because IAM is global; RunTask passes it into every region.
data "aws_iam_policy_document" "execution_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "rp2-relay-execution-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json
}

data "aws_iam_policy_document" "execution" {
  # The ECR auth token action cannot be scoped to a resource.
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  # Pull the relay image. Scoped to the relay repository in all three regions,
  # since a task pulls from whichever region it launched in.
  statement {
    sid    = "EcrPull"
    effect = "Allow"
    actions = [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
    ]
    resources = local.repo_arns
  }

  # Write container stdout/stderr into the per-region relay log group.
  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = local.log_group_arns
  }

  # Read the bootstrap secret that the task definition injects into the relay
  # container. SSM is regional; the parameter exists under the same name in each
  # region and the agent reads from the task's own region.
  statement {
    sid       = "SsmSecret"
    effect    = "Allow"
    actions   = ["ssm:GetParameters"]
    resources = local.ssm_parameter_arns
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "rp2-relay-execution-${var.environment}"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# There is deliberately no task role: the relay process makes no AWS API calls.
# Its only traffic is QUIC to game clients/peers and outbound WSS to the
# coordinator, so a task role would grant permissions nothing uses.

# Coordinator IAM user: the identity the coordinator's ECS provisioner uses to
# launch, stop, and inspect relay tasks. Its policy is scoped as tightly as the
# ECS/EC2 APIs allow, and confined to this environment's clusters.
resource "aws_iam_user" "coordinator" {
  name = "rp2-coordinator-${var.environment}"
}

data "aws_iam_policy_document" "coordinator" {
  # Launch a relay from the task family (any revision) in any of the three
  # regions. The ecs:cluster condition confines placement to this environment's
  # clusters, so the credential cannot launch tasks into another cluster.
  statement {
    sid       = "RunTask"
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = local.task_definition_arns

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = local.cluster_arns
    }
  }

  # Stop a drained task and read task state during reconcile. Task ARNs are
  # per-cluster wildcards (task ids are only known at runtime); the same cluster
  # condition keeps this to the environment's clusters.
  statement {
    sid    = "StopAndDescribeTasks"
    effect = "Allow"
    actions = [
      "ecs:StopTask",
      "ecs:DescribeTasks",
    ]
    resources = local.task_arns

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = local.cluster_arns
    }
  }

  # List this coordinator's running tasks. ecs:ListTasks has no resource-level
  # scoping — its resource type is the container instance, which Fargate has none
  # of — so it authorizes on * and is confined by the cluster condition instead.
  statement {
    sid       = "ListTasks"
    effect    = "Allow"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = local.cluster_arns
    }
  }

  # Resolve a task's public IPv4/IPv6 from its elastic network interface. EC2
  # describe calls cannot be scoped to particular interfaces, so this is
  # unavoidably on *.
  statement {
    sid       = "DescribeNetworkInterfaces"
    effect    = "Allow"
    actions   = ["ec2:DescribeNetworkInterfaces"]
    resources = ["*"]
  }

  # RunTask passes the execution role embedded in the task definition, so the
  # coordinator credential must be allowed to pass exactly that role, and only to
  # the ECS tasks service.
  statement {
    sid       = "PassExecutionRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.execution.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_user_policy" "coordinator" {
  name   = "rp2-coordinator-${var.environment}"
  user   = aws_iam_user.coordinator.name
  policy = data.aws_iam_policy_document.coordinator.json
}

resource "aws_iam_access_key" "coordinator" {
  count = var.create_coordinator_access_key ? 1 : 0

  user = aws_iam_user.coordinator.name
}
