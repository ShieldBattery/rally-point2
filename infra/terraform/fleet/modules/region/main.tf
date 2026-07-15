data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  region = var.aws_region
  state  = "available"
}

locals {
  name_prefix = "rp2-relay-${var.environment}-${var.coordinator_region_id}"
  relay_image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.repo_name}:${var.relay_image_tag}"
}

# Dual-stack VPC. AWS assigns the /56 IPv6 block; relays advertise both a public
# IPv4 and a public IPv6 address, so the VPC must carry both families. DNS
# support and hostnames are on so the ECR and coordinator endpoints resolve.
resource "aws_vpc" "this" {
  region                           = var.aws_region
  cidr_block                       = var.ipv4_cidr
  assign_generated_ipv6_cidr_block = true
  enable_dns_support               = true
  enable_dns_hostnames             = true

  tags = {
    Name = local.name_prefix
  }
}

# Two public subnets across the first two available AZs. Each carries an IPv4 /24
# slice and an IPv6 /64 slice. assign_ipv6_address_on_creation is load-bearing: a
# task's ENI must come up with a public IPv6 address, which is how clients and
# peer relays reach the relay over v6 and half of what the coordinator's
# enrollment source-address gate checks. (map_public_ip_on_launch is left unset;
# for Fargate the public IPv4 is decided by RunTask's network configuration, not
# the subnet.)
resource "aws_subnet" "public" {
  count = 2

  region                          = var.aws_region
  vpc_id                          = aws_vpc.this.id
  availability_zone               = data.aws_availability_zones.available.names[count.index]
  cidr_block                      = cidrsubnet(aws_vpc.this.cidr_block, 2, count.index)
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, count.index)
  assign_ipv6_address_on_creation = true

  tags = {
    Name = "${local.name_prefix}-public-${count.index}"
  }
}

resource "aws_internet_gateway" "this" {
  region = var.aws_region
  vpc_id = aws_vpc.this.id

  tags = {
    Name = local.name_prefix
  }
}

# One public route table for both subnets: default IPv4 and IPv6 routes to the
# internet gateway. Deliberately no NAT gateway — tasks hold public addresses and
# all egress (including ECR image pulls) rides the IGW directly. A NAT gateway
# would add roughly $32/mo per region and carry no traffic that needs it.
resource "aws_route_table" "public" {
  region = var.aws_region
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.this.id
  }

  tags = {
    Name = "${local.name_prefix}-public"
  }
}

resource "aws_route_table_association" "public" {
  count = 2

  region         = var.aws_region
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "relay" {
  region      = var.aws_region
  name        = local.name_prefix
  description = "Relay task traffic: inbound QUIC on the relay port, all outbound."
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = local.name_prefix
  }
}

# Game clients and peer relays worldwide reach the relay over QUIC (UDP) on the
# relay port, on both IPv4 and IPv6. There is deliberately no TCP ingress: the
# control plane is an outbound-only WSS connection the relay opens to the
# coordinator, so nothing connects in over TCP.
resource "aws_vpc_security_group_ingress_rule" "relay_udp_ipv4" {
  region            = var.aws_region
  security_group_id = aws_security_group.relay.id
  description       = "QUIC relay traffic from IPv4 clients and peer relays"
  ip_protocol       = "udp"
  from_port         = var.relay_port
  to_port           = var.relay_port
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "relay_udp_ipv6" {
  region            = var.aws_region
  security_group_id = aws_security_group.relay.id
  description       = "QUIC relay traffic from IPv6 clients and peer relays"
  ip_protocol       = "udp"
  from_port         = var.relay_port
  to_port           = var.relay_port
  cidr_ipv6         = "::/0"
}

resource "aws_vpc_security_group_egress_rule" "all_ipv4" {
  region            = var.aws_region
  security_group_id = aws_security_group.relay.id
  description       = "All outbound IPv4 (WSS to coordinator, ECR pulls)"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "all_ipv6" {
  region            = var.aws_region
  security_group_id = aws_security_group.relay.id
  description       = "All outbound IPv6"
  ip_protocol       = "-1"
  cidr_ipv6         = "::/0"
}

# containerInsights stays disabled: it bills per metric, and the coordinator's
# ledger — not CloudWatch — is the operational source of truth for relay and task
# state.
resource "aws_ecs_cluster" "this" {
  region = var.aws_region
  name   = var.cluster_name

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_cloudwatch_log_group" "relay" {
  region            = var.aws_region
  name              = var.log_group_name
  retention_in_days = var.log_retention_days
}

# The relay bootstrap secret. The task execution role reads it at launch and the
# task definition injects it into the container. SSM is regional, so the same
# value is stored in each region and the agent reads from the task's own region.
resource "aws_ssm_parameter" "coordinator_secret" {
  region = var.aws_region
  name   = var.ssm_parameter_name
  type   = "SecureString"
  value  = var.coordinator_bootstrap_secret
}

resource "aws_ecs_task_definition" "relay" {
  region                   = var.aws_region
  family                   = var.family
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = var.execution_role_arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([
    {
      name      = var.container_name
      image     = local.relay_image
      essential = true

      portMappings = [
        {
          containerPort = var.relay_port
          hostPort      = var.relay_port
          protocol      = "udp"
        }
      ]

      # On scale-down ECS sends SIGTERM and the relay drains live game traffic
      # for up to 90s (RELAY_DRAIN_TIMEOUT_SECS). Fargate's default stopTimeout is
      # 30s, which would kill a task mid-drain; 120s is the Fargate maximum and
      # comfortably covers the drain window.
      stopTimeout = 120

      # Static relay configuration — just the coordinator URL. The coordinator
      # injects RELAY_ID, RELAY_ENROLL_TOKEN, and RELAY_REGION as per-launch
      # container overrides at RunTask, so those three are deliberately absent
      # here. The tenant verifying keys a relay checks player tokens against
      # arrive over the coordinator control connection, so no tenant material
      # rides in the task environment either.
      environment = [
        {
          name  = "RELAY_COORDINATOR_URL"
          value = var.coordinator_url
        },
      ]

      # The bootstrap secret comes from SSM Parameter Store, never plain env, so
      # its value never appears in the task definition or the console.
      secrets = [
        {
          name      = "RELAY_COORDINATOR_SECRET"
          valueFrom = aws_ssm_parameter.coordinator_secret.arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.relay.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "relay"
        }
      }

      # No healthCheck: the distroless runtime has no shell to run a check
      # command, and the coordinator's launch-deadline sweep — not ECS — is the
      # authority on whether a relay came up and enrolled.
    }
  ])
}
