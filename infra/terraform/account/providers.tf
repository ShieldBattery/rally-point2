# One default provider covers every region. Each regional resource carries its
# own `region` argument (AWS provider 6.x), so the ECR repositories and ECS
# account settings are created across the union of fleet regions without a
# per-region provider alias. The default region is the home region — where the
# global IAM resources and the account-singleton ECR replication configuration
# live, and where CI pushes the relay image.

provider "aws" {
  region = var.home_region

  default_tags {
    tags = {
      project    = "rally-point2"
      managed-by = "terraform"
    }
  }
}
