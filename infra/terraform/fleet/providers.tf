# One default provider covers every region. Each regional resource carries its
# own `region` argument (AWS provider 6.x), so the region module places its
# resources without a per-region provider alias. The default region, us-east-1,
# is where this environment's global IAM lives (the execution role and the
# coordinator user). Adding a region is a catalog edit; nothing here changes.

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      project     = "rally-point2"
      managed-by  = "terraform"
      environment = var.environment
    }
  }
}
