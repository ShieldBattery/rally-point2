terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State lives in S3. The backend is intentionally empty here and configured at
  # init time so the bucket name is not committed:
  #   terraform init -backend-config=environments/account.s3.tfbackend
  backend "s3" {}
}
