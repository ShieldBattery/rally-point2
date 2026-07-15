terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State lives in S3, one state file per environment. The backend is empty here
  # and configured at init time so the bucket name is not committed:
  #   terraform init -backend-config=environments/staging.s3.tfbackend
  backend "s3" {}
}
