terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # Partial backend config — all values supplied via -backend-config flags in CI/CD.
  # The workflow passes role_arn separately so that S3 state access always uses
  # governance-account credentials regardless of which AWS provider creds are active.
  backend "s3" {}
}

provider "aws" {}
