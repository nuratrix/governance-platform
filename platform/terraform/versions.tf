# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/versions.tf
# Deploy this FIRST before any agent.
# Backend bucket renamed to gma-platform-state (multi-account project).
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}
