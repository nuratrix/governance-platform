# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/main.tf
# Multi-Account: primary governance account provider stays as-is.
# Member account providers are in organizations.tf (optional, when
# deploy_member_roles = true).
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudGovernance"
      Layer     = "Platform"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
