# ─────────────────────────────────────────────────────────────────────────────
# agents/compliance/terraform/main.tf
# Provider only. All resources are in named files.
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudGovernance"
      Agent     = "ComplianceAgent"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}
