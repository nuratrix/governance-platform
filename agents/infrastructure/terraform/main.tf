# ─────────────────────────────────────────────────────────────────────────────
# agents/infrastructure/terraform/main.tf
# Provider only. All resources are in named files.
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudGovernance"
      Agent     = "InfraAgent"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}
