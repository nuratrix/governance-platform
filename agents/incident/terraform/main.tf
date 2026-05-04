# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/main.tf
# Provider only. All resources are in named files.
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudGovernance"
      Agent     = "IncidentAgent"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}
