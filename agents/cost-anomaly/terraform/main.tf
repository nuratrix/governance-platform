# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/main.tf
# ─────────────────────────────────────────────────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS-Governance-Platform"
      Agent       = "cost-anomaly"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
