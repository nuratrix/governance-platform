provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "AWS-Governance-Platform"
      Agent       = "backup-dr"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
