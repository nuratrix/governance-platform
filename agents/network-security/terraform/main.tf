# agents/network-security/terraform/main.tf

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS-Governance-Platform"
      Agent       = "network-security"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
