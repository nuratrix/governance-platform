provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "CloudGovernance"
      Agent     = "SecurityAgent"
      ManagedBy = "Terraform"
      Env       = var.environment
    }
  }
}
