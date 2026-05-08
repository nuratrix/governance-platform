# agents/cost/terraform/versions.tf

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws  = { source = "hashicorp/aws",  version = "~> 5.0" }
    time = { source = "hashicorp/time", version = "~> 0.9" }
    null = { source = "hashicorp/null", version = "~> 3.0" }
  }
  backend "s3" {}
}
