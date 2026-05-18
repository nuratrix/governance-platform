variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "production"
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be production, staging, or development."
  }
}

variable "platform_state_bucket" {
  description = "S3 bucket containing the platform Terraform state"
  type        = string
}

variable "platform_state_key" {
  type    = string
  default = "platform/terraform.tfstate"
}

variable "foundation_model" {
  type    = string
  default = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "lambda_timeout_orchestrator" {
  type    = number
  default = 900
}

variable "lambda_memory_orchestrator" {
  type    = number
  default = 512
}

variable "lambda_timeout_checker" {
  type    = number
  default = 300
}

variable "lambda_memory_checker" {
  type    = number
  default = 256
}

variable "scan_schedule" {
  type    = string
  default = "cron(0 7 * * ? *)"
}

variable "enable_xray_tracing" {
  type    = bool
  default = true
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}
