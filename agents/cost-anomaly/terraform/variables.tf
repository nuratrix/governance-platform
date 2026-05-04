# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/variables.tf
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "platform_state_bucket" {
  description = "S3 bucket containing the platform Terraform state"
  type        = string
}

variable "platform_state_key" {
  description = "S3 key for the platform state file"
  type        = string
  default     = "platform/terraform.tfstate"
}

variable "foundation_model" {
  description = "Bedrock foundation model ID for the Cost Anomaly Agent"
  type        = string
  default     = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "lambda_timeout_checker" {
  description = "Timeout in seconds for checker Lambdas"
  type        = number
  default     = 300
}

variable "lambda_memory_checker" {
  description = "Memory in MB for checker Lambdas"
  type        = number
  default     = 256
}

variable "lambda_timeout_orchestrator" {
  description = "Timeout in seconds for the trigger Lambda"
  type        = number
  default     = 900
}

variable "lambda_memory_orchestrator" {
  description = "Memory in MB for the trigger Lambda"
  type        = number
  default     = 512
}

variable "scan_schedule" {
  description = "EventBridge cron schedule for the anomaly scan"
  type        = string
  default     = "cron(50 7 * * ? *)"  # Daily at 08:00 UTC — before business hours
}

variable "enable_xray_tracing" {
  description = "Enable X-Ray tracing on Lambda functions"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
