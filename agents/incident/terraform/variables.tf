# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/variables.tf
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
  description = "Bedrock foundation model ID for the Incident Agent"
  type        = string
  default     = "amazon.nova-pro-v1:0"
}

variable "scan_schedule" {
  description = "EventBridge cron for periodic incident detection scans"
  type        = string
  default     = "cron(0/15 * * * ? *)"  # Every 15 minutes
}

variable "lambda_timeout_checker" {
  description = "Timeout in seconds for detector and diagnostic Lambdas"
  type        = number
  default     = 300
}

variable "lambda_memory_checker" {
  description = "Memory in MB for detector and diagnostic Lambdas"
  type        = number
  default     = 256
}

variable "lambda_timeout_trigger" {
  description = "Timeout in seconds for the trigger Lambda"
  type        = number
  default     = 900
}

variable "lambda_memory_trigger" {
  description = "Memory in MB for the trigger Lambda"
  type        = number
  default     = 256
}

variable "enable_xray_tracing" {
  description = "Enable X-Ray active tracing on Lambda functions"
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
