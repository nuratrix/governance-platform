variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "environment" {
  type    = string
  default = "production"
}
variable "platform_state_bucket" {
  type = string
}
variable "platform_state_key" {
  type    = string
  default = "platform/terraform.tfstate"
}
variable "foundation_model" {
  type    = string
  default = "anthropic.claude-haiku-4-5-20251001-v1:0"
}
variable "lambda_timeout_checker" {
  type    = number
  default = 300
}
variable "lambda_memory_checker" {
  type    = number
  default = 256
}
variable "lambda_timeout_orchestrator" {
  type    = number
  default = 900
}
variable "lambda_memory_orchestrator" {
  type    = number
  default = 512
}
variable "scan_schedule" {
  type    = string
  default = "cron(30 7 * * ? *)"
} # 05:00 UTC daily
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
