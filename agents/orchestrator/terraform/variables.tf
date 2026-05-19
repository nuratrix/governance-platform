# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/variables.tf
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "production"
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
  description = "Bedrock foundation model for the Orchestrator Agent"
  type        = string
  default     = "amazon.nova-pro-v1:0"
}

# ── Enabled agents — controls which sub-agents the Orchestrator references ────
# Comma-separated list matching the bundle selection (e.g. "security,cost").
# The Orchestrator only references agents whose IDs are non-empty AND whose
# name appears in this list. Defaults to all agents for backwards compatibility.
variable "enabled_agents" {
  description = "Comma-separated list of deployed sub-agent names. Controls Orchestrator scope."
  type        = string
  default     = "security,cost,infrastructure,compliance,incident,cost_anomaly,network_security,access_analyzer,backup_dr"
}

# ── Sub-agent IDs — populated from each agent's terraform output ──────────────
# All default to "" so the Orchestrator can be deployed for partial bundles.
# The Orchestrator's Lambda and Bedrock instruction skip agents with empty IDs.

variable "security_agent_id" {
  description = "Bedrock Agent ID of the Security Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "security_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Security Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "cost_agent_id" {
  description = "Bedrock Agent ID of the Cost Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "cost_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Cost Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "compliance_agent_id" {
  description = "Bedrock Agent ID of the Compliance Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "compliance_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Compliance Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "incident_agent_id" {
  description = "Bedrock Agent ID of the Incident Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "incident_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Incident Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "infrastructure_agent_id" {
  description = "Bedrock Agent ID of the Infrastructure Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "infrastructure_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Infrastructure Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "cost_anomaly_agent_id" {
  description = "Bedrock Agent ID of the Cost Anomaly Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "cost_anomaly_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Cost Anomaly Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "network_security_agent_id" {
  description = "Bedrock Agent ID of the Network Security Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "network_security_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Network Security Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "access_analyzer_agent_id" {
  description = "Bedrock Agent ID of the IAM Access Analyzer Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "access_analyzer_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the IAM Access Analyzer Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "backup_dr_agent_id" {
  description = "Bedrock Agent ID of the Backup & DR Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "backup_dr_agent_alias_id" {
  description = "Bedrock Agent Alias ID of the Backup & DR Agent. Empty string if not deployed."
  type        = string
  default     = ""
}

variable "lambda_timeout_router" {
  description = "Timeout for the SNS router Lambda (must be short — SNS times out at 15s)"
  type        = number
  default     = 60
}

variable "lambda_timeout_handler" {
  description = "Timeout for the action handler Lambda"
  type        = number
  default     = 300
}

variable "lambda_timeout_trigger" {
  description = "Timeout for the Bedrock Agent trigger Lambda"
  type        = number
  default     = 900
}

variable "lambda_memory" {
  description = "Memory in MB for Lambda functions"
  type        = number
  default     = 256
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
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
