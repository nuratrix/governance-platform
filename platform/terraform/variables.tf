# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/variables.tf
# Multi-Account: adds member_accounts variable to define all governed accounts.
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy into (governance account)"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name — used in default tags"
  type        = string
  default     = "production"
}

variable "alert_email" {
  description = "Email address to receive platform-level alerts"
  type        = string
}

variable "kms_key_arn" {
  description = "Optional CMK ARN for DynamoDB and SNS encryption. Leave empty to use AWS-managed keys."
  type        = string
  default     = ""
}

variable "github_org" {
  description = "GitHub username or organisation name (e.g. acme-corp)"
  type        = string
  default     = "unalla"
}

variable "github_repo" {
  description = "Repository name without the org prefix"
  type        = string
  default     = "aws-governance-platform-multi-account"
}

variable "github_branch" {
  description = "Branch allowed to deploy"
  type        = string
  default     = "main"
}

variable "findings_ttl_days" {
  description = "Number of days before findings expire from DynamoDB"
  type        = number
  default     = 90
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 30
}

variable "teams_webhook_url" {
  description = "Microsoft Teams Incoming Webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL"
  type        = string
  default     = ""
  sensitive   = true
}

# ─────────────────────────────────────────────────────────────────────────────
# Multi-Account: List of AWS accounts the platform will govern.
# The governance account itself is added automatically via data sources.
# Each member account must have the cross-account reader role deployed
# (see platform/terraform/modules/member_account/).
# ─────────────────────────────────────────────────────────────────────────────
variable "member_accounts" {
  description = <<-EOT
    List of AWS member accounts for the governance platform to scan.
    Each object requires:
      account_id  — 12-digit AWS account ID
      name        — human-readable alias (used in alerts and DynamoDB tags)
      env         — environment tier: production | staging | sandbox
      reader_role — name of the cross-account IAM role deployed in that account
                    (default: governance-platform-reader)
  EOT

  type = list(object({
    account_id  = string
    name        = string
    env         = string
    reader_role = optional(string, "governance-platform-reader")
  }))

  default = []

  validation {
    condition = alltrue([
      for a in var.member_accounts :
      contains(["production", "staging", "sandbox", "development"], a.env)
    ])
    error_message = "Each member account env must be one of: production, staging, sandbox, development."
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# Multi-Account: Deploy cross-account reader roles via Terraform.
# Set to true only if you have Terraform credentials for all member accounts.
# If false, deploy member_account module manually or via a separate pipeline.
# ─────────────────────────────────────────────────────────────────────────────
variable "deploy_member_roles" {
  description = "If true, the platform will use provider aliases to deploy reader roles in each member account automatically."
  type        = bool
  default     = false
}

# ─────────────────────────────────────────────────────────────────────────────
# Findings access: no direct human/team access to the findings table.
# All reporting goes through the chatbot Lambda (see platform/terraform/rbac.tf).
# ─────────────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ─────────────────────────────────────────────────────────────────────────────
# StackSet: automatically deploy governance-platform-reader to member accounts.
# Set to one or more OU IDs (e.g. ["ou-ab12-cde34fgh"]) to enable.
# Requires CloudFormation trusted access with Organizations to be activated
# in the governance / management account before running terraform apply.
# Leave empty ([]) to manage reader roles manually or via the GitHub workflow.
# ─────────────────────────────────────────────────────────────────────────────
variable "stackset_target_ou_ids" {
  description = "OU IDs to deploy the governance-platform-reader role into via CloudFormation StackSets. Empty disables StackSet deployment."
  type        = list(string)
  default     = []
}

# ─────────────────────────────────────────────────────────────────────────────
# Multi-Region scanning: controls which AWS regions agent checkers scan.
# Empty (default) = deployment region only — no cost increase, no behaviour change.
# ["all"]         = all enabled regions discovered at runtime via describe_regions.
# ["us-east-1","eu-west-1"] = explicit region list.
# Customers opt in by setting SCAN_REGIONS in their GitHub Environment.
# ─────────────────────────────────────────────────────────────────────────────
variable "scan_regions" {
  description = "Regions for agent checkers to scan. Empty = deployment region only. [\"all\"] = all enabled regions."
  type        = list(string)
  default     = []
}

variable "dashboard_allowed_origins" {
  description = "Optional comma-separated extra origins to allow in addition to the CloudFront distribution URL (e.g. 'http://localhost:3000' for local dev). Leave empty in production."
  type        = string
  default     = ""
}
