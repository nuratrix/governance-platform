variable "governance_account_id" {
  description = "AWS account ID of the central governance account that will assume this role"
  type        = string
}

variable "account_name" {
  description = "Human-readable name for this member account (used in tags)"
  type        = string
}

variable "role_name" {
  description = "Name of the cross-account reader role to create"
  type        = string
  default     = "governance-platform-reader"
}
