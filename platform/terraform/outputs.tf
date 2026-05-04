# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/outputs.tf
# Multi-Account: added member_accounts, account_registry_table, and
# member_role_arns outputs consumed by all agent Terraform modules.
# ─────────────────────────────────────────────────────────────────────────────

output "findings_table_name" {
  description = "Shared DynamoDB findings table name"
  value       = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  description = "Shared DynamoDB findings table ARN"
  value       = aws_dynamodb_table.findings.arn
}

output "alerts_topic_arn" {
  description = "Shared SNS alerts topic ARN — used by all agents for human escalation"
  value       = aws_sns_topic.alerts.arn
}

output "orchestrator_topic_arn" {
  description = "SNS topic ARN for agent-to-orchestrator notifications"
  value       = aws_sns_topic.orchestrator.arn
}

output "account_id" {
  description = "Governance AWS account ID"
  value       = local.account_id
}

output "region" {
  description = "AWS region"
  value       = local.region
}

output "knowledge_base_bucket" {
  description = "S3 bucket name for uploading rule documents"
  value       = aws_s3_bucket.knowledge_base.bucket
}

# ── Multi-Account outputs ─────────────────────────────────────────────────────

output "member_accounts" {
  description = "Full list of governed accounts (governance + all members) — consumed by agents to iterate scans"
  value       = local.all_accounts
}

output "member_account_ids" {
  description = "Flat list of member account IDs (excludes governance account)"
  value       = local.member_account_ids
}

output "member_role_arns" {
  description = "Map of account_id → cross-account reader role ARN — used by Lambda to assume into each member account"
  value       = local.member_role_arns
}

output "account_registry_table_name" {
  description = "DynamoDB account registry table name — agents query this at runtime"
  value       = aws_dynamodb_table.account_registry.name
}

output "account_registry_table_arn" {
  description = "DynamoDB account registry table ARN"
  value       = aws_dynamodb_table.account_registry.arn
}

# ─ Notifications ─────────────────────────────────────────────────────────────

output "teams_webhook_url" {
  value     = var.teams_webhook_url
  sensitive = true
}

output "slack_webhook_url" {
  value     = var.slack_webhook_url
  sensitive = true
}

# ── Multi-Region ──────────────────────────────────────────────────────────────

output "scan_regions" {
  description = "Comma-separated regions for agent checkers — consumed by Lambda env var SCAN_REGIONS"
  value       = length(var.scan_regions) > 0 ? join(",", var.scan_regions) : var.aws_region
}
