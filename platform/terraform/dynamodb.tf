# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/dynamodb.tf
# Multi-Account changes:
#   1. Added account_id attribute — every finding must carry the source account.
#   2. Added account-agent-timestamp-index GSI — enables "all findings for
#      account X from agent Y in the last N hours" queries in the Orchestrator
#      and per-agent action handlers.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "findings" {
  name         = "${local.prefix}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  # Sort key enables range queries by timestamp
  attribute {
    name = "timestamp"
    type = "S"
  }

  # Original GSI: query all findings from a specific agent across all accounts
  attribute {
    name = "agent"
    type = "S"
  }

  global_secondary_index {
    name            = "agent-timestamp-index"
    hash_key        = "agent"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  # ── Multi-Account: account_id dimension ──────────────────────────────────────
  # Allows queries like: "all findings for account 123456789012 in the last 24h"
  attribute {
    name = "account_id"
    type = "S"
  }

  global_secondary_index {
    name            = "account-agent-timestamp-index"
    hash_key        = "account_id"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn != "" ? var.kms_key_arn : null
  }
}

# ── Account Registry Table ────────────────────────────────────────────────────
# Stores the list of governed accounts with metadata.
# Agents read this at runtime to know which accounts to scan.
# Seeded by platform Terraform; can also be updated manually.
resource "aws_dynamodb_table" "account_registry" {
  name         = "${local.prefix}-account-registry"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "account_id"

  attribute {
    name = "account_id"
    type = "S"
  }

  # Optional sort key for versioning / audit trail
  attribute {
    name = "updated_at"
    type = "S"
  }

  global_secondary_index {
    name            = "updated-at-index"
    hash_key        = "account_id"
    range_key       = "updated_at"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn != "" ? var.kms_key_arn : null
  }
}

# ── Seed the account registry with the configured member accounts ─────────────
# Uses a null_resource + local-exec is fragile; use aws_dynamodb_table_item instead.
resource "aws_dynamodb_table_item" "governance_account" {
  table_name = aws_dynamodb_table.account_registry.name
  hash_key   = aws_dynamodb_table.account_registry.hash_key

  item = jsonencode({
    account_id  = { S = local.account_id }
    name        = { S = "governance-account" }
    env         = { S = var.environment }
    reader_role = { S = "self" }
    updated_at  = { S = "bootstrapped" }
    is_governance = { BOOL = true }
  })
}

resource "aws_dynamodb_table_item" "member_accounts" {
  for_each   = { for a in var.member_accounts : a.account_id => a }
  table_name = aws_dynamodb_table.account_registry.name
  hash_key   = aws_dynamodb_table.account_registry.hash_key

  item = jsonencode({
    account_id  = { S = each.value.account_id }
    name        = { S = each.value.name }
    env         = { S = each.value.env }
    reader_role = { S = each.value.reader_role }
    role_arn    = { S = "arn:aws:iam::${each.value.account_id}:role/${each.value.reader_role}" }
    updated_at  = { S = "bootstrapped" }
    is_governance = { BOOL = false }
  })
}
