# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/locals.tf
# Multi-Account: derives member_account_ids list and reader role ARNs.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  prefix     = "governance-platform"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Build a flat list of all account IDs being governed (governance + members).
  # Agents use this to fan-out their scans.
  member_account_ids = [for a in var.member_accounts : a.account_id]

  # Build a map of account_id → cross-account reader role ARN.
  # Lambda functions assume these roles before calling AWS APIs in member accounts.
  member_role_arns = {
    for a in var.member_accounts :
    a.account_id => "arn:aws:iam::${a.account_id}:role/${a.reader_role}"
  }

  # Full account registry — governance account + all members — exposed as output
  # so agents can iterate without re-reading the variable.
  all_accounts = concat(
    [{
      account_id  = local.account_id
      name        = "governance-account"
      env         = var.environment
      reader_role = "self"           # governance account uses Lambda's own role
    }],
    var.member_accounts
  )
}
