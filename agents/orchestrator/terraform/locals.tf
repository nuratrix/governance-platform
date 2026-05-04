# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/locals.tf — Multi-Account Edition
# ─────────────────────────────────────────────────────────────────────────────

locals {
  prefix = "governance-orchestrator"

  findings_table_name    = data.terraform_remote_state.platform.outputs.findings_table_name
  findings_table_arn     = data.terraform_remote_state.platform.outputs.findings_table_arn
  alerts_topic_arn       = data.terraform_remote_state.platform.outputs.alerts_topic_arn
  orchestrator_topic_arn = data.terraform_remote_state.platform.outputs.orchestrator_topic_arn
  account_id             = data.terraform_remote_state.platform.outputs.account_id
  rules_bucket_name      = data.terraform_remote_state.platform.outputs.knowledge_base_bucket
  account_registry_table = data.terraform_remote_state.platform.outputs.account_registry_table_name

  # Environment variables for router and handler Lambdas
  lambda_env = {
    FINDINGS_TABLE         = local.findings_table_name
    ALERT_TOPIC_ARN        = local.alerts_topic_arn
    ORCHESTRATOR_TOPIC_ARN = local.orchestrator_topic_arn
    RULES_BUCKET           = local.rules_bucket_name
    TEAMS_WEBHOOK_URL      = data.terraform_remote_state.platform.outputs.teams_webhook_url
    SLACK_WEBHOOK_URL      = data.terraform_remote_state.platform.outputs.slack_webhook_url
    TEAMS_SECRET_ARN       = "governance-platform/teams-webhook-url"
    SLACK_SECRET_ARN       = "governance-platform/slack-webhook-url"
    # Sub-agent IDs so the action handler can invoke them on demand
    SECURITY_AGENT_ID             = var.security_agent_id
    SECURITY_AGENT_ALIAS_ID       = var.security_agent_alias_id
    COST_AGENT_ID                 = var.cost_agent_id
    COST_AGENT_ALIAS_ID           = var.cost_agent_alias_id
    COMPLIANCE_AGENT_ID           = var.compliance_agent_id
    COMPLIANCE_AGENT_ALIAS_ID     = var.compliance_agent_alias_id
    INCIDENT_AGENT_ID             = var.incident_agent_id
    INCIDENT_AGENT_ALIAS_ID       = var.incident_agent_alias_id
    INFRASTRUCTURE_AGENT_ID       = var.infrastructure_agent_id
    INFRASTRUCTURE_AGENT_ALIAS_ID = var.infrastructure_agent_alias_id
    # ── Multi-Account env vars ─────────────────────────────────────────────
    GOVERNANCE_ACCOUNT_ID         = local.account_id
    ACCOUNT_REGISTRY_TABLE        = local.account_registry_table
    SCAN_REGIONS                  = data.terraform_remote_state.platform.outputs.scan_regions
  }
}
