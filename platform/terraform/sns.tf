# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/sns.tf
# Unchanged from single-account version.
# All agents in all accounts publish to these central topics.
# ─────────────────────────────────────────────────────────────────────────────

# Human alert topic — all agents publish CRITICAL/HIGH findings here
resource "aws_sns_topic" "alerts" {
  name              = "${local.prefix}-alerts"
  kms_master_key_id = var.kms_key_arn != "" ? var.kms_key_arn : "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Orchestrator notification topic — agents publish scan completion events here
resource "aws_sns_topic" "orchestrator" {
  name              = "${local.prefix}-orchestrator"
  kms_master_key_id = var.kms_key_arn != "" ? var.kms_key_arn : "alias/aws/sns"
}
