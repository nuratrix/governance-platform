# ─────────────────────────────────────────────────────────────────────────────
# agents/infrastructure/terraform/eventbridge.tf
# Daily scheduled scan — triggers at 06:00 UTC.
# Prompt is passed in the EventBridge input so infra_agent_trigger.py
# stays generic and shared across all agents.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Infra Agent full scan daily at 06:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "InfraAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full infra audit. Identify unhealthy, wasteful,and non-compliant infrastructure. Always run check_ec2 and check_network first. Escalate HIGH findings via escalate_to_human. Never terminate or delete resources without human approval. End every session with save_infra_report"
  })
}

# Second target: fan-out publisher for parallel per-account scanning.
