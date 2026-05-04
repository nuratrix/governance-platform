# ─────────────────────────────────────────────────────────────────────────────
# agents/compliance/terraform/eventbridge.tf
# Daily scheduled scan — triggers at 06:00 UTC.
# Prompt is passed in the EventBridge input so bedrock_agent_trigger.py
# stays generic and shared across all agents.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Infra Agent full scan daily at 08:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "ComplianceAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full compliance audit covering CIS, SOC2, and AWS Config rules. Compute the compliance score and save the report."
  })
}

# Second target: fan-out publisher for parallel per-account scanning.
