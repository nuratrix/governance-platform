# ─────────────────────────────────────────────────────────────────────────────
# agents/cost/terraform/eventbridge.tf
# Daily scheduled scan — triggers at 09:00 UTC.
# Prompt is passed in the EventBridge input so bedrock_agent_trigger.py
# stays generic and shared across all agents.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Infra Agent full scan daily at 09:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "CostAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full cost analysis. Identify wasteful spend and recommend or execute savings actions.. Never terminate or delete resources without human approval. End every session with save_cost_report"
  })
}

resource "aws_lambda_permission" "eventbridge_trigger" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
