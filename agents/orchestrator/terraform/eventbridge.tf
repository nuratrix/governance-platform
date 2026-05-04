# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/eventbridge.tf
# Daily summary scan at 10:00 UTC — after all sub-agents have completed
# their morning scans (Security 06:00, Infra 07:00, Compliance 08:00, Cost 09:00)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_summary" {
  name                = "${local.prefix}-daily-summary"
  description         = "Trigger Orchestrator daily platform summary at 10:00 UTC"
  schedule_expression = "cron(0 10 * * ? *)"
}

resource "aws_cloudwatch_event_target" "daily_summary" {
  rule      = aws_cloudwatch_event_rule.daily_summary.name
  target_id = "OrchestratorDailySummary"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "daily_summary"
    triggered_by = "scheduled"
    prompt       = "Run the daily platform summary. Query all agent findings from the last 24 hours. Detect conflicts. Get overall platform health. Produce an executive summary covering: (1) security posture, (2) compliance score, (3) cost saving opportunities, (4) any active incidents, (5) any unresolved conflicts between agents. Escalate unresolved CRITICAL findings. Save the coordination report."
  })
}
