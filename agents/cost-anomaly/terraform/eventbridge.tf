# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/eventbridge.tf
# Daily anomaly scan — runs at 08:00 UTC before business hours.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Cost Anomaly Agent full scan daily at 08:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "CostAnomalyAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full cost anomaly scan. Check for active anomalies and analyse root causes. Escalate all CRITICAL and HIGH findings. End with save_anomaly_report."
  })
}

# Second target: fan-out publisher for parallel per-account scanning.
