# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/eventbridge.tf
# Periodic scan every 15 minutes — unlike other agents which run daily,
# the Incident Agent needs near-real-time detection.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "periodic_scan" {
  name                = "${local.prefix}-periodic-scan"
  description         = "Trigger Incident Agent detection scan every 15 minutes"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "periodic_scan" {
  rule      = aws_cloudwatch_event_rule.periodic_scan.name
  target_id = "IncidentAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "detection"
    triggered_by = "scheduled"
    prompt       = "Run incident detection. Check CloudWatch alarms, load balancer health, Lambda errors, EC2 status checks and log patterns. For every CRITICAL finding immediately run diagnostics and escalate to human. For HIGH findings run diagnostics and recommend action. Save the incident report at the end."
  })
}

resource "aws_lambda_permission" "eventbridge_trigger" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.periodic_scan.arn
}
