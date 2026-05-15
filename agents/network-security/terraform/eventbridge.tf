# agents/network-security/terraform/eventbridge.tf

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Network Security Agent full scan daily at 06:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "NetworkSecurityAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full network security scan. Check VPCs, security groups, NACLs, DNS, and Transit Gateways. Escalate CRITICAL and HIGH findings immediately. End with save_network_report."
  })
}

resource "aws_lambda_permission" "eventbridge_trigger" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
