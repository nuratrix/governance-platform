resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger Security Agent full scan daily at 06:00 UTC across all accounts"
  schedule_expression = var.scan_schedule
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "SecurityAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full security audit. Start with check_guardduty to identify active threats. Then run check_iam, check_s3, check_security_groups, check_cloudtrail and check_kms. If GuardDuty has CRITICAL findings use get_cloudtrail_events to investigate. Auto-remediate LOW severity only. Escalate CRITICAL and HIGH to escalate_to_human. End with save_scan_report including an executive summary."
  })
}

# Allow EventBridge to invoke the trigger Lambda
resource "aws_lambda_permission" "eventbridge_trigger" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
