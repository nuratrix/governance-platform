resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.prefix}-daily-scan"
  description         = "Trigger IAM Access Analyzer Agent daily at 07:00 UTC"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "AccessAnalyzerAgentTrigger"
  arn       = module.lambda_trigger.function_arn

  input = jsonencode({
    scan_type    = "full"
    triggered_by = "scheduled"
    prompt       = "Run a full IAM and access analyzer scan. Check for external/public resource access and unused credentials. Escalate CRITICAL and HIGH findings. End with save_iam_report."
  })
}

resource "aws_lambda_permission" "eventbridge_trigger" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
