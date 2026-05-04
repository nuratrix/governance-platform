# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/cloudwatch.tf
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "router_errors" {
  alarm_name          = "${local.prefix}-router-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Orchestrator router Lambda error — sub-agent notifications may be lost"
  alarm_actions       = [local.alerts_topic_arn]
  ok_actions          = [local.alerts_topic_arn]

  dimensions = {
    FunctionName = module.lambda_router.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "action_handler_errors" {
  alarm_name          = "${local.prefix}-action-handler-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Orchestrator action handler Lambda error"
  alarm_actions       = [local.alerts_topic_arn]

  dimensions = {
    FunctionName = module.lambda_action_handler.function_name
  }
}
