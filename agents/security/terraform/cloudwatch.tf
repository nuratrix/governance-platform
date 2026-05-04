resource "aws_cloudwatch_metric_alarm" "trigger_errors" {
  alarm_name          = "${local.prefix}-trigger-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Security Agent trigger Lambda threw an unhandled error"
  alarm_actions       = [local.alerts_topic_arn]
  ok_actions          = [local.alerts_topic_arn]
  dimensions          = { FunctionName = module.lambda_trigger.function_name }
}

resource "aws_cloudwatch_metric_alarm" "trigger_duration" {
  alarm_name          = "${local.prefix}-trigger-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Maximum"
  threshold           = var.lambda_timeout_orchestrator * 1000 * 0.9
  treat_missing_data  = "notBreaching"
  alarm_description   = "Security Agent trigger Lambda is approaching its timeout limit"
  alarm_actions       = [local.alerts_topic_arn]
  dimensions          = { FunctionName = module.lambda_trigger.function_name }
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
  alarm_description   = "Security Agent action handler Lambda threw an unhandled error"
  alarm_actions       = [local.alerts_topic_arn]
  dimensions          = { FunctionName = module.lambda_action_handler.function_name }
}
