# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/outputs.tf
# ─────────────────────────────────────────────────────────────────────────────

output "agent_id" {
  description = "Cost Anomaly Bedrock Agent ID"
  value       = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  description = "Cost Anomaly Bedrock Agent Name"
  value       = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  description = "Cost Anomaly Bedrock Agent Alias ID"
  value       = aws_bedrockagent_agent_alias.live.agent_alias_id
}

output "trigger_function_name" {
  description = "Name of the trigger Lambda function"
  value       = module.lambda_trigger.function_name
}

output "action_handler_function_name" {
  description = "Name of the Bedrock action handler Lambda"
  value       = module.lambda_action_handler.function_name
}

output "lambda_role_arn" {
  description = "IAM role ARN used by all Cost Anomaly Agent Lambda functions"
  value       = aws_iam_role.lambda.arn
}

output "lambda_role_name" {
  description = "IAM role name used by all Cost Anomaly Agent Lambda functions"
  value       = aws_iam_role.lambda.name
}

output "daily_scan_rule_arn" {
  description = "EventBridge rule ARN for the daily scheduled scan"
  value       = aws_cloudwatch_event_rule.daily_scan.arn
}

output "checker_function_arns" {
  description = "Map of checker name to Lambda function ARN"
  value = {
    anomaly_detector    = module.lambda_anomaly_detector.function_arn
    root_cause_analyzer = module.lambda_root_cause_analyzer.function_arn
  }
}

output "manual_invoke" {
  value = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run a full cost anomaly scan. Check for active anomalies and analyse root causes." \
      --region ${var.aws_region}
  CMD
}
