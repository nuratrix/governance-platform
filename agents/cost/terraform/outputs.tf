# ─────────────────────────────────────────────────────────────────────────────
# agents/cost/terraform/outputs.tf
# ─────────────────────────────────────────────────────────────────────────────

output "agent_id" {
  description = "Cost Bedrock Agent ID"
  value       = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  description = "Cost Bedrock Agent Name"
  value       = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  description = "Cost Bedrock Agent Alias ID"
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
  description = "IAM role ARN used by all Cost Agent Lambda functions"
  value       = aws_iam_role.lambda.arn
}

output "lambda_role_name" {
  description = "IAM role name used by all Cost Agent Lambda functions"
  value       = aws_iam_role.lambda.name
}

output "daily_scan_rule_arn" {
  description = "EventBridge rule ARN for the daily scheduled scan"
  value       = aws_cloudwatch_event_rule.daily_scan.arn
}

output "checker_function_arns" {
  description = "Map of checker name to Lambda function ARN"
  value = {
    ec2_cost     = module.lambda_ec2_cost_checker.function_arn
    reservations = module.lambda_reservations_checker.function_arn
    rds_cost     = module.lambda_rds_cost_checker.function_arn
    s3_cost      = module.lambda_s3_cost_checker.function_arn
  }
}

output "infra_manual_invoke" {
  value = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run a full cost analysis. Identify wasteful spend and recommend or execute savings actions." \
      --region ${var.aws_region}
  CMD
}
