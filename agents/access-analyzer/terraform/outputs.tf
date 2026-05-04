output "agent_id"       { value = aws_bedrockagent_agent.this.agent_id }
output "agent_name"     { value = aws_bedrockagent_agent.this.agent_name }
output "agent_alias_id" { value = aws_bedrockagent_agent_alias.live.agent_alias_id }
output "trigger_function_name"       { value = module.lambda_trigger.function_name }
output "action_handler_function_name" { value = module.lambda_action_handler.function_name }
output "lambda_role_arn"  { value = aws_iam_role.lambda.arn }
output "lambda_role_name" { value = aws_iam_role.lambda.name }
output "daily_scan_rule_arn" { value = aws_cloudwatch_event_rule.daily_scan.arn }
output "checker_function_arns" {
  value = {
    access_analyzer_checker    = module.lambda_access_analyzer_checker.function_arn
    unused_permissions_checker = module.lambda_unused_permissions_checker.function_arn
  }
}
output "manual_invoke" {
  value = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run a full IAM and access analyzer scan." \
      --region ${var.aws_region}
  CMD
}
