# agents/network-security/terraform/outputs.tf

output "agent_id" {
  description = "Network Security Bedrock Agent ID"
  value       = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  description = "Network Security Bedrock Agent Name"
  value       = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  description = "Network Security Bedrock Agent Alias ID"
  value       = aws_bedrockagent_agent_alias.live.agent_alias_id
}

output "trigger_function_name" {
  value = module.lambda_trigger.function_name
}

output "action_handler_function_name" {
  value = module.lambda_action_handler.function_name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda.arn
}

output "lambda_role_name" {
  value = aws_iam_role.lambda.name
}

output "daily_scan_rule_arn" {
  value = aws_cloudwatch_event_rule.daily_scan.arn
}

output "checker_function_arns" {
  value = {
    vpc_checker  = module.lambda_vpc_checker.function_arn
    nacl_checker = module.lambda_nacl_checker.function_arn
    dns_checker  = module.lambda_dns_checker.function_arn
  }
}

output "manual_invoke" {
  value = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run a full network security scan." \
      --region ${var.aws_region}
  CMD
}
