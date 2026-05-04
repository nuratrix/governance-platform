# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/outputs.tf
# ─────────────────────────────────────────────────────────────────────────────

output "agent_id" {
  description = "Incident Bedrock Agent ID"
  value       = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  description = "Incident Bedrock Agent Name"
  value       = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  description = "Incident Bedrock Agent Alias ID"
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

output "manual_invoke_command" {
  description = "AWS CLI command to manually trigger an incident scan"
  value       = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run a full incident detection scan and report findings." \
      --region ${var.aws_region}
  CMD
}
