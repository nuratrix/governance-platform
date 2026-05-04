# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/outputs.tf
# ─────────────────────────────────────────────────────────────────────────────

output "agent_id" {
  description = "Orchestrator Bedrock Agent ID"
  value       = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  description = "Orchestrator Bedrock Agent Name"
  value       = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  description = "Orchestrator Bedrock Agent Alias ID"
  value       = aws_bedrockagent_agent_alias.live.agent_alias_id
}

output "router_function_name" {
  description = "SNS router Lambda function name"
  value       = module.lambda_router.function_name
}

output "manual_invoke_command" {
  description = "CLI command to manually trigger the Orchestrator"
  value       = <<-CMD
    aws bedrock-agent-runtime invoke-agent \
      --agent-id ${aws_bedrockagent_agent.this.agent_id} \
      --agent-alias-id ${aws_bedrockagent_agent_alias.live.agent_alias_id} \
      --session-id manual-$(date +%s) \
      --input-text "Run the daily platform summary across all agents." \
      --region ${var.aws_region}
  CMD
}
