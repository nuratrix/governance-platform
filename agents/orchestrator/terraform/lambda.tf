# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/lambda.tf
# Three Lambda functions:
#   1. router         — receives SNS from sub-agents, decides to invoke Bedrock
#   2. action_handler — Bedrock Agent tool router
#   3. trigger        — daily summary scan at 10:00 UTC
# ─────────────────────────────────────────────────────────────────────────────

# ─── SNS Router ───────────────────────────────────────────────────────────────
# Triggered by SNS subscription on the orchestrator topic.
# Must be fast — SNS has a short delivery timeout.

module "lambda_router" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-router"
  handler       = "orchestrator_router.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_router
  memory_size   = var.lambda_memory
  environment   = merge(local.lambda_env, {
    BEDROCK_AGENT_ID       = aws_bedrockagent_agent.this.agent_id
    BEDROCK_AGENT_ALIAS_ID = aws_bedrockagent_agent_alias.live.agent_alias_id
  })
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Bedrock Action Handler ───────────────────────────────────────────────────
# Routes Bedrock Agent tool calls — findings queries, conflict detection,
# sub-agent invocation, platform health and reporting.

module "lambda_action_handler" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-action-handler"
  handler       = "bedrock_action_handler.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_handler
  memory_size   = 512
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Daily Summary Trigger ────────────────────────────────────────────────────
# Runs at 10:00 UTC — after all sub-agents have completed their morning scans
# (Security 06:00, Infra 07:00, Compliance 08:00, Cost 09:00)
# Produces a cross-agent executive summary for the day.

module "lambda_trigger" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-trigger"
  handler       = "bedrock_agent_trigger.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_trigger
  memory_size   = var.lambda_memory
  environment   = merge(local.lambda_env, {
    BEDROCK_AGENT_ID       = aws_bedrockagent_agent.this.agent_id
    BEDROCK_AGENT_ALIAS_ID = aws_bedrockagent_agent_alias.live.agent_alias_id
    BEDROCK_AGENT_NAME     = aws_bedrockagent_agent.this.agent_name
    DEFAULT_PROMPT         = "Run the daily platform summary. Query findings from all agents in the last 24 hours using query_agent_findings. Check for conflicts using detect_conflicts. Get the overall platform health using get_platform_health. Produce an executive summary covering security posture, compliance score, cost optimisation opportunities and any active incidents. Escalate any unresolved CRITICAL findings. Save the coordination report."
    BEDROCK_INVOKE_QUEUE_URL = aws_sqs_queue.bedrock_invoke_queue.url
  })
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# Bedrock invoker: SQS-triggered, calls invoke_agent for exactly one account per invocation.
module "lambda_bedrock_invoker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-bedrock-invoker"
  handler       = "bedrock_invoker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = 330
  memory_size   = 256
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}
