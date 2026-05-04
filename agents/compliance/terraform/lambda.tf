# ─────────────────────────────────────────────────────────────────────────────
# agents/compliance/terraform/lambda.tf
# All Lambda functions for the Compliance Agent.
# Uses the shared module from platform/terraform/modules/lambda.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  module_path = "../../../platform/terraform/modules/lambda"
}

# ─── Checker Lambdas ──────────────────────────────────────────────────────────

module "lambda_soc2_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-soc2-checker"
  handler       = "soc2_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

module "lambda_config_rules_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-config-rules-checker"
  handler       = "config_rules_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

module "lambda_cis_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-cis-checker"
  handler       = "cis_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# This single Lambda handles ALL action group tool calls from the agent
module "lambda_action_handler" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-action-handler"
  handler       = "bedrock_action_handler.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Bedrock Agent Trigger ────────────────────────────────────────────────────
# Shared trigger Lambda — prompt comes from EventBridge input payload

module "lambda_trigger" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-trigger"
  handler       = "bedrock_agent_trigger.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_orchestrator
  memory_size   = var.lambda_memory_orchestrator
  environment   = merge(local.lambda_env, {
    BEDROCK_AGENT_ID       = aws_bedrockagent_agent.this.agent_id
    BEDROCK_AGENT_ALIAS_ID = aws_bedrockagent_agent_alias.live.agent_alias_id
    BEDROCK_AGENT_NAME     = aws_bedrockagent_agent.this.agent_name
    DEFAULT_PROMPT         = "Run a full compliance audit covering CIS, SOC2, and AWS Config rules. Compute the compliance score and save the report."
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
