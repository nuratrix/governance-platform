# ─────────────────────────────────────────────────────────────────────────────
# agents/cost/terraform/lambda.tf
# All Lambda functions for the Cost Agent.
# Uses the shared module from platform/terraform/modules/lambda.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  module_path = "../../../platform/terraform/modules/lambda"
}

# ─── Checker Lambdas ──────────────────────────────────────────────────────────

module "lambda_ec2_cost_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-ec2-cost-checker"
  handler       = "ec2_cost_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

module "lambda_rds_cost_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-rds-cost-checker"
  handler       = "rds_cost_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

module "lambda_s3_cost_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-s3-cost-checker"
  handler       = "s3_cost_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

module "lambda_reservations_checker" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-reservations-checker"
  handler       = "reservations_checker.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Bedrock Action Handler ───────────────────────────────────────────────────
# Routes all Bedrock Agent tool calls to the checker Lambdas above.
# Also handles remediation (stop EC2, delete EBS) and reporting.

module "lambda_action_handler" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-action-handler"
  handler       = "bedrock_action_handler.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = 300
  memory_size   = 512
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Bedrock Agent Trigger ────────────────────────────────────────────────────
# Shared trigger Lambda from shared/bedrock_agent_trigger.py.
# Prompt is injected via EventBridge input payload — not hardcoded here.
# BEDROCK_AGENT_ID and BEDROCK_AGENT_ALIAS_ID are merged into the environment
# so the trigger knows which agent to invoke.

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
    DEFAULT_PROMPT         = "Run a full cost optimisation scan. Check EC2, RDS, S3 and reservations. For findings over $500/month saving, escalate to human. Auto-remediate unattached EBS volumes older than 30 days only. End with save_cost_report including total potential savings and top recommendations."
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
