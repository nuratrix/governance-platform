# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/lambda.tf
# All Lambda functions for the Incident Agent.
# Uses the shared module from platform/terraform/modules/lambda.
# ─────────────────────────────────────────────────────────────────────────────

# ─── Detector Lambda ──────────────────────────────────────────────────────────

module "lambda_incident_detector" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-detector"
  handler       = "incident_detector.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Diagnostic Runner Lambda ─────────────────────────────────────────────────

module "lambda_diagnostic_runner" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-diagnostic-runner"
  handler       = "diagnostic_runner.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_checker
  memory_size   = var.lambda_memory_checker
  environment   = local.lambda_env
  enable_xray   = var.enable_xray_tracing
  log_retention = var.log_retention_days
}

# ─── Auto Healer Lambda ───────────────────────────────────────────────────────

module "lambda_auto_healer" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-auto-healer"
  handler       = "auto_healer.lambda_handler"
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
# Routes all Bedrock Agent tool calls — detection, diagnostics, healing, reports

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
# Shared trigger from shared/bedrock_agent_trigger.py.
# Prompt injected via EventBridge input — not hardcoded here.

module "lambda_trigger" {
  source        = "../../../platform/terraform/modules/lambda"
  function_name = "${local.prefix}-trigger"
  handler       = "bedrock_agent_trigger.lambda_handler"
  role_arn      = aws_iam_role.lambda.arn
  zip_path      = data.archive_file.lambda_zip.output_path
  zip_hash      = data.archive_file.lambda_zip.output_base64sha256
  timeout       = var.lambda_timeout_trigger
  memory_size   = var.lambda_memory_trigger
  environment   = merge(local.lambda_env, {
    BEDROCK_AGENT_ID       = aws_bedrockagent_agent.this.agent_id
    BEDROCK_AGENT_ALIAS_ID = aws_bedrockagent_agent_alias.live.agent_alias_id
    BEDROCK_AGENT_NAME     = aws_bedrockagent_agent.this.agent_name
    DEFAULT_PROMPT         = "Run a full incident detection scan. Check CloudWatch alarms, load balancer health, Lambda errors, EC2 status checks and log patterns. For any CRITICAL finding run diagnostics and attempt auto-healing where safe. Escalate to human for anything that requires manual action. Save the incident report."
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
