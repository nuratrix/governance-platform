# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/modules/lambda/main.tf
# Reusable Lambda function + CloudWatch Log Group.
# Unchanged from single-account version.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention
}

resource "aws_lambda_function" "this" {
  function_name    = var.function_name
  handler          = var.handler
  runtime          = "python3.12"
  role             = var.role_arn
  filename         = var.zip_path
  source_code_hash = var.zip_hash
  timeout          = var.timeout
  memory_size      = var.memory_size

  environment {
    variables = var.environment
  }

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  depends_on = [aws_cloudwatch_log_group.this]
}
