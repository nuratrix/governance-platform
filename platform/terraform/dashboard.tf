# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/dashboard.tf
#
# Findings dashboard API — Lambda + API Gateway HTTP API v2.
# Uses the pre-existing chatbot IAM role (rbac.tf) which already has
# DynamoDB Query/GetItem on the findings table and both GSIs.
# CORS is locked to the CloudFront distribution (dashboard_hosting.tf).
# ─────────────────────────────────────────────────────────────────────────────

locals {
  # CloudFront origin is always allowed; append any extra origins from the variable.
  dashboard_cors_origins = compact(concat(
    ["https://${aws_cloudfront_distribution.dashboard.domain_name}"],
    var.dashboard_allowed_origins != "" ? split(",", var.dashboard_allowed_origins) : []
  ))
}

# ── Lambda packaging ──────────────────────────────────────────────────────────

data "archive_file" "dashboard_lambda" {
  type        = "zip"
  source_file = "${path.module}/../api/dashboard.py"
  output_path = "${path.module}/dashboard.zip"
}

# ── Lambda function ───────────────────────────────────────────────────────────

resource "aws_lambda_function" "dashboard" {
  function_name    = "${local.prefix}-dashboard-api"
  description      = "Findings dashboard API — GET /api/findings and GET /api/findings/{scanId}"
  role             = aws_iam_role.chatbot.arn
  handler          = "dashboard.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.dashboard_lambda.output_path
  source_code_hash = data.archive_file.dashboard_lambda.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      ALLOWED_ORIGINS = join(",", local.dashboard_cors_origins)
    }
  }
}

resource "aws_cloudwatch_log_group" "dashboard" {
  name              = "/aws/lambda/${aws_lambda_function.dashboard.function_name}"
  retention_in_days = var.log_retention_days
}

# ── API Gateway HTTP API v2 ───────────────────────────────────────────────────

resource "aws_apigatewayv2_api" "dashboard" {
  name          = "${local.prefix}-dashboard-api"
  protocol_type = "HTTP"
  description   = "Governance findings dashboard endpoint"

  cors_configuration {
    allow_origins = local.dashboard_cors_origins
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Content-Type"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_stage" "dashboard" {
  api_id      = aws_apigatewayv2_api.dashboard.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "dashboard" {
  api_id                 = aws_apigatewayv2_api.dashboard.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.dashboard.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_findings" {
  api_id    = aws_apigatewayv2_api.dashboard.id
  route_key = "GET /api/findings"
  target    = "integrations/${aws_apigatewayv2_integration.dashboard.id}"
}

resource "aws_apigatewayv2_route" "get_finding_detail" {
  api_id    = aws_apigatewayv2_api.dashboard.id
  route_key = "GET /api/findings/{scanId}"
  target    = "integrations/${aws_apigatewayv2_integration.dashboard.id}"
}

resource "aws_lambda_permission" "apigw_dashboard" {
  statement_id  = "AllowAPIGatewayInvokeDashboard"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dashboard.execution_arn}/*/*"
}

# ── Output ────────────────────────────────────────────────────────────────────

output "dashboard_api_url" {
  description = "Raw API Gateway URL (injected into the HTML automatically by dashboard_hosting.tf)"
  value       = aws_apigatewayv2_stage.dashboard.invoke_url
}
