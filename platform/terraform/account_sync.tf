# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/account_sync.tf
#
# Hourly Lambda that reads all active AWS Organizations accounts and writes
# them into the account_registry DynamoDB table.
#
# The bedrock_agent_trigger Lambda already reads from account_registry as its
# primary account source — so once this runs, every agent automatically scans
# all member accounts with zero per-account config.
#
# Prerequisites (one-time in the management account — only needed if governance
# account is NOT the management account):
#
#   aws organizations enable-aws-service-access \
#     --service-principal member.org.stacksets.cloudformation.amazonaws.com
#
#   aws organizations register-delegated-administrator \
#     --account-id <GOVERNANCE_ACCOUNT_ID> \
#     --service-principal organizations.amazonaws.com   # enables ListAccounts
#
# If the governance account IS the management account no extra setup is needed.
# ─────────────────────────────────────────────────────────────────────────────

data "archive_file" "account_sync_zip" {
  type        = "zip"
  output_path = "${path.module}/.build/account_sync.zip"

  source {
    content  = file("${path.module}/../api/account_sync.py")
    filename = "account_sync.py"
  }
}

resource "aws_iam_role" "account_sync" {
  name = "${local.prefix}-account-sync-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Purpose = "org-account-sync" })
}

resource "aws_iam_role_policy_attachment" "account_sync_basic" {
  role       = aws_iam_role.account_sync.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "account_sync" {
  name = "${local.prefix}-account-sync-policy"
  role = aws_iam_role.account_sync.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OrganizationsRead"
        Effect = "Allow"
        Action = [
          "organizations:ListAccounts",
          "organizations:DescribeAccount",
          "organizations:DescribeOrganization",
        ]
        Resource = "*"
      },
      {
        Sid    = "RegistryWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:Scan",
        ]
        Resource = [
          aws_dynamodb_table.account_registry.arn,
          "${aws_dynamodb_table.account_registry.arn}/index/*",
        ]
      },
    ]
  })
}

module "lambda_account_sync" {
  source        = "./modules/lambda"
  function_name = "${local.prefix}-account-sync"
  handler       = "account_sync.lambda_handler"
  role_arn      = aws_iam_role.account_sync.arn
  zip_path      = data.archive_file.account_sync_zip.output_path
  zip_hash      = data.archive_file.account_sync_zip.output_base64sha256
  timeout       = 120
  memory_size   = 128
  enable_xray   = false
  log_retention = var.log_retention_days

  environment = {
    ACCOUNT_REGISTRY_TABLE = aws_dynamodb_table.account_registry.name
    GOVERNANCE_ACCOUNT_ID  = local.account_id
    READER_ROLE_NAME       = "governance-platform-reader"
    DEFAULT_ENV            = var.environment
  }
}

resource "aws_cloudwatch_event_rule" "account_sync_schedule" {
  name                = "${local.prefix}-account-sync"
  description         = "Hourly sync of Organizations accounts into account registry"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "account_sync" {
  rule      = aws_cloudwatch_event_rule.account_sync_schedule.name
  target_id = "AccountSyncLambda"
  arn       = module.lambda_account_sync.function_arn
}

resource "aws_lambda_permission" "account_sync_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_account_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.account_sync_schedule.arn
}
