# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/rbac.tf
#
# Findings access — chatbot-only model.
#
# Access model:
#   Platform Lambda roles  → full read/write (governed by their IAM role policies)
#   Chatbot Lambda role    → Query on GSIs + GetItem (stubbed, ready for future build)
#   Everyone else          → DENIED via DynamoDB resource-based policy
#
# No team or human principal has direct access to the findings table.
# All reporting goes through the chatbot when it is built.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  # Principals allowed through the findings table resource policy.
  # Includes:
  #   - All agent Lambda roles (governance-<agent>-lambda-role)
  #   - Chatbot Lambda role
  #   - NuratrixGovCloudRole — the CI/CD deployer role must remain allowed so
  #     Terraform can update this resource policy on future deployments. Without
  #     it, DynamoDB rejects PutResourcePolicy with "will not allow you to update
  #     the resource policy in the future".
  #   - Account root (break-glass)
  findings_allowed_role_patterns = [
    "arn:aws:iam::${local.account_id}:role/governance-*-lambda-role",
    aws_iam_role.chatbot.arn,
    "arn:aws:iam::${local.account_id}:role/NuratrixGovCloudRole",
    "arn:aws:iam::${local.account_id}:root",
  ]
}

# ── Chatbot Lambda IAM role (stub) ────────────────────────────────────────────
# No Lambda function is attached yet. When the chatbot is built:
#   1. Create a Lambda function
#   2. Set role_arn = aws_iam_role.chatbot.arn
#   3. The role already has the correct DynamoDB + Bedrock permissions

resource "aws_iam_role" "chatbot" {
  name        = "${local.prefix}-chatbot"
  description = "Findings chatbot Lambda - read-only access to findings via GSI. Stub until chatbot is implemented."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowLambda"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, { Purpose = "chatbot-findings-reader", Status = "stub" })
}

resource "aws_iam_role_policy_attachment" "chatbot_basic" {
  role       = aws_iam_role.chatbot.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "chatbot_findings" {
  name = "${local.prefix}-chatbot-findings"
  role = aws_iam_role.chatbot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "QueryFindingsByAccount"
        Effect = "Allow"
        Action = ["dynamodb:Query"]
        Resource = [
          "${aws_dynamodb_table.findings.arn}/index/account-agent-timestamp-index",
          "${aws_dynamodb_table.findings.arn}/index/agent-timestamp-index",
        ]
      },
      {
        Sid      = "GetFindingDetail"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid    = "InvokeBedrockForNLU"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ]
        Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/*"
      },
      {
        Sid    = "XRayWrite"
        Effect = "Allow"
        Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      }
    ]
  })
}

# ── DynamoDB resource-based policy — lock the findings table ──────────────────
# Evaluated alongside IAM identity policies. An explicit Deny here blocks access
# even when an IAM policy allows it, so no human or non-platform role can reach
# the table regardless of what other permissions they hold.

resource "aws_dynamodb_resource_policy" "findings_lockdown" {
  resource_arn = aws_dynamodb_table.findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPlatformAndChatbot"
        Effect = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "dynamodb:PutItem", "dynamodb:GetItem",
          "dynamodb:Query",   "dynamodb:Scan",
          "dynamodb:UpdateItem", "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem", "dynamodb:BatchGetItem",
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          "${aws_dynamodb_table.findings.arn}/index/*",
        ]
        Condition = {
          ArnLike = { "aws:PrincipalArn" = local.findings_allowed_role_patterns }
        }
      },
      {
        Sid    = "DenyEverythingElse"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = "dynamodb:*"
        Resource = [
          aws_dynamodb_table.findings.arn,
          "${aws_dynamodb_table.findings.arn}/index/*",
        ]
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = local.findings_allowed_role_patterns }
        }
      }
    ]
  })
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "chatbot_role_arn" {
  description = "Assign this role to the chatbot Lambda when it is built."
  value       = aws_iam_role.chatbot.arn
}
