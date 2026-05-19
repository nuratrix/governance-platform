# ─────────────────────────────────────────────────────────────────────────────
# agents/cost/terraform/iam.tf — Multi-Account Edition
# Adds sts:AssumeRole permission so the Lambda can scan member accounts.
# Cost Explorer stays in governance account; EC2/RDS/S3 use cross-account session.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "bedrock_agent" {
  name = "${local.prefix}-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_agent_policy" {
  name = "${local.prefix}-agent-policy"
  role = aws_iam_role.bedrock_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:GetFoundationModel"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.foundation_model}",
          "arn:aws:bedrock:*::inference-profile/${var.foundation_model}",
          "arn:aws:bedrock:*::foundation-model/anthropic.*",
        ]
      },
      {
        Sid      = "InvokeLambda"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = module.lambda_action_handler.function_arn
      }
    ]
  })
}

resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.prefix}-lambda-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBFindings"
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = [
          local.findings_table_arn,
          "${local.findings_table_arn}/index/*",
          "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/${local.account_registry_table}",
        ]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [local.alerts_topic_arn, local.orchestrator_topic_arn]
      },
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeVolumes",
          "ec2:DescribeAddresses",
          "ec2:DescribeReservedInstances",
          "ec2:DescribeReservedInstancesOfferings",
          "ec2:DescribeSnapshots",
          "ec2:DescribeRegions"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2StopInstances"
        Effect = "Allow"
        Action = ["ec2:StopInstances"]
        Resource = "arn:aws:ec2:${var.aws_region}:${local.account_id}:instance/*"
      },
      {
        Sid    = "EBSDeleteVolume"
        Effect = "Allow"
        Action = [
          "ec2:DeleteVolume",
          "ec2:CreateSnapshot"
        ]
        Resource = "*"
      },
      {
        Sid      = "EBSSnapshotWaiter"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSnapshots"]
        Resource = "*"
      },
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots",
          "rds:DescribeDBClusterSnapshots",
          "rds:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketIntelligentTieringConfiguration",
          "s3:ListBucketIntelligentTieringConfigurations",
          "s3:GetAnalyticsConfiguration",
          "s3:ListBucketAnalyticsConfigurations",
          "s3:GetBucketPolicy",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Sid    = "CostExplorerReadOnly"
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetReservationCoverage",
          "ce:GetReservationUtilization",
          "ce:GetReservationPurchaseRecommendation",
          "ce:GetSavingsPlansCoverage",
          "ce:GetSavingsPlansUtilization",
          "ce:GetSavingsPlansPurchaseRecommendation",
          "ce:GetRightsizingRecommendation",
          "ce:ListCostAllocationTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricData"
        ]
        Resource = "*"
      },
      {
        Sid    = "BedrockAgentInvoke"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeAgent",
          "bedrock:ListAgents",
          "bedrock:ListAgentAliases",
          "bedrock:GetAgent",
          "bedrock:GetAgentAlias"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}:${local.account_id}:agent/*",
          "arn:aws:bedrock:${var.aws_region}:${local.account_id}:agent-alias/*"
        ]
      },
      {
        Sid    = "SecretsManagerWebhooks"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${local.account_id}:secret:governance-platform/teams-webhook-url*",
          "arn:aws:secretsmanager:${var.aws_region}:${local.account_id}:secret:governance-platform/slack-webhook-url*"
        ]
      },
      {
        Sid      = "XRayWrite"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      # ── Multi-Account: assume cross-account reader role ──────────────────
      {
        Sid      = "AssumeReaderRoles"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "arn:aws:iam::*:role/governance-platform-reader"
        Condition = {
          StringEquals = { "sts:ExternalId" = "governance-platform" }
        }
      },
      {
        Sid    = "SQSFanout"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage", "sqs:ReceiveMessage",
          "sqs:DeleteMessage", "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.bedrock_invoke_queue.arn,
          aws_sqs_queue.bedrock_invoke_dlq.arn
        ]
      },
    ]
  })
}

resource "aws_lambda_permission" "bedrock_invoke_action_handler" {
  statement_id  = "AllowBedrockInvoke"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_action_handler.function_name
  principal     = "bedrock.amazonaws.com"
  source_arn    = aws_bedrockagent_agent.this.agent_arn
  depends_on    = [aws_bedrockagent_agent.this]
}


resource "aws_iam_role_policy" "lambda_bedrock_runtime" {
  name = "${local.prefix}-lambda-bedrock-runtime"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeAgent"
      Effect   = "Allow"
      Action   = ["bedrock:InvokeAgent"]
      Resource = aws_bedrockagent_agent_alias.live.agent_alias_arn
    }]
  })
}
