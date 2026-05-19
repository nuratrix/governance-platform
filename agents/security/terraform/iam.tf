# ─────────────────────────────────────────────────────────────────────────────
# agents/security/terraform/iam.tf — Multi-Account Edition
# Adds sts:AssumeRole permission so the Lambda can scan member accounts.
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
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:us-east-1:${local.account_id}:agent/*" }
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
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:GetFoundationModel"]
        Resource = [
          "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0",
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
        Sid      = "DynamoDBFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
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
        Sid    = "IAMAudit"
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport", "iam:GetCredentialReport",
          "iam:GetAccountSummary",         "iam:GetAccountPasswordPolicy",
          "iam:ListUsers",                 "iam:ListRoles",
          "iam:ListAccessKeys",            "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",  "iam:ListUserPolicies",
          "iam:ListRolePolicies",          "iam:GetRolePolicy",
          "iam:GetUserPolicy",             "iam:GetRole",
          "iam:GetUser",                   "iam:UpdateAccessKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Audit"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",            "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicy",             "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",         "s3:GetBucketLogging",
          "s3:GetReplicationConfiguration", "s3:GetLifecycleConfiguration",
          "s3:GetObject",                   "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Audit"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",    "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeRegions",           "ec2:DescribeVpcs",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailAudit"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",    "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors", "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyRead"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors", "guardduty:GetDetector",
          "guardduty:ListFindings",  "guardduty:GetFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSAudit"
        Effect = "Allow"
        Action = [
          "kms:ListKeys",             "kms:DescribeKey",
          "kms:GetKeyRotationStatus", "kms:GetKeyPolicy",
          "kms:ListAliases"
        ]
        Resource = "*"
      },
      {
        Sid      = "SecretsManagerAudit"
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"]
        Resource = "*"
      },
      {
        Sid    = "ConfigAudit"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigurationRecorders",
          "config:DescribeDeliveryChannels",
          "config:GetComplianceSummaryByConfigRule",
          "config:DescribeComplianceByConfigRule"
        ]
        Resource = "*"
      },
      {
        Sid      = "BedrockAgentInvoke"
        Effect   = "Allow"
        Action   = [
          "bedrock:InvokeAgent", "bedrock:ListAgents",
          "bedrock:ListAgentAliases", "bedrock:GetAgent", "bedrock:GetAgentAlias"
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}:${local.account_id}:agent/*",
          "arn:aws:bedrock:${var.aws_region}:${local.account_id}:agent-alias/*"
        ]
      },
      {
        Sid      = "XRay"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      },
      {
        Sid      = "InvokeSubLambdas"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = "arn:aws:lambda:${var.aws_region}:*:function:${local.prefix}-*"
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
      # ── EKS: cluster and node group security audit ───────────────────────
      {
        Sid    = "EKSAudit"
        Effect = "Allow"
        Action = [
          "eks:ListClusters",
          "eks:DescribeCluster",
          "eks:ListNodegroups",
          "eks:DescribeNodegroup",
          "eks:ListFargateProfiles",
          "eks:DescribeFargateProfile",
          "eks:ListAddons",
          "eks:DescribeAddon"
        ]
        Resource = "*"
      },
      # ── ECR: repository and image security audit ─────────────────────────
      {
        Sid    = "ECRAudit"
        Effect = "Allow"
        Action = [
          "ecr:DescribeRepositories",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeImages",
          "ecr:DescribeImageScanFindings",
          "ecr:ListImages",
          "ecr:GetLifecyclePolicy",
          "ecr:GetLifecyclePolicyPreview"
        ]
        Resource = "*"
      },
      # ── Lambda: function security audit ─────────────────────────────────
      {
        Sid    = "LambdaSecurityAudit"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetPolicy",
          "lambda:GetFunctionCodeSigningConfig",
          "lambda:ListCodeSigningConfigs"
        ]
        Resource = "*"
      },
      # ── RDS: instance, cluster and snapshot security audit ───────────────
      {
        Sid    = "RDSSecurityAudit"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots",
          "rds:DescribeDBClusterSnapshots",
          "rds:ListTagsForResource",
          "rds:DescribeDBParameters",
          "rds:DescribeDBParameterGroups"
        ]
        Resource = "*"
      },
      # ── SSM: parameter store, documents, patch compliance ────────────────
      {
        Sid    = "SSMAudit"
        Effect = "Allow"
        Action = [
          "ssm:DescribeParameters",
          "ssm:ListDocuments",
          "ssm:DescribeDocument",
          "ssm:DescribeDocumentPermission",
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeInstancePatchStates",
          "ssm:DescribePatchBaselines",
          "ssm:GetPatchBaseline"
        ]
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
