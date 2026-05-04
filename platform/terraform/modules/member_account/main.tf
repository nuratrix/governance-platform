# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/modules/member_account/main.tf  (NEW — multi-account)
#
# Creates a read-only cross-account IAM role in a MEMBER account.
# The governance account's Lambda functions assume this role to scan resources.
#
# Deploy this module in each member account BEFORE adding it to member_accounts
# in platform.tfvars.
#
# Usage (run with credentials for the member account):
#
#   terraform -chdir=platform/terraform/modules/member_account apply \
#     -var="governance_account_id=<governance-acct>" \
#     -var="account_name=prod-workloads"
#
# Or use the member_account_setup.yml GitHub workflow which loops over accounts.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "governance_reader" {
  name        = var.role_name
  description = "Cross-account read-only role for the AWS Governance Platform (account: ${var.governance_account_id})"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.governance_account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        # IAM does not evaluate wildcards in the Principal element — restrict via condition instead.
        StringLike   = { "aws:PrincipalArn" = "arn:aws:iam::${var.governance_account_id}:role/governance-*-lambda-role" }
        StringEquals = { "sts:ExternalId"   = "governance-platform" }
      }
    }]
  })

  tags = {
    ManagedBy         = "Terraform"
    GovernanceAccount = var.governance_account_id
    AccountName       = var.account_name
    Purpose           = "cross-account-governance-reader"
  }
}

resource "aws_iam_role_policy" "governance_reader_policy" {
  name = "${var.role_name}-policy"
  role = aws_iam_role.governance_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ── IAM read-only ─────────────────────────────────────────────────────
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport", "iam:GetCredentialReport",
          "iam:GetAccountSummary",        "iam:GetAccountPasswordPolicy",
          "iam:ListUsers",                "iam:ListRoles",
          "iam:ListAccessKeys",           "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies", "iam:ListUserPolicies",
          "iam:ListRolePolicies",         "iam:GetRolePolicy",
          "iam:GetUserPolicy",            "iam:GetRole",
          "iam:GetUser",                  "iam:ListMFADevices",
          "iam:GetLoginProfile"
        ]
        Resource = "*"
      },
      # ── S3 read-only ──────────────────────────────────────────────────────
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:GetReplicationConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging"
        ]
        Resource = "*"
      },
      # ── EC2 / VPC / network read-only ─────────────────────────────────────
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",         "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeRegions",                "ec2:DescribeVpcs",
          "ec2:DescribeFlowLogs",               "ec2:DescribeInstances",
          "ec2:DescribeVolumes",                "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",                "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",       "ec2:DescribeNatGateways",
          "ec2:DescribeAddresses",              "ec2:DescribeTags",
          "ec2:DescribeTransitGateways",        "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeNetworkAcls",            "ec2:DescribeVpcPeeringConnections"
        ]
        Resource = "*"
      },
      # ── RDS read-only ─────────────────────────────────────────────────────
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",   "rds:DescribeDBClusters",
          "rds:DescribeDBSnapshots",   "rds:ListTagsForResource"
        ]
        Resource = "*"
      },
      # ── CloudTrail read-only ──────────────────────────────────────────────
      {
        Sid    = "CloudTrailReadOnly"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",    "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors", "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      # ── GuardDuty read-only ───────────────────────────────────────────────
      {
        Sid    = "GuardDutyReadOnly"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors",  "guardduty:GetDetector",
          "guardduty:ListFindings",   "guardduty:GetFindings"
        ]
        Resource = "*"
      },
      # ── KMS read-only ─────────────────────────────────────────────────────
      {
        Sid    = "KMSReadOnly"
        Effect = "Allow"
        Action = [
          "kms:ListKeys",             "kms:DescribeKey",
          "kms:GetKeyRotationStatus", "kms:GetKeyPolicy",
          "kms:ListAliases"
        ]
        Resource = "*"
      },
      # ── Secrets Manager read-only ─────────────────────────────────────────
      {
        Sid      = "SecretsManagerReadOnly"
        Effect   = "Allow"
        Action   = ["secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"]
        Resource = "*"
      },
      # ── AWS Config read-only ──────────────────────────────────────────────
      {
        Sid    = "ConfigReadOnly"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigRules",
          "config:DescribeComplianceByConfigRule",
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceSummaryByConfigRule",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "config:DescribeDeliveryChannels"
        ]
        Resource = "*"
      },
      # ── CloudWatch read-only ──────────────────────────────────────────────
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "logs:DescribeLogGroups",
          "logs:DescribeMetricFilters",
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      },
      # ── ECS read-only (for incident agent) ────────────────────────────────
      {
        Sid    = "ECSReadOnly"
        Effect = "Allow"
        Action = [
          "ecs:ListClusters",   "ecs:DescribeClusters",
          "ecs:ListServices",   "ecs:DescribeServices",
          "ecs:ListTasks",      "ecs:DescribeTasks"
        ]
        Resource = "*"
      },
      # ── Auto Scaling read-only (for incident agent) ───────────────────────
      {
        Sid    = "AutoScalingReadOnly"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeScalingActivities"
        ]
        Resource = "*"
      },
      # ── IAM Access Analyzer read-only (for access-analyzer agent) ─────────
      {
        Sid    = "AccessAnalyzerReadOnly"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding",
          "access-analyzer:ListFindingsV2",
          "access-analyzer:GetFindingV2",
          "access-analyzer:ListAnalyzedResources",
          "access-analyzer:GetAnalyzedResource"
        ]
        Resource = "*"
      },
      # ── AWS Backup read-only (for backup-dr agent) ────────────────────────
      {
        Sid    = "BackupReadOnly"
        Effect = "Allow"
        Action = [
          "backup:ListBackupPlans",
          "backup:GetBackupPlan",
          "backup:ListBackupVaults",
          "backup:DescribeBackupVault",
          "backup:ListRecoveryPointsByBackupVault",
          "backup:GetBackupVaultAccessPolicy"
        ]
        Resource = "*"
      },
      # ── Lambda read-only (for security agent) ─────────────────────────────
      {
        Sid    = "LambdaReadOnly"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunctionConfiguration",
          "lambda:GetPolicy"
        ]
        Resource = "*"
      },
      # ── EKS read-only (for security agent) ───────────────────────────────
      {
        Sid    = "EKSReadOnly"
        Effect = "Allow"
        Action = [
          "eks:ListClusters",    "eks:DescribeCluster",
          "eks:ListNodegroups",  "eks:DescribeNodegroup"
        ]
        Resource = "*"
      },
      # ── ECR read-only (for security agent) ───────────────────────────────
      {
        Sid    = "ECRReadOnly"
        Effect = "Allow"
        Action = [
          "ecr:DescribeRepositories",
          "ecr:GetLifecyclePolicy",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeImages"
        ]
        Resource = "*"
      },
      # ── SSM read-only (for security/compliance agents) ────────────────────
      {
        Sid    = "SSMReadOnly"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation",
          "ssm:ListAssociations",
          "ssm:DescribeInstancePatchStates"
        ]
        Resource = "*"
      },
      # ── Elastic Load Balancing read-only (for network/incident agents) ─────
      {
        Sid    = "ELBReadOnly"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeListeners"
        ]
        Resource = "*"
      },
      # ── Route 53 read-only (for network-security agent) ───────────────────
      {
        Sid    = "Route53ReadOnly"
        Effect = "Allow"
        Action = [
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets"
        ]
        Resource = "*"
      }
    ]
  })
}
