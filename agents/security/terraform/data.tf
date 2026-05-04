# ─────────────────────────────────────────────────────────────────────────────
# agents/security/terraform/data.tf — Multi-Account Edition
# Includes teams_notifier.py and updated shared files.
# ─────────────────────────────────────────────────────────────────────────────

data "terraform_remote_state" "platform" {
  backend = "s3"
  config = {
    bucket = var.platform_state_bucket
    key    = var.platform_state_key
    region = var.aws_region
  }
}

data "aws_caller_identity" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = file("${path.module}/../lambdas/bedrock_action_handler.py")
    filename = "bedrock_action_handler.py"
  }
  source {
    content  = file("${path.module}/../lambdas/iam_checker.py")
    filename = "iam_checker.py"
  }
  source {
    content  = file("${path.module}/../lambdas/guardduty_checker.py")
    filename = "guardduty_checker.py"
  }
  source {
    content  = file("${path.module}/../lambdas/cloudtrail_checker.py")
    filename = "cloudtrail_checker.py"
  }
  source {
    content  = file("${path.module}/../lambdas/kms_secrets_checker.py")
    filename = "kms_secrets_checker.py"
  }
  source {
    content  = file("${path.module}/../lambdas/security_agent_orchestrator.py")
    filename = "security_agent_orchestrator.py"
  }
  source {
    content  = file("${path.module}/../lambdas/sg_checker.py")
    filename = "sg_checker.py"
  }
  source {
    content  = file("${path.module}/../lambdas/s3_checker.py")
    filename = "s3_checker.py"
  }

  # ── Shared files (Multi-Account editions) ────────────────────────────────
  source {
    content  = file("${path.module}/../../../shared/utils.py")
    filename = "utils.py"
  }
  source {
    content  = file("${path.module}/../../../shared/build_finding.py")
    filename = "build_finding.py"
  }
  source {
    content  = file("${path.module}/../../../shared/bedrock_agent_trigger.py")
    filename = "bedrock_agent_trigger.py"
  }
  source {
    content  = file("${path.module}/../../../shared/teams_notifier.py")
    filename = "teams_notifier.py"
  }
  source {
    content  = file("${path.module}/../../../shared/slack_notifier.py")
    filename = "slack_notifier.py"
  }
  source {
    content  = file("${path.module}/../../../shared/bedrock_invoker.py")
    filename = "bedrock_invoker.py"
  }

}
