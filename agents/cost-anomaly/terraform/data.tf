# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/data.tf
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
    content  = file("${path.module}/../lambdas/anomaly_detector.py")
    filename = "anomaly_detector.py"
  }

  source {
    content  = file("${path.module}/../lambdas/root_cause_analyzer.py")
    filename = "root_cause_analyzer.py"
  }

  # Shared files — flattened to root so imports work
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
