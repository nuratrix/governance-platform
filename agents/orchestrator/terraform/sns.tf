# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/sns.tf
# Subscribe the router Lambda to the shared orchestrator SNS topic.
# This is what connects every sub-agent to the Orchestrator.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_sns_topic_subscription" "router_subscription" {
  topic_arn = local.orchestrator_topic_arn
  protocol  = "lambda"
  endpoint  = module.lambda_router.function_arn
}
