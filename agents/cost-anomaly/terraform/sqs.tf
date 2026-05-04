# Bedrock fan-out: one message per account → bedrock_invoker Lambda (parallel invoke_agent calls).
resource "aws_sqs_queue" "bedrock_invoke_dlq" {
  name                      = "${local.prefix}-bedrock-invoke-dlq"
  message_retention_seconds = 1209600
  tags                      = var.tags
}

resource "aws_sqs_queue" "bedrock_invoke_queue" {
  name                       = "${local.prefix}-bedrock-invoke-queue"
  visibility_timeout_seconds = 360
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.bedrock_invoke_dlq.arn
    maxReceiveCount     = 2
  })
  tags = var.tags
}

resource "aws_lambda_event_source_mapping" "bedrock_invoker" {
  event_source_arn = aws_sqs_queue.bedrock_invoke_queue.arn
  function_name    = module.lambda_bedrock_invoker.function_arn
  batch_size       = 1
  scaling_config {
    maximum_concurrency = 8
  }
  depends_on = [aws_iam_role_policy.lambda]
}
