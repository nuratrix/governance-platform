output "agent_id" {
  value = aws_bedrockagent_agent.this.agent_id
}

output "agent_name" {
  value = aws_bedrockagent_agent.this.agent_name
}

output "agent_alias_id" {
  value = aws_bedrockagent_agent_alias.live.agent_alias_id
}

output "trigger_function_name" {
  value = module.lambda_trigger.function_name
}

output "action_handler_function_name" {
  value = module.lambda_action_handler.function_name
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda.arn
}

output "lambda_role_name" {
  value = aws_iam_role.lambda.name
}

output "daily_scan_rule_arn" {
  value = aws_cloudwatch_event_rule.daily_scan.arn
}

output "checker_function_arns" {
  value = {
    iam        = module.lambda_iam_checker.function_arn
    s3         = module.lambda_s3_checker.function_arn
    sg         = module.lambda_sg_checker.function_arn
    cloudtrail = module.lambda_ct_checker.function_arn
    guardduty  = module.lambda_gd_checker.function_arn
    kms        = module.lambda_kms_checker.function_arn
  }
}
