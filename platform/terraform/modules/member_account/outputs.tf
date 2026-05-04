output "role_arn" {
  description = "ARN of the cross-account governance reader role"
  value       = aws_iam_role.governance_reader.arn
}

output "role_name" {
  description = "Name of the cross-account governance reader role"
  value       = aws_iam_role.governance_reader.name
}
