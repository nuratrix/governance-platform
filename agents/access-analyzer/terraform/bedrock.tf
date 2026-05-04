# ─────────────────────────────────────────────────────────────────────────────
# agents/access-analyzer/terraform/bedrock.tf
# IAM Access Analyzer Agent — Bedrock Agent, action group, and alias.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS IAM and access analyzer security agent. Your job is to audit
    IAM configurations for external resource exposure, unused credentials,
    and missing security controls like MFA.

    RULES:
    1. Always start with check_access_analyzer to pull active Access Analyzer findings
    2. Always follow with check_unused_permissions to find stale access keys and unused roles
    3. Escalate all CRITICAL and HIGH findings immediately via escalate_to_human
    4. Never modify IAM policies, delete users, or remove permissions — read-only only
    5. For any finding of public resource access (isPublic=true), treat as CRITICAL
    6. End every session with save_iam_report

    TOOLS:
    check_access_analyzer, check_unused_permissions, escalate_to_human, save_iam_report
  PROMPT

  depends_on = [aws_iam_role.bedrock_agent, aws_iam_role_policy.bedrock_agent_policy]
}

resource "aws_bedrockagent_agent_action_group" "iamtools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "iamtools"
  description       = "IAM Access Analyzer findings, unused permissions auditing, and MFA checks"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "IAM Access Analyzer Agent Tools", version = "1.0" }
      paths = {

        "/checkaccessanalyzer" = {
          post = {
            operationId = "check_access_analyzer"
            description = "Pulls all active IAM Access Analyzer findings across all enabled regions. Detects external and public access to S3 buckets, KMS keys, IAM roles, Lambda functions, SQS queues, and other resources. Also verifies an analyzer is deployed in each region."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  account_id   = { type = "string" }
                  account_name = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Access Analyzer findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object",
                  properties = {
                    rule_id = { type = "string" }, severity = { type = "string" },
                    resource_id = { type = "string" }, title = { type = "string" },
                    description = { type = "string" }, recommendation = { type = "string" },
                    is_public = { type = "boolean" }, resource_type = { type = "string" }
                  }
                } }
              }
            } } } } }
          }
        }

        "/checkunusedpermissions" = {
          post = {
            operationId = "check_unused_permissions"
            description = "Audits IAM for unused access keys (inactive > 45 days), IAM roles not assumed in > 90 days, and console users without MFA. Uses the IAM credential report for MFA checks."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  account_id   = { type = "string" }
                  account_name = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Unused permission findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object",
                  properties = {
                    rule_id = { type = "string" }, severity = { type = "string" },
                    resource_id = { type = "string" }, title = { type = "string" },
                    description = { type = "string" }, recommendation = { type = "string" },
                    days_unused = { type = "integer" }
                  }
                } }
              }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends an IAM security alert via SNS. Call for any CRITICAL or HIGH finding, especially public resource exposure."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object"
                required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  finding_summary    = { type = "string" }
                  resource_id        = { type = "string" }
                  recommended_action = { type = "string" }
                  agent_reasoning    = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation result", content = { "application/json" = { schema = {
              type = "object"
              properties = { success = { type = "boolean" }, message_id = { type = "string" }, escalated_at = { type = "string" } }
            } } } } }
          }
        }

        "/saveiamreport" = {
          post = {
            operationId = "save_iam_report"
            description = "Saves the IAM and Access Analyzer scan report to DynamoDB. Always call at end of session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object"
                required = ["scan_id", "total_findings"]
                properties = {
                  scan_id             = { type = "string" }
                  total_findings      = { type = "integer" }
                  public_exposures    = { type = "integer", description = "Count of publicly exposed resources" }
                  unused_credentials  = { type = "integer", description = "Count of unused access keys and roles" }
                  executive_summary   = { type = "string" }
                  top_findings        = { type = "string" }
                  escalations         = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Report saved", content = { "application/json" = { schema = {
              type = "object"
              properties = { success = { type = "boolean" }, scan_id = { type = "string" } }
            } } } } }
          }
        }

      }
    })
  }

  depends_on = [aws_bedrockagent_agent.this]
}

resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "access-analyzer-agent-live"
  description      = "Production alias for the IAM Access Analyzer Agent"
}
