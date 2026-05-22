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
    6. After all checks and escalations, call save_iam_report with ALL of these fields populated:
       - scan_id: Use the scan_id from sessionAttributes, or generate "scan-YYYYMMDD-HHMMSS"
       - total_findings: Total count of all findings (integer)
       - public_exposures: Count of resources with isPublic=true (integer)
       - unused_credentials: Count of unused access keys and roles (integer)
       - executive_summary: Write a 2-3 sentence paragraph stating (1) which checks ran, (2) public exposures and unused credentials count, (3) the most critical issues. Example: "IAM and Access Analyzer scan completed for account 123456789012. Found 1 public exposure (S3 bucket with public read access) and 3 unused credentials (2 access keys inactive for more than 45 days, 1 role not assumed in over 90 days). The publicly accessible S3 bucket requires immediate remediation."
       - top_findings: JSON array string of the top 10 findings. Each item: {"severity":"CRITICAL","title":"Public S3 Bucket","resource_id":"arn:aws:s3:::bucket-name","description":"S3 bucket allows public read access via Access Analyzer","recommendation":"Enable S3 Block Public Access and remove public bucket policy"}
       - escalations: String summarising escalations sent. Example: "Escalated 1 CRITICAL (public S3 bucket) and 2 HIGH (unused access keys)" — use "None" if no escalations.

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
                type     = "object"
                required = ["scan_id", "total_findings", "executive_summary", "public_exposures", "unused_credentials"]
                properties = {
                  scan_id             = { type = "string" }
                  total_findings      = { type = "integer" }
                  public_exposures    = { type = "integer", description = "Count of publicly exposed resources (isPublic=true)" }
                  unused_credentials  = { type = "integer", description = "Count of unused access keys and roles" }
                  executive_summary   = { type = "string", description = "2-3 sentence summary of findings and risk" }
                  top_findings        = { type = "string", description = "JSON array string of top 10 findings" }
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

# ─── Prepare agent before aliasing ───────────────────────────────────────────

resource "time_sleep" "wait_for_action_group" {
  create_duration = "15s"
  depends_on      = [aws_bedrockagent_agent_action_group.iamtools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id         = aws_bedrockagent_agent.this.agent_id
    action_group_id  = aws_bedrockagent_agent_action_group.iamtools.id
    foundation_model = var.foundation_model
  }

  provisioner "local-exec" {
    command = <<-CMD
      echo "Preparing Bedrock Agent ${self.triggers.agent_id}..."
      aws bedrock-agent prepare-agent \
        --agent-id ${self.triggers.agent_id} \
        --region ${var.aws_region}

      echo "Waiting for agent to reach PREPARED state..."
      for i in $(seq 1 12); do
        STATUS=$(aws bedrock-agent get-agent \
          --agent-id ${self.triggers.agent_id} \
          --region ${var.aws_region} \
          --query "agent.agentStatus" \
          --output text 2>/dev/null)
        echo "  Status: $STATUS"
        if [ "$STATUS" = "PREPARED" ] || [ "$STATUS" = "NOT_PREPARED" ]; then
          echo "Agent ready."
          break
        fi
        sleep 10
      done
    CMD
  }

  depends_on = [time_sleep.wait_for_action_group]
}

resource "time_sleep" "wait_for_prepare" {
  create_duration = "20s"
  depends_on      = [null_resource.prepare_agent]
}

resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "access-analyzer-agent-live"
  description      = "Production alias for the IAM Access Analyzer Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
