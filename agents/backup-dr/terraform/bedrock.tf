# agents/backup-dr/terraform/bedrock.tf

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS backup and disaster recovery agent. Your job is to audit
    AWS Backup configurations and identify gaps that could prevent recovery
    in the event of data loss, ransomware, or a regional outage.

    RULES:
    1. Always start with check_backup_plans to audit plan coverage and retention
    2. Always follow with check_backup_vaults to check encryption and job failures
    3. Escalate any CRITICAL finding immediately (e.g. no backup plans at all,
       critical resources with no backup, or repeated job failures)
    4. Never create or modify backup plans, vaults, or recovery points — read-only
    5. Provide RPO (recovery point objective) and RTO (recovery time objective)
       risk assessment in your findings summary
    6. End every session with save_backup_report

    TOOLS:
    check_backup_plans, check_backup_vaults, escalate_to_human, save_backup_report
  PROMPT

  depends_on = [aws_iam_role.bedrock_agent, aws_iam_role_policy.bedrock_agent_policy]
}

resource "aws_bedrockagent_agent_action_group" "backuptools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "backuptools"
  description       = "AWS Backup plan coverage, vault security, job monitoring, and DR auditing"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Backup & DR Agent Tools", version = "1.0" }
      paths = {

        "/checkbackupplans" = {
          post = {
            operationId = "check_backup_plans"
            description = "Audits AWS Backup plans for existence, retention policy adequacy, unprotected production resources, and cross-region copy configuration."
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
            responses = { "200" = { description = "Backup plan findings", content = { "application/json" = { schema = {
              type = "object"
              properties = { findings = { type = "array", items = { type = "object",
                properties = {
                  rule_id = { type = "string" }, severity = { type = "string" },
                  resource_id = { type = "string" }, title = { type = "string" },
                  description = { type = "string" }, recommendation = { type = "string" }
                }
              } } }
            } } } } }
          }
        }

        "/checkbackupvaults" = {
          post = {
            operationId = "check_backup_vaults"
            description = "Audits AWS Backup vaults for KMS encryption, access policies (ransomware protection), recent job failures in the last 7 days, and stale recovery points."
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
            responses = { "200" = { description = "Backup vault findings", content = { "application/json" = { schema = {
              type = "object"
              properties = { findings = { type = "array", items = { type = "object",
                properties = {
                  rule_id = { type = "string" }, severity = { type = "string" },
                  resource_id = { type = "string" }, title = { type = "string" },
                  description = { type = "string" }, recommendation = { type = "string" }
                }
              } } }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a backup and DR alert via SNS. Call for CRITICAL findings, especially no backup plans or repeated job failures."
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

        "/savebackupreport" = {
          post = {
            operationId = "save_backup_report"
            description = "Saves the backup and DR audit report to DynamoDB. Always call at end of session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object"
                required = ["scan_id", "total_findings"]
                properties = {
                  scan_id               = { type = "string" }
                  total_findings        = { type = "integer" }
                  unprotected_resources = { type = "integer" }
                  failed_jobs           = { type = "integer" }
                  executive_summary     = { type = "string" }
                  top_findings          = { type = "string" }
                  escalations           = { type = "string" }
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
  depends_on      = [aws_bedrockagent_agent_action_group.backuptools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id        = aws_bedrockagent_agent.this.agent_id
    action_group_id = aws_bedrockagent_agent_action_group.backuptools.id
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
  agent_alias_name = "backup-dr-agent-live"
  description      = "Production alias for the Backup & DR Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
