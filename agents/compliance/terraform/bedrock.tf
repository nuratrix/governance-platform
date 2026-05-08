# ─────────────────────────────────────────────────────────────────────────────
# agents/compliance/terraform/bedrock.tf
# Bedrock Agent, action group with inline schema, and alias.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800 # 30 min session timeout
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS compliance agent. Audit this account against CIS,
    SOC2, and AWS Config rules. Identify gaps and produce a compliance report.

    RULES:
    1. Run check_cis, check_soc2, and check_config_rules every scan
    2. Use get_compliance_score to compute the overall score
    3. Escalate CRITICAL findings via escalate_to_human
    4. Never modify infrastructure
    5. End every session with save_compliance_report including score and recommendations

    TOOLS:
    check_cis, check_soc2, check_config_rules, get_compliance_score,
    escalate_to_human, save_compliance_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy
  ]
}

resource "aws_bedrockagent_agent_action_group" "compliancetools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "compliancetools"
  description       = "CIS, SOC2, Config rules compliance checks and reporting"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Compliance Agent Tools", version = "1.0" }
      paths = {
        "/checkcis" = {
          post = {
            operationId = "check_cis"
            description = "Runs CIS AWS Foundations Benchmark v2.0 checks covering IAM password policy, root account, MFA, CloudTrail, Config, VPC Flow Logs and default security groups"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "CIS findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }

        "/checksoc2" = {
          post = {
            operationId = "check_soc2"
            description = "Checks SOC 2 Trust Service Criteria covering CC6 logical access, CC6.7 encryption, CC7 monitoring, CC8 change management, and A1 availability controls"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "SOC2 findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }

        "/checkconfigrules" = {
          post = {
            operationId = "check_config_rules"
            description = "Evaluates 20 AWS Config managed rules covering IAM, S3, CloudTrail, RDS, VPC, GuardDuty and Security Hub across CIS, SOC2, PCI-DSS and HIPAA frameworks"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "Config rules compliance", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }

        "/getcompliancescore" = {
          post = {
            operationId = "get_compliance_score"
            description = "Runs all three compliance checkers and computes an overall compliance score from 0 to 100 with breakdown by framework and severity. Call this at the end of every scan."
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "Overall compliance score and breakdown", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                compliance_score = { type = "number" }
                total_findings   = { type = "integer" }
                by_severity      = { type = "object" }
                by_framework     = { type = "object" }
              }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a compliance alert to the team via SNS for CRITICAL findings requiring immediate attention"
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  finding_summary    = { type = "string" }
                  recommended_action = { type = "string" }
                  affected_resources = { type = "string" }
                  frameworks         = { type = "string", description = "Comma-separated list of affected compliance frameworks" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation result", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }

        "/savecompliancereport" = {
          post = {
            operationId = "save_compliance_report"
            description = "Saves the compliance scan report to DynamoDB. Call at the end of every session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "compliance_score"]
                properties = {
                  scan_id           = { type = "string" }
                  compliance_score  = { type = "number", description = "Overall compliance score 0-100" }
                  executive_summary = { type = "string", description = "Plain English summary for non-technical stakeholders" }
                  frameworks_checked = { type = "string", description = "Comma-separated list of frameworks checked" }
                  critical_findings  = { type = "string", description = "Summary of critical compliance gaps" }
                  recommendations    = { type = "string", description = "Top 3-5 recommended remediation actions" }
                }
              } } }
            }
            responses = { "200" = { description = "Report saved", content = { "application/json" = { schema = { type = "object" } } } } }
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
  depends_on      = [aws_bedrockagent_agent_action_group.compliancetools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id        = aws_bedrockagent_agent.this.agent_id
    action_group_id = aws_bedrockagent_agent_action_group.compliancetools.id
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

# Agent Alias (needed to invoke the agent)
resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "compliance-agent-live"
  description      = "Production alias for the Compliance Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
