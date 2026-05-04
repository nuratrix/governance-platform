# ─────────────────────────────────────────────────────────────────────────────
# agents/infrastructure/terraform/bedrock.tf
# Bedrock Agent, action group with inline schema, and alias.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800 # 30 min session timeout

  instruction = <<-PROMPT
     You are an AWS infrastructure agent. Identify unhealthy, wasteful,
    and non-compliant infrastructure.

    RULES:
    1. Always run check_ec2 and check_network first
    2. Escalate HIGH findings via escalate_to_human
    3. Never terminate or delete resources without human approval
    4. End every session with save_infra_report

    TOOLS:
    check_ec2, check_rds, check_network, check_tagging,
    escalate_to_human, save_infra_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy
  ]
}

resource "aws_bedrockagent_agent_action_group" "infratools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "infratools"
  description       = "All infra audit, investigation, remediation and reporting tools"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Infra Agent Tools", version = "1.0" }
      paths = {
        "/checkec2" = {
          post = {
            operationId = "check_ec2"
            description = "Audits EC2 instances, EBS volumes, snapshots, AMIs and Elastic IPs for health and cost issues"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "EC2 findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checkrds" = {
          post = {
            operationId = "check_rds"
            description = "Audits RDS instances for public access, encryption, Multi-AZ, backup retention and old snapshots"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "RDS findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checknetwork" = {
          post = {
            operationId = "check_network"
            description = "Audits VPCs, NAT Gateways, load balancers and target group health"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "Network findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checktagging" = {
          post = {
            operationId = "check_tagging"
            description = "Checks all resources for missing required tags such as Environment, Owner, Project and CostCenter"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "Tagging findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends an alert to the infrastructure team via SNS for issues requiring human decision"
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type = "object", required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  finding_summary    = { type = "string" }
                  recommended_action = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation result", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/saveinfrareport" = {
          post = {
            operationId = "save_infra_report"
            description = "Saves the final infrastructure scan report to DynamoDB. Call at the end of every session."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type = "object", required = ["scan_id", "risk_score"]
                properties = {
                  scan_id           = { type = "string" }
                  risk_score        = { type = "number" }
                  executive_summary = { type = "string" }
                  actions_taken     = { type = "string" }
                  recommendations   = { type = "string" }
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

# Agent Alias (needed to invoke the agent)
resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "infrastructure-agent-live"
  description      = "Production alias for the Infra Agent"
}
