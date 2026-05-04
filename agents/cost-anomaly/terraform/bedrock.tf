# ─────────────────────────────────────────────────────────────────────────────
# agents/cost-anomaly/terraform/bedrock.tf
# Cost Anomaly Agent — Bedrock Agent, action group, and alias.
# Covers: AWS Cost Anomaly Detection, spend spike root cause analysis.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS cost anomaly detection agent. Your job is to identify
    unexpected spend spikes, determine their root cause, and escalate
    actionable alerts to the engineering team.

    RULES:
    1. Always start with check_anomalies to pull active AWS Cost Anomaly Detection alerts
    2. For every anomaly with total_impact >= $50, call analyze_root_causes to identify the
       driving service, linked account, or region
    3. Escalate ALL CRITICAL and HIGH findings via escalate_to_human immediately
    4. Never take any remediation actions — this agent is read-only and advisory only
    5. Always end every session with save_anomaly_report including total unexpected spend
       and all findings

    TOOLS:
    check_anomalies, analyze_root_causes, escalate_to_human, save_anomaly_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy,
  ]
}

# ─── Action Group ─────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_action_group" "anomalytools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "anomalytools"
  description       = "Cost anomaly detection, root cause analysis, escalation and reporting"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Cost Anomaly Agent Tools", version = "1.0" }
      paths = {

        "/checkanomalies" = {
          post = {
            operationId = "check_anomalies"
            description = "Pulls active cost anomalies from AWS Cost Anomaly Detection. Returns anomalies with severity, total unexpected spend, root causes, and anomaly IDs. Also checks whether anomaly monitors and alert subscriptions are properly configured."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  account_id   = { type = "string", description = "AWS account ID to scan" }
                  account_name = { type = "string", description = "Human-readable account name" }
                  days_back    = { type = "integer", description = "Number of days of anomaly history to pull. Default: 7" }
                }
              } } }
            }
            responses = { "200" = { description = "Anomaly findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id        = { type = "string" }
                      severity       = { type = "string", description = "CRITICAL, HIGH, MEDIUM, or LOW" }
                      resource_id    = { type = "string", description = "AWS Cost Anomaly ID" }
                      title          = { type = "string" }
                      description    = { type = "string" }
                      recommendation = { type = "string" }
                    }
                  }
                }
              }
            } } } } }
          }
        }

        "/analyzerootcauses" = {
          post = {
            operationId = "analyze_root_causes"
            description = "Performs cost breakdown analysis by SERVICE, LINKED_ACCOUNT, and REGION to identify which dimension is responsible for a spend spike. Compares current window spend against a prior baseline window."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  account_id    = { type = "string", description = "AWS account ID to analyse" }
                  account_name  = { type = "string", description = "Human-readable account name" }
                  days_back     = { type = "integer", description = "Spike window in days to analyse. Default: 7" }
                  compare_days  = { type = "integer", description = "Baseline window in days to compare against. Default: 14" }
                }
              } } }
            }
            responses = { "200" = { description = "Root cause findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id           = { type = "string" }
                      severity          = { type = "string" }
                      resource_id       = { type = "string", description = "Service name, account ID, or region" }
                      title             = { type = "string" }
                      description       = { type = "string" }
                      recommendation    = { type = "string" }
                      delta_daily_usd   = { type = "number", description = "Increase in spend per day (USD)" }
                      pct_change        = { type = "number", description = "Percentage increase vs baseline" }
                    }
                  }
                }
              }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a cost anomaly alert to the team via SNS. Call this for all CRITICAL and HIGH severity findings, and any anomaly with unexpected spend over $250."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity          = { type = "string", description = "CRITICAL, HIGH, or MEDIUM" }
                  title             = { type = "string" }
                  finding_summary   = { type = "string" }
                  anomaly_id        = { type = "string", description = "AWS Cost Anomaly Detection anomaly ID" }
                  total_impact_usd  = { type = "number", description = "Total unexpected spend in USD" }
                  root_causes       = { type = "string", description = "Summary of identified root causes" }
                  recommended_action = { type = "string" }
                  agent_reasoning   = { type = "string", description = "Why the agent is escalating" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success      = { type = "boolean" }
                message_id   = { type = "string" }
                escalated_at = { type = "string" }
              }
            } } } } }
          }
        }

        "/saveanomalyreport" = {
          post = {
            operationId = "save_anomaly_report"
            description = "Saves the final anomaly scan report to DynamoDB. Always call at the end of every session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "total_unexpected_spend_usd"]
                properties = {
                  scan_id                    = { type = "string" }
                  total_anomalies            = { type = "integer", description = "Total number of active anomalies found" }
                  total_unexpected_spend_usd = { type = "number", description = "Sum of all anomaly impacts in USD" }
                  executive_summary          = { type = "string", description = "2-3 sentence summary for non-technical stakeholders" }
                  top_findings               = { type = "string", description = "Top 3-5 anomalies ordered by impact" }
                  actions_taken              = { type = "string", description = "Comma-separated list of actions taken" }
                  escalations                = { type = "string", description = "Comma-separated list of escalated issues" }
                }
              } } }
            }
            responses = { "200" = { description = "Report saved", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success = { type = "boolean" }
                scan_id = { type = "string" }
              }
            } } } } }
          }
        }

      } # end paths
    })  # end jsonencode
  }     # end api_schema

  depends_on = [aws_bedrockagent_agent.this]
}

# ─── Agent Alias ──────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "cost-anomaly-agent-live"
  description      = "Production alias for the Cost Anomaly Agent"
}
