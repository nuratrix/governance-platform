# ─────────────────────────────────────────────────────────────────────────────
# agents/orchestrator/terraform/bedrock.tf
# Orchestrator Agent — the coordinator across all sub-agents.
# Model: amazon.nova-pro-v1:0
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800

  instruction = <<-PROMPT
    You are the Orchestrator for an AWS governance platform. You coordinate
    five specialist agents: Security, Infrastructure, Compliance, Cost and Incident.

    YOUR RESPONSIBILITIES:
    1. Correlate findings across agents — identify patterns one agent alone cannot see
    2. Detect and resolve conflicts — e.g. Cost wants to stop an instance
       that Security has flagged as under investigation
    3. Invoke sub-agents on demand when a finding from one agent requires
       another agent to take action immediately
    4. Produce executive summaries aggregating all agent findings into a
       single cross-domain health view
    5. Escalate unresolved CRITICAL findings that span multiple agents

    PRIORITY RULES (highest to lowest):
    1. Active incidents always take priority — never allow cost or compliance
       actions on resources involved in an active incident
    2. Security findings block cost remediation on the same resource
    3. Compliance requirements override cost optimisation recommendations
    4. Cost recommendations apply only when no higher-priority finding exists

    CONFLICT RESOLUTION:
    - security vs cost: security wins — pause cost action, notify cost agent
    - incident vs cost: incident wins — pause cost action
    - compliance vs cost: compliance wins — adjust cost recommendation
    - security vs compliance: escalate_to_human — human decides

    TOOLS:
    query_agent_findings, detect_conflicts, invoke_agent,
    get_platform_health, escalate_to_human, save_coordination_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy,
  ]
}

# Wait for the agent to finish preparing before attaching action groups
resource "time_sleep" "wait_for_agent" {
  create_duration = "30s"
  depends_on      = [aws_bedrockagent_agent.this]
}

# ─── Action Group ─────────────────────────────────────────────────────────────

# Bedrock requires action groups to be DISABLED before they can be deleted.
# This null_resource runs a disable call on destroy, before the action group
# resource itself is removed.
resource "null_resource" "disable_action_group_on_destroy" {
  triggers = {
    agent_id         = aws_bedrockagent_agent.this.agent_id
    action_group_id  = aws_bedrockagent_agent_action_group.orchestratortools.action_group_id
    region           = var.aws_region
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-CMD
      aws bedrock-agent update-agent-action-group \
        --agent-id ${self.triggers.agent_id} \
        --agent-version DRAFT \
        --action-group-id ${self.triggers.action_group_id} \
        --action-group-name orchestratortools \
        --action-group-state DISABLED \
        --region ${self.triggers.region} || true
    CMD
  }

  depends_on = [aws_bedrockagent_agent_action_group.orchestratortools]
}

resource "aws_bedrockagent_agent_action_group" "orchestratortools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "orchestratortools"
  description       = "Cross-agent coordination, conflict detection and platform health tools"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Orchestrator Agent Tools", version = "1.0" }
      paths = {

        "/queryagentfindings" = {
          post = {
            operationId = "query_agent_findings"
            description = "Queries DynamoDB for recent findings from one or all sub-agents. Use this to understand what every agent has found before making coordination decisions."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  agent_filter     = { type = "string", description = "Filter by specific agent e.g. security-agent, cost-agent, compliance-agent, incident-agent. Leave empty for all agents." }
                  hours_back       = { type = "integer", description = "How many hours of findings to retrieve. Default: 24" }
                  severity_filter  = { type = "string", description = "Filter by severity: CRITICAL, HIGH, MEDIUM or LOW. Leave empty for all." }
                  event_type       = { type = "string", description = "Filter by event type: scan_complete, critical_finding, remediation_taken." }
                  account_id       = { type = "string", description = "Filter by specific AWS account ID. Leave empty for all accounts." }
                }
              } } }
            }
            responses = { "200" = { description = "Agent findings grouped by agent", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                total_items     = { type = "integer" }
                agents_found    = { type = "array", items = { type = "string" } }
                by_agent        = { type = "object", description = "Findings grouped by agent name" }
                by_account      = { type = "object", description = "Findings grouped by account ID" }
              }
            } } } } }
          }
        }

        "/detectconflicts" = {
          post = {
            operationId = "detect_conflicts"
            description = "Identifies conflicts between agent recommendations on the same resources. Detects cost-vs-security, cost-vs-incident and compliance-vs-cost conflicts."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  hours_back = { type = "integer", description = "How many hours of history to check. Default: 48" }
                }
              } } }
            }
            responses = { "200" = { description = "Detected conflicts", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                conflicts_found    = { type = "integer" }
                resources_checked  = { type = "integer" }
                conflicts          = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      conflict_type    = { type = "string" }
                      resource_id      = { type = "string" }
                      account_id       = { type = "string" }
                      agents           = { type = "array", items = { type = "string" } }
                      description      = { type = "string" }
                      recommendation   = { type = "string" }
                      severity         = { type = "string" }
                    }
                  }
                }
              }
            } } } } }
          }
        }

        "/invokeagent" = {
          post = {
            operationId = "invoke_agent"
            description = "Invokes a specific sub-agent on demand with a targeted prompt. Use when a finding from one agent requires immediate action from another — e.g. a CRITICAL security finding should trigger the incident agent."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["agent_name", "prompt"]
                properties = {
                  agent_name = { type = "string", description = "Agent to invoke: security-agent, cost-agent, compliance-agent, incident-agent, or infrastructure-agent" }
                  prompt     = { type = "string", description = "Specific instruction for the agent to execute" }
                  account_id = { type = "string", description = "AWS account ID to target. Defaults to governance account if not specified." }
                }
              } } }
            }
            responses = { "200" = { description = "Agent invocation result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success    = { type = "boolean" }
                agent_name = { type = "string" }
                session_id = { type = "string" }
                completion = { type = "string", description = "Agent's response summary" }
              }
            } } } } }
          }
        }

        "/getplatformhealth" = {
          post = {
            operationId = "get_platform_health"
            description = "Aggregates recent findings from all agents into a single platform health view with an overall status of HEALTHY, WARNING, DEGRADED or CRITICAL."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  hours_back = { type = "integer", description = "Hours of findings to aggregate. Default: 24" }
                }
              } } }
            }
            responses = { "200" = { description = "Platform health summary", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                overall_status    = { type = "string", description = "HEALTHY, WARNING, DEGRADED or CRITICAL" }
                total_critical    = { type = "integer" }
                total_high        = { type = "integer" }
                agents_reporting  = { type = "array", items = { type = "string" } }
                by_agent          = { type = "object", description = "Per-agent finding counts by severity" }
                by_account        = { type = "object", description = "Per-account finding counts by severity" }
              }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a cross-agent coordination alert to the team. Use when conflicts cannot be resolved automatically or when unresolved CRITICAL findings span multiple agents."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "situation", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  situation          = { type = "string", description = "What is happening across the platform" }
                  agents_involved    = { type = "string", description = "Comma-separated list of agents involved" }
                  conflicts          = { type = "string", description = "Description of unresolved conflicts" }
                  recommended_action = { type = "string", description = "What the human should do" }
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

        "/savecoordinationreport" = {
          post = {
            operationId = "save_coordination_report"
            description = "Saves the coordination report to DynamoDB. Always call at the end of every session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "platform_status"]
                properties = {
                  scan_id           = { type = "string" }
                  trigger_agent     = { type = "string", description = "Which agent triggered this coordination session" }
                  trigger_event     = { type = "string", description = "What event triggered this session" }
                  platform_status   = { type = "string", description = "Overall platform status: HEALTHY, WARNING, DEGRADED or CRITICAL" }
                  conflicts_found   = { type = "string", description = "Summary of any conflicts detected and how they were resolved" }
                  actions_taken     = { type = "string", description = "What the Orchestrator did during this session" }
                  agents_invoked    = { type = "string", description = "Comma-separated list of sub-agents invoked on demand" }
                  executive_summary = { type = "string", description = "Plain English summary for non-technical stakeholders" }
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

  depends_on = [time_sleep.wait_for_agent]
}

# Step 3 — wait for action group to attach
resource "time_sleep" "wait_for_action_group" {
  create_duration = "15s"
  depends_on      = [aws_bedrockagent_agent_action_group.orchestratortools]
}

# Step 4 — prepare the agent (bakes DRAFT into a numbered version)
resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id         = aws_bedrockagent_agent.this.agent_id
    action_group_id  = aws_bedrockagent_agent_action_group.orchestratortools.id
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

# Step 5 — wait for prepare to complete
resource "time_sleep" "wait_for_prepare" {
  create_duration = "20s"
  depends_on      = [null_resource.prepare_agent]
}

# ─── Agent Alias ──────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "orchestrator-agent-live"
  description      = "Production alias for the Orchestrator Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
