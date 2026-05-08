# ─────────────────────────────────────────────────────────────────────────────
# agents/incident/terraform/bedrock.tf
# Incident Agent — Bedrock Agent, inline action group schema, alias.
# Model: amazon.nova-pro-v1:0
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800

  instruction = <<-PROMPT
    You are an AWS incident response agent. Detect, investigate and
    remediate active infrastructure incidents.

    RULES:
    1. Always start with detect_incidents to identify what is wrong
    2. For every CRITICAL finding, immediately run run_diagnostics
    3. Check recent deployments — most incidents correlate with a change
    4. Auto-heal only when safe:
         - restart_ecs_service: safe after escalate_to_human
         - reboot_ec2_instance: safe for system-impaired only, after escalation
         - scale_asg: safe to scale out, NEVER scale in during an incident
    5. Never take remediation actions without calling escalate_to_human first
    6. End every session with save_incident_report including timeline,
       root cause theory, actions taken and prevention steps

    TOOLS:
    detect_incidents, run_diagnostics, get_cloudwatch_metrics,
    get_recent_logs, restart_ecs_service, reboot_ec2_instance,
    scale_asg, escalate_to_human, save_incident_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy,
  ]
}

# ─── Action Group ─────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_action_group" "incidenttools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "incidenttools"
  description       = "Incident detection, diagnostics, auto-healing and reporting tools"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Incident Agent Tools", version = "1.0" }
      paths = {

        # ── Detection ──────────────────────────────────────────────────────
        "/detectincidents" = {
          post = {
            operationId = "detect_incidents"
            description = "Scans for active incidents including firing CloudWatch alarms, unhealthy load balancer targets, Lambda error spikes, EC2 status check failures and high log error rates. Always call this first."
            requestBody = {
              required = false
              content = { "application/json" = { schema = {
                type = "object"
                properties = {
                  lookback_minutes = {
                    type        = "integer"
                    description = "How many minutes of history to scan. Default: 60"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Detected incidents", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object" } }
                summary = {
                  type = "object"
                  properties = {
                    total    = { type = "integer" }
                    critical = { type = "integer" }
                    high     = { type = "integer" }
                    medium   = { type = "integer" }
                  }
                }
              }
            } } } } }
          }
        }

        # ── Diagnostics ────────────────────────────────────────────────────
        "/rundiagnostics" = {
          post = {
            operationId = "run_diagnostics"
            description = "Runs deep diagnostics on the affected resource including recent deployments from CloudTrail, ECS service health, RDS availability and key CloudWatch metrics. Call for every CRITICAL finding."
            requestBody = {
              required = false
              content = { "application/json" = { schema = {
                type = "object"
                properties = {
                  resource_id = {
                    type        = "string"
                    description = "ID of the affected resource e.g. i-0abc1234, my-ecs-service"
                  }
                  resource_type = {
                    type        = "string"
                    description = "AWS resource type e.g. AWS::EC2::Instance, AWS::ECS::Service"
                  }
                  lookback_hours = {
                    type        = "integer"
                    description = "Hours of history to check for recent deployments. Default: 4"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Diagnostic findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object" } }
                summary  = { type = "object" }
              }
            } } } } }
          }
        }

        # ── CloudWatch Metrics ─────────────────────────────────────────────
        "/getcloudwatchmetrics" = {
          post = {
            operationId = "get_cloudwatch_metrics"
            description = "Retrieves time-series CloudWatch metric data for a specific resource to understand trends leading up to and during the incident."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["namespace", "metric_name", "resource_id"]
                properties = {
                  namespace      = { type = "string", description = "CloudWatch namespace e.g. AWS/EC2, AWS/RDS, AWS/Lambda" }
                  metric_name    = { type = "string", description = "Metric name e.g. CPUUtilization, Errors, DatabaseConnections" }
                  resource_id    = { type = "string", description = "Resource identifier value" }
                  dimension_name = { type = "string", description = "Dimension key e.g. InstanceId, FunctionName, DBInstanceIdentifier. Default: InstanceId" }
                  lookback_hours = { type = "integer", description = "Hours of metric history to retrieve. Default: 4" }
                }
              } } }
            }
            responses = { "200" = { description = "Metric datapoints", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                datapoints = {
                  type = "array"
                  items = {
                    type = "object"
                    properties = {
                      timestamp = { type = "string" }
                      average   = { type = "number" }
                      maximum   = { type = "number" }
                      minimum   = { type = "number" }
                    }
                  }
                }
                count = { type = "integer" }
              }
            } } } } }
          }
        }

        # ── Log Retrieval ──────────────────────────────────────────────────
        "/getrecentlogs" = {
          post = {
            operationId = "get_recent_logs"
            description = "Retrieves recent log events from a CloudWatch Log Group with optional filter pattern. Use this to read actual error messages and stack traces for root cause analysis."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["log_group_name"]
                properties = {
                  log_group_name   = { type = "string", description = "CloudWatch Log Group name e.g. /aws/lambda/my-function" }
                  filter_pattern   = { type = "string", description = "CloudWatch filter pattern e.g. ERROR, Exception, FATAL. Default: ERROR" }
                  lookback_minutes = { type = "integer", description = "Minutes of log history to retrieve. Default: 30" }
                  limit            = { type = "integer", description = "Maximum number of log events to return. Default: 20" }
                }
              } } }
            }
            responses = { "200" = { description = "Log events", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                events = {
                  type = "array"
                  items = {
                    type = "object"
                    properties = {
                      timestamp = { type = "string" }
                      message   = { type = "string" }
                    }
                  }
                }
                count = { type = "integer" }
              }
            } } } } }
          }
        }

        # ── Remediation: Restart ECS Service ───────────────────────────────
        "/restartecsservice" = {
          post = {
            operationId = "restart_ecs_service"
            description = "Stops all running tasks in an ECS service. ECS automatically replaces stopped tasks. Only call after escalate_to_human has been called."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["cluster", "service", "approved_by", "reason"]
                properties = {
                  cluster     = { type = "string", description = "ECS cluster name or ARN" }
                  service     = { type = "string", description = "ECS service name" }
                  approved_by = { type = "string", description = "Human approval reference from escalate_to_human" }
                  reason      = { type = "string", description = "Why the service is being restarted" }
                }
              } } }
            }
            responses = { "200" = { description = "Restart result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success       = { type = "boolean" }
                message       = { type = "string" }
                tasks_stopped = { type = "integer" }
              }
            } } } } }
          }
        }

        # ── Remediation: Reboot EC2 ────────────────────────────────────────
        "/rebootec2instance" = {
          post = {
            operationId = "reboot_ec2_instance"
            description = "Reboots an EC2 instance that is failing status checks. Use only for system-impaired instances where the OS is unresponsive. Always call escalate_to_human first."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["instance_id", "approved_by", "reason"]
                properties = {
                  instance_id = { type = "string", description = "EC2 instance ID e.g. i-0abc1234" }
                  approved_by = { type = "string", description = "Human approval reference from escalate_to_human" }
                  reason      = { type = "string", description = "Why the instance is being rebooted" }
                }
              } } }
            }
            responses = { "200" = { description = "Reboot result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success        = { type = "boolean" }
                message        = { type = "string" }
                instance_id    = { type = "string" }
                previous_state = { type = "string" }
              }
            } } } } }
          }
        }

        # ── Remediation: Scale ASG ─────────────────────────────────────────
        "/scaleasg" = {
          post = {
            operationId = "scale_asg"
            description = "Increases the desired capacity of an Auto Scaling Group to add capacity during high traffic incidents. Never scale IN during an incident — only scale out. Always call escalate_to_human first."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["asg_name", "desired_capacity", "approved_by", "reason"]
                properties = {
                  asg_name         = { type = "string", description = "Auto Scaling Group name" }
                  desired_capacity = { type = "integer", description = "New desired instance count. Must be higher than current." }
                  approved_by      = { type = "string", description = "Human approval reference from escalate_to_human" }
                  reason           = { type = "string", description = "Why the ASG is being scaled" }
                }
              } } }
            }
            responses = { "200" = { description = "Scale result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success          = { type = "boolean" }
                message          = { type = "string" }
                previous_desired = { type = "integer" }
                new_desired      = { type = "integer" }
                max_size         = { type = "integer" }
              }
            } } } } }
          }
        }

        # ── Escalation ─────────────────────────────────────────────────────
        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends an incident alert to the on-call team via SNS. Must be called before any remediation action and for all CRITICAL incidents immediately."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "incident_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string", description = "CRITICAL, HIGH or MEDIUM" }
                  title              = { type = "string", description = "Short incident title" }
                  incident_summary   = { type = "string", description = "What is happening and what impact it is having" }
                  affected_resources = { type = "string", description = "Comma-separated list of affected resource IDs" }
                  root_cause_theory  = { type = "string", description = "Agent's best theory of root cause based on diagnostics" }
                  recommended_action = { type = "string", description = "What the agent recommends the human do" }
                  actions_taken      = { type = "string", description = "What the agent has already done" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation sent", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success      = { type = "boolean" }
                message_id   = { type = "string" }
                escalated_at = { type = "string" }
              }
            } } } } }
          }
        }

        # ── Save Report ────────────────────────────────────────────────────
        "/saveincidentreport" = {
          post = {
            operationId = "save_incident_report"
            description = "Saves the incident report to DynamoDB. Always call at the end of every session with a full timeline, root cause and prevention steps."
            requestBody = {
              required = true
              content = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "title", "severity"]
                properties = {
                  scan_id            = { type = "string" }
                  title              = { type = "string", description = "Short incident title" }
                  severity           = { type = "string" }
                  incident_summary   = { type = "string", description = "What happened and what the impact was" }
                  root_cause         = { type = "string", description = "Confirmed or probable root cause" }
                  affected_resources = { type = "string", description = "All affected resource IDs" }
                  timeline           = { type = "string", description = "Chronological sequence of events" }
                  actions_taken      = { type = "string", description = "All remediation actions taken during this incident" }
                  resolution         = { type = "string", description = "How the incident was resolved" }
                  prevention         = { type = "string", description = "Steps to prevent recurrence" }
                  duration_minutes   = { type = "integer", description = "Total incident duration in minutes" }
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

# ─── Prepare agent before aliasing ───────────────────────────────────────────

resource "time_sleep" "wait_for_action_group" {
  create_duration = "15s"
  depends_on      = [aws_bedrockagent_agent_action_group.incidenttools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id        = aws_bedrockagent_agent.this.agent_id
    action_group_id = aws_bedrockagent_agent_action_group.incidenttools.id
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

# ─── Agent Alias ──────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_alias" "live" {
  agent_id         = aws_bedrockagent_agent.this.agent_id
  agent_alias_name = "incident-agent-live"
  description      = "Production alias for the Incident Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
