# ─────────────────────────────────────────────────────────────────────────────
# agents/cost/terraform/bedrock.tf
# Cost Agent — Bedrock Agent, inline action group schema, and alias.
# Covers: EC2 rightsizing, RDS rightsizing, S3 cost analysis,
#         Reserved Instance recommendations, remediation and reporting.
# Model: amazon.nova-pro-v1:0
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS cost optimisation agent. Identify wasteful spend
    and recommend or execute savings actions.

    RULES:
    1. Always start with check_ec2_costs and check_rds_costs
    2. Run check_s3_costs and check_reservations every scan
    3. Never stop instances or delete resources without calling
       escalate_to_human first and receiving explicit approval
    4. Auto-remediate only unattached EBS volumes older than 30 days
       when severity is LOW — no other auto-remediation
    5. Always provide estimated monthly savings in every finding
    6. End every session with save_cost_report including total
       potential savings and top 3 recommendations

    TOOLS:
    check_ec2_costs, check_rds_costs, check_s3_costs,
    check_reservations, get_cost_explorer_data,
    stop_ec2_instance, delete_ebs_volume,
    escalate_to_human, save_cost_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy,
  ]
}

# ─── Action Group ─────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent_action_group" "costtools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "costtools"
  description       = "EC2/RDS rightsizing, S3 analysis, RI recommendations, remediation and reporting"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Cost Agent Tools", version = "1.0" }
      paths = {

        # ── EC2 Cost Analysis ─────────────────────────────────────────────────
        "/checkec2costs" = {
          post = {
            operationId = "check_ec2_costs"
            description = "Analyses EC2 instances for idle resources, oversized instance types, stopped instances still accruing EBS costs, and unattached Elastic IPs. Uses CloudWatch CPU and network metrics to identify candidates for rightsizing or termination."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  lookback_days = {
                    type        = "integer"
                    description = "Number of days of CloudWatch metrics to analyse. Default: 14"
                  }
                  cpu_threshold = {
                    type        = "number"
                    description = "Average CPU percentage below which an instance is considered idle. Default: 5"
                  }
                  include_stopped = {
                    type        = "boolean"
                    description = "Include stopped instances in the report. Default: true"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "EC2 cost findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id                  = { type = "string" }
                      severity                 = { type = "string" }
                      resource_id              = { type = "string" }
                      title                    = { type = "string" }
                      description              = { type = "string" }
                      recommendation           = { type = "string" }
                      estimated_monthly_saving = { type = "number", description = "Estimated monthly saving in USD" }
                      auto_remediable          = { type = "boolean" }
                    }
                  }
                }
                summary = {
                  type = "object"
                  properties = {
                    total_findings           = { type = "integer" }
                    total_potential_saving   = { type = "number", description = "Total monthly saving in USD" }
                    instances_scanned        = { type = "integer" }
                    idle_instances           = { type = "integer" }
                    stopped_instances        = { type = "integer" }
                    unattached_ebs_volumes   = { type = "integer" }
                  }
                }
              }
            } } } } }
          }
        }

        # ── RDS Cost Analysis ─────────────────────────────────────────────────
        "/checkrdscosts" = {
          post = {
            operationId = "check_rds_costs"
            description = "Analyses RDS instances and clusters for low utilisation, idle databases, oversized instance classes, and single-AZ instances that could be downsized. Uses CloudWatch DatabaseConnections and CPUUtilization metrics."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  lookback_days = {
                    type        = "integer"
                    description = "Number of days of CloudWatch metrics to analyse. Default: 14"
                  }
                  connection_threshold = {
                    type        = "integer"
                    description = "Max database connections below which an instance is considered idle. Default: 1"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "RDS cost findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id                  = { type = "string" }
                      severity                 = { type = "string" }
                      resource_id              = { type = "string" }
                      title                    = { type = "string" }
                      description              = { type = "string" }
                      recommendation           = { type = "string" }
                      estimated_monthly_saving = { type = "number" }
                      current_instance_class   = { type = "string" }
                      recommended_instance_class = { type = "string" }
                    }
                  }
                }
                summary = {
                  type = "object"
                  properties = {
                    total_findings         = { type = "integer" }
                    total_potential_saving = { type = "number" }
                    instances_scanned      = { type = "integer" }
                    idle_databases         = { type = "integer" }
                  }
                }
              }
            } } } } }
          }
        }

        # ── S3 Cost Analysis ──────────────────────────────────────────────────
        "/checks3costs" = {
          post = {
            operationId = "check_s3_costs"
            description = "Analyses S3 buckets for cost optimisation opportunities including missing lifecycle policies, buckets using expensive storage classes unnecessarily, buckets with no versioning expiry rules, and large buckets with no Intelligent-Tiering."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  min_size_gb = {
                    type        = "number"
                    description = "Only analyse buckets larger than this size in GB. Default: 1"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "S3 cost findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id                  = { type = "string" }
                      severity                 = { type = "string" }
                      resource_id              = { type = "string" }
                      title                    = { type = "string" }
                      description              = { type = "string" }
                      recommendation           = { type = "string" }
                      estimated_monthly_saving = { type = "number" }
                      bucket_size_gb           = { type = "number" }
                      storage_class            = { type = "string" }
                    }
                  }
                }
                summary = {
                  type = "object"
                  properties = {
                    total_findings         = { type = "integer" }
                    total_potential_saving = { type = "number" }
                    buckets_scanned        = { type = "integer" }
                    total_storage_gb       = { type = "number" }
                  }
                }
              }
            } } } } }
          }
        }

        # ── Reserved Instance & Savings Plan Analysis ─────────────────────────
        "/checkreservations" = {
          post = {
            operationId = "check_reservations"
            description = "Analyses Reserved Instance and Savings Plan coverage and utilisation. Identifies on-demand spend that could be covered by reservations, expiring reservations, and underutilised existing reservations. Uses AWS Cost Explorer."
            requestBody = {
              required = false
              content  = { "application/json" = { schema = {
                type = "object"
                properties = {
                  lookback_days = {
                    type        = "integer"
                    description = "Number of days to analyse for RI recommendations. Default: 30"
                  }
                  min_saving_threshold = {
                    type        = "number"
                    description = "Minimum estimated monthly saving in USD to report. Default: 50"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Reservation findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      rule_id                  = { type = "string" }
                      severity                 = { type = "string" }
                      resource_id              = { type = "string" }
                      title                    = { type = "string" }
                      description              = { type = "string" }
                      recommendation           = { type = "string" }
                      estimated_monthly_saving = { type = "number" }
                      payment_option           = { type = "string", description = "NO_UPFRONT, PARTIAL_UPFRONT, or ALL_UPFRONT" }
                      term                     = { type = "string", description = "ONE_YEAR or THREE_YEAR" }
                    }
                  }
                }
                summary = {
                  type = "object"
                  properties = {
                    total_findings              = { type = "integer" }
                    total_potential_saving      = { type = "number" }
                    ri_coverage_percentage      = { type = "number" }
                    ri_utilisation_percentage   = { type = "number" }
                    expiring_reservations       = { type = "integer" }
                  }
                }
              }
            } } } } }
          }
        }

        # ── Cost Explorer Data ────────────────────────────────────────────────
        "/getcostexplorerdata" = {
          post = {
            operationId = "get_cost_explorer_data"
            description = "Retrieves cost and usage data from AWS Cost Explorer for a specific service, time period, or account. Use this to get actual spend figures to include in the report or to investigate a specific cost spike."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["granularity", "lookback_days"]
                properties = {
                  granularity = {
                    type        = "string"
                    description = "DAILY, MONTHLY, or HOURLY"
                  }
                  lookback_days = {
                    type        = "integer"
                    description = "Number of days to retrieve cost data for. Max: 90"
                  }
                  group_by = {
                    type        = "string"
                    description = "Group results by: SERVICE, INSTANCE_TYPE, REGION, or USAGE_TYPE"
                  }
                  filter_service = {
                    type        = "string"
                    description = "Optional AWS service name to filter by e.g. Amazon EC2, Amazon RDS, Amazon S3"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Cost Explorer data", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                total_cost     = { type = "number", description = "Total cost in USD for the period" }
                currency       = { type = "string" }
                period_start   = { type = "string" }
                period_end     = { type = "string" }
                breakdown      = {
                  type  = "array"
                  items = {
                    type = "object"
                    properties = {
                      group  = { type = "string" }
                      cost   = { type = "number" }
                      period = { type = "string" }
                    }
                  }
                }
              }
            } } } } }
          }
        }

        # ── Remediation: Stop EC2 Instance ────────────────────────────────────
        "/stopec2instance" = {
          post = {
            operationId = "stop_ec2_instance"
            description = "Stops an idle EC2 instance to eliminate compute charges. Only call this AFTER escalate_to_human has been called and human approval obtained. Never call this autonomously on HIGH or CRITICAL severity findings."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["instance_id", "reason", "approved_by"]
                properties = {
                  instance_id = {
                    type        = "string"
                    description = "EC2 instance ID to stop e.g. i-0abc1234"
                  }
                  reason = {
                    type        = "string"
                    description = "Explanation of why this instance is being stopped"
                  }
                  approved_by = {
                    type        = "string"
                    description = "Who approved this action — from escalate_to_human response or human confirmation"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Stop result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success          = { type = "boolean" }
                message          = { type = "string" }
                previous_state   = { type = "string" }
                new_state        = { type = "string" }
                estimated_saving = { type = "number", description = "Estimated monthly saving from stopping this instance" }
              }
            } } } } }
          }
        }

        # ── Remediation: Delete EBS Volume ────────────────────────────────────
        "/deleteebsvolume" = {
          post = {
            operationId = "delete_ebs_volume"
            description = "Deletes an unattached EBS volume. Only call for LOW severity findings on volumes older than 30 days with no attachment history. Always call escalate_to_human first for volumes larger than 100GB."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["volume_id", "reason"]
                properties = {
                  volume_id = {
                    type        = "string"
                    description = "EBS volume ID to delete e.g. vol-0abc1234"
                  }
                  reason = {
                    type        = "string"
                    description = "Explanation of why this volume is being deleted"
                  }
                  create_snapshot_first = {
                    type        = "boolean"
                    description = "Create a safety snapshot before deleting. Default: true for volumes over 20GB"
                  }
                }
              } } }
            }
            responses = { "200" = { description = "Delete result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success          = { type = "boolean" }
                message          = { type = "string" }
                snapshot_id      = { type = "string", description = "Safety snapshot ID if created" }
                volume_size_gb   = { type = "number" }
                estimated_saving = { type = "number", description = "Estimated monthly saving in USD" }
              }
            } } } } }
          }
        }

        # ── Escalation ────────────────────────────────────────────────────────
        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a cost alert to the team via SNS. Call this before stopping any EC2 instance, before deleting any volume over 100GB, and for any finding with estimated saving over $500/month."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "finding_summary", "recommended_action", "estimated_monthly_saving"]
                properties = {
                  severity                 = { type = "string", description = "CRITICAL, HIGH, or MEDIUM" }
                  title                    = { type = "string" }
                  finding_summary          = { type = "string" }
                  recommended_action       = { type = "string" }
                  estimated_monthly_saving = { type = "number", description = "Estimated monthly saving in USD" }
                  affected_resources       = { type = "string", description = "Comma-separated list of affected resource IDs" }
                  agent_reasoning          = { type = "string", description = "Why the agent is escalating instead of acting" }
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

        # ── Save Report ───────────────────────────────────────────────────────
        "/savecostreport" = {
          post = {
            operationId = "save_cost_report"
            description = "Saves the final cost optimisation report to DynamoDB. Always call at the end of every session. Include total potential savings and top recommendations."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "total_potential_saving"]
                properties = {
                  scan_id                = { type = "string" }
                  total_potential_saving = { type = "number", description = "Total estimated monthly saving across all findings in USD" }
                  executive_summary      = { type = "string", description = "2-3 sentence plain English summary for non-technical stakeholders including total saving opportunity" }
                  top_recommendations    = { type = "string", description = "Top 3-5 cost saving actions ordered by impact" }
                  actions_taken          = { type = "string", description = "Comma-separated list of remediation actions taken this session" }
                  escalations            = { type = "string", description = "Comma-separated list of issues escalated to humans" }
                  ec2_saving             = { type = "number", description = "EC2 monthly saving opportunity in USD" }
                  rds_saving             = { type = "number", description = "RDS monthly saving opportunity in USD" }
                  s3_saving              = { type = "number", description = "S3 monthly saving opportunity in USD" }
                  reservation_saving     = { type = "number", description = "RI/Savings Plan monthly saving opportunity in USD" }
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
  agent_alias_name = "cost-agent-live"
  description      = "Production alias for the Cost Agent"
}
