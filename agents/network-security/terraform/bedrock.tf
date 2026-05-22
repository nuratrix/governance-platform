# ─────────────────────────────────────────────────────────────────────────────
# agents/network-security/terraform/bedrock.tf
# Network Security Agent — Bedrock Agent, action group, and alias.
# Covers: VPCs, Security Groups, NACLs, DNS, Transit Gateways.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800
  prepare_agent               = false

  instruction = <<-PROMPT
    You are an AWS network security agent. Your job is to audit network
    configurations and identify misconfigurations that expose resources
    to the internet or enable lateral movement between network segments.

    RULES:
    1. Always start with check_vpc then check_security_groups then check_dns
    2. Escalate any finding where a dangerous port (SSH, RDP, database ports) is
       exposed to 0.0.0.0/0 — these are CRITICAL and require immediate action
    3. Never modify security groups, NACLs, or routing tables — read-only only
    4. For Transit Gateway findings, always check whether cross-account sharing
       is explicitly approved
    5. After all checks and escalations, call save_network_report with ALL of these fields populated:
       - scan_id: Use the scan_id from sessionAttributes, or generate "scan-YYYYMMDD-HHMMSS"
       - total_findings: Total count of all findings across all checks (integer)
       - critical_findings: Count of CRITICAL severity findings (integer)
       - high_findings: Count of HIGH severity findings (integer)
       - executive_summary: Write a 2-3 sentence paragraph stating (1) which checks ran, (2) total findings by severity, (3) the most critical issues. Example: "Network security scan completed for account 123456789012. Found 1 CRITICAL finding: SSH port 22 is exposed to 0.0.0.0/0 on security group sg-abc123 in us-east-1. VPC flow logs are disabled on 2 VPCs (HIGH severity)."
       - top_findings: JSON array string of the top 10 findings. Each item: {"severity":"CRITICAL","title":"SSH Exposed to Internet","resource_id":"sg-abc123","description":"Security group allows inbound SSH from 0.0.0.0/0","recommendation":"Restrict SSH to known IP ranges only"}
       - escalations: String summarising escalations sent. Example: "Escalated 1 CRITICAL (SSH port 22 on sg-abc123)" — use "None" if no escalations.
       - actions_taken: Always set to "Read-only scan — no automated actions taken"

    TOOLS:
    check_vpc, check_security_groups, check_dns, escalate_to_human, save_network_report
  PROMPT

  depends_on = [
    aws_iam_role.bedrock_agent,
    aws_iam_role_policy.bedrock_agent_policy,
  ]
}

resource "aws_bedrockagent_agent_action_group" "networktools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "networktools"
  description       = "VPC, security group, NACL, DNS and Transit Gateway security auditing"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Network Security Agent Tools", version = "1.0" }
      paths = {

        "/checkvpc" = {
          post = {
            operationId = "check_vpc"
            description = "Audits VPC configurations across all regions for missing flow logs, resources in the default VPC, subnets auto-assigning public IPs, dangling Internet Gateways, and unexpected VPC peering connections."
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
            responses = { "200" = { description = "VPC findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object",
                  properties = {
                    rule_id = { type = "string" }, severity = { type = "string" },
                    resource_id = { type = "string" }, title = { type = "string" },
                    description = { type = "string" }, recommendation = { type = "string" }
                  }
                } }
              }
            } } } } }
          }
        }

        "/checksecuritygroups" = {
          post = {
            operationId = "check_security_groups"
            description = "Audits EC2 Security Groups and Network ACLs across all regions. Identifies groups with all-traffic allows from 0.0.0.0/0, dangerous port exposures (SSH, RDP, database ports), and overly permissive NACL rules."
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
            responses = { "200" = { description = "Security group and NACL findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object",
                  properties = {
                    rule_id = { type = "string" }, severity = { type = "string" },
                    resource_id = { type = "string" }, title = { type = "string" },
                    description = { type = "string" }, recommendation = { type = "string" }
                  }
                } }
              }
            } } } } }
          }
        }

        "/checkdns" = {
          post = {
            operationId = "check_dns"
            description = "Audits Route 53 Resolver DNS query logging and DNS Firewall configurations per VPC. Also checks Transit Gateway sharing configuration for AutoAcceptSharedAttachments and DefaultRouteTableAssociation risks."
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
            responses = { "200" = { description = "DNS and Transit Gateway findings", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                findings = { type = "array", items = { type = "object",
                  properties = {
                    rule_id = { type = "string" }, severity = { type = "string" },
                    resource_id = { type = "string" }, title = { type = "string" },
                    description = { type = "string" }, recommendation = { type = "string" }
                  }
                } }
              }
            } } } } }
          }
        }

        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends a network security alert via SNS. Call for CRITICAL or HIGH findings, especially any port exposed to 0.0.0.0/0."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  finding_summary    = { type = "string" }
                  resource_id        = { type = "string" }
                  region             = { type = "string" }
                  recommended_action = { type = "string" }
                  agent_reasoning    = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation result", content = { "application/json" = { schema = {
              type = "object"
              properties = {
                success = { type = "boolean" }, message_id = { type = "string" }, escalated_at = { type = "string" }
              }
            } } } } }
          }
        }

        "/savenetworkreport" = {
          post = {
            operationId = "save_network_report"
            description = "Saves the network security scan report to DynamoDB. Always call at end of session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type     = "object"
                required = ["scan_id", "total_findings", "executive_summary", "critical_findings", "high_findings"]
                properties = {
                  scan_id            = { type = "string" }
                  total_findings     = { type = "integer" }
                  critical_findings  = { type = "integer", description = "Count of CRITICAL severity findings" }
                  high_findings      = { type = "integer", description = "Count of HIGH severity findings" }
                  executive_summary  = { type = "string", description = "2-3 sentence summary of findings and risk" }
                  top_findings       = { type = "string", description = "JSON array string of top 10 findings" }
                  actions_taken      = { type = "string" }
                  escalations        = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Report saved", content = { "application/json" = { schema = {
              type = "object"
              properties = { success = { type = "boolean" }, scan_id = { type = "string" } }
            } } } } }
          }
        }

      } # end paths
    })
  }

  depends_on = [aws_bedrockagent_agent.this]
}

# ─── Prepare agent before aliasing ───────────────────────────────────────────

resource "time_sleep" "wait_for_action_group" {
  create_duration = "15s"
  depends_on      = [aws_bedrockagent_agent_action_group.networktools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id         = aws_bedrockagent_agent.this.agent_id
    action_group_id  = aws_bedrockagent_agent_action_group.networktools.id
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
  agent_alias_name = "network-security-agent-live"
  description      = "Production alias for the Network Security Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
