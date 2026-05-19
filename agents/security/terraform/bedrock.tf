# ─────────────────────────────────────────────────────────────────────────────
# agents/security/terraform/bedrock.tf
#
# AWS Bedrock Agents enforces a hard limit of 10 total APIs per agent across
# all action groups. This file keeps exactly 10 highest-priority APIs.
# Lower-priority checks (kms, eks, ecr, lambda, rds, ssm) are implemented in
# the Lambda handler and can be enabled once a quota increase is approved.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_bedrockagent_agent" "this" {
  agent_name                  = "${local.prefix}-agent"
  foundation_model            = var.foundation_model
  agent_resource_role_arn     = aws_iam_role.bedrock_agent.arn
  idle_session_ttl_in_seconds = 1800

  instruction = <<-PROMPT
    You are an AWS security agent. Identify and remediate security issues across all governed accounts.

    RULES:
    1. Always start with check_guardduty
    2. CRITICAL GuardDuty finding: run get_cloudtrail_events first
    3. Auto-remediate LOW severity only
    4. Escalate CRITICAL and HIGH via escalate_to_human
    5. Never delete resources. Always call checkers with no parameters — they scan the entire account automatically.
    6. End every session with save_scan_report

    TOOLS:
    check_iam, check_s3, check_security_groups, check_guardduty,
    check_cloudtrail, get_cloudtrail_events, remediate_security_group,
    disable_iam_access_key, escalate_to_human, save_scan_report
  PROMPT

  depends_on = [aws_iam_role.bedrock_agent, aws_iam_role_policy.bedrock_agent_policy]
}

# ── Single action group — 10 APIs (hard per-agent limit) ──────────────────────
resource "aws_bedrockagent_agent_action_group" "securitytools" {
  agent_id          = aws_bedrockagent_agent.this.agent_id
  agent_version     = "DRAFT"
  action_group_name = "securitytools"
  description       = "Core security checks, investigation, remediation and reporting"

  action_group_executor {
    lambda = module.lambda_action_handler.function_arn
  }

  api_schema {
    payload = jsonencode({
      openapi = "3.0.0"
      info    = { title = "Security Agent Tools", version = "1.0" }
      paths = {
        "/checkiam" = {
          post = {
            operationId = "check_iam"
            description = "Audits IAM users for MFA, access key age, password policy, admin roles and overly permissive trust policies"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = { focus_area = { type = "string" } } } } } }
            responses   = { "200" = { description = "IAM findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checks3" = {
          post = {
            operationId = "check_s3"
            description = "Checks S3 buckets for public access, encryption, versioning and logging"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = { bucket_name = { type = "string" } } } } } }
            responses   = { "200" = { description = "S3 findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checksecuritygroups" = {
          post = {
            operationId = "check_security_groups"
            description = "Checks security groups for exposed SSH, RDP, database ports and dangerous rules"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = { security_group_id = { type = "string" }, vpc_id = { type = "string" } } } } } }
            responses   = { "200" = { description = "Security group findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checkguardduty" = {
          post = {
            operationId = "check_guardduty"
            description = "Verifies GuardDuty is enabled and retrieves active threat findings. Always call this first."
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = { severity_filter = { type = "string" }, days_back = { type = "integer" } } } } } }
            responses   = { "200" = { description = "GuardDuty findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/checkcloudtrail" = {
          post = {
            operationId = "check_cloudtrail"
            description = "Verifies CloudTrail is enabled, multi-region, with log validation and KMS encryption"
            requestBody = { required = false, content = { "application/json" = { schema = { type = "object", properties = {} } } } }
            responses   = { "200" = { description = "CloudTrail findings", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/getcloudtrailevents" = {
          post = {
            operationId = "get_cloudtrail_events"
            description = "Retrieves recent API call history for a specific user or access key to investigate potential compromise"
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object", required = ["lookup_type", "lookup_value"]
                properties = {
                  lookup_type  = { type = "string" }
                  lookup_value = { type = "string" }
                  hours_back   = { type = "integer" }
                }
              } } }
            }
            responses = { "200" = { description = "CloudTrail events", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/remediatesecuritygroup" = {
          post = {
            operationId = "remediate_security_group"
            description = "Removes a dangerous inbound rule from a security group. LOW severity only."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object", required = ["security_group_id", "from_port", "to_port", "protocol", "cidr"]
                properties = {
                  security_group_id = { type = "string" }
                  from_port         = { type = "integer" }
                  to_port           = { type = "integer" }
                  protocol          = { type = "string" }
                  cidr              = { type = "string" }
                  reason            = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Remediation result", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/disableiamaccesskey" = {
          post = {
            operationId = "disable_iam_access_key"
            description = "Disables a compromised or stale IAM access key. Does not delete it."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object", required = ["username", "access_key_id", "reason"]
                properties = {
                  username      = { type = "string" }
                  access_key_id = { type = "string" }
                  reason        = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Key disable result", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/escalatetohuman" = {
          post = {
            operationId = "escalate_to_human"
            description = "Sends an alert to the security team via SNS. Always call for CRITICAL findings."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object", required = ["severity", "title", "finding_summary", "recommended_action"]
                properties = {
                  severity           = { type = "string" }
                  title              = { type = "string" }
                  finding_summary    = { type = "string" }
                  recommended_action = { type = "string" }
                  affected_resources = { type = "string" }
                  agent_reasoning    = { type = "string" }
                }
              } } }
            }
            responses = { "200" = { description = "Escalation sent", content = { "application/json" = { schema = { type = "object" } } } } }
          }
        }
        "/savescanreport" = {
          post = {
            operationId = "save_scan_report"
            description = "Saves the final security scan report to DynamoDB. Call at end of every session."
            requestBody = {
              required = true
              content  = { "application/json" = { schema = {
                type = "object", required = ["scan_id", "risk_score"]
                properties = {
                  scan_id           = { type = "string" }
                  risk_score        = { type = "number" }
                  executive_summary = { type = "string" }
                  actions_taken     = { type = "string" }
                  escalations       = { type = "string" }
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

# ─── Prepare agent before aliasing ───────────────────────────────────────────

resource "time_sleep" "wait_for_action_group" {
  create_duration = "15s"
  depends_on      = [aws_bedrockagent_agent_action_group.securitytools]
}

resource "null_resource" "prepare_agent" {
  triggers = {
    agent_id         = aws_bedrockagent_agent.this.agent_id
    action_group_id  = aws_bedrockagent_agent_action_group.securitytools.id
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
  agent_alias_name = "security-agent-live"
  description      = "Production alias for the Security Agent"

  depends_on = [time_sleep.wait_for_prepare]
}
