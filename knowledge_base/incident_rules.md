# Incident Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Incident Agent monitors each governed account for active operational incidents across two modules: `incident_detector.py` (detection, rule prefix `INC-DET-*`) and `diagnostic_runner.py` (deeper diagnostics, rule prefix `INC-DIAG-*`). It can perform three safe auto-healing actions via `auto_healer.py`. All API calls use the injected cross-account session. The agent runs every 15 minutes (`cron(0/15 * * * ? *)`, confirmed in `terraform/variables.tf` — this is materially faster than the other agents, most of which run daily).

---

## Detection Rules (`incident_detector.py`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| INC-DET-001 | CRITICAL if alarming >30 min; HIGH if >10 min; else MEDIUM | CloudWatch alarm currently in `ALARM` state — severity is derived purely from how long it has been alarming, not from the alarm's own configured severity |
| INC-DET-002 | CRITICAL if ≥50% of a target group's targets unhealthy, else HIGH | ALB/NLB target group has ≥1 unhealthy target |
| INC-DET-003 | CRITICAL if error rate ≥50%; HIGH if ≥20%; MEDIUM if ≥5% (skipped below 5%) | Lambda function error rate over the lookback window (default 60 min) |
| INC-DET-004 | CRITICAL if system status "impaired", else HIGH | Running EC2 instance failing a system or instance status check |
| INC-DET-005 | CRITICAL for "FATAL" (≥1 match); HIGH for "ERROR" (≥10 matches); MEDIUM for "Exception" (≥20 matches) | CloudWatch Logs pattern scan across up to 50 log groups (CloudTrail/flow-log/Control-Tower/access-log groups are skipped); emits at most one finding per log group, for the first pattern that meets its threshold |

## Diagnostic Rules (`diagnostic_runner.py`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| INC-DIAG-001 | HIGH (fixed) | CloudTrail shows a recent deployment event (`UpdateService`, `CreateService`, `RegisterTaskDefinition`, `DeregisterTaskDefinition`, `UpdateFunctionCode`) within the lookback window (default 24h). Note: the code defines 9 candidate event names but only ever queries 5 of them — `CreateDeployment`, `UpdateStack`, `ExecuteChangeSet`, `UpdateFunctionConfiguration` are listed but never looked up |
| INC-DIAG-002 | CRITICAL if running <50% of desired; HIGH if <100% but ≥50% | ECS service `runningCount < desiredCount` (services with `desiredCount == 0` are skipped). The only rule in this agent marked `auto_remediable: true` |
| INC-DIAG-003 | CRITICAL if status is `failed`/`incompatible-restore`; HIGH otherwise | RDS instance status is not `available` |
| INC-DIAG-004 | MEDIUM (informational) | On-demand CPU/Network (EC2) or CPU/Connections/FreeableMemory (RDS) metrics pull for a specific resource — not a real anomaly rule, and only supports EC2 instances and RDS instances (no ECS/ALB/Lambda branch) |

---

## Auto-Healing Actions (`auto_healer.py`)

| Action | API Path | Description | Safety checks |
|--------|----------|-------------|----------------|
| Restart ECS tasks | `/restartecsservice` | Lists all running tasks for the cluster/service and stops each individually via `ecs.stop_task()`, relying on the ECS scheduler to relaunch replacements — **not** a `forceNewDeployment` call | Requires `cluster`, `service`, and non-empty `approved_by` (rejects with "Call escalate_to_human first" if missing) |
| Reboot EC2 instance | `/rebootec2instance` | `ec2.reboot_instances()` | Requires `instance_id` and `approved_by`; refuses if the instance is not currently `running` |
| Scale ASG | `/scaleasg` | `autoscaling.set_desired_capacity(HonorCooldown=False)` | Requires `asg_name`, `approved_by`, `desired_capacity > 0`; caps the new desired capacity at the ASG's `MaxSize`; no-ops if the computed new desired ≤ current desired (won't scale down via this path) |

All three actions hard-require a non-empty `approved_by` string in the request or they fail immediately — there is no code path that executes remediation without that field present. (The LLM agent can populate it itself; the code enforces the field's presence, not that a human actually reviewed the action.) Every action writes a `FINDINGS_TABLE` audit record (365-day TTL) including `account_id`, approver, and reason.

Additional read-only API paths in `bedrock_action_handler.py`: `/detectincidents`, `/rundiagnostics`, `/getcloudwatchmetrics`, `/getrecentlogs`, `/escalatetohuman` (SNS + Teams + Slack + orchestrator notification), `/saveincidentreport` (DynamoDB, `FINDINGS_TABLE`, notifies orchestrator/Teams/Slack).

---

## Escalation Logic

**There is no severity-threshold escalation logic hardcoded in the Lambdas.** `/escalatetohuman` (`_escalate`) is a passive notifier — it fires SNS + Teams + Slack + an orchestrator notification for whatever severity/title the caller supplies, with no internal check of finding counts or severities. All "when to escalate" decisions are delegated to the Bedrock LLM agent via free-text prompts embedded in `eventbridge.tf` and `lambda.tf`:

- `eventbridge.tf` scheduled-scan prompt: *"For every CRITICAL finding immediately run diagnostics and escalate to human. For HIGH findings run diagnostics and recommend action. Save the incident report at the end."*
- `lambda.tf` default agent prompt: *"For any CRITICAL finding run diagnostics and attempt auto-healing where safe. Escalate to human for anything that requires manual action."*

Neither prompt encodes a "3+ HIGH findings in 15 minutes = cluster incident" rule or any other numeric clustering threshold — if that behavior is desired, it needs to be added to the prompt text (or to code), it does not currently exist anywhere in this agent.

---

## Multi-Account Notes

- Every finding includes `account_id`/`account_name` via `shared/build_finding.py`.
- Account enumeration: `shared/bedrock_agent_trigger.py::_get_accounts_to_scan()` reads the `account_registry` DynamoDB table (`ACCOUNT_REGISTRY_TABLE` env var, table name is actually `"${prefix}-account-registry"`); falls back to the `MEMBER_ACCOUNTS_JSON` env var, then to scanning only the governance account if both are unavailable.
- Per-account fan-out is via SQS (`BEDROCK_INVOKE_QUEUE_URL`) — one message per account, consumed by a separate `bedrock_invoker` Lambda that calls `invoke_agent` once per account. This replaced an earlier sequential for-loop that hit the 900s Lambda timeout at roughly 5 accounts.
- Auto-healing uses the cross-account session — the agent can restart ECS tasks and reboot EC2 instances in any governed account, subject to the `approved_by` requirement above.
