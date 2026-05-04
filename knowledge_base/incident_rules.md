# Incident Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Incident Agent monitors each governed account for active operational incidents: CloudWatch alarms, Lambda errors, ECS service failures, and unhealthy load balancer targets. It can perform safe auto-healing actions. All API calls use the injected cross-account session. The agent runs every 15 minutes.

---

## Detection Rules (INC-*)

### CloudWatch Alarms

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| INC-CW-001    | CRITICAL | CloudWatch alarm in ALARM state, severity ≥ CRITICAL |
| INC-CW-002    | HIGH     | CloudWatch alarm in ALARM state, severity ≥ HIGH |
| INC-CW-003    | MEDIUM   | CloudWatch alarm in ALARM state, severity = MEDIUM |
| INC-CW-004    | LOW      | CloudWatch alarm in INSUFFICIENT_DATA for > 1 hour |

### Lambda Health

| Rule ID        | Severity | Description |
|----------------|----------|-------------|
| INC-LAMBDA-001 | HIGH     | Lambda function error rate > 5% over last 15 minutes |
| INC-LAMBDA-002 | HIGH     | Lambda function throttle count > 100 over last 15 minutes |
| INC-LAMBDA-003 | MEDIUM   | Lambda function p99 duration > 80% of timeout |

### ECS Service Health

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| INC-ECS-001   | CRITICAL | ECS service has 0 running tasks (desired > 0) |
| INC-ECS-002   | HIGH     | ECS service running tasks < 50% of desired |
| INC-ECS-003   | MEDIUM   | ECS service has pending tasks > 5 minutes |

### Load Balancer Health

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| INC-ALB-001   | CRITICAL | All targets in a target group are unhealthy |
| INC-ALB-002   | HIGH     | Unhealthy target count > 30% of registered targets |
| INC-ALB-003   | MEDIUM   | ALB 5XX error rate > 5% over last 5 minutes |

### EC2 Status Checks

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| INC-EC2-001   | HIGH     | EC2 instance failing system status check |
| INC-EC2-002   | HIGH     | EC2 instance failing instance status check |

---

## Auto-Healing Actions

The following actions can be taken automatically or via agent instruction:

| Action | API Path | Description |
|--------|----------|-------------|
| Restart ECS service | `/restartecsservice` | Force new deployment to replace failed tasks |
| Reboot EC2 instance | `/rebootec2instance` | Soft reboot (not force-stop) |
| Scale ASG | `/scaleasg` | Adjust desired capacity up/down |

All auto-healing actions are recorded in DynamoDB with full audit trail including `account_id`.

---

## Escalation Thresholds

| Condition | Action |
|-----------|--------|
| CRITICAL alarm in production account | Immediate escalation via SNS + Teams/Slack |
| ECS service at 0 tasks | Immediate escalation + attempt restart |
| All ALB targets unhealthy | Immediate escalation |
| 3+ HIGH incidents in same account within 15 min | Escalate as cluster incident |

---

## Multi-Account Notes

- The incident detector runs every 15 minutes. Each run scans the account specified in the trigger event's `account_id`.
- The trigger Lambda reads the `account_registry` DynamoDB table and fans out a scan for each active account.
- Incidents are tagged with `account_id` so the Orchestrator can identify which account is affected.
- Auto-healing uses the cross-account session — the agent can restart ECS services and reboot EC2 instances in any governed account.
