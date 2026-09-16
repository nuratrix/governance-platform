# Access Analyzer Agent — Rules Reference
## Multi-Account Edition

> **Not yet coordinated by the Orchestrator.** This agent exists and runs on its own daily schedule, but the Orchestrator's `agent_map` and Bedrock instruction text only cover the original five agents (Security, Infrastructure, Compliance, Cost, Incident) — see [orchestrator_rules.md](orchestrator_rules.md) §1. Treat this agent as independently operated until that wiring is completed.

---

## Overview

The Access Analyzer Agent audits IAM Access Analyzer coverage/findings (external and public resource access) and general IAM hygiene (unused access keys, unused roles, missing console MFA), via two checker modules: `access_analyzer_checker.py` and `unused_permissions_checker.py`. Access Analyzer checks are per-region (`get_scan_regions(session)`); IAM hygiene checks are account-global. Uses the same cross-account `governance-platform-reader` assumed-role session pattern as the other agents.

---

## Rule Catalogue

| Rule ID     | Severity | Description |
|-------------|----------|-------------|
| IAM-AA-001  | HIGH     | No ACTIVE (ACCOUNT or ORGANIZATION type) IAM Access Analyzer exists in a region |
| IAM-AA-002  | CRITICAL / HIGH / MEDIUM | Active Access Analyzer finding — external/public access to S3, KMS, Secrets Manager, IAM Role, Lambda, SQS, SNS, etc. CRITICAL if `isPublic=true` **and** resource type is high-risk; HIGH if either condition alone; MEDIUM otherwise |
| IAM-AA-003  | HIGH / MEDIUM | Active IAM access key unused for >45 days; HIGH if >180 days |
| IAM-AA-004  | HIGH / MEDIUM | Non-service-linked IAM role not assumed in >90 days, with attached/inline policies; HIGH if >365 days |
| IAM-AA-005  | HIGH     | IAM user has console password enabled but no MFA device (via credential report) |

No rule in this agent sets `auto_remediable: true`.

---

## Remediation Capabilities

`bedrock_action_handler.py` is read-only — the Bedrock instruction explicitly mandates "never modify IAM." Exposed API paths:

- `/checkaccessanalyzer`, `/checkunusedpermissions` — read-only checks. Prompt mandates running Access Analyzer checks before unused-permissions checks.
- `/escalatetohuman` — SNS publish (`ALERT_TOPIC_ARN`), subject `[IAM/Access Analyzer] {title}`. Any finding with `isPublic=true` is treated as CRITICAL for escalation purposes regardless of computed severity.
- `/saveiamreport` — DynamoDB put to `FINDINGS_TABLE` (flat schema, 90-day TTL); triggers a Teams scan-complete notification at CRITICAL if `public_exposures > 0`, else HIGH if any findings exist, else LOW.

---

## Multi-Account Notes

- Every finding carries `account_id`/`account_name`/`region` via the shared `build_finding()` helper.
- Report persistence uses the same flat schema + `ttl` as Security/Network Security (as opposed to the `PK`/`SK` schema used by Backup & DR / Cost Anomaly).

## Schedule

Daily scan — `aws_cloudwatch_event_rule.daily_scan`, cron `20 7 * * ? *` (07:20 UTC). The rule's own description text says "07:00 UTC," which doesn't match the literal cron value; this mismatch exists in the source (`variables.tf`) itself.
