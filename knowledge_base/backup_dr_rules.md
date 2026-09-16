# Backup & DR Agent — Rules Reference
## Multi-Account Edition

> **Not yet coordinated by the Orchestrator.** This agent exists and runs on its own daily schedule, but the Orchestrator's `agent_map` and Bedrock instruction text only cover the original five agents (Security, Infrastructure, Compliance, Cost, Incident) — see [orchestrator_rules.md](orchestrator_rules.md) §1. Treat this agent as independently operated until that wiring is completed.

---

## Overview

The Backup & DR Agent audits AWS Backup plan coverage/retention, unprotected production/staging EC2 instances, cross-region copy (disaster-recovery) posture, backup vault encryption/access policy, and backup job/recovery-point health, via `backup_plan_checker.py` and `backup_vault_checker.py`. All checks are per-region (`get_scan_regions(session)`), using the `backup` and `ec2` clients with the same cross-account `governance-platform-reader` session pattern as the other agents.

---

## Rule Catalogue

| Rule ID  | Severity | Description |
|----------|----------|-------------|
| BDR-001  | CRITICAL | No AWS Backup plans configured at all in the account |
| BDR-002  | HIGH     | A backup plan rule's retention (`DeleteAfterDays`) is below minimum — 7 days for an apparently-daily schedule, 30 days otherwise |
| BDR-003  | HIGH     | ≥1 EC2 instance tagged `Environment`/`Env` = production/prod/staging is not present in AWS Backup's protected-resources list |
| BDR-004  | MEDIUM   | Backup plans exist but none has a `CopyActions` (cross-region copy) rule configured — no DR posture |
| BDR-005  | HIGH     | Backup vault has no `EncryptionKeyArn` (unencrypted) |
| BDR-005b | LOW      | Backup vault is encrypted with the AWS-managed key (`aws/backup`) rather than a customer-managed CMK |
| BDR-006  | MEDIUM   | Backup vault has no resource-based access policy |
| BDR-007  | HIGH     | ≥1 backup job in `FAILED` state within the last 7 days (grouped by resource ARN, capped at 10 findings) |
| BDR-008  | HIGH / MEDIUM | Protected resource's last backup is stale — HIGH if >7 days old, MEDIUM if >2 days |

No rule in this agent sets `auto_remediable: true`.

---

## Remediation Capabilities

Read-only checker agent — no write/remediation action exists. Exposed API paths:

- `/checkbackupplans`, `/checkbackupvaults` — read-only checks
- `/escalatetohuman` — SNS publish (`ALERT_TOPIC_ARN`), subject `[Backup & DR] {title}`
- `/savebackupreport` — DynamoDB put with a `PK=REPORT#{scan_id}` / `SK=BACKUP_DR` composite-key schema. Unlike Security/Network Security/Access Analyzer, this write has **no `ttl`** and does **not** trigger a Teams scan-complete notification.

---

## Multi-Account Notes

- Every finding carries `account_id`/`account_name`/`region` via the shared `build_finding()` helper.
- Report persistence schema differs from the flat-schema agents (Security, Access Analyzer, Network Security) — don't assume the report item shape is uniform across all agents when building cross-agent tooling.

## Schedule

Daily scan, cron `30 7 * * ? *` (07:30 UTC). The rule/target description text says "daily at 05:00 UTC," which doesn't match the literal cron value — this mismatch exists in the source (`variables.tf`) itself.
