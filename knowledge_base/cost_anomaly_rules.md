# Cost Anomaly Agent — Rules Reference
## Multi-Account Edition

> **Not yet coordinated by the Orchestrator.** This agent exists and runs on its own daily schedule, but the Orchestrator's `agent_map` and Bedrock instruction text only cover the original five agents (Security, Infrastructure, Compliance, Cost, Incident) — see [orchestrator_rules.md](orchestrator_rules.md) §1. It is also distinct from, and not coordinated with, the standalone Cost Agent — see [cost_rules.md](cost_rules.md).

---

## Overview

The Cost Anomaly Agent has two modules: `anomaly_detector.py` (native AWS Cost Anomaly Detection API — `get_anomalies`, `get_anomaly_monitors`, `get_anomaly_subscriptions`) and `root_cause_analyzer.py` (custom root-cause analysis via `ce.get_cost_and_usage`, comparing a recent window against a prior baseline, grouped by `SERVICE`/`LINKED_ACCOUNT`/`REGION`).

**Unlike every other agent, this one never uses the injected cross-account session.** Cost Explorer is a governance-account-global service, so both checkers always call `boto3.client("ce", region_name="us-east-1")` directly — there is no per-account or per-region loop. `bedrock_action_handler.py` still assumes a cross-account session but never passes it into either checker.

---

## Rule Catalogue

### Anomaly Detection (`anomaly_detector.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-ANO-001  | CRITICAL / HIGH / MEDIUM / LOW | Active Cost Anomaly Detection anomaly over the last `days_back` (default 7) days, excluding `Feedback=PLANNED_ACTIVITY`. Thresholds on `TotalImpact` USD: CRITICAL ≥ $1000, HIGH ≥ $250, MEDIUM ≥ $50, else LOW |
| COST-ANO-002  | HIGH     | No AWS Cost Anomaly Detection monitors configured at all |
| COST-ANO-003  | MEDIUM   | Monitors exist but no subscriptions configured — anomalies would be detected but nobody alerted |
| COST-ANO-003b | LOW      | A subscription exists with `Threshold=0` (alerts on every anomaly — alert fatigue) |

### Root Cause Analysis (`root_cause_analyzer.py`)

Compares a recent window (`days_back`, default 7) against a prior baseline window (`compare_days`, default 14), normalized to daily averages.

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-RCA-001  | CRITICAL / HIGH / MEDIUM / LOW | Per-SERVICE spend spike, daily delta ≥ $10. CRITICAL if pct change ≥200% or delta ≥$100/day; HIGH if ≥100% or ≥$50/day; MEDIUM if ≥50% or ≥$10/day; else LOW |
| COST-RCA-002  | HIGH / MEDIUM | Per-account (`LINKED_ACCOUNT`, excluding the governance/payer account) spend spike, daily delta ≥ $10. HIGH if pct change ≥100% or delta ≥$50/day, else MEDIUM |
| COST-RCA-003  | HIGH / MEDIUM / LOW | Per-region spend spike, or spend appearing in a brand-new region (baseline $0). HIGH if new region; else MEDIUM if pct change ≥100%, else LOW |

No rule in this agent sets `auto_remediable: true`.

---

## Remediation Capabilities

Read-only agent — no write/remediation action exists. Exposed API paths:

- `/checkanomalies`, `/analyzerootcause` — read-only checks
- `/escalatetohuman` — SNS publish (`ALERT_TOPIC_ARN`), subject `[Cost Anomaly] {title}`, includes `total_impact_usd` and `root_causes` in the message
- `/saveanomalyreport` — DynamoDB put, `PK=REPORT#{scan_id}` / `SK=COST_ANOMALY`. No `ttl`, no Teams notification (same report-schema family as Backup & DR, not the flat-schema family used by Security/Access Analyzer/Network Security).

---

## Multi-Account Notes

- Findings do **not** originate from a per-account assumed-role scan — they come from Cost Explorer data that already spans the whole organisation (via `LINKED_ACCOUNT` grouping). `account_id` on a COST-RCA-002 finding identifies which linked account the spike belongs to, not which account the API call was made in.
- This is the only agent whose checkers cannot be meaningfully re-run "for account X" via `get_or_assume_session` — the governance account's own CE access already covers every linked account.

## Schedule

Daily scan, cron `50 7 * * ? *` (07:50 UTC). The rule description text says "Daily anomaly scan — runs at 08:00 UTC before business hours," which doesn't match the literal cron value — this mismatch exists in the source (`variables.tf`) itself.
