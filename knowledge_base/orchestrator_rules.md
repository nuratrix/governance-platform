# Orchestrator Agent — Rules and Coordination Guidelines
## Multi-Account Edition

---

## 1. Role and Responsibilities

The Orchestrator Agent is the top-level coordinator of the AWS Governance Platform. It:

- Queries findings produced by five sub-agents (Security, Infrastructure, Compliance, Cost, Incident)
- Detects genuine conflicts across agents — i.e., recommendations that contradict each other
- Invokes sub-agents on demand when deeper analysis is needed
- Produces daily executive summaries across all governed accounts
- Escalates critical cross-account events to human operators

The Orchestrator **does not** perform its own AWS API calls. It relies on sub-agent findings persisted in DynamoDB.

**Still five, not nine — a half-finished migration.** The platform now has 9 agent directories (the original 5 plus Cost Anomaly, Network Security, Access Analyzer, Backup & DR — see their own knowledge-base files), but the Orchestrator has not been extended to coordinate them: its Bedrock instruction text (`terraform/bedrock.tf`) still says *"You coordinate five specialist agents: Security, Infrastructure, Compliance, Cost and Incident,"* and `bedrock_action_handler.py`'s `agent_map` only has 5 entries. `variables.tf` does declare an `enabled_agents` variable defaulting to all 9 names plus ID/alias variables for the 4 new agents, but `locals.tf` never merges them into `lambda_env` and `enabled_agents` is never referenced anywhere else — it's a dead variable. Until that wiring is finished, treat the Orchestrator's scope as the original 5 agents only.

---

## 2. Multi-Account Principles

### 2.1 Account-Scoped Queries

When a user asks about a specific account, always pass `account_id` to `query_agent_findings`. This uses the `account-agent-timestamp-index` GSI which is more efficient than scanning all findings.

### 2.2 Cross-Account Conflict Rules

A **conflict** requires:
1. Two agents that recommend **contradictory actions** on the **same resource**
2. The resource must be **in the same account** — findings on `sg-abc` in account `111` and `sg-abc` in account `222` are NOT a conflict

When calling `detect_conflicts`, the resource key format is `account_id::resource_id`. If the `account_id` portion differs, do not flag as a conflict.

### 2.3 Platform Health Grouping

When producing platform health reports, group by `(agent, account_id)` so per-account health is visible. A high-severity finding in one account must not suppress reporting for another account.

### 2.4 Invoking Sub-Agents for Specific Accounts

When invoking a sub-agent via `invoke_agent`, always pass the `account_id` in the request. This ensures the sub-agent assumes the correct cross-account role and reports findings tagged to the correct account.

Example prompt:
```
Scan account 123456789012 (prod-workload). Run a full security audit.
```

The Orchestrator should set `account_id = "123456789012"` in the `invoke_agent` call.

---

## 3. Finding Priority Rules

When multiple findings relate to the same account and resource, prioritise by severity:
`CRITICAL > HIGH > MEDIUM > LOW`

For the executive summary, always lead with CRITICAL and HIGH findings, grouped by account.

### Severity Thresholds for Escalation

| Severity | Action | Enforced in code? |
|----------|--------|---|
| CRITICAL | Escalate immediately via SNS + Teams/Slack notification | Yes — `orchestrator_router.py`'s `should_invoke` triggers on `severity == "CRITICAL"`; `_escalate` fires SNS + Teams + Slack |
| HIGH     | Include in daily summary, escalate if count > 5 in single account | Partially — `total_high > 5` only flips `_get_platform_health`'s `overall_status` to `DEGRADED` (a status label). Whether that actually triggers `escalate_to_human` depends on the LLM following this document's prose, not hardcoded Lambda logic |
| MEDIUM   | Include in weekly digest | No — there is no weekly schedule anywhere in `terraform/eventbridge.tf` (only a daily 10:00 UTC cron exists), and `should_invoke` won't even invoke the agent for a MEDIUM `scan_complete` unless `critical_count > 0`. This tier is LLM-prompt policy only |
| LOW      | Record for trend analysis only | No — same as MEDIUM, no code enforces this; it's prompt policy only |

`_get_platform_health`'s `overall_status` is the one genuinely hardcoded piece of this story — a 4-tier status (HEALTHY/WARNING/DEGRADED/CRITICAL) computed from `total_critical`/`total_high` counts in `bedrock_action_handler.py`.

---

## 4. Conflict Detection Logic

Run `detect_conflicts` after every query of findings from multiple agents. 

**True conflicts to flag:**
- Security Agent says "restrict S3 bucket" while Cost Agent says "enable Intelligent-Tiering" on same bucket — these are complementary, NOT a conflict. Do not flag.
- Security Agent says "terminate idle EC2 instance" while Incident Agent says "do not modify — it is used by the on-call runbook" — this IS a conflict. Flag it.
- Compliance says "enable Multi-AZ RDS" while Cost says "delete idle RDS" — same resource, contradictory actions. Flag it.

**Not conflicts:**
- Same rule firing in two different accounts
- Two agents flagging the same resource for different reasons (they are additive, not contradictory)
- Cost savings recommendations alongside security hardening recommendations

---

## 5. Daily Summary Format

The daily executive summary should include:

1. **Account Overview**: list of governed accounts with overall health score (0-100)
2. **Top Findings by Account**: top 3 CRITICAL/HIGH findings per account
3. **Cross-Account Patterns**: any finding type that appears in 3 or more accounts (systemic issue)
4. **Conflicts**: list of detected conflicts requiring human decision
5. **Cost Optimisation Summary**: total estimated monthly savings across all accounts
6. **Compliance Score**: per-account compliance percentage
7. **Actions Taken**: any auto-remediations performed (e.g. unattached EBS volumes older than 30 days)

---

## 6. Governance Account vs Member Account

The **governance account** (where this platform is deployed) is also scanned by all agents. Treat it like any other account in summaries and conflict detection.

The governance account's `account_id` is available from the `GOVERNANCE_ACCOUNT_ID` environment variable, but **not** in the Orchestrator's own Lambdas — `orchestrator_router.py` and `bedrock_action_handler.py` never read it; it's consumed by `shared/bedrock_agent_trigger.py` (the daily fan-out trigger) and by each sub-agent's own action handler.

Member accounts are registered in a DynamoDB table (actual name: `"${prefix}-account-registry"`, exposed via the `ACCOUNT_REGISTRY_TABLE` env var — not literally `account_registry`). The Orchestrator's Bedrock Agent has **no tool/API path to query it directly** — `bedrock_action_handler.py`'s `_route` only exposes `queryagentfindings`, `detectconflicts`, `invokeagent`, `getplatformhealth`, `escalatetohuman`, `savecoordinationreport`. Only `shared/bedrock_agent_trigger.py::_get_accounts_to_scan()` reads the table, internally, during the daily fan-out — the Orchestrator LLM itself cannot enumerate accounts on demand.

A fourth Lambda not covered elsewhere in this document, `lambda_trigger` (`shared/bedrock_agent_trigger.py`), runs daily at 10:00 UTC and fans out via SQS (`bedrock_invoke_queue`) — one `invoke_agent` call per account, consumed by a separate `bedrock_invoker` Lambda. This replaced an earlier sequential loop that hit the Lambda 900s ceiling at roughly 5 accounts.

---

## 7. Reader Role Pattern

All sub-agents assume the `governance-platform-reader` IAM role in member accounts (or a custom role name passed via `reader_role` session attribute). This role is created by the `member_account` Terraform module. This pattern lives entirely in each **sub-agent's own** action handler (e.g. `agents/security/lambdas/bedrock_action_handler.py`) — the Orchestrator's own Lambdas never import `get_or_assume_session` or call `sts` themselves, since the Orchestrator makes no AWS API calls of its own (see §1).

If a sub-agent cannot assume the reader role in an account, it falls back to the governance account session and logs an **error** (not merely a warning — `logger.error(...)`, confirmed in code). The Orchestrator should treat findings from such scans as governance-account findings, not member-account findings.

Confirmed for the original 5 sub-agents; not independently verified for the 4 newer agents (Cost Anomaly, Network Security, Access Analyzer, Backup & DR) beyond their `iam.tf` granting `sts:AssumeRole` on the same role ARN.

---

## 8. Escalation Decision Tree

```
Receive scan_complete notification from sub-agent
  │
  ├─ CRITICAL findings present?
  │     YES → escalate_to_human immediately
  │            include: account_id, account_name, finding summary, recommended action
  │
  ├─ HIGH findings count > 5 in single account?
  │     YES → escalate_to_human
  │
  ├─ Cross-account pattern detected (same issue in 3+ accounts)?
  │     YES → escalate_to_human with note: "systemic issue across organisation"
  │
  └─ Otherwise → include in next daily summary
```

---

## 9. Data Retention and TTL

Standard findings written by sub-agents to DynamoDB have a TTL of 90 days.

**Correction:** the Orchestrator's own writes are also 90 days, not 365 — both `orchestrator_router.py::_store_orchestration_result` and `bedrock_action_handler.py::_save_report` (the "coordination report") use a 90-day TTL. `orchestrator_router.py::_store_notification` (every raw SNS message the router logs) uses a separate, shorter **30-day** TTL — a third retention tier.

A 365-day TTL genuinely exists elsewhere in the platform, just not on anything the Orchestrator writes — it's used by some *other* agents for their own remediation/audit-style records (e.g. Security Agent's `/remediatesecuritygroup` and `/disableiamaccesskey` audit entries, Incident Agent's auto-healing audit entries).

When querying historical data, be aware that findings older than 90 days will have been automatically deleted, and Orchestrator notifications older than 30 days will have been deleted even sooner.
