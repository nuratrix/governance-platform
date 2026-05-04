# Orchestrator Agent — Rules and Coordination Guidelines
## Multi-Account Edition

---

## 1. Role and Responsibilities

The Orchestrator Agent is the top-level coordinator of the AWS Governance Platform. It:

- Queries findings produced by all five sub-agents (Security, Infrastructure, Compliance, Cost, Incident)
- Detects genuine conflicts across agents — i.e., recommendations that contradict each other
- Invokes sub-agents on demand when deeper analysis is needed
- Produces daily executive summaries across all governed accounts
- Escalates critical cross-account events to human operators

The Orchestrator **does not** perform its own AWS API calls. It relies on sub-agent findings persisted in DynamoDB.

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

| Severity | Action |
|----------|--------|
| CRITICAL | Escalate immediately via SNS + Teams/Slack notification |
| HIGH     | Include in daily summary, escalate if count > 5 in single account |
| MEDIUM   | Include in weekly digest |
| LOW      | Record for trend analysis only |

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

The governance account's `account_id` is available from the `GOVERNANCE_ACCOUNT_ID` environment variable in all Lambda functions.

Member accounts are registered in the `account_registry` DynamoDB table. Query it to enumerate all governed accounts for organisation-wide sweeps.

---

## 7. Reader Role Pattern

All sub-agents assume the `governance-platform-reader` IAM role in member accounts (or a custom role name passed via `reader_role` session attribute). This role is created by the `member_account` Terraform module.

If a sub-agent cannot assume the reader role in an account, it falls back to the governance account session and logs a warning. The Orchestrator should treat findings from such scans as governance-account findings, not member-account findings.

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

All findings written to DynamoDB have a TTL of 90 days. Coordination reports (from the Orchestrator) have a TTL of 365 days for audit purposes.

When querying historical data, be aware that findings older than 90 days will have been automatically deleted.
