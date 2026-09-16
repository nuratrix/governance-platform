# Cost Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Cost Agent identifies waste and savings opportunities across EC2, RDS, S3, and reservation/Savings Plan coverage. It uses the injected cross-account session for EC2/RDS/S3 API calls. **Cost Explorer always runs in the governance account** — member accounts are filtered using the `LINKED_ACCOUNT` CE dimension.

---

## Rule Catalogue

### EC2 Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-EC2-001  | HIGH if avg CPU < 1%, else MEDIUM | Running instance with avg CPU ≤ threshold (default 5%) over lookback period (default 14 days) |
| COST-EC2-002  | HIGH if stopped >30 days; MEDIUM if >7 days; else LOW | Stopped instance still accruing attached-EBS storage costs |
| COST-EC2-003  | HIGH if unattached > 30 days, else LOW | Unattached EBS volume (`auto_remediable` only when age > 30 days — not unconditional) |
| COST-EC2-004  | LOW      | Unused Elastic IP (`auto_remediable: true` unconditionally) |
| COST-EC2-005  | LOW      | Previous generation instance type — `m1,m2,m3,c1,c3,r3,t1,i2,hs1,g2` |

### RDS Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-RDS-001  | HIGH     | RDS instance with max connections ≤ 1 over lookback period (default 14 days) |
| COST-RDS-002  | MEDIUM   | Non-micro/small instance, avg CPU < 20% and max CPU < 40% — downsize candidate. Suppressed if computed saving < $20 |
| COST-RDS-003  | LOW      | Not Multi-AZ and instance price ≥ $200/month |
| COST-RDS-004  | LOW      | Manual RDS snapshot older than 90 days |

### S3 Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-S3-001   | MEDIUM   | Bucket (≥ 1 GB) with no lifecycle policy. Suppressed if computed saving < $1 |
| COST-S3-002   | LOW      | S3 bucket ≥ 50 GB without Intelligent-Tiering |
| COST-S3-003   | MEDIUM   | Versioned bucket with no noncurrent-version expiry/transition rule. Suppressed if computed saving < $1 |
| COST-S3-004   | LOW      | S3 bucket ≥ 100 GB without Storage Class Analysis (no cost estimate — Analysis itself is free) |

### Reservation / Savings Plan Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-RI-001   | HIGH/MEDIUM | Per instance-family coverage < 50% — HIGH if < 20%. Only raised if computed saving ≥ `min_saving_threshold` (default $50) |
| COST-RI-002   | MEDIUM   | Reserved Instance with utilisation < 80% and unused cost > $20 |
| COST-RI-003   | HIGH/MEDIUM | Active RI expiring within 60 days — HIGH if ≤ 30 days (no cost estimate — informational only) |
| COST-RI-004   | MEDIUM   | Savings Plan coverage < 60% of eligible compute and computed saving > $50 |
| COST-RI-005   | LOW      | AWS RI purchase recommendation — overall saving ≥ threshold, and each reported detail (top 3 only) individually ≥ $10 |

---

## Cost Explorer — Multi-Account Behaviour

Cost Explorer is a **global governance-account service**. It cannot be called from assumed-role sessions in member accounts. Instead:

- The CE client always uses the governance account's default credentials
- A `LINKED_ACCOUNT` dimension filter is applied to all CE calls when `account_id` is provided
- This correctly scopes coverage, utilisation, and recommendation data to the target member account

Example filter applied automatically (`reservations_checker.py::_account_filter`):
```python
{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["123456789012"]}}
```

Note: `bedrock_action_handler.py`'s ad hoc `/getcostexplorerdata` action (`_get_cost_explorer_data`) applies the same filter but only when `account_id and account_id != GOVERNANCE_ACCOUNT_ID` — a second, slightly different implementation of the same pattern, not used by the four checker lambdas above.

---

## Savings Estimates

All savings estimates are approximate:
- EC2 idle (COST-EC2-001): 90% of current on-demand cost
- EC2 stopped-but-storage (COST-EC2-002): sum of attached EBS volume monthly cost (or $8.00/volume fallback)
- EC2 unattached EBS (COST-EC2-003): `size_gb × price/GB-month` (fallback $0.08/GB)
- EC2 unused EIP (COST-EC2-004): flat $3.60/month
- EC2 previous gen (COST-EC2-005): 15% of current cost
- RDS idle (COST-RDS-001): flat lookup by instance class (fallback $200/month)
- RDS downsize (COST-RDS-002): difference between current and suggested class cost (fallback: current × 0.5)
- RDS single-AZ overprovisioned (COST-RDS-003): 30% of instance cost
- RDS old snapshot (COST-RDS-004): `size_gb × $0.095/GB-month`
- S3 lifecycle (COST-S3-001): 50% of (Standard − Standard-IA) delta for affected portion
- S3 Intelligent-Tiering (COST-S3-002): 30% of current Standard cost
- S3 noncurrent-version expiry (COST-S3-003): 30% of current Standard cost — same percentage as COST-S3-002 but computed independently against a different bucket
- RI coverage gap (COST-RI-001): 35% of unprotected on-demand spend
- RI underutilised (COST-RI-002): actual wasted spend from CE (`UnusedAmortizedUpfrontFeeForBillingPeriod + UnusedRecurringFee`), not a percentage
- RI expiring (COST-RI-003): no estimate — informational only
- Savings Plan gap (COST-RI-004): 20% of eligible unprotected spend
- RI purchase recommendation (COST-RI-005): taken directly from AWS's `EstimatedMonthlySavingsAmount`

---

## Auto-Remediable Findings

Only two rule IDs can produce `auto_remediable: true`:
- **COST-EC2-003**: unattached EBS volumes, only when `age_days > 30` (not a blanket property of the rule)
- **COST-EC2-004**: unused Elastic IPs, unconditionally

The flag is advisory only — the Bedrock Agent's decision logic, not enforced code, decides whether to act on it.

## Remediation Capabilities

Implemented in `bedrock_action_handler.py`:

- **Stop EC2 instance** (`/stopec2instance`): requires `instance_id` and a non-empty `approved_by` (rejects with "Call escalate_to_human first" if missing). No-ops if already stopped.
- **Delete EBS volume** (`/deleteebsvolume`): refuses if the volume is `in-use`. If `create_snapshot_first` (default `True`) and size ≥ 20GB, creates a safety snapshot and waits for it to complete before deleting.

Both write an audit log entry to DynamoDB (`FINDINGS_TABLE`). Other API paths: `/checkec2costs`, `/checkrdscosts`, `/checks3costs`, `/checkreservations` (read-only, one per checker), `/getcostexplorerdata` (ad hoc CE query), `/escalatetohuman` (SNS + Teams + Slack), `/savecostreport` (DynamoDB, 90-day TTL, notifies orchestrator).
