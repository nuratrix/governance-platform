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
| COST-EC2-001  | HIGH/MEDIUM | Running instance with avg CPU ≤ threshold (default 5%) over lookback period |
| COST-EC2-002  | HIGH/MEDIUM/LOW | Stopped instance still accruing EBS storage costs |
| COST-EC2-003  | HIGH/LOW | Unattached EBS volume (HIGH if unattached > 30 days; auto-remediable) |
| COST-EC2-004  | LOW      | Unused Elastic IP (auto-remediable) |
| COST-EC2-005  | LOW      | Previous generation instance type (m1/m2/m3/c1/c3/r3/t1) |

### RDS Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-RDS-001  | HIGH     | RDS instance with max connections ≤ 1 over lookback period |
| COST-RDS-002  | MEDIUM   | RDS instance with avg CPU < 20% and max CPU < 40% — downsize candidate |
| COST-RDS-003  | LOW      | Large single-AZ RDS instance (≥ $200/month) |
| COST-RDS-004  | LOW      | Manual RDS snapshot older than 90 days |

### S3 Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-S3-001   | MEDIUM   | S3 bucket with no lifecycle policy |
| COST-S3-002   | LOW      | S3 bucket ≥ 50 GB without Intelligent-Tiering |
| COST-S3-003   | MEDIUM   | Versioned bucket with no noncurrent version expiry rule |
| COST-S3-004   | LOW      | S3 bucket ≥ 100 GB without Storage Class Analysis |

### Reservation / Savings Plan Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| COST-RI-001   | HIGH/MEDIUM | RI coverage < 50% for a service — HIGH if < 20% |
| COST-RI-002   | MEDIUM   | Reserved Instance with utilisation < 80% |
| COST-RI-003   | HIGH/MEDIUM | RI expiring within 60 days — HIGH if ≤ 30 days |
| COST-RI-004   | MEDIUM   | Savings Plan coverage < 60% of eligible compute |
| COST-RI-005   | LOW      | AWS RI purchase recommendation (estimated saving ≥ threshold) |

---

## Cost Explorer — Multi-Account Behaviour

Cost Explorer is a **global governance-account service**. It cannot be called from assumed-role sessions in member accounts. Instead:

- The CE client always uses the governance account's default credentials
- A `LINKED_ACCOUNT` dimension filter is applied to all CE calls when `account_id` is provided
- This correctly scopes coverage, utilisation, and recommendation data to the target member account

Example filter applied automatically:
```python
{"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": ["123456789012"]}}
```

---

## Savings Estimates

All savings estimates are approximate:
- EC2 idle: 90% of current on-demand cost
- EC2 previous gen: 15% of current cost
- RDS downsize: difference between current and suggested class
- S3 lifecycle: 50% of (Standard − Standard-IA) delta for affected portion
- S3 Intelligent-Tiering: 30% of current Standard cost
- RI coverage gap: 35% of unprotected on-demand spend
- Savings Plan gap: 20% of eligible unprotected spend

---

## Auto-Remediable Findings

Only the following findings are marked `auto_remediable: true`:
- **COST-EC2-003**: Unattached EBS volumes older than 30 days
- **COST-EC2-004**: Unused Elastic IPs

Auto-remediation requires explicit approval via the action handler — the flag is advisory for the Bedrock Agent's decision logic.
