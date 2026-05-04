# Compliance Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Compliance Agent evaluates each governed account against CIS Benchmarks, SOC 2 controls, and AWS Config managed rules. All AWS API calls use the injected cross-account session.

---

## CIS Benchmark Rules (SEC-CIS-*)

| Rule ID       | Severity | CIS Control | Description |
|---------------|----------|-------------|-------------|
| SEC-CIS-001   | CRITICAL | 1.1  | Root account used in last 30 days |
| SEC-CIS-002   | CRITICAL | 1.5  | Root account MFA not enabled |
| SEC-CIS-003   | HIGH     | 1.2  | IAM user without MFA |
| SEC-CIS-004   | HIGH     | 1.3  | Access keys not rotated in 90 days |
| SEC-CIS-005   | MEDIUM   | 1.9  | Password policy below minimum standards |
| SEC-CIS-006   | CRITICAL | 2.1  | CloudTrail not enabled |
| SEC-CIS-007   | HIGH     | 2.2  | CloudTrail log validation disabled |
| SEC-CIS-008   | HIGH     | 2.3  | CloudTrail S3 bucket not publicly accessible (verify) |
| SEC-CIS-009   | MEDIUM   | 2.4  | CloudTrail integrated with CloudWatch Logs |
| SEC-CIS-010   | HIGH     | 2.5  | AWS Config not enabled |
| SEC-CIS-011   | CRITICAL | 4.1  | SSH open to 0.0.0.0/0 |
| SEC-CIS-012   | CRITICAL | 4.2  | RDP open to 0.0.0.0/0 |
| SEC-CIS-013   | HIGH     | 4.3  | No VPC Flow Logs |

---

## SOC 2 Controls (COMP-SOC2-*)

| Rule ID        | Severity | SOC 2 Control | Description |
|----------------|----------|---------------|-------------|
| COMP-SOC2-001  | CRITICAL | CC6.1 | S3 bucket publicly accessible |
| COMP-SOC2-002  | HIGH     | CC6.1 | S3 bucket not encrypted |
| COMP-SOC2-003  | HIGH     | CC6.1 | EBS volume not encrypted |
| COMP-SOC2-004  | HIGH     | CC6.1 | RDS storage not encrypted |
| COMP-SOC2-005  | HIGH     | CC7.1 | GuardDuty not enabled |
| COMP-SOC2-006  | MEDIUM   | CC7.1 | Security Hub not enabled |
| COMP-SOC2-007  | CRITICAL | CC7.2 | CloudTrail not enabled |
| COMP-SOC2-008  | HIGH     | CC8.1 | No AWS Backup plan with adequate retention |
| COMP-SOC2-009  | HIGH     | A1.2 | RDS or EC2 not in Multi-AZ / multiple AZs |

---

## AWS Config Managed Rules (COMP-CONFIG-*)

| Rule ID           | Severity | Config Rule Name                                |
|-------------------|----------|-------------------------------------------------|
| COMP-CONFIG-000   | CRITICAL | AWS Config not enabled (meta-finding) |
| COMP-CONFIG-001   | CRITICAL | root-account-mfa-enabled |
| COMP-CONFIG-002   | HIGH     | mfa-enabled-for-iam-console-access |
| COMP-CONFIG-003   | HIGH     | access-keys-rotated |
| COMP-CONFIG-004   | CRITICAL | restricted-ssh |
| COMP-CONFIG-005   | HIGH     | restricted-common-ports |
| COMP-CONFIG-006   | CRITICAL | s3-bucket-public-read-prohibited |
| COMP-CONFIG-007   | CRITICAL | s3-bucket-public-write-prohibited |
| COMP-CONFIG-008   | HIGH     | s3-bucket-server-side-encryption-enabled |
| COMP-CONFIG-009   | CRITICAL | cloud-trail-enabled |
| COMP-CONFIG-010   | MEDIUM   | cloud-trail-log-file-validation-enabled |
| COMP-CONFIG-011   | HIGH     | encrypted-volumes |
| COMP-CONFIG-012   | HIGH     | rds-storage-encrypted |
| COMP-CONFIG-013   | HIGH     | rds-instance-public-access-check |
| COMP-CONFIG-014   | MEDIUM   | vpc-flow-logs-enabled |
| COMP-CONFIG-015   | HIGH     | multi-region-cloudtrail-enabled |
| COMP-CONFIG-016   | MEDIUM   | iam-password-policy |
| COMP-CONFIG-017   | HIGH     | guardduty-enabled-centralized |
| COMP-CONFIG-018   | MEDIUM   | securityhub-enabled |
| COMP-CONFIG-019   | HIGH     | kms-cmk-not-scheduled-for-deletion |
| COMP-CONFIG-020   | HIGH     | backup-plan-min-frequency-and-min-retention-check |

---

## Compliance Score Calculation

```
score = 100 − (CRITICAL × 15) − (HIGH × 5) − (MEDIUM × 2) − (LOW × 0.5)
score = max(0, min(100, score))
```

Thresholds:
- 80–100: COMPLIANT (green)
- 60–79:  PARTIAL (amber)
- 0–59:   NON_COMPLIANT (red)

---

## Multi-Account Notes

- AWS Config rules are evaluated in the target account via the cross-account session
- If AWS Config is not enabled in an account, a COMP-CONFIG-000 CRITICAL finding is raised and rule evaluation is skipped for that account
- Compliance scores are computed per-account; the Orchestrator aggregates organisation-wide
