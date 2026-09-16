# Compliance Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Compliance Agent evaluates each governed account against CIS Benchmarks, SOC 2 controls, and AWS Config managed rules across three checker modules (`cis_checker.py`, `soc2_checker.py`, `config_rules_checker.py`). All AWS API calls use the injected cross-account session. All CIS and SOC2 findings are forced to `region = "global"` (region is not meaningful for those two checkers, even though the fan-out scanner calls them per-region).

---

## CIS Benchmark Rules (`COMP-CIS-*`)

Note the real prefix is `COMP-CIS-*`, and there are 17 rules (001–017) — not the 20 the module's own docstring implies.

| Rule ID       | Severity | CIS Control | Description |
|---------------|----------|-------------|-------------|
| COMP-CIS-001  | MEDIUM (HIGH if no policy at all) | 1.8  | Password minimum length < 14 |
| COMP-CIS-002  | MEDIUM   | 1.9  | Password policy doesn't require uppercase |
| COMP-CIS-003  | MEDIUM   | 1.10 | Password policy doesn't require lowercase |
| COMP-CIS-004  | MEDIUM   | 1.11 | Password policy doesn't require symbols |
| COMP-CIS-005  | MEDIUM   | 1.12 | Password policy doesn't require numbers |
| COMP-CIS-006  | LOW      | 1.13 | Max password age unset or > 365 days |
| COMP-CIS-007  | LOW      | 1.14 | Password reuse prevention unset or < 24 |
| COMP-CIS-008  | CRITICAL | 1.4  | Root account has an active access key |
| COMP-CIS-009  | CRITICAL | 1.5  | Root account MFA not active |
| COMP-CIS-010  | CRITICAL / HIGH | 1.14 | IAM user access key older than 90/180 days (CRITICAL if >180d) |
| COMP-CIS-011  | HIGH     | 1.10 | IAM user has console access (login profile) but no MFA device |
| COMP-CIS-012  | CRITICAL | 3.1  | No multi-region CloudTrail trail, or a trail exists but isn't logging |
| COMP-CIS-013  | MEDIUM   | 3.2  | Trail log file validation disabled |
| COMP-CIS-014  | MEDIUM   | 3.5  | Trail has no KMS key configured |
| COMP-CIS-015  | HIGH     | 3.5  | No AWS Config recorder, or a recorder exists but isn't recording |
| COMP-CIS-016  | HIGH     | 3.9  | VPC has no active Flow Log |
| COMP-CIS-017  | MEDIUM   | 5.4  | Default security group has ingress or egress rules defined |

> Control-number collisions (1.10 used by both 003 and 011; 3.5 used by both 014 and 015) exist in the code itself — these are not documentation errors, don't "fix" them by inventing distinct numbers.

Only COMP-CIS-010 is ever marked `auto_remediable: true` in code, but nothing in `bedrock_action_handler.py` consumes that flag — there is no automated remediation for this or any other CIS finding.

---

## SOC 2 Controls (`COMP-SOC2-*`)

12 rules (001–012), not the 15 the docstring implies. GuardDuty and Security Hub checks do **not** live here — see COMP-CONFIG-017/018 below.

| Rule ID        | Severity | SOC 2 Control | Description |
|----------------|----------|----------------|-------------|
| COMP-SOC2-001  | CRITICAL | CC6.1 | IAM user has an "AdministratorAccess"-named policy attached and no MFA device |
| COMP-SOC2-002  | CRITICAL | CC6.2 | IAM role trust policy has `Principal: "*"` (or `AWS: "*"`) |
| COMP-SOC2-003  | HIGH     | CC6.7 | S3 bucket has no default server-side encryption |
| COMP-SOC2-004  | MEDIUM   | CC6.7 | S3 bucket policy has no `Deny` for non-HTTPS traffic (or no policy at all) |
| COMP-SOC2-005  | MEDIUM   | CC7.2 | No CloudWatch Logs metric filter for root-login events |
| COMP-SOC2-006  | MEDIUM   | CC7.2 | No metric filter for console auth failures |
| COMP-SOC2-007  | MEDIUM   | CC7.3 | No metric filter for IAM policy changes |
| COMP-SOC2-008  | MEDIUM   | CC7.3 | No metric filter for security group changes |
| COMP-SOC2-009  | HIGH     | CC8.1 | Account has zero AWS Config rules configured |
| COMP-SOC2-010  | MEDIUM   | CC8.1 | A specific Config rule is `NON_COMPLIANT` (one finding per rule) |
| COMP-SOC2-011  | MEDIUM   | A1.2  | Non-micro RDS instance is not Multi-AZ |
| COMP-SOC2-012  | HIGH     | A1.2  | Non-micro RDS instance backup retention < 7 days |

Behavior when AWS Config is disabled differs across the three checkers (see below) — `soc2_checker.py`'s `_check_cc8_change_management` swallows the `describe_config_rules` failure silently and produces **no finding at all**, unlike the other two checkers.

---

## AWS Config Managed Rules (`COMP-CONFIG-*`)

Verified accurate against code as-is — rule names, IDs, and severities all match.

| Rule ID           | Severity | Config Rule Name                                | Frameworks |
|-------------------|----------|---------------------------------------------------|------------|
| COMP-CONFIG-000   | CRITICAL | *(meta-finding — Config not enabled)*            | — |
| COMP-CONFIG-001   | CRITICAL | root-account-mfa-enabled                         | CIS, SOC2, PCI-DSS |
| COMP-CONFIG-002   | HIGH     | mfa-enabled-for-iam-console-access               | CIS, SOC2 |
| COMP-CONFIG-003   | HIGH     | access-keys-rotated                              | CIS, SOC2 |
| COMP-CONFIG-004   | CRITICAL | restricted-ssh                                   | CIS, SOC2, PCI-DSS |
| COMP-CONFIG-005   | HIGH     | restricted-common-ports                          | CIS, PCI-DSS |
| COMP-CONFIG-006   | CRITICAL | s3-bucket-public-read-prohibited                 | CIS, SOC2, PCI-DSS, HIPAA |
| COMP-CONFIG-007   | CRITICAL | s3-bucket-public-write-prohibited                | CIS, SOC2, PCI-DSS |
| COMP-CONFIG-008   | HIGH     | s3-bucket-server-side-encryption-enabled         | SOC2, HIPAA, PCI-DSS |
| COMP-CONFIG-009   | CRITICAL | cloud-trail-enabled                              | CIS, SOC2, PCI-DSS, HIPAA |
| COMP-CONFIG-010   | MEDIUM   | cloud-trail-log-file-validation-enabled          | CIS, SOC2 |
| COMP-CONFIG-011   | HIGH     | encrypted-volumes                                | SOC2, HIPAA, PCI-DSS |
| COMP-CONFIG-012   | HIGH     | rds-storage-encrypted                            | SOC2, HIPAA, PCI-DSS |
| COMP-CONFIG-013   | HIGH     | rds-instance-public-access-check                 | CIS, SOC2, PCI-DSS |
| COMP-CONFIG-014   | MEDIUM   | vpc-flow-logs-enabled                            | CIS, SOC2 |
| COMP-CONFIG-015   | HIGH     | multi-region-cloudtrail-enabled                  | CIS |
| COMP-CONFIG-016   | MEDIUM   | iam-password-policy                              | CIS, SOC2 |
| COMP-CONFIG-017   | HIGH     | guardduty-enabled-centralized                    | CIS, SOC2 |
| COMP-CONFIG-018   | MEDIUM   | securityhub-enabled                              | SOC2 |
| COMP-CONFIG-019   | HIGH     | kms-cmk-not-scheduled-for-deletion               | SOC2 |
| COMP-CONFIG-020   | HIGH     | backup-plan-min-frequency-and-min-retention-check| SOC2, HIPAA |

For each of 001–020: if the named Config rule isn't deployed in a region, a finding fires ("rule not deployed"); if deployed and `NON_COMPLIANT`, a finding fires listing up to 5 offending resource IDs. Severity is identical for both cases — the code doesn't distinguish "not deployed" from "deployed and failing."

---

## Behavior When AWS Config Is Not Enabled

Inconsistent across the three checkers — worth knowing before debugging a "missing findings" report:

- **`config_rules_checker.py`**: no configuration recorder → one COMP-CONFIG-000 CRITICAL meta-finding for that region, then the 20 managed-rule checks are skipped **for that region only**.
- **`cis_checker.py`**: no recorder / not recording → COMP-CIS-015 HIGH finding, other CIS checks still run.
- **`soc2_checker.py`**: `describe_config_rules()` failure is caught by a bare `except Exception` and logged — **no finding is produced at all**.

---

## Compliance Score Calculation

The formula actually implemented in `bedrock_action_handler.py::_get_compliance_score`:

```python
score = max(0, 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1))
```

There is no upper clamp (`min(100, ...)`), and it's moot since the formula only ever subtracts. Findings from all three checkers are aggregated with **no dedup**, so the same underlying gap (e.g. no root MFA) can be counted 2–3× across CIS/SOC2/Config rule IDs and push the score down further than a single gap would suggest. `by_framework` counts are computed via substring match on `rule_id` (`"CIS" in rule_id`, etc.) — this works for current prefixes but would silently break if a prefix changed.

**No COMPLIANT / PARTIAL / NON_COMPLIANT banding exists in any compliance-agent code.** If a score threshold table is needed for the portal/reporting layer, it must be sourced from wherever the frontend or another service implements it — do not assume the 80/60 cutoffs previously documented here without confirming against that code.

---

## Multi-Account Notes

- AWS Config rules are evaluated in the target account via the cross-account session
- Every finding carries `account_id`; `account_name` is only populated for Bedrock-agent-invoked scans (`bedrock_action_handler.py` reads it from `promptSessionAttributes`) — the scheduled fan-out entry points (`run_checks(account_id, region)`) hardcode `account_name=""`, so don't rely on `account_name` for scheduled-scan correlation
- Compliance scores are computed per-account; the Orchestrator aggregates organisation-wide

## Remediation

`bedrock_action_handler.py` exposes no automated remediation — only `/checkcis`, `/checksoc2`, `/checkconfigrules`, `/getcompliancescore`, `/escalatetohuman` (SNS + Teams + Slack), and `/savecompliancereport` (DynamoDB, 90-day TTL, notifies orchestrator).
