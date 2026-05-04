# Security Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Security Agent scans each governed account for IAM, S3, security group, GuardDuty, CloudTrail, and KMS/Secrets Manager misconfigurations. All scans are performed using a cross-account assumed role (`governance-platform-reader`) so the agent always operates with read-only access in member accounts.

---

## Rule Catalogue

### IAM Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-IAM-001   | CRITICAL | Root account used in the last 30 days |
| SEC-IAM-001b  | CRITICAL | Root account MFA not enabled |
| SEC-IAM-002   | HIGH     | IAM console user without MFA |
| SEC-IAM-003   | HIGH/CRITICAL | Access key not rotated in 90+ days (CRITICAL if 180+ days) |
| SEC-IAM-004   | MEDIUM/HIGH | Password policy below CIS benchmark |
| SEC-IAM-005   | HIGH     | User has AdministratorAccess or PowerUserAccess |
| SEC-IAM-005b  | CRITICAL | Role has wildcard Allow `*/*` inline policy |
| SEC-IAM-006   | MEDIUM   | Console credentials unused for 90+ days |
| SEC-IAM-007   | LOW      | User has inline policies (prefer managed) |
| SEC-IAM-008   | CRITICAL | Role trust policy allows Principal `*` |

### S3 Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-S3-001    | CRITICAL | Bucket allows public read |
| SEC-S3-002    | CRITICAL | Bucket allows public write |
| SEC-S3-003    | HIGH     | Bucket not encrypted (no default SSE) |
| SEC-S3-004    | MEDIUM   | Bucket versioning not enabled |
| SEC-S3-005    | HIGH     | Bucket access logging not enabled |

### Security Group Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-SG-001    | CRITICAL | SSH (port 22) open to 0.0.0.0/0 |
| SEC-SG-002    | CRITICAL | RDP (port 3389) open to 0.0.0.0/0 |
| SEC-SG-003    | HIGH     | All traffic inbound from 0.0.0.0/0 |
| SEC-SG-004    | MEDIUM   | Common dangerous port open to internet |

### GuardDuty Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-GD-001    | CRITICAL | GuardDuty not enabled in region |
| SEC-GD-001b   | LOW      | Finding frequency set to 6 hours (not 15 min) |
| SEC-GD-002    | CRITICAL/HIGH/MEDIUM | Active GuardDuty threat finding |
| SEC-GD-003    | MEDIUM   | S3 Protection not enabled |

### CloudTrail Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-CT-001    | CRITICAL | CloudTrail not enabled |
| SEC-CT-002    | HIGH     | No multi-region trail |
| SEC-CT-003    | MEDIUM   | Log file validation disabled |
| SEC-CT-004    | MEDIUM   | CloudTrail not logging to S3 with SSE |

### KMS / Secrets Manager Rules

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-KMS-001   | HIGH     | CMK scheduled for deletion |
| SEC-KMS-002   | MEDIUM   | CMK rotation not enabled |
| SEC-SM-001    | HIGH     | Secret not rotated within 90 days |
| SEC-SM-002    | MEDIUM   | Secret has no rotation configured |

---

## Remediation Capabilities

The Security Agent can perform the following remediations (requires explicit human confirmation unless `auto_remediable: true`):

- **Remove security group rule** (`/remediatesecuritygroup`): Revokes a specific inbound rule
- **Disable IAM access key** (`/disableiamaccesskey`): Sets key status to Inactive

All remediation actions are recorded in DynamoDB with an `action-` prefix scan_id for audit purposes.

---

## Multi-Account Notes

- All AWS API calls use the injected cross-account session from `bedrock_action_handler.py`
- Findings include `account_id` and `account_name` for correlation
- Root account checks query the credential report in the target account
- GuardDuty findings are scoped to the target account's detectors only
