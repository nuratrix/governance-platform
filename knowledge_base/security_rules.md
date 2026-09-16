# Security Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Security Agent scans each governed account for IAM, S3, security group, GuardDuty, CloudTrail, KMS/Secrets Manager, ECR, EKS, Lambda, RDS, and SSM misconfigurations across 11 checker modules. All scans are performed using a cross-account assumed role (`governance-platform-reader`) so the agent always operates with read-only access in member accounts. Every finding carries `account_id`, `account_name`, and `region` (global services are stamped `region="global"`).

**Wiring gap:** the scheduled/fan-out orchestrator (`security_agent_orchestrator.py`) only invokes 6 of the 11 checkers — `iam`, `s3`, `sg`, `cloudtrail`, `guardduty`, `kms`. The other 5 (`ecr`, `eks`, `lambda_security`, `rds_security`, `ssm`) exist as full checker modules and are reachable via the Bedrock action handler's direct API paths (interactive agent conversations), but are **not** part of a scheduled `full` scan. Treat this as a real platform gap, not a documentation gap.

---

## Rule Catalogue

### IAM Rules (`iam_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-IAM-001   | CRITICAL | Root account password used in the last 30 days |
| SEC-IAM-001b  | CRITICAL | Root account MFA not enabled |
| SEC-IAM-002   | HIGH     | Console-enabled IAM user has no MFA device |
| SEC-IAM-003   | HIGH / CRITICAL | Access key not rotated in 90+ days (CRITICAL if 180+ days) |
| SEC-IAM-004   | MEDIUM / HIGH | Password policy below standard (min length <14, missing char classes, max age >90d, reuse prevention <24); HIGH if no password policy exists at all |
| SEC-IAM-005   | HIGH     | User has `AdministratorAccess` or `PowerUserAccess` attached |
| SEC-IAM-005b  | CRITICAL | Role has an inline policy with `Effect: Allow, Action: "*", Resource: "*"` |
| SEC-IAM-006   | MEDIUM   | Console credentials unused for 90+ days |
| SEC-IAM-007   | LOW      | User has inline policies (prefer managed) |
| SEC-IAM-008   | CRITICAL | Role trust policy allows `Principal: "*"` or `{"AWS": "*"}` |

### S3 Rules (`s3_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-S3-001    | HIGH / CRITICAL | Public Access Block not fully enabled; CRITICAL if no PAB configuration exists at all |
| SEC-S3-002    | CRITICAL | Bucket policy has an `Allow` + `Principal: *` statement granting `s3:*`/`GetObject`/`PutObject`/`DeleteObject` |
| SEC-S3-003    | HIGH     | No default encryption (SSE) configured |
| SEC-S3-004    | MEDIUM   | Bucket versioning not enabled |
| SEC-S3-005    | MEDIUM   | Server access logging not enabled |
| SEC-S3-006    | LOW      | No lifecycle policy configured |
| SEC-S3-007    | LOW      | Bucket name suggests importance (prod/backup/critical/data/db/database) but has no cross-region replication |

### Security Group Rules (`sg_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-SG-001    | CRITICAL | Ingress allows ALL protocols (`-1`) from `0.0.0.0/0` or `::/0` |
| SEC-SG-002    | Port-dependent (see below) | Ingress exposes a specific dangerous port to the internet |
| SEC-SG-003    | MEDIUM   | Ingress opens a port range >100 wide (excluding 80/443/-1) to the internet |
| SEC-SG-004    | LOW      | Egress allows all protocols to `0.0.0.0/0`/`::/0` (possible exfiltration path) |
| SEC-SG-005    | MEDIUM   | Default VPC security group has inbound rules defined (should be empty) |
| SEC-SG-006    | LOW      | Non-default security group has no attached ENIs (unused) |

SEC-SG-002 per-port severity (`DANGEROUS_PORTS`):

| Port | Service | Severity | Port | Service | Severity |
|---|---|---|---|---|---|
| 22 | SSH | CRITICAL | 5601 | Kibana | HIGH |
| 3389 | RDP | CRITICAL | 2181 | Zookeeper | HIGH |
| 1433 | MSSQL | CRITICAL | 9092 | Kafka | HIGH |
| 3306 | MySQL | CRITICAL | 11211 | Memcached | HIGH |
| 5432 | PostgreSQL | CRITICAL | 5984 | CouchDB | HIGH |
| 27017 | MongoDB | CRITICAL | 8080 | HTTP-Alt | MEDIUM |
| 6379 | Redis | CRITICAL | 8443 | HTTPS-Alt | MEDIUM |
| 9200 | Elasticsearch | CRITICAL | | | |
| 2379 | etcd | CRITICAL | | | |
| 4444 | Metasploit/RAT | CRITICAL | | | |

### GuardDuty Rules (`guardduty_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-GD-001    | CRITICAL | No detector exists in region, or detector not `ENABLED` |
| SEC-GD-001b   | LOW      | Finding publishing frequency is `SIX_HOURS` (not `FIFTEEN_MINUTES`) |
| SEC-GD-002    | CRITICAL / HIGH / MEDIUM | Active GuardDuty finding from the last 7 days, mapped from GuardDuty's numeric severity (≥7.0=CRITICAL, ≥4.0=HIGH, ≥1.0=MEDIUM; LOW findings are filtered out and never raised) |
| SEC-GD-003    | MEDIUM   | S3 Protection (`S3_DATA_EVENTS`) not enabled |

### CloudTrail Rules (`cloudtrail_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-CT-001    | CRITICAL | No CloudTrail trails configured in account/region |
| SEC-CT-001*   | HIGH     | *(rule ID reused)* — an individual trail is not multi-region |
| SEC-CT-001b   | HIGH     | None of the account's trails is multi-region |
| SEC-CT-002    | MEDIUM   | Log file validation disabled |
| SEC-CT-003    | MEDIUM   | Trail not encrypted with a KMS key |
| SEC-CT-004    | MEDIUM   | Trail not delivering logs to CloudWatch Logs |
| SEC-CT-005    | CRITICAL | Trail's S3 log bucket does not fully block public access |
| SEC-CT-006    | HIGH     | Trail's event selectors don't include all management events (Read+Write) |

> Known code issue: `SEC-CT-001` is emitted for two distinct conditions ("no trails at all" vs. "this trail isn't multi-region"). Worth splitting into a distinct ID in a future change rather than documenting it away.

### KMS / Secrets Manager Rules (`kms_secrets_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-KMS-001   | MEDIUM   | Customer-managed symmetric CMK does not have automatic rotation enabled |
| SEC-KMS-002   | CRITICAL | KMS key policy has an `Allow` + `Principal: *` statement |
| SEC-KMS-003   | HIGH     | KMS key is in `PendingDeletion` state |
| SEC-SEC-001   | HIGH / MEDIUM | Secret has no rotation configured; HIGH if name matches password/api_key/secret/token/credential |
| SEC-SEC-002   | LOW      | Secret not accessed in 90+ days |
| SEC-SEC-003   | LOW      | Secret uses the default AWS-managed key instead of a customer-managed CMK |

Only customer-managed keys (`KeyManager != "AWS"`) in `Enabled`/`PendingDeletion` state are evaluated.

### ECR Rules (`ecr_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-ECR-001   | HIGH     | Repository does not have `scanOnPush` image scanning enabled |
| SEC-ECR-002   | MEDIUM   | `imageTagMutability` is `MUTABLE` |
| SEC-ECR-003   | LOW      | No lifecycle policy configured |
| SEC-ECR-004   | CRITICAL | Repository resource policy allows a wildcard principal (public pull access) |
| SEC-ECR-005   | CRITICAL | Most-recently-pushed image has ≥1 CRITICAL CVE per ECR scan |
| SEC-ECR-005b  | HIGH     | Most-recently-pushed image has >5 HIGH CVEs (and no CRITICAL) |

### EKS Rules (`eks_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-EKS-001   | HIGH     | Cluster API endpoint public with no CIDR restriction |
| SEC-EKS-001b  | LOW      | Cluster API endpoint public but CIDR-restricted |
| SEC-EKS-002   | HIGH / MEDIUM | Control plane logging missing `api`/`audit` (HIGH) or other log types (MEDIUM) |
| SEC-EKS-003   | CRITICAL / HIGH | Kubernetes version below minimum supported (1.29); CRITICAL if >2 minor versions behind |
| SEC-EKS-004   | HIGH     | No envelope encryption configured for `secrets` resources |
| SEC-EKS-005   | MEDIUM   | No OIDC identity provider configured (blocks IRSA) |
| SEC-EKS-006   | MEDIUM   | Node group has no custom launch template (can't enforce IMDSv2) |
| SEC-EKS-007   | LOW      | Node group AMI type is not `AL2023`/`BOTTLEROCKET` |

### Lambda Security Rules (`lambda_security_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-LMB-001   | HIGH     | Runtime is deprecated/EOL (python3.6-3.8, nodejs10/12/14.x, java8, dotnet6, ruby2.7, go1.x, `provided`) |
| SEC-LMB-002   | HIGH     | Environment variable key looks secret-like with a plaintext value ≥8 chars |
| SEC-LMB-003   | LOW      | No Dead Letter Queue configured |
| SEC-LMB-004   | CRITICAL | Resource-based policy allows a wildcard principal with no narrowing condition |
| SEC-LMB-005   | MEDIUM   | No code signing configuration associated |
| SEC-LMB-006   | HIGH     | Execution role name contains a suspicious term (admin/root/superuser/fullaccess) |

### RDS Security Rules (`rds_security_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-RDS-001   | CRITICAL | DB instance is publicly accessible |
| SEC-RDS-002 / -002c | HIGH | Instance / Aurora cluster storage not encrypted |
| SEC-RDS-003 / -003c | HIGH (prod-tagged) or MEDIUM / HIGH | Instance / Aurora cluster has deletion protection disabled |
| SEC-RDS-004 / -004c | MEDIUM | Instance / Aurora cluster backup retention < 7 days |
| SEC-RDS-005   | LOW      | Auto minor-version upgrade disabled |
| SEC-RDS-006   | MEDIUM   | Instance tagged `env=production` but not Multi-AZ |
| SEC-RDS-007   | LOW      | Master username is a well-known default (admin, root, postgres, etc.) |
| SEC-RDS-008   | LOW      | No Enhanced Monitoring configured |
| SEC-RDS-009   | MEDIUM   | Aurora cluster has no IAM database authentication |
| SEC-RDS-010   | CRITICAL | Own-account DB snapshot is publicly shared |

DB instances that are cluster members are skipped in the instance-level loop to avoid double-counting against the cluster-level checks.

### SSM Rules (`ssm_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| SEC-SSM-001   | HIGH     | Parameter Store parameter has a secret-like name but type `String` (not `SecureString`) |
| SEC-SSM-002   | HIGH     | Own SSM document is shared with `"all"` accounts |
| SEC-SSM-003   | MEDIUM   | Running EC2 instance is not visible in SSM at all (unmanaged) |
| SEC-SSM-003b  | MEDIUM   | Instance known to SSM but agent's last ping is stale (>7 days) |
| SEC-SSM-004   | CRITICAL | ≥1 missing CRITICAL patch per Patch Manager |
| SEC-SSM-004b  | HIGH     | ≥1 missing SECURITY patch (and 0 CRITICAL) |

---

## Remediation Capabilities

Implemented in `bedrock_action_handler.py`. Both actions execute **immediately with no human-confirmation gate in the Lambda code itself** — any approval step must live at the Bedrock Agent prompt/action-group layer, not in this handler:

- **Remove security group rule** (`/remediatesecuritygroup`): calls `ec2.revoke_security_group_ingress` to remove a specific inbound rule
- **Disable IAM access key** (`/disableiamaccesskey`): calls `iam.update_access_key(Status="Inactive")`

Both write a `REMEDIATION` audit entry to DynamoDB (`FINDINGS_TABLE`, 365-day TTL).

Other API paths: `/checkiam`, `/check{s3,securitygroups,guardduty,cloudtrail,kms,eks,ecr,lambdasecurity,rdssecurity,ssm}` (read-only scans, one per checker), `/getcloudtrailevents` (CloudTrail `lookup_events` lookup, up to 168h back), `/escalatetohuman` (SNS + Teams + Slack), `/savescanreport` (persists scan summary, 90-day TTL).

**`auto_remediable` is never set to `True` by any of the 11 checkers** — none of the findings actually drive automated remediation; the two remediation actions above are only invoked directly by the LLM agent, not triggered by a finding flag.

---

## Multi-Account Notes

- All AWS API calls use the injected cross-account session from `bedrock_action_handler.py` (`get_or_assume_session(account_id, governance_account_id, role_name="governance-platform-reader")`)
- Every finding includes `account_id`, `account_name`, and `region` for correlation
- Root account checks query the credential report in the target account
- GuardDuty findings are scoped to the target account's detectors only
- Scheduled fan-out scans (`security_agent_orchestrator.py`) dedupe findings on `rule_id-resource_id-account_id`, compute a severity-weighted risk score (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1), persist to DynamoDB (`FINDINGS_TABLE`, 90-day TTL), and SNS-alert if any CRITICAL/HIGH finding is present
