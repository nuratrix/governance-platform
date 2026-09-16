# Infrastructure Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Infrastructure Agent checks EC2 instances/volumes, RDS databases, VPC networking, and resource tagging across each governed account, across four checker modules (`ec2_checker.py`, `network_checker.py`, `rds_checker.py`, `tagging_checker.py`). All API calls use the injected cross-account session.

**Rule ID prefix note:** findings use bare `EC2-*`, `RDS-*`, `NET-*`, `TAG-*` rule IDs — there is **no `INFRA-` prefix** anywhere in `build_finding.py` or the checkers.

---

## EC2 Rules (`EC2-*`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| EC2-001 | LOW      | Instance is stopped |
| EC2-002 | MEDIUM if unattached ≥30 days, else LOW | EBS volume unattached (`auto_remediable: true`) |
| EC2-003 | LOW      | Self-owned EBS snapshot older than 90 days |
| EC2-004 | HIGH     | Self-owned AMI is public |
| EC2-005 | LOW      | Elastic IP with no association (`auto_remediable: true`) |
| EC2-006 | MEDIUM   | Attached (in-use) EBS volume is not encrypted |

## RDS Rules (`RDS-*`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| RDS-001 | HIGH     | Instance is publicly accessible |
| RDS-002 | HIGH     | Storage not encrypted |
| RDS-003 | MEDIUM   | Not Multi-AZ (micro instance classes `db.t2.micro`/`db.t3.micro` are exempt) |
| RDS-004 | HIGH     | Automated backups disabled (`BackupRetentionPeriod == 0`) |
| RDS-005 | LOW      | Manual snapshot older than 90 days |

There is no minor-version-auto-upgrade check in this agent.

## Network Rules (`NET-*`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| NET-001 | MEDIUM   | A NAT Gateway exists (flagged for manual usage/cost review — this does not itself detect zero traffic) |
| NET-002 | HIGH     | ≥1 target in an ELBv2 target group is unhealthy |
| NET-003 | LOW      | Non-default VPC has zero running instances (empty VPC) |
| NET-004 | MEDIUM   | The default VPC has ≥1 instance running in it |

There is no VPC Flow Logs check, no Internet-Gateway-on-private-VPC check, and no unused-subnet check in this agent — VPC Flow Logs are covered by the Network Security Agent instead (see [network_security_rules.md](network_security_rules.md)).

## Tagging Rules (`TAG-*`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| TAG-001 | LOW      | EC2 instance missing one or more required tags |
| TAG-002 | LOW      | RDS instance missing one or more required tags |
| TAG-003 | LOW      | ELBv2 load balancer missing one or more required tags |

There is no S3 or Lambda tagging check, and there is no `TAG-004`.

Required tags are a **hardcoded Python constant** in `tagging_checker.py` (line 16) — there is no environment variable controlling this:

```python
REQUIRED_TAGS = ["Environment", "Owner", "Project", "CostCenter"]
```

To change the required tag set, edit this list in code and redeploy.

---

## Multi-Account Notes

- All checks use the cross-account session — clients are created as `ec2 = session.client("ec2")` etc.
- Region scope is controlled by `shared/utils.py::get_scan_regions(session)`, resolved from the `SCAN_REGIONS` env var:
  - unset/empty → single region only: the Lambda's own deployment region (`AWS_REGION`)
  - `SCAN_REGIONS=all` → every enabled region (multi-region)
  - `SCAN_REGIONS=us-east-1,eu-west-1,...` → an explicit region list (multi-region)

  This is a configurable multi-region loop, not a hardcoded single-region agent — set the env var to scan more than the deployment region in one invocation.
- Tagging checks enumerate all resources in the target account. Tag compliance is especially valuable for cost allocation across accounts.

## Remediation

`bedrock_action_handler.py` exposes `/checkec2`, `/checkrds`, `/checknetwork`, `/checktagging` (read-only, each wraps the corresponding checker + adds a severity-count summary), `/escalatetohuman` (SNS + Teams + Slack), and `/saveinfrareport` (DynamoDB, `FINDINGS_TABLE`, 90-day TTL).

**There is no mutating remediation action anywhere in this agent** — no volume deletion, EIP release, or instance termination exists in the codebase. The `auto_remediable: true` flags set on EC2-002 (unattached volume) and EC2-005 (unused EIP) are therefore currently aspirational: nothing in this agent can act on them. Don't advertise auto-remediation as a working capability for this agent until a corresponding action is implemented.
