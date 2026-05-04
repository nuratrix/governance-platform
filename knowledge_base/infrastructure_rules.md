# Infrastructure Agent — Rules Reference
## Multi-Account Edition

---

## Overview

The Infrastructure Agent checks EC2 instances, RDS databases, VPC networking, and resource tagging across each governed account. All API calls use the injected cross-account session.

---

## EC2 Rules (INFRA-EC2-*)

| Rule ID        | Severity | Description |
|----------------|----------|-------------|
| INFRA-EC2-001  | HIGH     | EC2 instance not in an Auto Scaling Group (single point of failure) |
| INFRA-EC2-002  | MEDIUM   | EC2 instance uses an AMI older than 6 months |
| INFRA-EC2-003  | HIGH     | EC2 instance has no termination protection |
| INFRA-EC2-004  | MEDIUM   | EC2 instance does not have detailed monitoring enabled |
| INFRA-EC2-005  | LOW      | EC2 instance not using instance profile (uses access keys instead) |

---

## RDS Rules (INFRA-RDS-*)

| Rule ID         | Severity | Description |
|-----------------|----------|-------------|
| INFRA-RDS-001   | HIGH     | RDS instance not in Multi-AZ |
| INFRA-RDS-002   | HIGH     | RDS instance publicly accessible |
| INFRA-RDS-003   | MEDIUM   | Automated backups disabled or retention < 7 days |
| INFRA-RDS-004   | MEDIUM   | Minor version auto-upgrade not enabled |
| INFRA-RDS-005   | HIGH     | RDS storage not encrypted |

---

## Network Rules (INFRA-NET-*)

| Rule ID         | Severity | Description |
|-----------------|----------|-------------|
| INFRA-NET-001   | HIGH     | VPC has no Flow Logs enabled |
| INFRA-NET-002   | MEDIUM   | Default VPC not deleted or locked down |
| INFRA-NET-003   | HIGH     | Internet Gateway attached to VPC with only private workloads |
| INFRA-NET-004   | MEDIUM   | No NAT Gateway — private subnets cannot reach internet |
| INFRA-NET-005   | LOW      | Unused subnet (no ENIs attached) |

---

## Tagging Rules (INFRA-TAG-*)

| Rule ID         | Severity | Description |
|-----------------|----------|-------------|
| INFRA-TAG-001   | MEDIUM   | EC2 instance missing required tags (Environment, Owner, CostCentre) |
| INFRA-TAG-002   | MEDIUM   | RDS instance missing required tags |
| INFRA-TAG-003   | LOW      | S3 bucket missing required tags |
| INFRA-TAG-004   | LOW      | Lambda function missing required tags |

Required tags are configurable via the `required_tags` Lambda environment variable (comma-separated). Default: `Environment,Owner,CostCentre`.

---

## Multi-Account Notes

- All checks use the cross-account session — clients are created as `ec2 = session.client("ec2")` etc.
- Region scope: the agent checks only the region it is deployed in (the governance account region). For multi-region checks, invoke the agent with a region override.
- Tagging checks enumerate all resources in the target account. Tag compliance is especially valuable for cost allocation across accounts.
