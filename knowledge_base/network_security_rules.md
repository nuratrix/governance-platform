# Network Security Agent — Rules Reference
## Multi-Account Edition

> **Not yet coordinated by the Orchestrator.** This agent exists and runs on its own daily schedule, but the Orchestrator's `agent_map` and Bedrock instruction text only cover the original five agents (Security, Infrastructure, Compliance, Cost, Incident) — see [orchestrator_rules.md](orchestrator_rules.md) §1. Its security-group/NACL checks overlap with (but are distinct from) the Security Agent's `sg_checker.py` — see [security_rules.md](security_rules.md).

---

## Overview

The Network Security Agent covers three domains, all per-region (`get_scan_regions(session)`), using the same cross-account `governance-platform-reader` session pattern as the other agents:

- **`dns_checker.py`** — Route 53 Resolver query logging / DNS Firewall coverage, and Transit Gateway sharing/routing settings
- **`nacl_checker.py`** — Security Group and NACL exposure of dangerous ports or all-traffic to the internet
- **`vpc_checker.py`** — VPC Flow Logs, default-VPC usage, public-IP-assigning subnets, cross-account VPC peering, orphaned Internet Gateways

---

## Rule Catalogue

### DNS & Transit Gateway (`dns_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| NET-DNS-001   | MEDIUM   | VPC has no ACTIVE Route 53 Resolver query-log-config association |
| NET-DNS-002   | MEDIUM   | No DNS Firewall rule group associations exist for any VPC in the account |
| NET-DNS-002b  | LOW      | This VPC has no DNS Firewall association, but the account has ≥1 other VPC that does |
| NET-TGW-001   | HIGH     | Transit Gateway `AutoAcceptSharedAttachments` is enabled |
| NET-TGW-002   | MEDIUM   | Transit Gateway `DefaultRouteTableAssociation` is enabled |

### Security Groups & NACLs (`nacl_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| NET-SG-001    | CRITICAL | Security group ingress allows ALL traffic from a public CIDR (`0.0.0.0/0`/`::/0`) |
| NET-SG-002    | HIGH     | Security group ingress exposes a dangerous port (22, 3389, 23, 21, 1433, 3306, 5432, 6379, 27017, 9200, 2375, 2379) to a public CIDR |
| NET-NACL-001  | HIGH / MEDIUM | NACL inbound entry allows all traffic (`allow`, protocol `-1`) from a public CIDR — HIGH for a custom NACL, MEDIUM for the default NACL |
| NET-NACL-002  | MEDIUM   | NACL inbound entry allows a dangerous port (same list as NET-SG-002) from a public CIDR |

### VPC Posture (`vpc_checker.py`)

| Rule ID       | Severity | Description |
|---------------|----------|-------------|
| NET-VPC-001   | HIGH     | VPC has no VPC Flow Log configured |
| NET-VPC-002   | MEDIUM   | The default VPC has running/stopped EC2 instance reservations |
| NET-VPC-003   | LOW      | Non-default-VPC subnet auto-assigns public IPs and its Name tag doesn't suggest a public-facing purpose (public/dmz/ingress/alb/elb) |
| NET-VPC-004   | MEDIUM   | Active VPC peering connection where neither requester nor accepter is the scanned account (unexpected external peering) |
| NET-VPC-005   | LOW      | Internet Gateway exists with no VPC attachment |

No rule in this agent sets `auto_remediable: true`.

---

## Remediation Capabilities

Read-only agent — the Bedrock instruction mandates checking VPC → security-group/NACL → DNS in that order, escalating CRITICAL/HIGH immediately, and ending with a report save. No write/remediation action exists. Exposed API paths:

- `/checkvpc`, `/checksgnacl`, `/checkdns` — read-only checks
- `/escalatetohuman` — SNS publish (`ALERT_TOPIC_ARN`), subject `[Network Security] {title}`, includes `region`
- `/savenetworkreport` — DynamoDB put to `FINDINGS_TABLE` (flat schema, 90-day TTL), tracking `critical_findings`/`high_findings`; triggers a Teams scan-complete notification (CRITICAL if any critical findings, else HIGH if any high findings, else LOW)

---

## Multi-Account Notes

- Every finding carries `account_id`/`account_name`/`region` via the shared `build_finding()` helper.
- Report persistence uses the same flat schema + `ttl` as Security/Access Analyzer (as opposed to the `PK`/`SK` schema used by Backup & DR / Cost Anomaly).
- NET-SG-001/002 overlap in intent with the Security Agent's SEC-SG-* rules but are computed independently by a different checker — expect some duplicate-in-spirit findings on the same security group from both agents until they're reconciled or one is retired.

## Schedule

Daily scan, cron `10 8 * * ? *` (08:10 UTC). The rule description text says "daily at 06:00 UTC," which doesn't match the literal cron value — this mismatch exists in the source (`variables.tf`) itself.
