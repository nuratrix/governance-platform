# Compliance Framework Mapping
## Cross-Agent Rule Catalogue → SOC 2 / PCI-DSS / HIPAA / FedRAMP / SOX / FRB

---

## Methodology & Confidence Levels

This document maps every rule across all 9 governance agents (Security, Compliance, Infrastructure, Incident, Access Analyzer, Backup & DR, Cost Anomaly, Network Security, and Cost) to six audit frameworks. Two different levels of confidence apply:

- **Code-verified (`COMP-CONFIG-*` rules only):** `config_rules_checker.py` already tags each AWS Config managed rule with the frameworks it maps to (CIS, SOC2, PCI-DSS, HIPAA) as a literal Python list in the source. Those tags are reproduced as-is in [compliance_rules.md](compliance_rules.md) and are authoritative.
- **Interpretive (everything else — the other ~140 rules across all 9 agents):** no rule outside `COMP-CONFIG-*` carries framework metadata in code. The mappings below are a security-engineering judgment call based on standard control intent (e.g., "MFA enforcement satisfies PCI-DSS Req 8.4"), not something you can `grep` for. **Treat this document as an audit-prep starting point, not an attestation.** Have compliance/legal/the control owner for each framework validate the specific control citations before using this in an actual SOC 2 evidence package, PCI ROC, or examiner response.

FedRAMP and SOX in particular have no canonical "this AWS finding = this control" mapping the way PCI-DSS or HIPAA sometimes do — the FedRAMP and SOX columns below reflect the control family/domain a reasonable auditor would file the finding under, not a specific numbered control unless noted.

---

## Framework Primers

| Framework | Scope | What it mostly cares about here |
|---|---|---|
| **SOC 2** | AICPA Trust Services Criteria (Security = "Common Criteria" CC1–CC9, plus Availability A1, Confidentiality C1, Processing Integrity PI1) | Logical access (CC6), system operations/monitoring (CC7), change management (CC8), risk mitigation (CC9), availability (A1) |
| **PCI-DSS v4.0** | Payment Card Industry Data Security Standard, 12 requirements | Network segmentation (Req 1), secure config (Req 2), data protection (Req 3–4), vulnerability mgmt (Req 5–6), access control (Req 7–8), logging (Req 10), testing (Req 11) |
| **HIPAA** | HHS Security Rule (45 CFR §164.308/310/312) — Administrative, Physical, Technical safeguards | Access control, audit controls, integrity, transmission security, contingency planning. Physical safeguards (§164.310) are largely N/A to a cloud config scanner |
| **FedRAMP** | Built on NIST SP 800-53 Rev 5 control families (typically Moderate baseline for commercial SaaS) | AC (access control), AU (audit), CM (config mgmt), CP (contingency planning), IA (identification/auth), IR (incident response), SC (system/comms protection), SI (system integrity) |
| **SOX** | Section 404 — internal controls over financial reporting, realized via IT General Controls (ITGC) since SOX itself has no technical standard | Access control & segregation of duties, change management, backup/recovery, logging — for any system that touches financial reporting or the infrastructure it runs on |
| **FRB / FFIEC** | Federal Reserve bank examinations use the interagency FFIEC IT Examination Handbook (shared with OCC/FDIC/NCUA) — there is no separate "FRB-only" technical standard | Information Security booklet, Business Continuity Management booklet, Audit booklet, Management booklet — strong emphasis on resilience, access governance, and third-party/vendor risk |

---

## 1. Root & Privileged Access Management

**Rules:** SEC-IAM-001, SEC-IAM-001b, SEC-IAM-005, SEC-IAM-005b, SEC-IAM-008, COMP-CIS-008, COMP-CIS-009, COMP-SOC2-001, COMP-SOC2-002, COMP-CONFIG-001, IAM-AA-004

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.3 |
| PCI-DSS | Req 7.2 (privilege assignment), 8.6 (service/admin accounts) |
| HIPAA | §164.308(a)(3) Workforce Security, §164.312(a)(2)(i) Unique User ID |
| FedRAMP | AC-6 (Least Privilege), AC-6(5) (Privileged Accounts), IA-2(1) |
| SOX (ITGC) | Privileged Access Control |
| FRB/FFIEC | InfoSec Booklet — Access Rights Management |

---

## 2. Authentication, MFA & Password Policy

**Rules:** SEC-IAM-002, SEC-IAM-004, SEC-IAM-006, COMP-CIS-001–007, COMP-CIS-011, COMP-CONFIG-002, COMP-CONFIG-016, IAM-AA-005

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.6 |
| PCI-DSS | Req 8.3 (MFA), 8.4, 8.6 |
| HIPAA | §164.312(d) Person or Entity Authentication |
| FedRAMP | IA-2, IA-5, IA-5(1) (password-based auth) |
| SOX (ITGC) | Authentication Controls |
| FRB/FFIEC | InfoSec Booklet — Authentication |

---

## 3. Least Privilege & Access Hygiene

**Rules:** SEC-IAM-003, SEC-IAM-007, COMP-CIS-010, COMP-CONFIG-003, IAM-AA-001, IAM-AA-002, IAM-AA-003

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.2, CC6.3 |
| PCI-DSS | Req 7.1, 8.2.4 (credential/key rotation) |
| HIPAA | §164.308(a)(4) Information Access Management |
| FedRAMP | AC-2, AC-2(3) (inactive account disablement), IA-5(1) |
| SOX (ITGC) | Periodic User Access Review / Segregation of Duties |
| FRB/FFIEC | InfoSec Booklet — Access Review |

---

## 4. Data Encryption at Rest

**Rules:** SEC-S3-003, SEC-KMS-001, SEC-KMS-003, SEC-RDS-002, SEC-RDS-002c, RDS-002 *(Infrastructure agent)*, EC2-006 *(Infrastructure agent)*, COMP-SOC2-003, COMP-CONFIG-008, COMP-CONFIG-011, COMP-CONFIG-012, COMP-CONFIG-019, BDR-005, BDR-005b

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.7 |
| PCI-DSS | Req 3.5, 3.6 (cryptographic key management) |
| HIPAA | §164.312(a)(2)(iv) Encryption/Decryption |
| FedRAMP | SC-28 (Protection at Rest), SC-12/SC-13 (key management) |
| SOX (ITGC) | Data Protection Controls |
| FRB/FFIEC | InfoSec Booklet — Encryption |

---

## 5. Secrets Management & Data-in-Transit

**Rules:** SEC-SEC-001, SEC-SEC-002, SEC-SEC-003, SEC-KMS-002, SEC-SSM-001, SEC-LMB-002, COMP-SOC2-004

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.7 |
| PCI-DSS | Req 3.6, 4.2 (transmission), 6.3 (no hardcoded credentials) |
| HIPAA | §164.312(e)(1) Transmission Security, §164.312(a)(2)(iv) |
| FedRAMP | SC-12, SC-28, IA-5(7) (no embedded static credentials) |
| SOX (ITGC) | Credential Management |
| FRB/FFIEC | InfoSec Booklet — Data Protection |

---

## 6. Public Exposure & Data Loss Prevention

**Rules:** SEC-S3-001, SEC-S3-002, SEC-RDS-001, SEC-RDS-010, SEC-ECR-004, SEC-LMB-004, SEC-EKS-001, SEC-EKS-001b, RDS-001 *(Infrastructure agent)*, EC2-004 *(Infrastructure agent — public AMI)*, IAM-AA-002, COMP-CONFIG-006, COMP-CONFIG-007, COMP-CONFIG-013

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.6 |
| PCI-DSS | Req 1.3 (untrusted network boundary), 3.3 (data exposure), 7.1 |
| HIPAA | §164.312(a)(1) Access Control, §164.308(a)(1)(ii)(A) Risk Analysis |
| FedRAMP | AC-3, AC-4, SC-7 (Boundary Protection) |
| SOX (ITGC) | Data Exposure Controls |
| FRB/FFIEC | InfoSec Booklet — Data Loss Prevention |

---

## 7. Network Segmentation & Perimeter Controls

**Rules:** SEC-SG-001–006, NET-SG-001, NET-SG-002, NET-NACL-001, NET-NACL-002, NET-VPC-002, NET-VPC-003, NET-VPC-004, NET-VPC-005, NET-DNS-001, NET-DNS-002, NET-DNS-002b, NET-TGW-001, NET-TGW-002, COMP-CIS-017, COMP-CONFIG-004, COMP-CONFIG-005, NET-003 *(Infrastructure agent)*, NET-004 *(Infrastructure agent)*

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.6 |
| PCI-DSS | Req 1.2, 1.3, 1.4 (network security controls) |
| HIPAA | §164.312(e)(1), §164.308(a)(1)(ii)(A) |
| FedRAMP | SC-7, SC-7(3) (Access Points), AC-4 |
| SOX (ITGC) | Network Access Control |
| FRB/FFIEC | InfoSec Booklet — Network Security |

---

## 8. Logging, Audit Trail & Monitoring

**Rules:** SEC-CT-001–006, COMP-CIS-012, COMP-CIS-013, COMP-CIS-014, COMP-CIS-016 *(VPC Flow Logs)*, COMP-SOC2-005–008, COMP-CONFIG-009, COMP-CONFIG-010, COMP-CONFIG-014, COMP-CONFIG-015, NET-VPC-001

| Framework | Control reference |
|---|---|
| SOC 2 | CC7.2, CC7.3 |
| PCI-DSS | Req 10.1–10.5 (audit trails) |
| HIPAA | §164.312(b) Audit Controls |
| FedRAMP | AU-2, AU-6, AU-9 (log protection), AU-12 |
| SOX (ITGC) | Audit Trail / Logging Controls — a core pillar for evidencing change history on financially-relevant systems |
| FRB/FFIEC | Audit Booklet; InfoSec Booklet — Logging & Monitoring |

---

## 9. Threat Detection & Anomaly Monitoring

**Rules:** SEC-GD-001, SEC-GD-001b, SEC-GD-002, SEC-GD-003, COMP-CONFIG-017, COMP-CONFIG-018, COST-ANO-001, COST-ANO-002, COST-ANO-003, COST-ANO-003b, COST-RCA-001, COST-RCA-002, COST-RCA-003

| Framework | Control reference |
|---|---|
| SOC 2 | CC7.1, CC7.2 |
| PCI-DSS | Req 11.5 (intrusion-detection techniques) |
| HIPAA | §164.308(a)(1)(ii)(D) Information System Activity Review |
| FedRAMP | SI-4 (System Monitoring), AU-6(1) |
| SOX (ITGC) | Anomaly/Fraud Detection — cost-anomaly rules are relevant here for unexplained spend/expense irregularities |
| FRB/FFIEC | InfoSec Booklet — Intrusion Detection; Management Booklet — Financial Anomaly Oversight |

---

## 10. Vulnerability & Patch Management

**Rules:** SEC-ECR-001, SEC-ECR-002, SEC-ECR-003, SEC-ECR-005, SEC-ECR-005b, SEC-SSM-004, SEC-SSM-004b, SEC-EKS-003

| Framework | Control reference |
|---|---|
| SOC 2 | CC7.1 |
| PCI-DSS | Req 6.3 (vuln remediation), 11.3, 11.4 |
| HIPAA | §164.308(a)(5)(ii)(B) Protection from Malicious Software |
| FedRAMP | RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation) |
| SOX (ITGC) | Vulnerability Management |
| FRB/FFIEC | InfoSec Booklet — Patch/Vulnerability Management |

---

## 11. Workload / Container Hardening

**Rules:** SEC-EKS-002, SEC-EKS-004, SEC-EKS-005, SEC-EKS-006, SEC-EKS-007, SEC-LMB-001, SEC-LMB-003, SEC-LMB-005, SEC-LMB-006

| Framework | Control reference |
|---|---|
| SOC 2 | CC6.1, CC6.6, CC8.1 |
| PCI-DSS | Req 2.2 (secure configuration standards), 6.2 |
| HIPAA | §164.312(c)(1) Integrity |
| FedRAMP | CM-6 (Config Settings), CM-7 (Least Functionality), SC-39 |
| SOX (ITGC) | Secure Configuration Baseline |
| FRB/FFIEC | InfoSec Booklet — Secure Configuration |

---

## 12. Configuration & Change Management

**Rules:** COMP-CIS-015, COMP-CONFIG-000, TAG-001 *(Infrastructure agent)*, TAG-002, TAG-003, INC-DIAG-001

| Framework | Control reference |
|---|---|
| SOC 2 | CC8.1 |
| PCI-DSS | Req 6.5 (secure development), 11.5 (change/file-integrity detection) |
| HIPAA | §164.308(a)(1)(ii)(A) — via risk management process |
| FedRAMP | CM-2 (Baseline Config), CM-3 (Change Control), CM-8 (Component Inventory — tagging) |
| SOX (ITGC) | Change Management — one of the two or three pillars examiners test most heavily |
| FRB/FFIEC | Management Booklet — Change Control |

---

## 13. Backup, Recovery & Business Continuity

**Rules:** BDR-001, BDR-002, BDR-003, BDR-004, BDR-006, BDR-007, BDR-008, EC2-002 *(Infrastructure agent)*, EC2-003 *(Infrastructure agent)*, RDS-003 *(Infrastructure agent)*, RDS-004 *(Infrastructure agent)*, RDS-005 *(Infrastructure agent)*, COST-RDS-004, COMP-CONFIG-020, COMP-SOC2-011, COMP-SOC2-012

| Framework | Control reference |
|---|---|
| SOC 2 | A1.2, A1.3 (Availability) |
| PCI-DSS | Req 12.10.1 (recovery — limited applicability) |
| HIPAA | §164.308(a)(7) Contingency Plan (data backup, disaster recovery, emergency mode) |
| FedRAMP | CP-9 (System Backup), CP-10 (Recovery/Reconstitution), CP-6 (Alternate Storage Site — cross-region copy) |
| SOX (ITGC) | Backup & Recovery Controls |
| FRB/FFIEC | Business Continuity Management Booklet |

---

## 14. Incident Response & Operational Resilience

**Rules:** INC-DET-001–005, INC-DIAG-002, INC-DIAG-003, INC-DIAG-004, NET-002 *(Infrastructure agent — unhealthy LB targets)*

| Framework | Control reference |
|---|---|
| SOC 2 | CC7.3, CC7.4, A1.2 |
| PCI-DSS | Req 12.10 (Incident Response Plan) |
| HIPAA | §164.308(a)(6) Security Incident Procedures |
| FedRAMP | IR-4 (Incident Handling), IR-6 (Reporting), IR-8 (Plan) |
| SOX (ITGC) | Incident Management — evidence of control-failure detection/response |
| FRB/FFIEC | Business Continuity Management Booklet — Incident Response; Management Booklet |

> Note: as documented in [incident_rules.md](incident_rules.md), the escalation *thresholds* an auditor might expect (e.g. "CRITICAL always escalates within N minutes") are enforced by LLM prompt text, not hardcoded Lambda logic, for MEDIUM/LOW severities and the orchestrator's ">5 HIGH in one account" case. If an examiner asks for proof of a deterministic SLA, only the CRITICAL path (`should_invoke` → `_escalate`) is code-enforced today.

---

## 15. Cost Governance & Financial Controls

**Rules:** COST-EC2-001–005, COST-RDS-001–003, COST-S3-001–004, COST-RI-001–005

These rules are cost-optimization findings, not security controls — their compliance relevance is narrow and indirect.

| Framework | Control reference |
|---|---|
| SOC 2 | Minimal (CC1.1, control-environment context only) |
| PCI-DSS | Not applicable |
| HIPAA | Not applicable |
| FedRAMP | Not applicable |
| SOX (ITGC) | IT Cost Governance / expense allocation accuracy — relevant only if cloud spend materially affects financial statements |
| FRB/FFIEC | Management Booklet — IT Expense/Budget Oversight |

---

## Coverage Gaps — What This Platform Does *Not* Attest To

These are automated cloud-configuration scanners. They produce strong technical evidence for the "logical access / encryption / logging / network / patching / backup" slice of each framework, but none of the frameworks above are satisfiable by technical scanning alone. Gaps to flag before relying on this platform for an actual audit response:

- **Policy & procedure documentation** — none of these agents check whether a written InfoSec policy, incident response plan, or acceptable-use policy exists; they check the *technical controls* those policies would mandate.
- **Workforce training & awareness** — HIPAA §164.308(a)(5), PCI Req 12.6, SOC 2 CC1.4 all require training records. Not scanned.
- **Vendor / third-party risk management** — FRB/FFIEC's Outsourcing Technology Services booklet, HIPAA Business Associate Agreements, SOC 2 CC9.2. Not scanned; no agent inventories third-party integrations or SaaS vendors.
- **Physical security** — HIPAA §164.310, PCI Req 9. Not applicable to a cloud-config scanner and not attempted.
- **Segregation of duties in application/financial systems** — SOX's core control is often about who can approve journal entries or release payments in the *business application* layer, not the AWS account. This platform only sees infrastructure-layer access, not app-layer roles.
- **Penetration testing & external attack-surface validation** — PCI Req 11.4, FedRAMP CA-8. GuardDuty/Access Analyzer findings are a signal, not a substitute for an actual pen test.
- **FedRAMP authorization artifacts** — System Security Plan (SSP), Plan of Action & Milestones (POA&M), continuous-monitoring ConMon packages, and a 3PAO assessment are all process/document deliverables this platform doesn't produce, even though its findings are useful raw input for them.
- **Data classification & content-aware DLP** — rules here check bucket/database *configuration* (encryption, public access), not the sensitivity of the data actually stored inside — no HIPAA PHI or PCI cardholder-data content inspection exists.
- **Business Impact Analysis (BIA)** — FRB/FFIEC Business Continuity Management booklet expects a documented BIA ranking systems by recovery priority; Backup & DR agent findings (BDR-*) show *whether* backups/DR exist, not whether the RTO/RPO chosen matches a BIA-derived requirement.

## How to Use This Document

- For a SOC 2 Type II evidence request: start with categories 1–4, 8, 13–14 (access, encryption, logging, availability) — these map most directly to the Trust Services Criteria auditors sample against.
- For a PCI-DSS ROC/SAQ: categories 1–2, 4–5, 7–8, 10 cover the technical majority of Requirements 1–8, 10–11; Requirements 9 (physical) and 12 (policy) are out of scope for this platform entirely.
- For a FedRAMP ConMon deliverable: the `COMP-CONFIG-*` catalogue (code-verified) plus categories 1, 2, 8, 10, 12, 14 map most cleanly onto AC/AU/CM/IR/RA/SI control families.
- For a FRB/FFIEC IT exam: lead with category 13–14 (Business Continuity Management booklet is usually the single most heavily-weighted booklet), then category 8 (Audit booklet) and categories 1–2, 7 (InfoSec booklet).
- For SOX ITGC testing: categories 1, 3, 8, 12, 13 are the four pillars examiners test almost every cycle (access, logging, change management, backup/recovery) — prioritize closing findings there first.
