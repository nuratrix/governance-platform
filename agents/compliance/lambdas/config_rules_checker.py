"""
Compliance Agent - AWS Config Rules Checker (Multi-Account Edition)
Evaluates AWS Config managed rules and surfaces non-compliant resources.
Rules: COMP-CONFIG-001 through COMP-CONFIG-020
Cross-account: config client created from the injected session.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Managed Config rules mapped to compliance frameworks
MANAGED_RULES = [
    {
        "rule":        "root-account-mfa-enabled",
        "rule_id":     "COMP-CONFIG-001",
        "severity":    "CRITICAL",
        "title":       "Config: Root account MFA not enabled",
        "description": "AWS Config rule root-account-mfa-enabled is non-compliant. Root account lacks MFA.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS"],
        "recommendation": "Enable MFA on root account immediately.",
    },
    {
        "rule":        "mfa-enabled-for-iam-console-access",
        "rule_id":     "COMP-CONFIG-002",
        "severity":    "HIGH",
        "title":       "Config: IAM console users without MFA",
        "description": "Users have console access without MFA enabled.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Enable MFA for all IAM users with console access.",
    },
    {
        "rule":        "access-keys-rotated",
        "rule_id":     "COMP-CONFIG-003",
        "severity":    "HIGH",
        "title":       "Config: Access keys not rotated within 90 days",
        "description": "Active IAM access keys older than 90 days detected.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Rotate access keys every 90 days.",
    },
    {
        "rule":        "restricted-ssh",
        "rule_id":     "COMP-CONFIG-004",
        "severity":    "CRITICAL",
        "title":       "Config: SSH (port 22) open to internet",
        "description": "Security groups allow SSH access from 0.0.0.0/0.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS"],
        "recommendation": "Remove SSH rules allowing 0.0.0.0/0. Use SSM Session Manager instead.",
    },
    {
        "rule":        "restricted-common-ports",
        "rule_id":     "COMP-CONFIG-005",
        "severity":    "HIGH",
        "title":       "Config: Dangerous ports open to internet",
        "description": "Security groups allow access to common dangerous ports from 0.0.0.0/0.",
        "frameworks":  ["CIS", "PCI-DSS"],
        "recommendation": "Restrict all dangerous ports to specific IP ranges.",
    },
    {
        "rule":        "s3-bucket-public-read-prohibited",
        "rule_id":     "COMP-CONFIG-006",
        "severity":    "CRITICAL",
        "title":       "Config: S3 bucket allows public read",
        "description": "S3 buckets are publicly readable.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS", "HIPAA"],
        "recommendation": "Enable S3 Block Public Access on all buckets.",
    },
    {
        "rule":        "s3-bucket-public-write-prohibited",
        "rule_id":     "COMP-CONFIG-007",
        "severity":    "CRITICAL",
        "title":       "Config: S3 bucket allows public write",
        "description": "S3 buckets are publicly writable.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS"],
        "recommendation": "Enable S3 Block Public Access and remove public write permissions.",
    },
    {
        "rule":        "s3-bucket-server-side-encryption-enabled",
        "rule_id":     "COMP-CONFIG-008",
        "severity":    "HIGH",
        "title":       "Config: S3 bucket not encrypted",
        "description": "S3 buckets lack default server-side encryption.",
        "frameworks":  ["SOC2", "HIPAA", "PCI-DSS"],
        "recommendation": "Enable default SSE-S3 or SSE-KMS encryption on all buckets.",
    },
    {
        "rule":        "cloud-trail-enabled",
        "rule_id":     "COMP-CONFIG-009",
        "severity":    "CRITICAL",
        "title":       "Config: CloudTrail not enabled",
        "description": "AWS CloudTrail is not enabled for API call logging.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS", "HIPAA"],
        "recommendation": "Enable a multi-region CloudTrail trail immediately.",
    },
    {
        "rule":        "cloud-trail-log-file-validation-enabled",
        "rule_id":     "COMP-CONFIG-010",
        "severity":    "MEDIUM",
        "title":       "Config: CloudTrail log validation disabled",
        "description": "CloudTrail log file integrity validation is not enabled.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Enable log file validation on all CloudTrail trails.",
    },
    {
        "rule":        "encrypted-volumes",
        "rule_id":     "COMP-CONFIG-011",
        "severity":    "HIGH",
        "title":       "Config: EBS volumes not encrypted",
        "description": "EBS volumes attached to EC2 instances are not encrypted.",
        "frameworks":  ["SOC2", "HIPAA", "PCI-DSS"],
        "recommendation": "Enable EBS encryption by default in EC2 settings. Encrypt existing volumes.",
    },
    {
        "rule":        "rds-storage-encrypted",
        "rule_id":     "COMP-CONFIG-012",
        "severity":    "HIGH",
        "title":       "Config: RDS storage not encrypted",
        "description": "RDS database instances are not using encrypted storage.",
        "frameworks":  ["SOC2", "HIPAA", "PCI-DSS"],
        "recommendation": "Enable storage encryption on RDS instances.",
    },
    {
        "rule":        "rds-instance-public-access-check",
        "rule_id":     "COMP-CONFIG-013",
        "severity":    "HIGH",
        "title":       "Config: RDS instance publicly accessible",
        "description": "RDS databases are publicly accessible from the internet.",
        "frameworks":  ["CIS", "SOC2", "PCI-DSS"],
        "recommendation": "Disable public accessibility on RDS instances and use VPC-only access.",
    },
    {
        "rule":        "vpc-flow-logs-enabled",
        "rule_id":     "COMP-CONFIG-014",
        "severity":    "MEDIUM",
        "title":       "Config: VPC Flow Logs not enabled",
        "description": "VPC Flow Logs are not enabled on all VPCs.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Enable VPC Flow Logs on all VPCs and deliver to S3 or CloudWatch.",
    },
    {
        "rule":        "multi-region-cloudtrail-enabled",
        "rule_id":     "COMP-CONFIG-015",
        "severity":    "HIGH",
        "title":       "Config: No multi-region CloudTrail",
        "description": "No multi-region CloudTrail trail exists covering all regions.",
        "frameworks":  ["CIS"],
        "recommendation": "Create a multi-region CloudTrail trail.",
    },
    {
        "rule":        "iam-password-policy",
        "rule_id":     "COMP-CONFIG-016",
        "severity":    "MEDIUM",
        "title":       "Config: IAM password policy non-compliant",
        "description": "Account password policy does not meet requirements.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Update IAM password policy to meet CIS benchmark requirements.",
    },
    {
        "rule":        "guardduty-enabled-centralized",
        "rule_id":     "COMP-CONFIG-017",
        "severity":    "HIGH",
        "title":       "Config: GuardDuty not enabled",
        "description": "Amazon GuardDuty is not enabled for threat detection.",
        "frameworks":  ["CIS", "SOC2"],
        "recommendation": "Enable GuardDuty in all regions.",
    },
    {
        "rule":        "securityhub-enabled",
        "rule_id":     "COMP-CONFIG-018",
        "severity":    "MEDIUM",
        "title":       "Config: AWS Security Hub not enabled",
        "description": "AWS Security Hub is not enabled. Centralised compliance posture monitoring unavailable.",
        "frameworks":  ["SOC2"],
        "recommendation": "Enable AWS Security Hub and subscribe to CIS and SOC 2 standards.",
    },
    {
        "rule":        "kms-cmk-not-scheduled-for-deletion",
        "rule_id":     "COMP-CONFIG-019",
        "severity":    "HIGH",
        "title":       "Config: KMS CMK scheduled for deletion",
        "description": "A customer-managed KMS key is scheduled for deletion.",
        "frameworks":  ["SOC2"],
        "recommendation": "Verify no active resources use this key before deletion. Cancel deletion if in doubt.",
    },
    {
        "rule":        "backup-plan-min-frequency-and-min-retention-check",
        "rule_id":     "COMP-CONFIG-020",
        "severity":    "HIGH",
        "title":       "Config: Backup plan frequency or retention insufficient",
        "description": "Resources do not have backup plans meeting minimum frequency and retention requirements.",
        "frameworks":  ["SOC2", "HIPAA"],
        "recommendation": "Create AWS Backup plans with daily backups and at least 35-day retention.",
    },
]


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    findings = []
    for region in get_scan_regions(session):
        s      = session or boto3
        config = s.client("config", region_name=region)
        region_findings = []

        try:
            recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
            if not recorders:
                region_findings.append(build_finding(
                    rule_id="COMP-CONFIG-000", severity="CRITICAL",
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_id="account",
                    title="AWS Config is not enabled — cannot evaluate managed rules",
                    description="AWS Config is required to evaluate all compliance rules. Enable it first.",
                    recommendation="Enable AWS Config with all resource types in all active regions.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
                for f in region_findings:
                    f["region"] = region
                findings.extend(region_findings)
                continue
        except Exception as e:
            logger.error(f"Config recorder check failed: {e}")
            continue

        # Get all existing Config rules
        existing_rules = {}
        try:
            paginator = config.get_paginator("describe_config_rules")
            for page in paginator.paginate():
                for rule in page["ConfigRules"]:
                    existing_rules[rule["ConfigRuleName"].lower()] = rule
        except Exception as e:
            logger.error(f"Failed to list Config rules: {e}")

        for managed_rule in MANAGED_RULES:
            rule_name      = managed_rule["rule"]
            rule_id        = managed_rule["rule_id"]
            severity       = managed_rule["severity"]
            title          = managed_rule["title"]
            description    = managed_rule["description"]
            frameworks     = managed_rule["frameworks"]
            recommendation = managed_rule["recommendation"]

            found = any(rule_name in key for key in existing_rules.keys())
            if not found:
                region_findings.append(build_finding(
                    rule_id=rule_id, severity=severity,
                    resource_type="AWS::Config::ConfigRule",
                    resource_id=rule_name,
                    title=f"{title} (rule not deployed)",
                    description=f"Config rule '{rule_name}' is not deployed. Frameworks: {', '.join(frameworks)}. {description}",
                    recommendation=f"Deploy Config rule '{rule_name}'. {recommendation}",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
                continue

            try:
                rule_key   = next(k for k in existing_rules if rule_name in k)
                compliance = config.describe_compliance_by_config_rule(
                    ConfigRuleNames=[existing_rules[rule_key]["ConfigRuleName"]]
                )["ComplianceByConfigRules"]

                for c in compliance:
                    compliance_type = c.get("Compliance", {}).get("ComplianceType", "INSUFFICIENT_DATA")
                    if compliance_type == "NON_COMPLIANT":
                        try:
                            resources    = config.get_compliance_details_by_config_rule(
                                ConfigRuleName=existing_rules[rule_key]["ConfigRuleName"],
                                ComplianceTypes=["NON_COMPLIANT"],
                                Limit=10
                            )["EvaluationResults"]
                            resource_ids = [
                                r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                                for r in resources
                            ]
                            count = len(resource_ids)
                            region_findings.append(build_finding(
                                rule_id=rule_id, severity=severity,
                                resource_type="AWS::Config::ConfigRule",
                                resource_id=existing_rules[rule_key]["ConfigRuleName"],
                                title=f"{title} — {count} non-compliant resource(s)",
                                description=f"{description} Non-compliant: {', '.join(resource_ids[:5])}{'...' if count > 5 else ''}. Frameworks: {', '.join(frameworks)}.",
                                recommendation=recommendation,
                                auto_remediable=False,
                                account_id=account_id, account_name=account_name,
                            ))
                        except Exception as e:
                            logger.warning(f"Could not get compliance details for {rule_name}: {e}")
                            region_findings.append(build_finding(
                                rule_id=rule_id, severity=severity,
                                resource_type="AWS::Config::ConfigRule",
                                resource_id=rule_name,
                                title=f"{title} — non-compliant",
                                description=f"{description} Frameworks: {', '.join(frameworks)}.",
                                recommendation=recommendation,
                                auto_remediable=False,
                                account_id=account_id, account_name=account_name,
                            ))

            except Exception as e:
                logger.warning(f"Could not check compliance for {rule_name}: {e}")

        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Config rules checker complete for {account_id}. {len(findings)} findings.")
    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
    }


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    event = {"account_id": account_id, "account_name": "", "scan_id": "scheduled"}
    result = lambda_handler(event, None, session=session)
    return result.get("findings", [])
