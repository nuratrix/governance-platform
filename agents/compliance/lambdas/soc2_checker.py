"""
Compliance Agent - SOC 2 Checker (Multi-Account Edition)
Maps AWS controls to SOC 2 Trust Service Criteria (TSC).
Rules: COMP-SOC2-001 through COMP-SOC2-015
Cross-account: all clients created from the injected session.
"""

import boto3
import json
import logging
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    s      = session or boto3
    iam    = s.client("iam")
    s3c    = s.client("s3")
    cfg    = s.client("config")
    logs   = s.client("logs")

    findings = []
    findings += _check_cc6_logical_access(iam, account_id, account_name)
    findings += _check_cc6_encryption(s3c, account_id, account_name)
    findings += _check_cc7_monitoring(logs, account_id, account_name)
    findings += _check_cc8_change_management(cfg, account_id, account_name)
    findings += _check_availability(s, account_id, account_name)

    for f in findings:
        f["region"] = "global"
    logger.info(f"SOC2 checker complete for {account_id}. {len(findings)} findings.")
    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "framework":    "SOC2-TSC",
        "account_id":   account_id,
        "account_name": account_name,
    }


def _check_cc6_logical_access(iam, account_id, account_name):
    """CC6.1-CC6.3: Logical access controls"""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                attached     = iam.list_attached_user_policies(UserName=user["UserName"])["AttachedPolicies"]
                admin_policies = [p for p in attached if "AdministratorAccess" in p["PolicyName"]]
                if admin_policies:
                    mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                    if not mfa_devices:
                        findings.append(build_finding(
                            rule_id="COMP-SOC2-001", severity="CRITICAL",
                            resource_type="AWS::IAM::User",
                            resource_id=user["UserName"],
                            title=f"SOC2 CC6.1: Admin user without MFA — {user['UserName']}",
                            description=f"User {user['UserName']} has AdministratorAccess but no MFA device.",
                            recommendation="Enable MFA immediately. Consider revoking AdministratorAccess and replacing with least-privilege policies.",
                            auto_remediable=False,
                            account_id=account_id, account_name=account_name,
                        ))

        roles_paginator = iam.get_paginator("list_roles")
        for page in roles_paginator.paginate():
            for role in page["Roles"]:
                trust = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*" or principal.get("AWS") == "*":
                        findings.append(build_finding(
                            rule_id="COMP-SOC2-002", severity="CRITICAL",
                            resource_type="AWS::IAM::Role",
                            resource_id=role["RoleName"],
                            title=f"SOC2 CC6.2: Role allows assumption by any principal — {role['RoleName']}",
                            description="A role trust policy uses a wildcard principal. Any AWS entity can assume this role.",
                            recommendation="Restrict role trust policy to specific accounts, services, or role ARNs.",
                            auto_remediable=False,
                            account_id=account_id, account_name=account_name,
                        ))

    except Exception as e:
        logger.error(f"SOC2 CC6 logical access check failed: {e}")
    return findings


def _check_cc6_encryption(s3c, account_id, account_name):
    """CC6.7: Data encryption in transit and at rest"""
    findings = []
    try:
        buckets = s3c.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]

            try:
                s3c.get_bucket_encryption(Bucket=name)
            except s3c.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append(build_finding(
                        rule_id="COMP-SOC2-003", severity="HIGH",
                        resource_type="AWS::S3::Bucket", resource_id=name,
                        title=f"SOC2 CC6.7: S3 bucket not encrypted at rest — {name}",
                        description="Bucket has no default server-side encryption.",
                        recommendation="Enable SSE-S3 or SSE-KMS default encryption on the bucket.",
                        auto_remediable=False,
                        account_id=account_id, account_name=account_name,
                    ))

            try:
                policy = json.loads(s3c.get_bucket_policy(Bucket=name)["Policy"])
                https_enforced = any(
                    stmt.get("Effect") == "Deny" and
                    stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
                    for stmt in policy.get("Statement", [])
                )
                if not https_enforced:
                    findings.append(build_finding(
                        rule_id="COMP-SOC2-004", severity="MEDIUM",
                        resource_type="AWS::S3::Bucket", resource_id=name,
                        title=f"SOC2 CC6.7: S3 bucket allows HTTP (unencrypted transit) — {name}",
                        description="Bucket policy does not enforce HTTPS-only access.",
                        recommendation="Add a bucket policy statement denying s3:* when aws:SecureTransport is false.",
                        auto_remediable=False,
                        account_id=account_id, account_name=account_name,
                    ))
            except s3c.exceptions.ClientError:
                findings.append(build_finding(
                    rule_id="COMP-SOC2-004", severity="MEDIUM",
                    resource_type="AWS::S3::Bucket", resource_id=name,
                    title=f"SOC2 CC6.7: S3 bucket has no policy enforcing HTTPS — {name}",
                    description="No bucket policy exists. HTTP access is not explicitly blocked.",
                    recommendation="Create a bucket policy that denies all actions when aws:SecureTransport is false.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

    except Exception as e:
        logger.error(f"SOC2 CC6 encryption check failed: {e}")
    return findings


def _check_cc7_monitoring(logs, account_id, account_name):
    """CC7.1-CC7.3: System monitoring and anomaly detection"""
    findings = []
    try:
        required_filters = [
            ("root-login",           "$.userIdentity.type = Root",                               "COMP-SOC2-005",
             "SOC2 CC7.2: No CloudWatch alarm for root account login",
             "Root account usage should trigger an immediate alert for SOC 2 monitoring."),
            ("console-auth-failure", "$.errorCode = ConsoleLogin",                               "COMP-SOC2-006",
             "SOC2 CC7.2: No CloudWatch alarm for console authentication failures",
             "Failed console logins should trigger monitoring alerts."),
            ("iam-policy-change",    "$.eventName = DeleteGroupPolicy OR $.eventName = PutGroupPolicy", "COMP-SOC2-007",
             "SOC2 CC7.3: No CloudWatch alarm for IAM policy changes",
             "IAM policy changes are significant events requiring monitoring."),
            ("sg-change",            "$.eventName = AuthorizeSecurityGroupIngress",              "COMP-SOC2-008",
             "SOC2 CC7.3: No CloudWatch alarm for security group changes",
             "Security group modifications should be monitored and alerted on."),
        ]

        log_groups  = logs.describe_log_groups()["logGroups"]
        all_filters = []
        for lg in log_groups:
            filters = logs.describe_metric_filters(logGroupName=lg["logGroupName"])["metricFilters"]
            all_filters.extend([f["filterPattern"] for f in filters])

        for _, pattern_hint, rule_id, title, description in required_filters:
            filter_found = any(
                any(term in f for term in pattern_hint.split())
                for f in all_filters
            )
            if not filter_found:
                findings.append(build_finding(
                    rule_id=rule_id, severity="MEDIUM",
                    resource_type="AWS::Logs::MetricFilter", resource_id="account",
                    title=title, description=description,
                    recommendation=f"Create a CloudWatch metric filter and alarm matching pattern: {pattern_hint}",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

    except Exception as e:
        logger.error(f"SOC2 CC7 monitoring check failed: {e}")
    return findings


def _check_cc8_change_management(cfg, account_id, account_name):
    """CC8.1: Change management controls"""
    findings = []
    try:
        rules_response = cfg.describe_config_rules()
        if not rules_response.get("ConfigRules"):
            findings.append(build_finding(
                rule_id="COMP-SOC2-009", severity="HIGH",
                resource_type="AWS::Config::ConfigRule", resource_id="account",
                title="SOC2 CC8.1: No AWS Config rules are configured",
                description="AWS Config rules provide automated change detection. None are configured.",
                recommendation="Deploy AWS Security Hub to automatically create SOC 2 relevant Config rules.",
                auto_remediable=False,
                account_id=account_id, account_name=account_name,
            ))
            return findings

        non_compliant = cfg.describe_compliance_by_config_rule(
            ComplianceTypes=["NON_COMPLIANT"]
        ).get("ComplianceByConfigRules", [])

        for rule in non_compliant:
            findings.append(build_finding(
                rule_id="COMP-SOC2-010", severity="MEDIUM",
                resource_type="AWS::Config::ConfigRule",
                resource_id=rule.get("ConfigRuleName", "unknown"),
                title=f"SOC2 CC8.1: Config rule non-compliant — {rule.get('ConfigRuleName')}",
                description=f"AWS Config rule {rule.get('ConfigRuleName')} has non-compliant resources.",
                recommendation="Review non-compliant resources in AWS Config and remediate.",
                auto_remediable=False,
                account_id=account_id, account_name=account_name,
            ))

    except Exception as e:
        logger.error(f"SOC2 CC8 change management check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    iam = session.client("iam")
    s3c = session.client("s3")
    cfg = session.client("config", region_name=region)
    logs = session.client("logs", region_name=region)
    findings = []
    findings.extend(_check_cc6_logical_access(iam, account_id, ""))
    findings.extend(_check_cc6_encryption(s3c, account_id, ""))
    findings.extend(_check_cc7_monitoring(logs, account_id, ""))
    findings.extend(_check_cc8_change_management(cfg, account_id, ""))
    findings.extend(_check_availability(session, account_id, ""))
    return findings


def _check_availability(s, account_id, account_name):
    """A1.1-A1.2: Availability controls"""
    findings = []
    try:
        rds = s.client("rds")
        dbs = rds.describe_db_instances()["DBInstances"]
        for db in dbs:
            if db["DBInstanceClass"] in ["db.t2.micro", "db.t3.micro"]:
                continue

            if not db.get("MultiAZ"):
                findings.append(build_finding(
                    rule_id="COMP-SOC2-011", severity="MEDIUM",
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=db["DBInstanceIdentifier"],
                    title=f"SOC2 A1.2: RDS instance not Multi-AZ — {db['DBInstanceIdentifier']}",
                    description="Production RDS instance lacks Multi-AZ configuration. Single point of failure for availability.",
                    recommendation="Enable Multi-AZ for production databases to meet availability commitments.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

            if db.get("BackupRetentionPeriod", 0) < 7:
                findings.append(build_finding(
                    rule_id="COMP-SOC2-012", severity="HIGH",
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=db["DBInstanceIdentifier"],
                    title=f"SOC2 A1.2: RDS backup retention insufficient — {db['DBInstanceIdentifier']}",
                    description=f"Backup retention is {db.get('BackupRetentionPeriod', 0)} days. SOC 2 A1.2 requires adequate backup.",
                    recommendation="Set backup retention to at least 7 days (30 days recommended for production).",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

    except Exception as e:
        logger.error(f"SOC2 availability check failed: {e}")
    return findings
