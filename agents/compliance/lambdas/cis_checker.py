"""
Compliance Agent - CIS Benchmark Checker (Multi-Account Edition)
Checks AWS environment against CIS AWS Foundations Benchmark v2.0 controls.
Rules: COMP-CIS-001 through COMP-CIS-020
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

    s          = session or boto3
    iam        = s.client("iam")
    ec2        = s.client("ec2")
    cloudtrail = s.client("cloudtrail")
    cfg        = s.client("config")

    findings = []
    findings += _check_iam_password_policy(iam, account_id, account_name)
    findings += _check_root_account(iam, account_id, account_name)
    findings += _check_access_keys_rotation(iam, account_id, account_name)
    findings += _check_mfa_console_users(iam, account_id, account_name)
    findings += _check_cloudtrail_enabled(cloudtrail, account_id, account_name)
    findings += _check_cloudtrail_log_validation(cloudtrail, account_id, account_name)
    findings += _check_cloudtrail_kms(cloudtrail, account_id, account_name)
    findings += _check_config_enabled(cfg, account_id, account_name)
    findings += _check_vpc_flow_logs(ec2, account_id, account_name)
    findings += _check_default_security_groups(ec2, account_id, account_name)

    for f in findings:
        f["region"] = "global"
    logger.info(f"CIS checker complete for {account_id}. {len(findings)} findings.")
    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "framework":    "CIS-AWS-v2.0",
        "account_id":   account_id,
        "account_name": account_name,
    }


def _check_iam_password_policy(iam, account_id, account_name):
    """CIS 1.8 - 1.15: IAM password policy controls"""
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        checks = [
            ("MinimumPasswordLength", lambda v: v >= 14, "COMP-CIS-001", "MEDIUM",
             "CIS 1.8: Password minimum length must be 14 or greater",
             f"Current minimum length is {policy.get('MinimumPasswordLength', 0)}",
             "Set minimum password length to 14 in IAM Account Settings"),
            ("RequireUppercaseCharacters", lambda v: v, "COMP-CIS-002", "MEDIUM",
             "CIS 1.9: Password policy must require uppercase characters",
             "Uppercase characters not required", "Enable RequireUppercaseCharacters"),
            ("RequireLowercaseCharacters", lambda v: v, "COMP-CIS-003", "MEDIUM",
             "CIS 1.10: Password policy must require lowercase characters",
             "Lowercase characters not required", "Enable RequireLowercaseCharacters"),
            ("RequireSymbols", lambda v: v, "COMP-CIS-004", "MEDIUM",
             "CIS 1.11: Password policy must require symbols",
             "Symbols not required", "Enable RequireSymbols"),
            ("RequireNumbers", lambda v: v, "COMP-CIS-005", "MEDIUM",
             "CIS 1.12: Password policy must require numbers",
             "Numbers not required", "Enable RequireNumbers"),
            ("MaxPasswordAge", lambda v: v and v <= 365, "COMP-CIS-006", "LOW",
             "CIS 1.13: Password expiry must be 365 days or less",
             f"MaxPasswordAge is {policy.get('MaxPasswordAge', 'not set')}",
             "Set MaxPasswordAge to 90 or less"),
            ("PasswordReusePrevention", lambda v: v and v >= 24, "COMP-CIS-007", "LOW",
             "CIS 1.14: Password reuse prevention must be 24 or greater",
             f"PasswordReusePrevention is {policy.get('PasswordReusePrevention', 0)}",
             "Set PasswordReusePrevention to 24"),
        ]

        for attr, check, rule_id, severity, title, description, recommendation in checks:
            if not check(policy.get(attr)):
                findings.append(build_finding(
                    rule_id=rule_id, severity=severity,
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    resource_id="account",
                    title=title, description=description,
                    recommendation=recommendation, auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

    except iam.exceptions.NoSuchEntityException:
        findings.append(build_finding(
            rule_id="COMP-CIS-001", severity="HIGH",
            resource_type="AWS::IAM::AccountPasswordPolicy",
            resource_id="account",
            title="CIS 1.8-1.15: No IAM password policy configured",
            description="No account-level IAM password policy exists",
            recommendation="Configure a password policy in IAM Account Settings",
            auto_remediable=False,
            account_id=account_id, account_name=account_name,
        ))
    except Exception as e:
        logger.error(f"Password policy check failed: {e}")
    return findings


def _check_root_account(iam, account_id, account_name):
    """CIS 1.4, 1.5: Root account activity and MFA"""
    findings = []
    try:
        iam.generate_credential_report()
        import time
        time.sleep(2)
        report_content = iam.get_credential_report()["Content"].decode("utf-8")
        lines   = report_content.strip().split("\n")
        headers = lines[0].split(",")

        for line in lines[1:]:
            fields = dict(zip(headers, line.split(",")))
            if fields.get("user") != "<root_account>":
                continue

            if fields.get("access_key_1_active") == "true" or fields.get("access_key_2_active") == "true":
                findings.append(build_finding(
                    rule_id="COMP-CIS-008", severity="CRITICAL",
                    resource_type="AWS::IAM::User", resource_id="root",
                    title="CIS 1.4: Root account has active access keys",
                    description="Active access keys exist for the root account. Root access keys pose extreme security risk.",
                    recommendation="Delete root account access keys immediately. Use IAM roles instead.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

            if fields.get("mfa_active") != "true":
                findings.append(build_finding(
                    rule_id="COMP-CIS-009", severity="CRITICAL",
                    resource_type="AWS::IAM::User", resource_id="root",
                    title="CIS 1.5: Root account MFA is not enabled",
                    description="The root account does not have MFA enabled.",
                    recommendation="Enable hardware MFA on the root account immediately.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))

    except Exception as e:
        logger.error(f"Root account check failed: {e}")
    return findings


def _check_access_keys_rotation(iam, account_id, account_name):
    """CIS 1.14: Access keys rotated within 90 days"""
    findings = []
    try:
        from datetime import datetime, timezone, timedelta
        cutoff_warn     = datetime.now(timezone.utc) - timedelta(days=90)
        cutoff_critical = datetime.now(timezone.utc) - timedelta(days=180)

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    age = datetime.now(timezone.utc) - key["CreateDate"].replace(tzinfo=timezone.utc)
                    if age > cutoff_critical:
                        findings.append(build_finding(
                            rule_id="COMP-CIS-010", severity="CRITICAL",
                            resource_type="AWS::IAM::AccessKey",
                            resource_id=f"{user['UserName']}/{key['AccessKeyId']}",
                            title=f"CIS 1.14: Access key over 180 days old — {user['UserName']}",
                            description=f"Access key {key['AccessKeyId']} for {user['UserName']} is {age.days} days old.",
                            recommendation="Rotate or disable this access key immediately.",
                            auto_remediable=True,
                            account_id=account_id, account_name=account_name,
                        ))
                    elif age > cutoff_warn:
                        findings.append(build_finding(
                            rule_id="COMP-CIS-010", severity="HIGH",
                            resource_type="AWS::IAM::AccessKey",
                            resource_id=f"{user['UserName']}/{key['AccessKeyId']}",
                            title=f"CIS 1.14: Access key over 90 days old — {user['UserName']}",
                            description=f"Access key {key['AccessKeyId']} for {user['UserName']} is {age.days} days old.",
                            recommendation="Rotate this access key within the next 30 days.",
                            auto_remediable=False,
                            account_id=account_id, account_name=account_name,
                        ))
    except Exception as e:
        logger.error(f"Access key rotation check failed: {e}")
    return findings


def _check_mfa_console_users(iam, account_id, account_name):
    """CIS 1.10: MFA enabled for all console users"""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                try:
                    iam.get_login_profile(UserName=user["UserName"])
                except iam.exceptions.NoSuchEntityException:
                    continue

                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                if not mfa_devices:
                    findings.append(build_finding(
                        rule_id="COMP-CIS-011", severity="HIGH",
                        resource_type="AWS::IAM::User",
                        resource_id=user["UserName"],
                        title=f"CIS 1.10: Console user without MFA — {user['UserName']}",
                        description=f"IAM user {user['UserName']} has console access but no MFA device.",
                        recommendation="Enable MFA for this user or migrate to IAM Identity Center with enforced MFA.",
                        auto_remediable=False,
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"MFA check failed: {e}")
    return findings


def _check_cloudtrail_enabled(cloudtrail, account_id, account_name):
    """CIS 3.1: CloudTrail enabled in all regions"""
    findings = []
    try:
        trails       = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        if not multi_region:
            findings.append(build_finding(
                rule_id="COMP-CIS-012", severity="CRITICAL",
                resource_type="AWS::CloudTrail::Trail", resource_id="account",
                title="CIS 3.1: No multi-region CloudTrail trail exists",
                description="No multi-region CloudTrail trail is enabled. API calls in some regions are not logged.",
                recommendation="Create a multi-region trail and enable logging to a secure S3 bucket.",
                auto_remediable=False,
                account_id=account_id, account_name=account_name,
            ))
        for trail in trails:
            status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging"):
                findings.append(build_finding(
                    rule_id="COMP-CIS-012", severity="CRITICAL",
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail["TrailARN"],
                    title=f"CIS 3.1: CloudTrail trail is not logging — {trail['Name']}",
                    description=f"Trail {trail['Name']} exists but logging is disabled.",
                    recommendation="Start logging on this trail immediately.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"CloudTrail check failed: {e}")
    return findings


def _check_cloudtrail_log_validation(cloudtrail, account_id, account_name):
    """CIS 3.2: CloudTrail log file validation enabled"""
    findings = []
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]
        for trail in trails:
            if not trail.get("LogFileValidationEnabled"):
                findings.append(build_finding(
                    rule_id="COMP-CIS-013", severity="MEDIUM",
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail["TrailARN"],
                    title=f"CIS 3.2: Log file validation disabled — {trail['Name']}",
                    description="CloudTrail log file validation is not enabled. Log tampering cannot be detected.",
                    recommendation="Enable log file validation on the trail.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"CloudTrail validation check failed: {e}")
    return findings


def _check_cloudtrail_kms(cloudtrail, account_id, account_name):
    """CIS 3.5: CloudTrail logs encrypted with KMS"""
    findings = []
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]
        for trail in trails:
            if not trail.get("KMSKeyId"):
                findings.append(build_finding(
                    rule_id="COMP-CIS-014", severity="MEDIUM",
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail["TrailARN"],
                    title=f"CIS 3.5: CloudTrail not encrypted with KMS — {trail['Name']}",
                    description="Trail logs are not encrypted with a customer-managed KMS key.",
                    recommendation="Configure a KMS CMK for CloudTrail log encryption.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"CloudTrail KMS check failed: {e}")
    return findings


def _check_config_enabled(cfg, account_id, account_name):
    """CIS 3.5: AWS Config enabled"""
    findings = []
    try:
        recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
        statuses  = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]

        if not recorders:
            findings.append(build_finding(
                rule_id="COMP-CIS-015", severity="HIGH",
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id="account",
                title="CIS 3.5: AWS Config is not enabled",
                description="No AWS Config recorder exists. Continuous compliance monitoring is unavailable.",
                recommendation="Enable AWS Config with all resource types in all regions.",
                auto_remediable=False,
                account_id=account_id, account_name=account_name,
            ))
            return findings

        for status in statuses:
            if not status.get("recording"):
                findings.append(build_finding(
                    rule_id="COMP-CIS-015", severity="HIGH",
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_id=status.get("name", "unknown"),
                    title="CIS 3.5: AWS Config recorder is not recording",
                    description="An AWS Config recorder exists but is not actively recording.",
                    recommendation="Start the Config recorder.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"Config check failed: {e}")
    return findings


def _check_vpc_flow_logs(ec2, account_id, account_name):
    """CIS 3.9: VPC Flow Logs enabled in all VPCs"""
    findings = []
    try:
        vpcs      = ec2.describe_vpcs()["Vpcs"]
        flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        covered   = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}

        for vpc in vpcs:
            if vpc["VpcId"] not in covered:
                findings.append(build_finding(
                    rule_id="COMP-CIS-016", severity="HIGH",
                    resource_type="AWS::EC2::VPC",
                    resource_id=vpc["VpcId"],
                    title=f"CIS 3.9: VPC Flow Logs not enabled — {vpc['VpcId']}",
                    description=f"VPC {vpc['VpcId']} does not have active Flow Logs.",
                    recommendation="Enable VPC Flow Logs and deliver to S3 or CloudWatch Logs.",
                    auto_remediable=False,
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"VPC flow logs check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)
    cloudtrail = session.client("cloudtrail", region_name=region)
    cfg = session.client("config", region_name=region)
    findings = []
    findings.extend(_check_iam_password_policy(iam, account_id, ""))
    findings.extend(_check_root_account(iam, account_id, ""))
    findings.extend(_check_access_keys_rotation(iam, account_id, ""))
    findings.extend(_check_mfa_console_users(iam, account_id, ""))
    findings.extend(_check_cloudtrail_enabled(cloudtrail, account_id, ""))
    findings.extend(_check_cloudtrail_log_validation(cloudtrail, account_id, ""))
    findings.extend(_check_cloudtrail_kms(cloudtrail, account_id, ""))
    findings.extend(_check_config_enabled(cfg, account_id, ""))
    findings.extend(_check_vpc_flow_logs(ec2, account_id, ""))
    findings.extend(_check_default_security_groups(ec2, account_id, ""))
    return findings


def _check_default_security_groups(ec2, account_id, account_name):
    """CIS 5.4: Default security groups restrict all traffic"""
    findings = []
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id",     "Values": [vpc["VpcId"]]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )["SecurityGroups"]
            for sg in sgs:
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    findings.append(build_finding(
                        rule_id="COMP-CIS-017", severity="MEDIUM",
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_id=sg["GroupId"],
                        title=f"CIS 5.4: Default security group has rules — {sg['GroupId']}",
                        description=f"Default SG {sg['GroupId']} in VPC {vpc['VpcId']} has inbound or outbound rules.",
                        recommendation="Remove all rules from default SGs. Use purpose-built security groups.",
                        auto_remediable=False,
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"Default SG check failed: {e}")
    return findings
