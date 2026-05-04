"""
Security Agent - IAM Checker — Multi-Account Edition
Accepts an optional boto3 session so the checker can audit member accounts
via cross-account assumed-role credentials.
"""

import json
import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"IAM Checker starting for scan_id={scan_id} account={account_id}")

    # Use the passed session (cross-account) or fall back to default
    iam = (session or boto3).client("iam")

    findings = []
    findings.extend(_check_root_account_usage(iam, account_id, account_name))
    findings.extend(_check_mfa_on_users(iam, account_id, account_name))
    findings.extend(_check_old_access_keys(iam, account_id, account_name))
    findings.extend(_check_password_policy(iam, account_id, account_name))
    findings.extend(_check_admin_policies(iam, account_id, account_name))
    findings.extend(_check_unused_credentials(iam, account_id, account_name))
    findings.extend(_check_inline_policies(iam, account_id, account_name))
    findings.extend(_check_overly_permissive_roles(iam, account_id, account_name))

    for f in findings:
        f["region"] = "global"
    logger.info(f"IAM Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_root_account_usage(iam, account_id, account_name):
    findings = []
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        credential_report = _get_credential_report(iam)

        for row in credential_report:
            if row.get("user") != "<root_account>":
                continue
            last_used = row.get("password_last_used", "no_information")
            if last_used not in ("no_information", "N/A", "not_supported"):
                last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                days_ago = (datetime.now(timezone.utc) - last_used_dt).days
                if days_ago < 30:
                    findings.append(build_finding(
                        rule_id="SEC-IAM-001", severity="CRITICAL",
                        resource_type="AWS::IAM::RootAccount", resource_id="root",
                        title="Root account was used recently",
                        description=f"Root account was used {days_ago} day(s) ago.",
                        recommendation="Use IAM users or roles with least privilege instead of root.",
                        account_id=account_id, account_name=account_name,
                    ))

        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(build_finding(
                rule_id="SEC-IAM-001b", severity="CRITICAL",
                resource_type="AWS::IAM::RootAccount", resource_id="root",
                title="Root account does not have MFA enabled",
                description="The root account does not have MFA enabled.",
                recommendation="Enable virtual or hardware MFA on the root account immediately.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.error(f"SEC-IAM-001 check failed: {e}")
    return findings


def _check_mfa_on_users(iam, account_id, account_name):
    findings = []
    try:
        for row in _get_credential_report(iam):
            if row.get("user") == "<root_account>":
                continue
            if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
                findings.append(build_finding(
                    rule_id="SEC-IAM-002", severity="HIGH",
                    resource_type="AWS::IAM::User", resource_id=row["user"],
                    title=f"IAM user '{row['user']}' has no MFA enabled",
                    description="Console-enabled IAM user does not have MFA configured.",
                    recommendation="Enable MFA for this user or disable console access if not needed.",
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.error(f"SEC-IAM-002 check failed: {e}")
    return findings


def _check_old_access_keys(iam, account_id, account_name):
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username  = user["UserName"]
                keys_resp = iam.list_access_keys(UserName=username)
                for key in keys_resp["AccessKeyMetadata"]:
                    if key["Status"] != "Active":
                        continue
                    age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    if age_days > 90:
                        severity = "CRITICAL" if age_days > 180 else "HIGH"
                        findings.append(build_finding(
                            rule_id="SEC-IAM-003", severity=severity,
                            resource_type="AWS::IAM::AccessKey",
                            resource_id=f"{username}/{key['AccessKeyId']}",
                            title=f"Access key for '{username}' is {age_days} days old",
                            description=f"Key {key['AccessKeyId']} has not been rotated in {age_days} days.",
                            recommendation="Rotate the access key and update applications using it.",
                            account_id=account_id, account_name=account_name,
                        ))
    except Exception as e:
        logger.error(f"SEC-IAM-003 check failed: {e}")
    return findings


def _check_password_policy(iam, account_id, account_name):
    findings = []
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("Minimum password length is less than 14 characters")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Lowercase characters not required")
        if not policy.get("RequireNumbers", False):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols", False):
            issues.append("Symbols not required")
        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append("Password expiry is more than 90 days")
        if policy.get("PasswordReusePrevention", 0) < 24:
            issues.append("Password reuse prevention is less than 24 generations")
        if issues:
            findings.append(build_finding(
                rule_id="SEC-IAM-004", severity="MEDIUM",
                resource_type="AWS::IAM::PasswordPolicy",
                resource_id="account-password-policy",
                title="IAM password policy does not meet security standards",
                description="Issues: " + "; ".join(issues),
                recommendation="Update password policy to enforce: 14+ chars, upper/lower/number/symbol, 90-day expiry.",
                account_id=account_id, account_name=account_name,
            ))
    except iam.exceptions.NoSuchEntityException:
        findings.append(build_finding(
            rule_id="SEC-IAM-004", severity="HIGH",
            resource_type="AWS::IAM::PasswordPolicy",
            resource_id="account-password-policy",
            title="No IAM password policy configured",
            description="Account has no password policy.",
            recommendation="Configure a strong IAM password policy.",
            account_id=account_id, account_name=account_name,
        ))
    except Exception as e:
        logger.error(f"SEC-IAM-004 check failed: {e}")
    return findings


def _check_admin_policies(iam, account_id, account_name):
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                for policy in attached:
                    if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                        findings.append(build_finding(
                            rule_id="SEC-IAM-005", severity="HIGH",
                            resource_type="AWS::IAM::User", resource_id=username,
                            title=f"IAM user '{username}' has {policy['PolicyName']}",
                            description=f"User has overly broad administrative access.",
                            recommendation="Replace with least-privilege policies.",
                            account_id=account_id, account_name=account_name,
                        ))

        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                if "aws-service-role" in role.get("Path", ""):
                    continue
                inline_policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
                for policy_name in inline_policies:
                    doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                            findings.append(build_finding(
                                rule_id="SEC-IAM-005b", severity="CRITICAL",
                                resource_type="AWS::IAM::Role", resource_id=role_name,
                                title=f"Role '{role_name}' has wildcard Allow */* inline policy",
                                description=f"Inline policy '{policy_name}' grants full administrative access.",
                                recommendation="Replace with least-privilege policy.",
                                account_id=account_id, account_name=account_name,
                            ))
    except Exception as e:
        logger.error(f"SEC-IAM-005 check failed: {e}")
    return findings


def _check_unused_credentials(iam, account_id, account_name):
    findings = []
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        for row in _get_credential_report(iam):
            if row.get("user") == "<root_account>":
                continue
            last_used = row.get("password_last_used", "N/A")
            if last_used not in ("N/A", "no_information", "not_supported"):
                last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                if last_used_dt < cutoff and row.get("password_enabled") == "true":
                    days = (datetime.now(timezone.utc) - last_used_dt).days
                    findings.append(build_finding(
                        rule_id="SEC-IAM-006", severity="MEDIUM",
                        resource_type="AWS::IAM::User", resource_id=row["user"],
                        title=f"IAM user '{row['user']}' credentials unused for {days} days",
                        description="Console access has not been used in over 90 days.",
                        recommendation="Disable console access or remove the user.",
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"SEC-IAM-006 check failed: {e}")
    return findings


def _check_inline_policies(iam, account_id, account_name):
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                inline   = iam.list_user_policies(UserName=username)["PolicyNames"]
                if inline:
                    findings.append(build_finding(
                        rule_id="SEC-IAM-007", severity="LOW",
                        resource_type="AWS::IAM::User", resource_id=username,
                        title=f"IAM user '{username}' has inline policies",
                        description=f"Inline policies: {', '.join(inline)}.",
                        recommendation="Convert inline policies to managed policies.",
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"SEC-IAM-007 check failed: {e}")
    return findings


def _check_overly_permissive_roles(iam, account_id, account_name):
    findings = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                trust = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        findings.append(build_finding(
                            rule_id="SEC-IAM-008", severity="CRITICAL",
                            resource_type="AWS::IAM::Role", resource_id=role["RoleName"],
                            title=f"Role '{role['RoleName']}' trust policy allows any AWS principal",
                            description="Trust policy uses Principal: '*'.",
                            recommendation="Restrict trust policy to specific account IDs or services.",
                            account_id=account_id, account_name=account_name,
                        ))
    except Exception as e:
        logger.error(f"SEC-IAM-008 check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    iam = session.client("iam")
    findings = []
    findings.extend(_check_root_account_usage(iam, account_id, ""))
    findings.extend(_check_mfa_on_users(iam, account_id, ""))
    findings.extend(_check_old_access_keys(iam, account_id, ""))
    findings.extend(_check_password_policy(iam, account_id, ""))
    findings.extend(_check_admin_policies(iam, account_id, ""))
    findings.extend(_check_unused_credentials(iam, account_id, ""))
    findings.extend(_check_inline_policies(iam, account_id, ""))
    findings.extend(_check_overly_permissive_roles(iam, account_id, ""))
    return findings


def _get_credential_report(iam):
    try:
        iam.generate_credential_report()
    except Exception:
        pass
    import time
    for _ in range(10):
        try:
            resp    = iam.get_credential_report()
            lines   = resp["Content"].decode("utf-8").splitlines()
            headers = lines[0].split(",")
            return [dict(zip(headers, line.split(","))) for line in lines[1:]]
        except Exception:
            time.sleep(2)
    return []
