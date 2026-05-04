"""
IAM Access Analyzer Agent - Unused Permissions Checker
Uses IAM Access Analyzer's unused access analysis to identify:
- IAM roles/users with unused permissions (last used > 90 days)
- Unused access keys
- Over-privileged service roles
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Days of inactivity before flagging a permission as unused
UNUSED_DAYS_THRESHOLD = 90
KEY_UNUSED_DAYS       = 45   # Access keys rotate faster


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    iam = session.client("iam") if session else boto3.client("iam")

    findings = []
    findings.extend(_check_unused_access_keys(iam, account_id, account_name))
    findings.extend(_check_unused_iam_roles(iam, account_id, account_name))
    findings.extend(_check_console_users_no_mfa(iam, account_id, account_name))

    for f in findings:
        f["region"] = "global"
    logger.info(f"Unused Permissions Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _days_since(date_str_or_dt):
    """Return number of days since a datetime or ISO string."""
    if date_str_or_dt is None:
        return 9999
    if isinstance(date_str_or_dt, str):
        dt = datetime.fromisoformat(date_str_or_dt.replace("Z", "+00:00"))
    else:
        dt = date_str_or_dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _check_unused_access_keys(iam, account_id, account_name):
    """Find active access keys not used in > KEY_UNUSED_DAYS days."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                try:
                    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                    for key in keys:
                        if key.get("Status") != "Active":
                            continue
                        key_id = key["AccessKeyId"]
                        try:
                            last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                            used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            days = _days_since(used_date) if used_date else 9999
                        except Exception:
                            days = 9999

                        if days > KEY_UNUSED_DAYS:
                            severity = "HIGH" if days > 180 else "MEDIUM"
                            findings.append(build_finding(
                                rule_id="IAM-AA-003", severity=severity,
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=f"{username}/{key_id}",
                                title=f"Unused access key {key_id} for IAM user '{username}' ({days} days)",
                                description=(
                                    f"IAM user '{username}' has an active access key {key_id} "
                                    f"that has not been used in {days} days "
                                    f"({'never used' if days == 9999 else f'last used {days} days ago'}). "
                                    "Unused active access keys are a persistent credential exposure risk."
                                ),
                                recommendation=(
                                    f"Deactivate and delete access key {key_id} for user '{username}'. "
                                    "If the key is still needed, rotate it and confirm it works within 7 days. "
                                    "Prefer IAM roles over long-lived access keys for application authentication."
                                ),
                                account_id=account_id, account_name=account_name,
                                extra={"username": username, "key_id": key_id, "days_unused": days}
                            ))
                except Exception as e:
                    logger.warning(f"Key check failed for {username}: {e}")
    except Exception as e:
        logger.error(f"Unused access key check failed: {e}")
    return findings


def _check_unused_iam_roles(iam, account_id, account_name):
    """Find IAM roles not assumed in > UNUSED_DAYS_THRESHOLD days."""
    findings = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                role_arn  = role["Arn"]

                # Skip AWS service-linked roles — they are managed by AWS
                if "aws-service-role" in role_arn:
                    continue

                try:
                    detail    = iam.get_role(RoleName=role_name)["Role"]
                    last_used = detail.get("RoleLastUsed", {}).get("LastUsedDate")
                    days      = _days_since(last_used) if last_used else 9999
                except Exception as e:
                    logger.warning(f"Could not get role detail for {role_name}: {e}")
                    continue

                if days <= UNUSED_DAYS_THRESHOLD:
                    continue

                # Check whether the role has any policies attached
                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                    inline   = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                    has_permissions = bool(attached or inline)
                except Exception:
                    has_permissions = True  # assume has permissions if we can't check

                if not has_permissions:
                    continue  # No permissions — no risk

                severity = "HIGH" if days > 365 else "MEDIUM"
                findings.append(build_finding(
                    rule_id="IAM-AA-004", severity=severity,
                    resource_type="AWS::IAM::Role",
                    resource_id=role_name,
                    title=f"IAM role '{role_name}' unused for {days if days < 9999 else 'all time'} days",
                    description=(
                        f"IAM role '{role_name}' has not been assumed in "
                        f"{days if days < 9999 else 'its entire lifetime'} days "
                        f"but still has {len(attached)} managed and {len(inline)} inline policies attached. "
                        "Unused privileged roles increase the blast radius of credential compromise."
                    ),
                    recommendation=(
                        f"Investigate whether role '{role_name}' is still needed. "
                        "If unused, remove all attached policies first, then delete the role. "
                        "If needed but dormant, consider removing excess permissions while retaining the role."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={
                        "role_name": role_name,
                        "role_arn": role_arn,
                        "days_unused": days,
                        "attached_policies": len(attached),
                        "inline_policies": len(inline),
                    }
                ))
    except Exception as e:
        logger.error(f"Unused roles check failed: {e}")
    return findings


def _check_console_users_no_mfa(iam, account_id, account_name):
    """Flag IAM users with console access but no MFA enabled."""
    findings = []
    try:
        for cred_report_entry in _get_credential_report(iam):
            username      = cred_report_entry.get("user", "")
            if username in ("<root_account>", ""):
                continue
            password_enabled = cred_report_entry.get("password_enabled", "false").lower() == "true"
            mfa_active       = cred_report_entry.get("mfa_active", "false").lower() == "true"

            if password_enabled and not mfa_active:
                last_login = cred_report_entry.get("password_last_used", "N/A")
                findings.append(build_finding(
                    rule_id="IAM-AA-005", severity="HIGH",
                    resource_type="AWS::IAM::User",
                    resource_id=username,
                    title=f"IAM user '{username}' has console access without MFA",
                    description=(
                        f"IAM user '{username}' has AWS console password login enabled "
                        f"but no MFA device configured. Last console login: {last_login}. "
                        "Users without MFA are vulnerable to credential stuffing and phishing attacks."
                    ),
                    recommendation=(
                        f"Enforce MFA for user '{username}'. "
                        "Add an IAM policy condition `aws:MultiFactorAuthPresent: true` "
                        "or use a Service Control Policy to deny console actions without MFA. "
                        "Consider migrating human users to AWS IAM Identity Center (SSO) with MFA enforcement."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"username": username, "last_login": last_login}
                ))
    except Exception as e:
        logger.error(f"Console MFA check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    iam = session.client("iam")
    findings.extend(_check_unused_access_keys(iam, account_id, ""))
    findings.extend(_check_unused_iam_roles(iam, account_id, ""))
    findings.extend(_check_console_users_no_mfa(iam, account_id, ""))
    return findings


def _get_credential_report(iam):
    """Generate and retrieve IAM credential report."""
    try:
        # Trigger generation
        iam.generate_credential_report()
        import time
        for _ in range(5):
            try:
                resp = iam.get_credential_report()
                content = resp["Content"].decode("utf-8")
                lines   = content.strip().split("\n")
                headers = lines[0].split(",")
                return [dict(zip(headers, line.split(","))) for line in lines[1:]]
            except iam.exceptions.ReportNotPresentException:
                time.sleep(2)
    except Exception as e:
        logger.warning(f"Could not get credential report: {e}")
    return []
