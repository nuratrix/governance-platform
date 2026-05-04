"""
Security Agent - KMS & Secrets Manager Checker — Multi-Account Edition
Accepts an optional boto3 session for cross-account scanning.
"""

import json
import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"KMS & Secrets Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        kms = (session or boto3).client("kms", region_name=region)
        sm  = (session or boto3).client("secretsmanager", region_name=region)
        region_findings = []
        region_findings.extend(_check_kms_keys(kms, account_id, account_name))
        region_findings.extend(_check_secrets(sm, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"KMS & Secrets Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_kms_keys(kms, account_id, account_name):
    findings = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                try:
                    key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") not in ("Enabled", "PendingDeletion"):
                        continue
                    findings.extend(_check_key_rotation(kms, key_meta, account_id, account_name))
                    findings.extend(_check_key_policy(kms, key_id, key_meta, account_id, account_name))
                    findings.extend(_check_pending_deletion(key_meta, account_id, account_name))
                except Exception as e:
                    logger.warning(f"Could not describe key {key_id}: {e}")
    except Exception as e:
        logger.error(f"KMS check failed: {e}")
    return findings


def _check_key_rotation(kms, key_meta, account_id, account_name):
    key_id = key_meta["KeyId"]
    key_arn = key_meta["Arn"]
    if key_meta.get("KeySpec") == "SYMMETRIC_DEFAULT":
        try:
            if not kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"):
                return [build_finding(
                    rule_id="SEC-KMS-001", severity="MEDIUM",
                    resource_type="AWS::KMS::Key", resource_id=key_arn,
                    title=f"KMS key {key_id} does not have automatic rotation enabled",
                    description="Automatic key rotation is not enabled.",
                    recommendation="Enable automatic annual key rotation for this CMK.",
                    account_id=account_id, account_name=account_name,
                )]
        except Exception as e:
            logger.warning(f"Could not check rotation for key {key_id}: {e}")
    return []


def _check_key_policy(kms, key_id, key_meta, account_id, account_name):
    findings = []
    try:
        policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            if stmt.get("Effect") == "Allow" and (
                principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
            ):
                findings.append(build_finding(
                    rule_id="SEC-KMS-002", severity="CRITICAL",
                    resource_type="AWS::KMS::Key", resource_id=key_meta["Arn"],
                    title=f"KMS key {key_id} policy allows any AWS principal",
                    description="Key policy uses Principal: '*'.",
                    recommendation="Restrict the key policy to specific IAM roles and users.",
                    account_id=account_id, account_name=account_name,
                ))
    except Exception as e:
        logger.warning(f"Could not check policy for key {key_id}: {e}")
    return findings


def _check_pending_deletion(key_meta, account_id, account_name):
    if key_meta.get("KeyState") == "PendingDeletion":
        deletion_date = key_meta.get("DeletionDate")
        return [build_finding(
            rule_id="SEC-KMS-003", severity="HIGH",
            resource_type="AWS::KMS::Key", resource_id=key_meta["Arn"],
            title=f"KMS key {key_meta['KeyId']} is pending deletion on {deletion_date}",
            description="If services depend on this key, deleting it will cause decryption failures.",
            recommendation="Verify no services use this key before deletion.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_secrets(sm, account_id, account_name):
    findings = []
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page["SecretList"]:
                findings.extend(_check_secret_rotation(secret, account_id, account_name))
                findings.extend(_check_secret_unused(secret, account_id, account_name))
                findings.extend(_check_secret_encryption(secret, account_id, account_name))
    except Exception as e:
        logger.error(f"Secrets Manager check failed: {e}")
    return findings


def _check_secret_rotation(secret, account_id, account_name):
    if not secret.get("RotationEnabled"):
        name     = secret.get("Name", "")
        severity = "HIGH" if any(kw in name.lower() for kw in ["password", "api_key", "secret", "token", "credential"]) else "MEDIUM"
        return [build_finding(
            rule_id="SEC-SEC-001", severity=severity,
            resource_type="AWS::SecretsManager::Secret", resource_id=secret["ARN"],
            title=f"Secret '{name}' does not have rotation enabled",
            description="Automatic rotation is not configured.",
            recommendation="Enable automatic rotation with an appropriate Lambda rotation function.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_secret_unused(secret, account_id, account_name):
    findings     = []
    last_accessed = secret.get("LastAccessedDate")
    if last_accessed:
        days_unused = (datetime.now(timezone.utc) - last_accessed.replace(tzinfo=timezone.utc)).days
        if days_unused > 90:
            findings.append(build_finding(
                rule_id="SEC-SEC-002", severity="LOW",
                resource_type="AWS::SecretsManager::Secret", resource_id=secret["ARN"],
                title=f"Secret '{secret['Name']}' has not been accessed in {days_unused} days",
                description="Secret may be orphaned.",
                recommendation="Delete unused secrets or verify they are still needed.",
                account_id=account_id, account_name=account_name,
            ))
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    kms = session.client("kms", region_name=region)
    sm = session.client("secretsmanager", region_name=region)
    findings = []
    findings.extend(_check_kms_keys(kms, account_id, ""))
    findings.extend(_check_secrets(sm, account_id, ""))
    return findings


def _check_secret_encryption(secret, account_id, account_name):
    if not secret.get("KmsKeyId"):
        return [build_finding(
            rule_id="SEC-SEC-003", severity="LOW",
            resource_type="AWS::SecretsManager::Secret", resource_id=secret["ARN"],
            title=f"Secret '{secret['Name']}' uses default AWS-managed encryption",
            description="Secret is encrypted with the AWS-managed key, not a customer-managed KMS key.",
            recommendation="Encrypt sensitive secrets with a customer-managed KMS CMK.",
            account_id=account_id, account_name=account_name,
        )]
    return []
