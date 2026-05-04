"""
Security Agent - S3 Checker — Multi-Account Edition
Accepts an optional boto3 session for cross-account scanning.
"""

import json
import boto3
import logging
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"S3 Checker starting for scan_id={scan_id} account={account_id}")

    s3 = (session or boto3).client("s3")

    findings = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        logger.info(f"Found {len(buckets)} buckets in account {account_id}")
        for bucket in buckets:
            bucket_name = bucket["Name"]
            findings.extend(_check_public_access(s3, bucket_name, account_id, account_name))
            findings.extend(_check_bucket_policy(s3, bucket_name, account_id, account_name))
            findings.extend(_check_encryption(s3, bucket_name, account_id, account_name))
            findings.extend(_check_versioning(s3, bucket_name, account_id, account_name))
            findings.extend(_check_logging(s3, bucket_name, account_id, account_name))
            findings.extend(_check_lifecycle(s3, bucket_name, account_id, account_name))
            findings.extend(_check_replication(s3, bucket_name, account_id, account_name))
    except Exception as e:
        logger.error(f"S3 Checker failed: {e}")

    for f in findings:
        f["region"] = "global"
    logger.info(f"S3 Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_public_access(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        issues = []
        if not config.get("BlockPublicAcls"):        issues.append("BlockPublicAcls is disabled")
        if not config.get("IgnorePublicAcls"):        issues.append("IgnorePublicAcls is disabled")
        if not config.get("BlockPublicPolicy"):       issues.append("BlockPublicPolicy is disabled")
        if not config.get("RestrictPublicBuckets"):   issues.append("RestrictPublicBuckets is disabled")
        if issues:
            findings.append(build_finding(
                rule_id="SEC-S3-001", severity="HIGH",
                resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                title=f"S3 bucket '{bucket_name}' has public access not fully blocked",
                description="Public access block settings: " + "; ".join(issues),
                recommendation="Enable all four public access block settings.",
                account_id=account_id, account_name=account_name,
            ))
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        findings.append(build_finding(
            rule_id="SEC-S3-001", severity="CRITICAL",
            resource_type="AWS::S3::Bucket", resource_id=bucket_name,
            title=f"S3 bucket '{bucket_name}' has no public access block configuration",
            description="No public access block settings configured. Bucket may be publicly accessible.",
            recommendation="Apply public access block settings to the bucket.",
            account_id=account_id, account_name=account_name,
        ))
    except Exception as e:
        logger.warning(f"Could not check public access for {bucket_name}: {e}")
    return findings


def _check_bucket_policy(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
        for stmt in policy.get("Statement", []):
            principal  = stmt.get("Principal", {})
            is_public  = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
            if is_public and stmt.get("Effect") == "Allow":
                actions   = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                dangerous = [a for a in actions if a in ("s3:*", "s3:GetObject", "s3:PutObject", "s3:DeleteObject")]
                if dangerous:
                    findings.append(build_finding(
                        rule_id="SEC-S3-002", severity="CRITICAL",
                        resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                        title=f"S3 bucket '{bucket_name}' policy allows public access",
                        description=f"Bucket policy allows Principal: * to perform: {', '.join(dangerous)}",
                        recommendation="Remove public principal from policy.",
                        account_id=account_id, account_name=account_name,
                    ))
    except s3.exceptions.NoSuchBucketPolicy:
        pass
    except Exception as e:
        logger.warning(f"Could not check bucket policy for {bucket_name}: {e}")
    return findings


def _check_encryption(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        enc   = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
        for rule in rules:
            algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
            if algo not in ("AES256", "aws:kms", "aws:kms:dsse"):
                findings.append(build_finding(
                    rule_id="SEC-S3-003", severity="HIGH",
                    resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                    title=f"S3 bucket '{bucket_name}' uses weak encryption: {algo}",
                    description="Bucket encryption algorithm is not AES-256 or KMS.",
                    recommendation="Configure SSE-S3 (AES256) or SSE-KMS encryption.",
                    account_id=account_id, account_name=account_name,
                ))
    except Exception:
        findings.append(build_finding(
            rule_id="SEC-S3-003", severity="HIGH",
            resource_type="AWS::S3::Bucket", resource_id=bucket_name,
            title=f"S3 bucket '{bucket_name}' has no default encryption",
            description="Bucket does not have server-side encryption configured.",
            recommendation="Enable SSE-S3 (AES256) or SSE-KMS as default encryption.",
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _check_versioning(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        status = s3.get_bucket_versioning(Bucket=bucket_name).get("Status", "")
        if status != "Enabled":
            findings.append(build_finding(
                rule_id="SEC-S3-004", severity="MEDIUM",
                resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                title=f"S3 bucket '{bucket_name}' versioning is not enabled",
                description=f"Versioning status: '{status or 'Disabled'}'.",
                recommendation="Enable versioning on the bucket.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check versioning for {bucket_name}: {e}")
    return findings


def _check_logging(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        if not s3.get_bucket_logging(Bucket=bucket_name).get("LoggingEnabled"):
            findings.append(build_finding(
                rule_id="SEC-S3-005", severity="MEDIUM",
                resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                title=f"S3 bucket '{bucket_name}' does not have access logging enabled",
                description="Server access logging is disabled.",
                recommendation="Enable S3 server access logging to a dedicated logging bucket.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check logging for {bucket_name}: {e}")
    return findings


def _check_lifecycle(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    except s3.exceptions.NoSuchLifecycleConfiguration:
        findings.append(build_finding(
            rule_id="SEC-S3-006", severity="LOW",
            resource_type="AWS::S3::Bucket", resource_id=bucket_name,
            title=f"S3 bucket '{bucket_name}' has no lifecycle policy",
            description="No lifecycle policy configured. Old objects may accumulate indefinitely.",
            recommendation="Define lifecycle rules for your data retention policy.",
            account_id=account_id, account_name=account_name,
        ))
    except Exception as e:
        logger.warning(f"Could not check lifecycle for {bucket_name}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    s3 = session.client("s3")
    findings = []
    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            bucket_name = bucket["Name"]
            findings.extend(_check_public_access(s3, bucket_name, account_id, ""))
            findings.extend(_check_bucket_policy(s3, bucket_name, account_id, ""))
            findings.extend(_check_encryption(s3, bucket_name, account_id, ""))
            findings.extend(_check_versioning(s3, bucket_name, account_id, ""))
            findings.extend(_check_logging(s3, bucket_name, account_id, ""))
            findings.extend(_check_lifecycle(s3, bucket_name, account_id, ""))
            findings.extend(_check_replication(s3, bucket_name, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"S3 run_checks failed: {e}")
    return findings


def _check_replication(s3, bucket_name, account_id, account_name):
    findings = []
    try:
        s3.get_bucket_replication(Bucket=bucket_name)
    except Exception:
        important_keywords = ["prod", "production", "backup", "critical", "data", "db", "database"]
        if any(kw in bucket_name.lower() for kw in important_keywords):
            findings.append(build_finding(
                rule_id="SEC-S3-007", severity="LOW",
                resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                title=f"S3 bucket '{bucket_name}' has no cross-region replication",
                description="Important bucket has no cross-region replication configured.",
                recommendation="Consider enabling CRR for disaster recovery.",
                account_id=account_id, account_name=account_name,
            ))
    return findings
