"""
Backup & DR Agent - Backup Vault & Recovery Point Checker
Audits AWS Backup vaults for encryption, access policies, and recent job failures.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RECENT_DAYS = 7   # Check backup jobs from the last 7 days


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    findings = []
    for region in get_scan_regions(session):
        backup = session.client("backup", region_name=region) if session else boto3.client("backup", region_name=region)
        region_findings = []
        region_findings.extend(_check_vault_encryption(backup, account_id, account_name))
        region_findings.extend(_check_vault_access_policy(backup, account_id, account_name))
        region_findings.extend(_check_recent_job_failures(backup, account_id, account_name))
        region_findings.extend(_check_recovery_point_age(backup, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Backup Vault Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_vault_encryption(backup, account_id, account_name):
    """Flag backup vaults not encrypted with a customer-managed KMS key."""
    findings = []
    try:
        paginator = backup.get_paginator("list_backup_vaults")
        for page in paginator.paginate():
            for vault in page.get("BackupVaultList", []):
                vault_name   = vault["BackupVaultName"]
                kms_key_arn  = vault.get("EncryptionKeyArn", "")

                if not kms_key_arn:
                    findings.append(build_finding(
                        rule_id="BDR-005", severity="HIGH",
                        resource_type="AWS::Backup::BackupVault",
                        resource_id=vault_name,
                        title=f"Backup vault '{vault_name}' has no KMS encryption key",
                        description=(
                            f"Backup vault '{vault_name}' is not encrypted with a KMS key. "
                            "Unencrypted vaults are non-compliant with most security frameworks "
                            "and expose backup data to unauthorized access if the account is compromised."
                        ),
                        recommendation=(
                            "Create a new backup vault with a customer-managed KMS key. "
                            "Migrate existing recovery points to the encrypted vault. "
                            "Note: vault encryption cannot be changed after creation — "
                            "you must create a new vault."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"vault_name": vault_name}
                    ))
                elif "aws/backup" in kms_key_arn.lower():
                    findings.append(build_finding(
                        rule_id="BDR-005b", severity="LOW",
                        resource_type="AWS::Backup::BackupVault",
                        resource_id=vault_name,
                        title=f"Backup vault '{vault_name}' uses AWS-managed key (not customer-managed)",
                        description=(
                            f"Backup vault '{vault_name}' uses the AWS-managed key (aws/backup) "
                            "instead of a customer-managed KMS key. "
                            "AWS-managed keys cannot be rotated on demand or have custom key policies."
                        ),
                        recommendation=(
                            "Create a customer-managed KMS key for backup vault encryption "
                            "to maintain control over key rotation, access policies, and audit trails."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"vault_name": vault_name, "kms_key_arn": kms_key_arn}
                    ))
    except Exception as e:
        logger.error(f"Vault encryption check failed: {e}")
    return findings


def _check_vault_access_policy(backup, account_id, account_name):
    """Flag vaults with no access policy (no explicit deny for deletion)."""
    findings = []
    try:
        paginator = backup.get_paginator("list_backup_vaults")
        for page in paginator.paginate():
            for vault in page.get("BackupVaultList", []):
                vault_name = vault["BackupVaultName"]
                try:
                    backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
                    # Policy exists — OK
                except backup.exceptions.ResourceNotFoundException:
                    findings.append(build_finding(
                        rule_id="BDR-006", severity="MEDIUM",
                        resource_type="AWS::Backup::BackupVault",
                        resource_id=vault_name,
                        title=f"Backup vault '{vault_name}' has no resource-based access policy",
                        description=(
                            f"Backup vault '{vault_name}' has no vault access policy. "
                            "Without an explicit Deny on backup:DeleteRecoveryPoint, "
                            "any IAM principal with the permission can delete recovery points, "
                            "undermining ransomware protection."
                        ),
                        recommendation=(
                            f"Add a vault access policy to '{vault_name}' that denies "
                            "backup:DeleteRecoveryPoint for all principals (including the account root). "
                            "Use an AWS Backup Vault Lock to make this immutable for compliance."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"vault_name": vault_name}
                    ))
                except Exception as e:
                    logger.warning(f"Could not get access policy for vault {vault_name}: {e}")
    except Exception as e:
        logger.error(f"Vault access policy check failed: {e}")
    return findings


def _check_recent_job_failures(backup, account_id, account_name):
    """Flag backup jobs that have failed in the last RECENT_DAYS days."""
    findings = []
    try:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=RECENT_DAYS)

        failed_jobs = []
        paginator = backup.get_paginator("list_backup_jobs")
        for page in paginator.paginate(ByState="FAILED"):
            for job in page.get("BackupJobs", []):
                created = job.get("CreationDate")
                if created and created >= start:
                    failed_jobs.append(job)

        if failed_jobs:
            # Group by resource ARN to avoid duplicate findings
            by_resource = {}
            for job in failed_jobs:
                arn = job.get("ResourceArn", "unknown")
                by_resource.setdefault(arn, []).append(job)

            for arn, jobs in list(by_resource.items())[:10]:
                resource_type = jobs[0].get("ResourceType", "Unknown")
                findings.append(build_finding(
                    rule_id="BDR-007", severity="HIGH",
                    resource_type=f"AWS::Backup::BackupJob",
                    resource_id=arn,
                    title=f"Backup job failed {len(jobs)}x in the last {RECENT_DAYS} days for {arn}",
                    description=(
                        f"AWS Backup failed {len(jobs)} time(s) in the last {RECENT_DAYS} days "
                        f"for resource '{arn}' (type: {resource_type}). "
                        "Repeated backup failures mean this resource has no recent recovery point."
                    ),
                    recommendation=(
                        "Investigate the failed backup jobs in AWS Backup console → Jobs. "
                        "Common causes: IAM permission errors, resource in wrong state, "
                        "vault capacity limits. Fix the root cause and trigger a manual backup "
                        "to ensure a current recovery point exists."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"resource_arn": arn, "resource_type": resource_type,
                           "failure_count": len(jobs), "recent_days": RECENT_DAYS}
                ))
    except Exception as e:
        logger.error(f"Backup job failure check failed: {e}")
    return findings


def _check_recovery_point_age(backup, account_id, account_name):
    """Flag protected resources whose most recent recovery point is too old."""
    findings = []
    max_age_days = 2  # Alert if no backup in the last 2 days for daily plans
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        paginator = backup.get_paginator("list_protected_resources")
        for page in paginator.paginate():
            for resource in page.get("Results", []):
                arn       = resource.get("ResourceArn", "")
                last_used = resource.get("LastBackupTime")

                if last_used and last_used < cutoff:
                    age_days = (datetime.now(timezone.utc) - last_used).days
                    findings.append(build_finding(
                        rule_id="BDR-008", severity="HIGH" if age_days > 7 else "MEDIUM",
                        resource_type=resource.get("ResourceType", "AWS::Backup::ProtectedResource"),
                        resource_id=arn,
                        title=f"Stale backup: {arn} last backed up {age_days} days ago",
                        description=(
                            f"Resource '{arn}' is assigned to a backup plan but its most recent "
                            f"successful backup is {age_days} days old. "
                            "This suggests backup jobs are failing silently or the plan is misconfigured."
                        ),
                        recommendation=(
                            "Check the backup job history for this resource. "
                            "Trigger a manual on-demand backup to create a current recovery point. "
                            "Verify the backup schedule and IAM permissions are correct."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"resource_arn": arn, "last_backup_age_days": age_days,
                               "last_backup_time": last_used.isoformat() if last_used else None}
                    ))
    except Exception as e:
        logger.error(f"Recovery point age check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    backup = session.client("backup", region_name=region)
    findings.extend(_check_vault_encryption(backup, account_id, ""))
    findings.extend(_check_vault_access_policy(backup, account_id, ""))
    findings.extend(_check_recent_job_failures(backup, account_id, ""))
    findings.extend(_check_recovery_point_age(backup, account_id, ""))
    return findings
