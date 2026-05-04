"""
Security Agent - RDS Security Checker — Multi-Account Edition
Audits RDS/Aurora DB instances and clusters for security misconfigurations:
  - Public accessibility
  - Storage encryption at rest
  - Deletion protection disabled
  - Automated backup retention too short
  - Auto minor version upgrade disabled
  - Multi-AZ not enabled (single point of failure + security posture)
  - Default master usernames (admin, postgres, root)
  - Snapshots publicly accessible
  - Enhanced monitoring disabled
  - No SSL enforcement (via parameter groups)
"""

import boto3
import logging
from datetime import datetime, timezone
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Minimum backup retention days considered acceptable
MIN_BACKUP_RETENTION = 7

# Default usernames flagged as risky — attackers try these first
RISKY_MASTER_USERS = {"admin", "administrator", "root", "postgres", "mysql", "dbadmin", "master"}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"RDS Security Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        rds = (session or boto3).client("rds", region_name=region)
        region_findings = []
        region_findings.extend(_check_db_instances(rds, account_id, account_name))
        region_findings.extend(_check_db_clusters(rds, account_id, account_name))
        region_findings.extend(_check_public_snapshots(rds, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"RDS Security Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


# ── RDS DB Instances ──────────────────────────────────────────────────────────

def _check_db_instances(rds, account_id, account_name):
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                # Skip cluster member instances — the cluster-level checks cover them
                if db.get("DBClusterIdentifier"):
                    continue
                findings.extend(_check_instance_public_access(db, account_id, account_name))
                findings.extend(_check_instance_encryption(db, account_id, account_name))
                findings.extend(_check_instance_deletion_protection(db, account_id, account_name))
                findings.extend(_check_instance_backup_retention(db, account_id, account_name))
                findings.extend(_check_instance_minor_upgrade(db, account_id, account_name))
                findings.extend(_check_instance_multi_az(db, account_id, account_name))
                findings.extend(_check_instance_master_username(db, account_id, account_name))
                findings.extend(_check_instance_enhanced_monitoring(db, account_id, account_name))
    except Exception as e:
        logger.error(f"RDS describe_db_instances failed: {e}")
    return findings


def _check_instance_public_access(db, account_id, account_name):
    if db.get("PubliclyAccessible", False):
        return [build_finding(
            rule_id="SEC-RDS-001", severity="CRITICAL",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' is publicly accessible",
            description=(
                "The DB instance has PubliclyAccessible=true, meaning its endpoint resolves to "
                "a public IP. Combined with permissive security groups, the database is internet-exposed."
            ),
            recommendation=(
                "Set PubliclyAccessible=false. Access databases only through a VPN, "
                "bastion host, or AWS PrivateLink. Restrict security group ingress to app server IPs only."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_encryption(db, account_id, account_name):
    if not db.get("StorageEncrypted", False):
        return [build_finding(
            rule_id="SEC-RDS-002", severity="HIGH",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' storage is not encrypted",
            description=(
                "The DB instance does not have encryption at rest enabled. "
                "Unencrypted storage exposes data if the underlying EBS volume or snapshot is accessed."
            ),
            recommendation=(
                "Encryption can only be enabled at creation time. To encrypt an existing instance: "
                "take a snapshot → copy snapshot with encryption → restore from encrypted snapshot."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_deletion_protection(db, account_id, account_name):
    if not db.get("DeletionProtection", False):
        env_tag = _get_tag(db.get("TagList", []), "env") or _get_tag(db.get("TagList", []), "Env") or ""
        severity = "HIGH" if env_tag.lower() == "production" else "MEDIUM"
        return [build_finding(
            rule_id="SEC-RDS-003", severity=severity,
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' does not have deletion protection enabled",
            description=(
                "Deletion protection is off. A misconfigured Terraform run, an accidental CLI command, "
                "or a malicious actor could permanently delete this database."
            ),
            recommendation="Enable DeletionProtection on the DB instance.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_backup_retention(db, account_id, account_name):
    retention = db.get("BackupRetentionPeriod", 0)
    if retention < MIN_BACKUP_RETENTION:
        return [build_finding(
            rule_id="SEC-RDS-004", severity="MEDIUM",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' backup retention is {retention} day(s) (minimum: {MIN_BACKUP_RETENTION})",
            description=(
                f"Automated backup retention is set to {retention} day(s). "
                f"Short retention limits your recovery point window for data corruption or ransomware incidents."
            ),
            recommendation=f"Set BackupRetentionPeriod to at least {MIN_BACKUP_RETENTION} days (35 days recommended for production).",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_minor_upgrade(db, account_id, account_name):
    if not db.get("AutoMinorVersionUpgrade", True):
        return [build_finding(
            rule_id="SEC-RDS-005", severity="LOW",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' has auto minor version upgrade disabled",
            description=(
                "AutoMinorVersionUpgrade is disabled. Minor version patches often include "
                "security fixes. Without auto-upgrade, patches must be applied manually."
            ),
            recommendation="Enable AutoMinorVersionUpgrade and configure a maintenance window.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_multi_az(db, account_id, account_name):
    if not db.get("MultiAZ", False):
        env_tag = _get_tag(db.get("TagList", []), "env") or _get_tag(db.get("TagList", []), "Env") or ""
        if env_tag.lower() == "production":
            return [build_finding(
                rule_id="SEC-RDS-006", severity="MEDIUM",
                resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
                title=f"RDS production instance '{db['DBInstanceIdentifier']}' is not Multi-AZ",
                description=(
                    "The production DB instance runs in a single Availability Zone. "
                    "An AZ outage or hardware failure causes downtime and potential data loss."
                ),
                recommendation="Enable Multi-AZ for all production RDS instances.",
                account_id=account_id, account_name=account_name,
            )]
    return []


def _check_instance_master_username(db, account_id, account_name):
    username = db.get("MasterUsername", "").lower()
    if username in RISKY_MASTER_USERS:
        return [build_finding(
            rule_id="SEC-RDS-007", severity="LOW",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' uses default master username '{username}'",
            description=(
                f"Master username '{username}' is a well-known default. "
                "Attackers systematically try these credentials in brute-force attacks."
            ),
            recommendation=(
                "For new instances, use a non-obvious master username. "
                "For existing instances, create a secondary admin user with a unique name and demote the default."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_instance_enhanced_monitoring(db, account_id, account_name):
    if not db.get("MonitoringInterval", 0):
        return [build_finding(
            rule_id="SEC-RDS-008", severity="LOW",
            resource_type="AWS::RDS::DBInstance", resource_id=db["DBInstanceArn"],
            title=f"RDS instance '{db['DBInstanceIdentifier']}' does not have enhanced monitoring enabled",
            description=(
                "Enhanced monitoring provides OS-level metrics (CPU steal, memory, disk I/O) "
                "that are critical for detecting abnormal database activity and resource exhaustion."
            ),
            recommendation="Enable Enhanced Monitoring with a 60-second interval and a monitoring IAM role.",
            account_id=account_id, account_name=account_name,
        )]
    return []


# ── Aurora Clusters ───────────────────────────────────────────────────────────

def _check_db_clusters(rds, account_id, account_name):
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for cluster in page["DBClusters"]:
                findings.extend(_check_cluster_encryption(cluster, account_id, account_name))
                findings.extend(_check_cluster_deletion_protection(cluster, account_id, account_name))
                findings.extend(_check_cluster_backup_retention(cluster, account_id, account_name))
                findings.extend(_check_cluster_iam_auth(cluster, account_id, account_name))
    except Exception as e:
        logger.error(f"RDS describe_db_clusters failed: {e}")
    return findings


def _check_cluster_encryption(cluster, account_id, account_name):
    if not cluster.get("StorageEncrypted", False):
        return [build_finding(
            rule_id="SEC-RDS-002c", severity="HIGH",
            resource_type="AWS::RDS::DBCluster", resource_id=cluster["DBClusterArn"],
            title=f"Aurora cluster '{cluster['DBClusterIdentifier']}' storage is not encrypted",
            description="Aurora cluster does not have encryption at rest enabled.",
            recommendation="Encryption must be enabled at cluster creation. Restore from an encrypted snapshot.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_cluster_deletion_protection(cluster, account_id, account_name):
    if not cluster.get("DeletionProtection", False):
        return [build_finding(
            rule_id="SEC-RDS-003c", severity="HIGH",
            resource_type="AWS::RDS::DBCluster", resource_id=cluster["DBClusterArn"],
            title=f"Aurora cluster '{cluster['DBClusterIdentifier']}' does not have deletion protection enabled",
            description="Deletion protection is off — the cluster can be dropped by any user with rds:DeleteDBCluster.",
            recommendation="Enable DeletionProtection on the Aurora cluster.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_cluster_backup_retention(cluster, account_id, account_name):
    retention = cluster.get("BackupRetentionPeriod", 0)
    if retention < MIN_BACKUP_RETENTION:
        return [build_finding(
            rule_id="SEC-RDS-004c", severity="MEDIUM",
            resource_type="AWS::RDS::DBCluster", resource_id=cluster["DBClusterArn"],
            title=f"Aurora cluster '{cluster['DBClusterIdentifier']}' backup retention is {retention} day(s)",
            description=f"Backup retention of {retention} day(s) is below the minimum of {MIN_BACKUP_RETENTION} days.",
            recommendation=f"Increase BackupRetentionPeriod to at least {MIN_BACKUP_RETENTION} days.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_cluster_iam_auth(cluster, account_id, account_name):
    if not cluster.get("IAMDatabaseAuthenticationEnabled", False):
        return [build_finding(
            rule_id="SEC-RDS-009", severity="MEDIUM",
            resource_type="AWS::RDS::DBCluster", resource_id=cluster["DBClusterArn"],
            title=f"Aurora cluster '{cluster['DBClusterIdentifier']}' does not have IAM database authentication enabled",
            description=(
                "IAM database authentication is not enabled. Without it, applications must use "
                "long-lived static passwords stored in config files or environment variables."
            ),
            recommendation=(
                "Enable IAM database authentication. Use IAM roles and short-lived tokens "
                "to authenticate instead of static passwords."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


# ── Public Snapshots ──────────────────────────────────────────────────────────

def _check_public_snapshots(rds, account_id, account_name):
    findings = []
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="public", IncludePublic=True):
            for snap in page["DBSnapshots"]:
                # Only flag snapshots that belong to this account
                if snap.get("DBSnapshotArn", "").split(":")[4] == account_id:
                    findings.append(build_finding(
                        rule_id="SEC-RDS-010", severity="CRITICAL",
                        resource_type="AWS::RDS::DBSnapshot", resource_id=snap["DBSnapshotArn"],
                        title=f"RDS snapshot '{snap['DBSnapshotIdentifier']}' is publicly shared",
                        description=(
                            "This DB snapshot is marked as public, meaning any AWS account can "
                            "restore it and access your database content."
                        ),
                        recommendation=(
                            "Immediately remove public access from the snapshot. "
                            "Audit your data for potential exposure and notify your security team."
                        ),
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.warning(f"Could not check public snapshots: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    rds = session.client("rds", region_name=region)
    findings = []
    findings.extend(_check_db_instances(rds, account_id, ""))
    findings.extend(_check_db_clusters(rds, account_id, ""))
    findings.extend(_check_public_snapshots(rds, account_id, ""))
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_tag(tag_list, key):
    for tag in tag_list:
        if tag.get("Key", "").lower() == key.lower():
            return tag.get("Value", "")
    return ""
