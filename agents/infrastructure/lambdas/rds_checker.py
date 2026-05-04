"""
Infra Agent - RDS Checker — Multi-Account Edition
Audits & Identify RDS - public accessibility, unencrypted storage,
non-resiliency, disabled backups and snapshots older than 90 days.
Rules: RDS-001 through RDS-005
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"RDS check — account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        rds = (session or boto3).client("rds", region_name=region)
        region_findings = []
        region_findings += _check_public_instances(rds, account_id, account_name)
        region_findings += _check_unencrypted_instances(rds, account_id, account_name)
        region_findings += _check_no_multi_az(rds, account_id, account_name)
        region_findings += _check_no_backup(rds, account_id, account_name)
        region_findings += _check_old_snapshots(rds, account_id, account_name)
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    return {"findings": findings, "scan_id": scan_id,
            "account_id": account_id, "account_name": account_name}


def _check_public_instances(rds, account_id, account_name):
    findings = []
    resp = rds.describe_db_instances()
    for db in resp["DBInstances"]:
        if db.get("PubliclyAccessible"):
            findings.append(build_finding(
                rule_id        = "RDS-001",
                severity       = "HIGH",
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db["DBInstanceIdentifier"],
                title          = "RDS instance publicly accessible",
                description    = (
                    f"RDS instance {db['DBInstanceIdentifier']} ({db['Engine']}) "
                    "is publicly accessible"
                ),
                recommendation  = "Disable public accessibility and use VPC-only access",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _check_unencrypted_instances(rds, account_id, account_name):
    findings = []
    resp = rds.describe_db_instances()
    for db in resp["DBInstances"]:
        if not db.get("StorageEncrypted"):
            findings.append(build_finding(
                rule_id        = "RDS-002",
                severity       = "HIGH",
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db["DBInstanceIdentifier"],
                title          = "RDS instance storage not encrypted",
                description    = (
                    f"RDS instance {db['DBInstanceIdentifier']} does not have "
                    "storage encryption enabled"
                ),
                recommendation  = "Encrypt by creating encrypted snapshot and restoring",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _check_no_multi_az(rds, account_id, account_name):
    findings = []
    resp = rds.describe_db_instances()
    for db in resp["DBInstances"]:
        if not db.get("MultiAZ") and db["DBInstanceClass"] not in ["db.t2.micro", "db.t3.micro"]:
            findings.append(build_finding(
                rule_id        = "RDS-003",
                severity       = "MEDIUM",
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db["DBInstanceIdentifier"],
                title          = "RDS instance not Multi-AZ",
                description    = (
                    f"Production-sized RDS instance {db['DBInstanceIdentifier']} "
                    f"({db['DBInstanceClass']}) has no Multi-AZ failover"
                ),
                recommendation  = "Enable Multi-AZ for production databases",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _check_no_backup(rds, account_id, account_name):
    findings = []
    resp = rds.describe_db_instances()
    for db in resp["DBInstances"]:
        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(build_finding(
                rule_id        = "RDS-004",
                severity       = "HIGH",
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db["DBInstanceIdentifier"],
                title          = "RDS automated backups disabled",
                description    = (
                    f"RDS instance {db['DBInstanceIdentifier']} has automated backups disabled"
                ),
                recommendation  = "Enable automated backups with at least 7 day retention",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    rds = session.client("rds", region_name=region)
    findings = []
    findings.extend(_check_public_instances(rds, account_id, ""))
    findings.extend(_check_unencrypted_instances(rds, account_id, ""))
    findings.extend(_check_no_multi_az(rds, account_id, ""))
    findings.extend(_check_no_backup(rds, account_id, ""))
    findings.extend(_check_old_snapshots(rds, account_id, ""))
    return findings


def _check_old_snapshots(rds, account_id, account_name):
    findings = []
    resp   = rds.describe_db_snapshots(SnapshotType="manual")
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for snap in resp["DBSnapshots"]:
        if snap["SnapshotCreateTime"] < cutoff:
            age = (datetime.now(timezone.utc) - snap["SnapshotCreateTime"]).days
            findings.append(build_finding(
                rule_id        = "RDS-005",
                severity       = "LOW",
                resource_type  = "AWS::RDS::DBSnapshot",
                resource_id    = snap["DBSnapshotIdentifier"],
                title          = "RDS manual snapshot older than 90 days",
                description    = f"Snapshot {snap['DBSnapshotIdentifier']} is {age} days old",
                recommendation  = "Delete if no longer needed to reduce storage costs",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings
