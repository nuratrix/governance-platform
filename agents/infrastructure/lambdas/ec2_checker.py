"""
Infra Agent - EC2 Checker — Multi-Account Edition
Audits & Identify unhealthy, wasteful, and non-compliant EC2 infrastructure.
Rules: EC2-001 through EC2-006
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
    logger.info(f"EC2 check — account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        s          = session or boto3
        ec2        = s.client("ec2", region_name=region)
        cloudwatch = s.client("cloudwatch", region_name=region)
        region_findings = []
        region_findings += _check_stopped_instances(ec2, account_id, account_name)
        region_findings += _check_unattached_volumes(ec2, account_id, account_name)
        region_findings += _check_old_snapshots(ec2, account_id, account_name)
        region_findings += _check_public_amis(ec2, account_id, account_name)
        region_findings += _check_unused_elastic_ips(ec2, account_id, account_name)
        region_findings += _check_unencrypted_volumes(ec2, account_id, account_name)
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    return {"findings": findings, "scan_id": scan_id,
            "account_id": account_id, "account_name": account_name}


def _check_stopped_instances(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            state_reason = i.get("StateTransitionReason", "")
            findings.append(build_finding(
                rule_id        = "EC2-001",
                severity       = "LOW",
                resource_type  = "AWS::EC2::Instance",
                resource_id    = i["InstanceId"],
                title          = "Stopped EC2 instance",
                description    = (
                    f"Instance {i['InstanceId']} ({i['InstanceType']}) has been stopped. "
                    f"Reason: {state_reason}"
                ),
                recommendation = "Terminate if no longer needed to avoid EBS charges",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _check_unattached_volumes(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_volumes(
        Filters=[{"Name": "status", "Values": ["available"]}]
    )
    for vol in resp["Volumes"]:
        age_days = (datetime.now(timezone.utc) - vol["CreateTime"]).days
        findings.append(build_finding(
            rule_id        = "EC2-002",
            severity       = "MEDIUM" if age_days > 30 else "LOW",
            resource_type  = "AWS::EC2::Volume",
            resource_id    = vol["VolumeId"],
            title          = "Unattached EBS volume",
            description    = (
                f"Volume {vol['VolumeId']} ({vol['Size']}GB, {vol['VolumeType']}) "
                f"has been unattached for ~{age_days} days"
            ),
            recommendation  = "Delete if not needed — you are paying for unused storage",
            auto_remediable = True,
            account_id      = account_id,
            account_name    = account_name,
        ))
    return findings


def _check_old_snapshots(ec2, account_id, account_name):
    findings = []
    resp   = ec2.describe_snapshots(OwnerIds=["self"])
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for snap in resp["Snapshots"]:
        if snap["StartTime"] < cutoff:
            age_days = (datetime.now(timezone.utc) - snap["StartTime"]).days
            findings.append(build_finding(
                rule_id        = "EC2-003",
                severity       = "LOW",
                resource_type  = "AWS::EC2::Snapshot",
                resource_id    = snap["SnapshotId"],
                title          = "Snapshot older than 90 days",
                description    = (
                    f"Snapshot {snap['SnapshotId']} is {age_days} days old "
                    f"({snap['VolumeSize']}GB)"
                ),
                recommendation  = "Review retention policy — delete if no longer needed",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _check_public_amis(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_images(
        Owners=["self"],
        Filters=[{"Name": "is-public", "Values": ["true"]}]
    )
    for ami in resp["Images"]:
        findings.append(build_finding(
            rule_id        = "EC2-004",
            severity       = "HIGH",
            resource_type  = "AWS::EC2::Image",
            resource_id    = ami["ImageId"],
            title          = "Publicly shared AMI",
            description    = (
                f"AMI {ami['ImageId']} ({ami.get('Name', '')}) is publicly accessible"
            ),
            recommendation  = "Make the AMI private unless intentionally public",
            auto_remediable = False,
            account_id      = account_id,
            account_name    = account_name,
        ))
    return findings


def _check_unused_elastic_ips(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_addresses()
    for addr in resp["Addresses"]:
        if "AssociationId" not in addr:
            findings.append(build_finding(
                rule_id        = "EC2-005",
                severity       = "LOW",
                resource_type  = "AWS::EC2::EIP",
                resource_id    = addr["AllocationId"],
                title          = "Unassociated Elastic IP",
                description    = (
                    f"Elastic IP {addr['PublicIp']} is allocated but not associated "
                    "with any resource"
                ),
                recommendation  = "Release the EIP to avoid unnecessary charges ($0.005/hr)",
                auto_remediable = True,
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
    ec2 = session.client("ec2", region_name=region)
    findings = []
    findings.extend(_check_stopped_instances(ec2, account_id, ""))
    findings.extend(_check_unattached_volumes(ec2, account_id, ""))
    findings.extend(_check_old_snapshots(ec2, account_id, ""))
    findings.extend(_check_public_amis(ec2, account_id, ""))
    findings.extend(_check_unused_elastic_ips(ec2, account_id, ""))
    findings.extend(_check_unencrypted_volumes(ec2, account_id, ""))
    return findings


def _check_unencrypted_volumes(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_volumes()
    for vol in resp["Volumes"]:
        if not vol.get("Encrypted", False) and vol["State"] == "in-use":
            findings.append(build_finding(
                rule_id        = "EC2-006",
                severity       = "MEDIUM",
                resource_type  = "AWS::EC2::Volume",
                resource_id    = vol["VolumeId"],
                title          = "Unencrypted EBS volume in use",
                description    = (
                    f"Volume {vol['VolumeId']} ({vol['Size']}GB) attached to instance "
                    "is not encrypted"
                ),
                recommendation  = "Create encrypted snapshot and replace volume",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings
