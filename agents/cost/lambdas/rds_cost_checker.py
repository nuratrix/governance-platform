"""
Cost Agent - RDS Cost Checker (Multi-Account Edition)
Identifies idle databases, oversized instance classes,
and single-AZ instances that could be downsized.
Rules: COST-RDS-001 through COST-RDS-004
Cross-account: all clients created from the injected session.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Approximate monthly on-demand prices USD (single-AZ, us-east-1)
RDS_MONTHLY_PRICE = {
    "db.t3.micro":   15,   "db.t3.small":   30,   "db.t3.medium":  60,
    "db.t3.large":   120,  "db.t3.xlarge":  240,  "db.t3.2xlarge": 480,
    "db.m5.large":   138,  "db.m5.xlarge":  276,  "db.m5.2xlarge": 552,
    "db.m5.4xlarge": 1104, "db.m5.8xlarge": 2208,
    "db.r5.large":   180,  "db.r5.xlarge":  360,  "db.r5.2xlarge": 720,
    "db.r5.4xlarge": 1440,
}

DOWNSIZE_MAP = {
    "db.m5.8xlarge": "db.m5.4xlarge", "db.m5.4xlarge": "db.m5.2xlarge",
    "db.m5.2xlarge": "db.m5.xlarge",  "db.m5.xlarge":  "db.m5.large",
    "db.r5.4xlarge": "db.r5.2xlarge", "db.r5.2xlarge": "db.r5.xlarge",
    "db.r5.xlarge":  "db.r5.large",
    "db.t3.2xlarge": "db.t3.xlarge",  "db.t3.xlarge":  "db.t3.large",
    "db.t3.large":   "db.t3.medium",  "db.t3.medium":  "db.t3.small",
}


def lambda_handler(event, context, session=None):
    scan_id              = event.get("scan_id", "manual")
    account_id           = event.get("account_id", "")
    account_name         = event.get("account_name", "")
    lookback_days        = int(event.get("lookback_days", 14))
    connection_threshold = int(event.get("connection_threshold", 1))

    logger.info(f"RDS cost check for {account_id} — lookback={lookback_days}d")

    findings = []
    for region in get_scan_regions(session):
        s          = session or boto3
        rds        = s.client("rds", region_name=region)
        cloudwatch = s.client("cloudwatch", region_name=region)
        region_findings = []
        region_findings += _check_idle_databases(rds, cloudwatch, lookback_days, connection_threshold, account_id, account_name)
        region_findings += _check_low_cpu_databases(rds, cloudwatch, lookback_days, account_id, account_name)
        region_findings += _check_single_az_overprovisioned(rds, account_id, account_name)
        region_findings += _check_old_snapshots(rds, account_id, account_name)
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    total_saving = sum(f.get("estimated_monthly_saving", 0) for f in findings)

    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
        "summary": {
            "total_findings":         len(findings),
            "total_potential_saving": round(total_saving, 2),
            "instances_scanned":      len(rds.describe_db_instances()["DBInstances"]),
            "idle_databases":         len([f for f in findings if "COST-RDS-001" in f.get("rule_id", "")]),
        }
    }


def _check_idle_databases(rds, cloudwatch, lookback_days, connection_threshold, account_id, account_name):
    """COST-RDS-001: Databases with near-zero connections."""
    findings   = []
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    try:
        for db in rds.describe_db_instances()["DBInstances"]:
            db_id    = db["DBInstanceIdentifier"]
            db_class = db["DBInstanceClass"]
            engine   = db["Engine"]

            metrics    = cloudwatch.get_metric_statistics(
                Namespace  = "AWS/RDS",
                MetricName = "DatabaseConnections",
                Dimensions = [{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime  = start_time, EndTime = end_time,
                Period     = lookback_days * 86400,
                Statistics = ["Average", "Maximum"],
            )
            datapoints = metrics.get("Datapoints", [])
            if not datapoints:
                continue

            avg_connections = datapoints[0].get("Average", 999)
            max_connections = datapoints[0].get("Maximum", 999)

            if max_connections <= connection_threshold:
                monthly_cost = RDS_MONTHLY_PRICE.get(db_class, 200)
                findings.append({
                    **build_finding(
                        rule_id        = "COST-RDS-001",
                        severity       = "HIGH",
                        resource_type  = "AWS::RDS::DBInstance",
                        resource_id    = db_id,
                        title          = f"Idle RDS database — {db_id} ({db_class})",
                        description    = (
                            f"RDS {db_id} ({engine}, {db_class}) had max {max_connections:.0f} connections "
                            f"over {lookback_days} days (avg: {avg_connections:.1f}). "
                            f"Cost: ~${monthly_cost}/month."
                        ),
                        recommendation = (
                            "Stop or delete if not needed. Consider RDS scheduled start/stop for dev/test. "
                            f"Estimated saving: ${monthly_cost}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving":   monthly_cost,
                    "avg_connections":            round(avg_connections, 1),
                    "max_connections":            int(max_connections),
                    "current_instance_class":     db_class,
                    "recommended_instance_class": "",
                })

    except Exception as e:
        logger.error(f"Idle database check failed: {e}")
    return findings


def _check_low_cpu_databases(rds, cloudwatch, lookback_days, account_id, account_name):
    """COST-RDS-002: Databases with consistently low CPU — candidate for downsizing."""
    findings   = []
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    try:
        for db in rds.describe_db_instances()["DBInstances"]:
            db_id    = db["DBInstanceIdentifier"]
            db_class = db["DBInstanceClass"]
            engine   = db["Engine"]

            if any(s in db_class for s in ["micro", "small"]):
                continue

            metrics    = cloudwatch.get_metric_statistics(
                Namespace  = "AWS/RDS",
                MetricName = "CPUUtilization",
                Dimensions = [{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime  = start_time, EndTime = end_time,
                Period     = lookback_days * 86400,
                Statistics = ["Average", "Maximum"],
            )
            datapoints = metrics.get("Datapoints", [])
            if not datapoints:
                continue

            avg_cpu = datapoints[0].get("Average", 100)
            max_cpu = datapoints[0].get("Maximum", 100)

            if avg_cpu < 20 and max_cpu < 40:
                suggested      = DOWNSIZE_MAP.get(db_class)
                current_cost   = RDS_MONTHLY_PRICE.get(db_class, 200)
                suggested_cost = RDS_MONTHLY_PRICE.get(suggested, current_cost * 0.5) if suggested else current_cost * 0.5
                saving         = current_cost - suggested_cost

                if saving < 20:
                    continue

                findings.append({
                    **build_finding(
                        rule_id        = "COST-RDS-002",
                        severity       = "MEDIUM",
                        resource_type  = "AWS::RDS::DBInstance",
                        resource_id    = db_id,
                        title          = f"Oversized RDS instance — {db_id} ({db_class})",
                        description    = (
                            f"RDS {db_id} ({engine}) averaged {avg_cpu:.1f}% CPU (max: {max_cpu:.1f}%) "
                            f"over {lookback_days} days. Class {db_class} costs ~${current_cost}/month."
                        ),
                        recommendation = (
                            f"Consider downsizing to {suggested or 'a smaller class'}. "
                            f"Estimated saving: ${saving:.0f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving":   round(saving, 2),
                    "avg_cpu_percent":            round(avg_cpu, 2),
                    "max_cpu_percent":            round(max_cpu, 2),
                    "current_instance_class":     db_class,
                    "recommended_instance_class": suggested or "",
                })

    except Exception as e:
        logger.error(f"Low CPU database check failed: {e}")
    return findings


def _check_single_az_overprovisioned(rds, account_id, account_name):
    """COST-RDS-003: Large single-AZ instances."""
    findings = []
    try:
        for db in rds.describe_db_instances()["DBInstances"]:
            db_class = db["DBInstanceClass"]
            if db.get("MultiAZ"):
                continue
            monthly = RDS_MONTHLY_PRICE.get(db_class, 0)
            if monthly < 200:
                continue
            findings.append({
                **build_finding(
                    rule_id        = "COST-RDS-003",
                    severity       = "LOW",
                    resource_type  = "AWS::RDS::DBInstance",
                    resource_id    = db["DBInstanceIdentifier"],
                    title          = f"Large single-AZ RDS — {db['DBInstanceIdentifier']} ({db_class})",
                    description    = (
                        f"Large RDS instance ({db_class}, ${monthly}/month) is running without Multi-AZ. "
                        "If production — this is a risk. If dev/test — consider downsizing."
                    ),
                    recommendation = (
                        "For production: enable Multi-AZ. "
                        "For dev/test: downsize to a smaller class."
                    ),
                    auto_remediable = False,
                    account_id=account_id, account_name=account_name,
                ),
                "estimated_monthly_saving": round(monthly * 0.3, 2),
                "current_instance_class":   db_class,
                "recommended_instance_class": DOWNSIZE_MAP.get(db_class, ""),
            })

    except Exception as e:
        logger.error(f"Single AZ check failed: {e}")
    return findings


def _check_old_snapshots(rds, account_id, account_name):
    """COST-RDS-004: Manual RDS snapshots older than 90 days."""
    findings = []
    cutoff   = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        for snap in rds.describe_db_snapshots(SnapshotType="manual")["DBSnapshots"]:
            created = snap["SnapshotCreateTime"].replace(tzinfo=timezone.utc)
            if created < cutoff:
                age_days = (datetime.now(timezone.utc) - created).days
                size_gb  = snap.get("AllocatedStorage", 0)
                monthly  = size_gb * 0.095  # $0.095/GB-month

                findings.append({
                    **build_finding(
                        rule_id        = "COST-RDS-004",
                        severity       = "LOW",
                        resource_type  = "AWS::RDS::DBSnapshot",
                        resource_id    = snap["DBSnapshotIdentifier"],
                        title          = f"Old RDS snapshot — {snap['DBSnapshotIdentifier']} ({age_days} days)",
                        description    = (
                            f"Manual RDS snapshot {snap['DBSnapshotIdentifier']} is {age_days} days old "
                            f"({size_gb}GB). Cost: ~${monthly:.2f}/month."
                        ),
                        recommendation = (
                            "Delete if no longer needed for recovery. "
                            f"Estimated saving: ${monthly:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(monthly, 2),
                    "age_days":                 age_days,
                    "size_gb":                  size_gb,
                })

    except Exception as e:
        logger.error(f"Old snapshot check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    rds = session.client("rds", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    findings = []
    findings.extend(_check_idle_databases(rds, cloudwatch, 14, 1, account_id, ""))
    findings.extend(_check_low_cpu_databases(rds, cloudwatch, 14, account_id, ""))
    findings.extend(_check_single_az_overprovisioned(rds, account_id, ""))
    findings.extend(_check_old_snapshots(rds, account_id, ""))
    return findings
