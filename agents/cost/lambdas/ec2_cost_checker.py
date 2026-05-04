"""
Cost Agent - EC2 Cost Checker (Multi-Account Edition)
Identifies idle instances, stopped instances, unattached EBS volumes,
and unused Elastic IPs.
Rules: COST-EC2-001 through COST-EC2-006
Cross-account: all clients created from the injected session.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Approximate on-demand hourly prices USD
EC2_HOURLY_PRICE = {
    "t3.micro":    0.0104, "t3.small":   0.0208, "t3.medium":  0.0416,
    "t3.large":    0.0832, "t3.xlarge":  0.1664, "t3.2xlarge": 0.3328,
    "m5.large":    0.096,  "m5.xlarge":  0.192,  "m5.2xlarge": 0.384,
    "m5.4xlarge":  0.768,  "m5.8xlarge": 1.536,
    "c5.large":    0.085,  "c5.xlarge":  0.170,  "c5.2xlarge": 0.340,
    "r5.large":    0.126,  "r5.xlarge":  0.252,  "r5.2xlarge": 0.504,
}

EBS_GB_MONTH = {
    "gp3": 0.08, "gp2": 0.10, "io1": 0.125,
    "io2": 0.125, "st1": 0.045, "sc1": 0.015,
}

ELASTIC_IP_MONTH = 3.60


def lambda_handler(event, context, session=None):
    scan_id          = event.get("scan_id", "manual")
    account_id       = event.get("account_id", "")
    account_name     = event.get("account_name", "")
    lookback         = int(event.get("lookback_days", 14))
    cpu_threshold    = float(event.get("cpu_threshold", 5.0))
    include_stopped  = event.get("include_stopped", True)

    logger.info(f"EC2 cost check for {account_id} — lookback={lookback}d cpu_threshold={cpu_threshold}%")

    findings = []
    for region in get_scan_regions(session):
        s          = session or boto3
        ec2        = s.client("ec2", region_name=region)
        cloudwatch = s.client("cloudwatch", region_name=region)
        region_findings = []
        region_findings += _check_idle_instances(ec2, cloudwatch, lookback, cpu_threshold, account_id, account_name)
        region_findings += _check_stopped_instances(ec2, include_stopped, account_id, account_name)
        region_findings += _check_unattached_volumes(ec2, account_id, account_name)
        region_findings += _check_unused_elastic_ips(ec2, account_id, account_name)
        region_findings += _check_previous_gen_instances(ec2, account_id, account_name)
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
            "instances_scanned":      _count_instances(ec2),
            "idle_instances":         len([f for f in findings if "COST-EC2-001" in f.get("rule_id","")]),
            "stopped_instances":      len([f for f in findings if "COST-EC2-002" in f.get("rule_id","")]),
            "unattached_ebs_volumes": len([f for f in findings if "COST-EC2-003" in f.get("rule_id","")]),
        }
    }


def _count_instances(ec2):
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )
        return sum(len(r["Instances"]) for r in resp["Reservations"])
    except Exception:
        return 0


def _check_idle_instances(ec2, cloudwatch, lookback_days, cpu_threshold, account_id, account_name):
    """COST-EC2-001: Running instances with very low CPU utilisation."""
    findings = []
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=lookback_days)

    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        for reservation in resp["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id   = instance["InstanceId"]
                instance_type = instance["InstanceType"]
                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance_id
                )

                metrics = cloudwatch.get_metric_statistics(
                    Namespace  = "AWS/EC2",
                    MetricName = "CPUUtilization",
                    Dimensions = [{"Name": "InstanceId", "Value": instance_id}],
                    StartTime  = start_time,
                    EndTime    = end_time,
                    Period     = lookback_days * 86400,
                    Statistics = ["Average", "Maximum"],
                )

                datapoints = metrics.get("Datapoints", [])
                if not datapoints:
                    continue

                avg_cpu = datapoints[0].get("Average", 100)
                max_cpu = datapoints[0].get("Maximum", 100)

                if avg_cpu <= cpu_threshold:
                    hourly_price = EC2_HOURLY_PRICE.get(instance_type, 0.10)
                    monthly_cost = hourly_price * 24 * 30
                    saving       = monthly_cost * 0.9
                    severity     = "HIGH" if avg_cpu < 1.0 else "MEDIUM"

                    findings.append({
                        **build_finding(
                            rule_id        = "COST-EC2-001",
                            severity       = severity,
                            resource_type  = "AWS::EC2::Instance",
                            resource_id    = instance_id,
                            title          = f"Idle EC2 instance — {name} ({instance_type})",
                            description    = (
                                f"Instance {name} ({instance_id}) has averaged {avg_cpu:.1f}% CPU "
                                f"over the last {lookback_days} days (max: {max_cpu:.1f}%). "
                                f"Current cost: ~${monthly_cost:.2f}/month."
                            ),
                            recommendation = (
                                f"Stop this instance if it is not needed. "
                                f"Estimated saving: ${saving:.2f}/month."
                            ),
                            auto_remediable = False,
                            account_id=account_id, account_name=account_name,
                        ),
                        "estimated_monthly_saving": round(saving, 2),
                        "avg_cpu_percent":          round(avg_cpu, 2),
                        "max_cpu_percent":          round(max_cpu, 2),
                        "instance_type":            instance_type,
                        "monthly_cost":             round(monthly_cost, 2),
                    })

    except Exception as e:
        logger.error(f"Idle instance check failed: {e}")
    return findings


def _check_stopped_instances(ec2, include_stopped, account_id, account_name):
    """COST-EC2-002: Stopped instances still accruing EBS storage costs."""
    if not include_stopped:
        return []

    findings = []
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        )
        for reservation in resp["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id   = instance["InstanceId"]
                instance_type = instance["InstanceType"]
                name = next(
                    (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                    instance_id
                )

                ebs_cost  = 0.0
                volume_ids = [
                    bdm["Ebs"]["VolumeId"]
                    for bdm in instance.get("BlockDeviceMappings", [])
                    if "Ebs" in bdm
                ]
                for vol_id in volume_ids:
                    try:
                        vol      = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
                        rate     = EBS_GB_MONTH.get(vol["VolumeType"], 0.08)
                        ebs_cost += vol["Size"] * rate
                    except Exception:
                        ebs_cost += 8.0

                state_reason = instance.get("StateTransitionReason", "")
                age_days = 0
                if "(" in state_reason and ")" in state_reason:
                    try:
                        date_str   = state_reason.split("(")[1].split(")")[0]
                        stopped_at = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                        age_days   = (datetime.now(timezone.utc) - stopped_at).days
                    except Exception:
                        pass

                severity = "HIGH" if age_days > 30 else "MEDIUM" if age_days > 7 else "LOW"

                findings.append({
                    **build_finding(
                        rule_id        = "COST-EC2-002",
                        severity       = severity,
                        resource_type  = "AWS::EC2::Instance",
                        resource_id    = instance_id,
                        title          = f"Stopped instance with EBS charges — {name} ({instance_type})",
                        description    = (
                            f"Instance {name} ({instance_id}) has been stopped "
                            f"{'for ~' + str(age_days) + ' days' if age_days else 'for an unknown period'}. "
                            f"EBS storage is still accruing ~${ebs_cost:.2f}/month."
                        ),
                        recommendation = (
                            "Terminate this instance if it is no longer needed. "
                            f"Estimated saving: ${ebs_cost:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(ebs_cost, 2),
                    "days_stopped":             age_days,
                    "instance_type":            instance_type,
                    "ebs_monthly_cost":         round(ebs_cost, 2),
                })

    except Exception as e:
        logger.error(f"Stopped instance check failed: {e}")
    return findings


def _check_unattached_volumes(ec2, account_id, account_name):
    """COST-EC2-003: EBS volumes not attached to any instance."""
    findings = []
    try:
        resp = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )
        for vol in resp["Volumes"]:
            size     = vol["Size"]
            vol_type = vol["VolumeType"]
            rate     = EBS_GB_MONTH.get(vol_type, 0.08)
            monthly  = size * rate
            age_days = (datetime.now(timezone.utc) - vol["CreateTime"].replace(tzinfo=timezone.utc)).days
            severity = "HIGH" if age_days > 30 else "LOW"

            findings.append({
                **build_finding(
                    rule_id        = "COST-EC2-003",
                    severity       = severity,
                    resource_type  = "AWS::EC2::Volume",
                    resource_id    = vol["VolumeId"],
                    title          = f"Unattached EBS volume — {vol['VolumeId']} ({size}GB {vol_type})",
                    description    = (
                        f"Volume {vol['VolumeId']} ({size}GB, {vol_type}) has been unattached "
                        f"for ~{age_days} days. Cost: ~${monthly:.2f}/month."
                    ),
                    recommendation = (
                        f"Delete this volume if it is no longer needed. "
                        f"Consider creating a snapshot first. Estimated saving: ${monthly:.2f}/month."
                    ),
                    auto_remediable = age_days > 30,
                    account_id=account_id, account_name=account_name,
                ),
                "estimated_monthly_saving": round(monthly, 2),
                "volume_size_gb":           size,
                "volume_type":              vol_type,
                "days_unattached":          age_days,
            })

    except Exception as e:
        logger.error(f"Unattached volume check failed: {e}")
    return findings


def _check_unused_elastic_ips(ec2, account_id, account_name):
    """COST-EC2-004: Elastic IPs not associated with any resource."""
    findings = []
    try:
        for addr in ec2.describe_addresses()["Addresses"]:
            if "AssociationId" not in addr:
                findings.append({
                    **build_finding(
                        rule_id        = "COST-EC2-004",
                        severity       = "LOW",
                        resource_type  = "AWS::EC2::EIP",
                        resource_id    = addr["AllocationId"],
                        title          = f"Unused Elastic IP — {addr['PublicIp']}",
                        description    = (
                            f"Elastic IP {addr['PublicIp']} is allocated but not associated. "
                            f"Cost: ~${ELASTIC_IP_MONTH:.2f}/month."
                        ),
                        recommendation = f"Release this Elastic IP. Estimated saving: ${ELASTIC_IP_MONTH:.2f}/month.",
                        auto_remediable = True,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": ELASTIC_IP_MONTH,
                    "public_ip":               addr["PublicIp"],
                })

    except Exception as e:
        logger.error(f"Elastic IP check failed: {e}")
    return findings


def _check_previous_gen_instances(ec2, account_id, account_name):
    """COST-EC2-005: Instances using previous generation instance types."""
    PREV_GEN = {"m1", "m2", "m3", "c1", "c3", "r3", "t1", "i2", "hs1", "g2"}
    findings = []
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
        for reservation in resp["Reservations"]:
            for instance in reservation["Instances"]:
                instance_type = instance["InstanceType"]
                family        = instance_type.split(".")[0]

                if family in PREV_GEN:
                    name    = next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        instance["InstanceId"]
                    )
                    hourly  = EC2_HOURLY_PRICE.get(instance_type, 0.10)
                    monthly = hourly * 24 * 30
                    saving  = monthly * 0.15

                    findings.append({
                        **build_finding(
                            rule_id        = "COST-EC2-005",
                            severity       = "LOW",
                            resource_type  = "AWS::EC2::Instance",
                            resource_id    = instance["InstanceId"],
                            title          = f"Previous generation instance type — {name} ({instance_type})",
                            description    = (
                                f"Instance {name} is using {instance_type}, a previous generation type."
                            ),
                            recommendation = (
                                f"Migrate to a current generation equivalent. "
                                f"Estimated saving: ~${saving:.2f}/month with improved performance."
                            ),
                            auto_remediable = False,
                            account_id=account_id, account_name=account_name,
                        ),
                        "estimated_monthly_saving": round(saving, 2),
                        "instance_type":            instance_type,
                        "current_gen_suggestion":   _suggest_current_gen(family),
                    })

    except Exception as e:
        logger.error(f"Previous gen check failed: {e}")
    return findings


def _suggest_current_gen(family):
    return {"m1":"m5","m2":"r5","m3":"m5","c1":"c5","c3":"c5","r3":"r5","t1":"t3","i2":"i3","g2":"g4dn"}.get(family,"m5")


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    findings = []
    findings.extend(_check_idle_instances(ec2, cloudwatch, 14, 5.0, account_id, ""))
    findings.extend(_check_stopped_instances(ec2, True, account_id, ""))
    findings.extend(_check_unattached_volumes(ec2, account_id, ""))
    findings.extend(_check_unused_elastic_ips(ec2, account_id, ""))
    findings.extend(_check_previous_gen_instances(ec2, account_id, ""))
    return findings
