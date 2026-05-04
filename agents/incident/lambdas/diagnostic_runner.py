"""
Incident Agent - Diagnostic Runner — Multi-Account Edition
Runs diagnostic checks on affected resources including recent deployments,
dependency health, and resource metrics to help identify root cause.
Rules: INC-DIAG-001 through INC-DIAG-004
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id       = event.get("scan_id", "manual")
    resource_id   = event.get("resource_id", "")
    resource_type = event.get("resource_type", "")
    lookback_hours = int(event.get("lookback_hours", 24))
    account_id    = event.get("account_id", "")
    account_name  = event.get("account_name", "")
    logger.info(f"Diagnostic run — account={account_id} resource={resource_id} lookback={lookback_hours}h")

    s = session or boto3
    cloudwatch = s.client("cloudwatch")
    ecs        = s.client("ecs")
    ec2        = s.client("ec2")
    rds        = s.client("rds")
    cloudtrail = s.client("cloudtrail")
    elbv2      = s.client("elbv2")

    findings = []
    findings += _check_recent_deployments(cloudtrail, lookback_hours, account_id, account_name)
    findings += _check_ecs_service_health(ecs, account_id, account_name)
    findings += _check_rds_health(rds, account_id, account_name)
    findings += _get_resource_metrics(cloudwatch, resource_id, resource_type, lookback_hours, account_id, account_name)

    logger.info(f"Diagnostic runner complete. {len(findings)} findings.")
    return {
        "findings":       findings,
        "scan_id":        scan_id,
        "resource_id":    resource_id,
        "lookback_hours": lookback_hours,
        "account_id":     account_id,
        "account_name":   account_name,
        "summary": {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
        }
    }


def _check_recent_deployments(cloudtrail, lookback_hours, account_id, account_name):
    """INC-DIAG-001: CloudTrail events for recent deployments that may correlate with incident."""
    findings = []
    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    deployment_events = [
        "UpdateService",          "CreateService",
        "RegisterTaskDefinition", "DeregisterTaskDefinition",
        "UpdateFunctionCode",     "UpdateFunctionConfiguration",
        "CreateDeployment",       "UpdateStack",
        "ExecuteChangeSet",
    ]

    try:
        resp = cloudtrail.lookup_events(
            StartTime  = start_time,
            EndTime    = datetime.now(timezone.utc),
            LookupAttributes=[{
                "AttributeKey":   "EventName",
                "AttributeValue": deployment_events[0],
            }],
            MaxResults = 50,
        )
        events_found = resp.get("Events", [])

        for event_name in deployment_events[1:5]:
            try:
                extra = cloudtrail.lookup_events(
                    StartTime  = start_time,
                    EndTime    = datetime.now(timezone.utc),
                    LookupAttributes=[{
                        "AttributeKey":   "EventName",
                        "AttributeValue": event_name,
                    }],
                    MaxResults = 10,
                )
                events_found += extra.get("Events", [])
            except Exception:
                pass

        if events_found:
            event_summaries = []
            for ev in events_found[:10]:
                event_summaries.append(
                    f"{ev.get('EventName')} by {ev.get('Username', 'unknown')} "
                    f"at {ev.get('EventTime', '').strftime('%H:%M:%S') if ev.get('EventTime') else 'unknown'}"
                )

            findings.append(build_finding(
                rule_id        = "INC-DIAG-001",
                severity       = "HIGH",
                resource_type  = "AWS::CloudTrail::Event",
                resource_id    = "recent-deployments",
                title          = f"{len(events_found)} deployment events in last {lookback_hours}h",
                description    = (
                    f"Found {len(events_found)} deployment-related events in the last "
                    f"{lookback_hours} hours that may correlate with the incident. "
                    f"Events: {'; '.join(event_summaries[:5])}"
                ),
                recommendation = (
                    "Review these recent changes and determine if they correlate with "
                    "the incident timeline. Consider rolling back the most recent deployment."
                ),
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    except Exception as e:
        logger.error(f"Recent deployments check failed: {e}")
    return findings


def _check_ecs_service_health(ecs, account_id, account_name):
    """INC-DIAG-002: ECS services with unhealthy task counts."""
    findings = []
    try:
        clusters = ecs.list_clusters()["clusterArns"]
        for cluster_arn in clusters:
            services = ecs.list_services(cluster=cluster_arn)["serviceArns"]
            if not services:
                continue

            described = ecs.describe_services(
                cluster  = cluster_arn,
                services = services[:10],
            )["services"]

            for svc in described:
                name    = svc["serviceName"]
                desired = svc["desiredCount"]
                running = svc["runningCount"]
                pending = svc["pendingCount"]

                if desired == 0:
                    continue

                if running < desired:
                    pct_running = running / desired * 100
                    severity    = "CRITICAL" if pct_running < 50 else "HIGH"

                    events     = svc.get("events", [])[:3]
                    event_msgs = [e.get("message", "") for e in events]

                    findings.append(build_finding(
                        rule_id        = "INC-DIAG-002",
                        severity       = severity,
                        resource_type  = "AWS::ECS::Service",
                        resource_id    = name,
                        title          = f"ECS service degraded — {name} ({running}/{desired} tasks running)",
                        description    = (
                            f"ECS service {name} has {running} of {desired} desired tasks running "
                            f"with {pending} pending. "
                            f"Recent events: {'; '.join(event_msgs[:2])}"
                        ),
                        recommendation = (
                            "Check task stopped reasons in ECS console. "
                            "Inspect CloudWatch Logs for the task container. "
                            "Verify task memory and CPU limits are sufficient."
                        ),
                        auto_remediable = True,
                        account_id      = account_id,
                        account_name    = account_name,
                    ))
    except Exception as e:
        logger.error(f"ECS health check failed: {e}")
    return findings


def _check_rds_health(rds, account_id, account_name):
    """INC-DIAG-003: RDS instances not in available state."""
    findings = []
    try:
        instances = rds.describe_db_instances()["DBInstances"]
        for db in instances:
            status   = db["DBInstanceStatus"]
            db_id    = db["DBInstanceIdentifier"]
            db_class = db["DBInstanceClass"]

            if status == "available":
                continue

            severity = "CRITICAL" if status in ["failed", "incompatible-restore"] else "HIGH"

            findings.append(build_finding(
                rule_id        = "INC-DIAG-003",
                severity       = severity,
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db_id,
                title          = f"RDS instance not available — {db_id} (status: {status})",
                description    = (
                    f"RDS instance {db_id} ({db_class}) is in '{status}' state. "
                    "Database may be unavailable to applications."
                ),
                recommendation = (
                    "Check RDS events in the AWS console for this instance. "
                    "If status is 'failed', consider restoring from latest snapshot. "
                    "Check for pending maintenance or parameter group changes."
                ),
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    except Exception as e:
        logger.error(f"RDS health check failed: {e}")
    return findings


def _get_resource_metrics(cloudwatch, resource_id, resource_type, lookback_hours, account_id, account_name):
    """INC-DIAG-004: Fetch key metrics for the affected resource."""
    findings = []
    if not resource_id or not resource_type:
        return findings

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    try:
        if "EC2::Instance" in resource_type or resource_id.startswith("i-"):
            metrics = _get_ec2_metrics(cloudwatch, resource_id, start_time, end_time)
            if metrics:
                findings.append(build_finding(
                    rule_id         = "INC-DIAG-004",
                    severity        = "MEDIUM",
                    resource_type   = "AWS::EC2::Instance",
                    resource_id     = resource_id,
                    title           = f"Resource metrics for {resource_id}",
                    description     = metrics,
                    recommendation  = "Use these metrics to identify the root cause pattern.",
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))

        elif "RDS" in resource_type:
            metrics = _get_rds_metrics(cloudwatch, resource_id, start_time, end_time)
            if metrics:
                findings.append(build_finding(
                    rule_id         = "INC-DIAG-004",
                    severity        = "MEDIUM",
                    resource_type   = "AWS::RDS::DBInstance",
                    resource_id     = resource_id,
                    title           = f"Database metrics for {resource_id}",
                    description     = metrics,
                    recommendation  = "Review CPU, connections and freeable memory trends.",
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))

    except Exception as e:
        logger.error(f"Resource metrics check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    cloudtrail = session.client("cloudtrail", region_name=region)
    ecs = session.client("ecs", region_name=region)
    rds = session.client("rds", region_name=region)
    findings = []
    findings.extend(_check_recent_deployments(cloudtrail, 24, account_id, ""))
    findings.extend(_check_ecs_service_health(ecs, account_id, ""))
    findings.extend(_check_rds_health(rds, account_id, ""))
    return findings


def _get_ec2_metrics(cloudwatch, instance_id, start_time, end_time):
    try:
        period  = int((end_time - start_time).total_seconds())
        results = {}
        for metric in ["CPUUtilization", "NetworkIn", "NetworkOut"]:
            pts = cloudwatch.get_metric_statistics(
                Namespace   = "AWS/EC2",
                MetricName  = metric,
                Dimensions  = [{"Name": "InstanceId", "Value": instance_id}],
                StartTime   = start_time,
                EndTime     = end_time,
                Period      = period,
                Statistics  = ["Average", "Maximum"],
            ).get("Datapoints", [])
            if pts:
                results[metric] = {
                    "avg": round(pts[0].get("Average", 0), 1),
                    "max": round(pts[0].get("Maximum", 0), 1),
                }
        if results:
            parts = [f"{k}: avg={v['avg']} max={v['max']}" for k, v in results.items()]
            return f"Metrics for {instance_id}: {', '.join(parts)}"
    except Exception as e:
        logger.warning(f"EC2 metrics failed: {e}")
    return None


def _get_rds_metrics(cloudwatch, db_id, start_time, end_time):
    try:
        period  = int((end_time - start_time).total_seconds())
        results = {}
        for metric in ["CPUUtilization", "DatabaseConnections", "FreeableMemory"]:
            pts = cloudwatch.get_metric_statistics(
                Namespace   = "AWS/RDS",
                MetricName  = metric,
                Dimensions  = [{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime   = start_time,
                EndTime     = end_time,
                Period      = period,
                Statistics  = ["Average"],
            ).get("Datapoints", [])
            if pts:
                results[metric] = round(pts[0].get("Average", 0), 1)
        if results:
            parts = [f"{k}={v}" for k, v in results.items()]
            return f"Metrics for {db_id}: {', '.join(parts)}"
    except Exception as e:
        logger.warning(f"RDS metrics failed: {e}")
    return None
