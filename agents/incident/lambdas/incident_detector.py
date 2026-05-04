"""
Incident Agent - Incident Detector — Multi-Account Edition
Monitors CloudWatch alarms, load balancer health, Lambda errors,
EC2 status checks and log error patterns to detect active incidents.
Rules: INC-DET-001 through INC-DET-005
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    lookback_min = int(event.get("lookback_minutes", 60))
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"Incident detection — account={account_id} lookback={lookback_min}min")

    s = session or boto3
    cloudwatch = s.client("cloudwatch")
    logs       = s.client("logs")
    ec2        = s.client("ec2")
    elbv2      = s.client("elbv2")

    findings = []
    findings += _check_alarming_alarms(cloudwatch, account_id, account_name)
    findings += _check_unhealthy_targets(elbv2, account_id, account_name)
    findings += _check_lambda_error_spikes(cloudwatch, lookback_min, account_id, account_name)
    findings += _check_ec2_status_checks(ec2, account_id, account_name)
    findings += _check_log_error_patterns(logs, lookback_min, account_id, account_name)

    logger.info(f"Incident detector complete. {len(findings)} findings.")
    return {
        "findings":         findings,
        "scan_id":          scan_id,
        "lookback_minutes": lookback_min,
        "account_id":       account_id,
        "account_name":     account_name,
        "summary": {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        }
    }


def _check_alarming_alarms(cloudwatch, account_id, account_name):
    """INC-DET-001: CloudWatch alarms currently in ALARM state."""
    findings = []
    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for page in paginator.paginate(StateValue="ALARM"):
            for alarm in page.get("MetricAlarms", []):
                name        = alarm["AlarmName"]
                description = alarm.get("AlarmDescription", "No description")
                metric      = alarm.get("MetricName", "unknown")
                namespace   = alarm.get("Namespace", "unknown")
                state_since = alarm.get("StateUpdatedTimestamp")
                age_minutes = 0

                if state_since:
                    age_minutes = int(
                        (datetime.now(timezone.utc) - state_since.replace(tzinfo=timezone.utc))
                        .total_seconds() / 60
                    )

                severity = (
                    "CRITICAL" if age_minutes > 30
                    else "HIGH"  if age_minutes > 10
                    else "MEDIUM"
                )

                findings.append(build_finding(
                    rule_id        = "INC-DET-001",
                    severity       = severity,
                    resource_type  = "AWS::CloudWatch::Alarm",
                    resource_id    = name,
                    title          = f"CloudWatch alarm firing — {name}",
                    description    = (
                        f"Alarm '{name}' has been in ALARM state for {age_minutes} minutes. "
                        f"Metric: {namespace}/{metric}. Description: {description}"
                    ),
                    recommendation = (
                        "Investigate the root cause. Check CloudWatch metrics and correlate "
                        "with recent deployments or configuration changes."
                    ),
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    except Exception as e:
        logger.error(f"Alarm check failed: {e}")
    return findings


def _check_unhealthy_targets(elbv2, account_id, account_name):
    """INC-DET-002: Load balancer targets in unhealthy state."""
    findings = []
    try:
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        for lb in lbs:
            lb_name = lb["LoadBalancerName"]
            tgs     = elbv2.describe_target_groups(
                LoadBalancerArn=lb["LoadBalancerArn"]
            )["TargetGroups"]

            for tg in tgs:
                health    = elbv2.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"]
                )["TargetHealthDescriptions"]
                unhealthy = [t for t in health if t["TargetHealth"]["State"] == "unhealthy"]
                total     = len(health)
                if not unhealthy:
                    continue

                pct      = len(unhealthy) / total * 100 if total else 100
                severity = "CRITICAL" if pct >= 50 else "HIGH"
                reasons  = list({t["TargetHealth"].get("Reason", "Unknown") for t in unhealthy})
                ids      = [t["Target"]["Id"] for t in unhealthy[:5]]

                findings.append(build_finding(
                    rule_id        = "INC-DET-002",
                    severity       = severity,
                    resource_type  = "AWS::ElasticLoadBalancingV2::TargetGroup",
                    resource_id    = tg["TargetGroupArn"],
                    title          = f"{len(unhealthy)}/{total} targets unhealthy — {lb_name}/{tg['TargetGroupName']}",
                    description    = (
                        f"{len(unhealthy)} of {total} targets are unhealthy ({pct:.0f}%). "
                        f"Affected: {', '.join(ids)}. Reasons: {', '.join(reasons)}."
                    ),
                    recommendation = (
                        "Check application logs on unhealthy targets. Verify the health check "
                        "path returns HTTP 200. Check security groups allow ALB traffic."
                    ),
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    except Exception as e:
        logger.error(f"Target health check failed: {e}")
    return findings


def _check_lambda_error_spikes(cloudwatch, lookback_minutes, account_id, account_name):
    """INC-DET-003: Lambda functions with elevated error rates."""
    findings  = []
    end_time  = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=lookback_minutes)

    try:
        metrics   = cloudwatch.list_metrics(Namespace="AWS/Lambda", MetricName="Errors")
        processed = set()
        for metric in metrics.get("Metrics", []):
            fn_name = next(
                (d["Value"] for d in metric.get("Dimensions", []) if d["Name"] == "FunctionName"),
                None
            )
            if not fn_name or fn_name in processed:
                continue
            processed.add(fn_name)

            kwargs = dict(StartTime=start_time, EndTime=end_time,
                          Period=lookback_minutes * 60, Statistics=["Sum"],
                          Dimensions=[{"Name": "FunctionName", "Value": fn_name}])

            err_pts  = cloudwatch.get_metric_statistics(Namespace="AWS/Lambda", MetricName="Errors", **kwargs)
            inv_pts  = cloudwatch.get_metric_statistics(Namespace="AWS/Lambda", MetricName="Invocations", **kwargs)
            err_cnt  = sum(d["Sum"] for d in err_pts.get("Datapoints", []))
            inv_cnt  = sum(d["Sum"] for d in inv_pts.get("Datapoints", []))

            if err_cnt == 0:
                continue
            error_rate = (err_cnt / inv_cnt * 100) if inv_cnt > 0 else 100
            if error_rate < 5:
                continue

            severity = "CRITICAL" if error_rate >= 50 else "HIGH" if error_rate >= 20 else "MEDIUM"
            findings.append(build_finding(
                rule_id        = "INC-DET-003",
                severity       = severity,
                resource_type  = "AWS::Lambda::Function",
                resource_id    = fn_name,
                title          = f"Lambda error spike — {fn_name} ({error_rate:.0f}% error rate)",
                description    = (
                    f"Function {fn_name} had {err_cnt:.0f} errors from {inv_cnt:.0f} invocations "
                    f"in the last {lookback_minutes} minutes ({error_rate:.1f}% error rate)."
                ),
                recommendation = (
                    "Check CloudWatch Logs for this function. Look for recent deployments. "
                    "Use X-Ray traces to identify the failing code path."
                ),
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    except Exception as e:
        logger.error(f"Lambda error check failed: {e}")
    return findings


def _check_ec2_status_checks(ec2, account_id, account_name):
    """INC-DET-004: EC2 instances failing status checks."""
    findings = []
    try:
        paginator = ec2.get_paginator("describe_instance_status")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
            IncludeAllInstances=False
        ):
            for status in page.get("InstanceStatuses", []):
                sys_status  = status["SystemStatus"]["Status"]
                inst_status = status["InstanceStatus"]["Status"]
                if sys_status == "ok" and inst_status == "ok":
                    continue

                failing  = []
                if sys_status  != "ok": failing.append(f"system: {sys_status}")
                if inst_status != "ok": failing.append(f"instance: {inst_status}")
                severity = "CRITICAL" if sys_status == "impaired" else "HIGH"

                findings.append(build_finding(
                    rule_id        = "INC-DET-004",
                    severity       = severity,
                    resource_type  = "AWS::EC2::Instance",
                    resource_id    = status["InstanceId"],
                    title          = f"EC2 status check failing — {status['InstanceId']}",
                    description    = (
                        f"Instance {status['InstanceId']} is failing: {', '.join(failing)}. "
                        "May be unresponsive or experiencing hardware issues."
                    ),
                    recommendation = (
                        "Check instance console output. If system status is impaired, "
                        "stop and start to move to healthy hardware."
                    ),
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    except Exception as e:
        logger.error(f"EC2 status check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    cloudwatch = session.client("cloudwatch", region_name=region)
    logs = session.client("logs", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    elbv2 = session.client("elbv2", region_name=region)
    findings = []
    findings.extend(_check_alarming_alarms(cloudwatch, account_id, ""))
    findings.extend(_check_unhealthy_targets(elbv2, account_id, ""))
    findings.extend(_check_lambda_error_spikes(cloudwatch, 60, account_id, ""))
    findings.extend(_check_ec2_status_checks(ec2, account_id, ""))
    findings.extend(_check_log_error_patterns(logs, 60, account_id, ""))
    return findings


def _check_log_error_patterns(logs, lookback_minutes, account_id, account_name):
    """INC-DET-005: CloudWatch Log Groups with high error volume."""
    findings = []
    start_ms = int(
        (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).timestamp() * 1000
    )
    patterns   = [
        {"pattern": "FATAL",     "severity": "CRITICAL", "threshold": 1},
        {"pattern": "ERROR",     "severity": "HIGH",      "threshold": 10},
        {"pattern": "Exception", "severity": "MEDIUM",    "threshold": 20},
    ]
    skip_words = ["CloudTrail", "flow-logs", "vpc-flow", "aws-controltower", "access-logs"]

    try:
        log_groups = logs.describe_log_groups(limit=50)["logGroups"]
        for lg in log_groups:
            lg_name = lg["logGroupName"]
            if any(s in lg_name for s in skip_words):
                continue
            for cfg in patterns:
                try:
                    events = logs.filter_log_events(
                        logGroupName  = lg_name,
                        startTime     = start_ms,
                        filterPattern = cfg["pattern"],
                        limit         = 25,
                    ).get("events", [])
                    if len(events) < cfg["threshold"]:
                        continue
                    sample = events[0].get("message", "")[:300] if events else ""
                    findings.append(build_finding(
                        rule_id        = "INC-DET-005",
                        severity       = cfg["severity"],
                        resource_type  = "AWS::Logs::LogGroup",
                        resource_id    = lg_name,
                        title          = f"High {cfg['pattern']} rate in logs — {lg_name}",
                        description    = (
                            f"Found {len(events)}+ '{cfg['pattern']}' events in {lg_name} "
                            f"in the last {lookback_minutes} minutes. Sample: {sample}"
                        ),
                        recommendation = (
                            f"Investigate the {cfg['pattern']} messages in {lg_name}. "
                            "Correlate with other alerts and recent deployments."
                        ),
                        auto_remediable = False,
                        account_id      = account_id,
                        account_name    = account_name,
                    ))
                    break  # One finding per log group
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Log pattern check failed: {e}")
    return findings
