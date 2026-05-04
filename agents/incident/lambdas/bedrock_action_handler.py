"""
Incident Agent - Bedrock Action Handler — Multi-Account Edition
Extracts account_id from promptSessionAttributes and includes it
in all findings, notifications, and DynamoDB records.
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

import incident_detector
import diagnostic_runner
import auto_healer
from utils import get_or_assume_session
from teams_notifier import notify_teams, notify_teams_scan_complete
from slack_notifier import notify_slack, notify_slack_scan_complete

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns      = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

FINDINGS_TABLE         = os.environ.get("FINDINGS_TABLE", "governance-platform-findings")
ALERT_TOPIC_ARN        = os.environ.get("ALERT_TOPIC_ARN", "")
ORCHESTRATOR_TOPIC_ARN = os.environ.get("ORCHESTRATOR_TOPIC_ARN", "")
GOVERNANCE_ACCOUNT_ID  = os.environ.get("GOVERNANCE_ACCOUNT_ID", "")


def lambda_handler(event, context):
    logger.info(f"RAW EVENT: {json.dumps(event)}")

    action_group = event.get("actionGroup", "")
    api_path     = event.get("apiPath", "")
    http_method  = event.get("httpMethod", "POST")
    parameters   = _extract_parameters(event)

    # ── Multi-Account: pull account context ───────────────────────────────
    session_attrs = event.get("sessionAttributes", {})
    prompt_attrs  = event.get("promptSessionAttributes", {})
    account_id    = prompt_attrs.get("account_id", session_attrs.get("account_id", GOVERNANCE_ACCOUNT_ID))
    account_name  = prompt_attrs.get("account_name", session_attrs.get("account_name", ""))
    reader_role   = prompt_attrs.get("reader_role", "governance-platform-reader")

    try:
        session = get_or_assume_session(account_id, GOVERNANCE_ACCOUNT_ID, role_name=reader_role)
    except Exception as e:
        logger.error(f"Could not assume role for account {account_id}: {e}")
        session = boto3.Session()

    api_path_normalized = "/" + api_path.strip().strip("/").lower()
    logger.info(f"Routing: {action_group} → {api_path_normalized} account={account_id}")

    try:
        result = _route(api_path_normalized, parameters, session, account_id, account_name)
    except Exception as e:
        logger.error(f"Handler error: {e}", exc_info=True)
        result = {"error": str(e), "success": False}

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup":    action_group,
            "apiPath":        api_path,
            "httpMethod":     http_method,
            "httpStatusCode": 200,
            "responseBody": {"application/json": {"body": json.dumps(result)}}
        }
    }


def _route(api_path, params, session, account_id, account_name):
    scan_id    = f"incident-{account_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    event_base = {"account_id": account_id, "account_name": account_name, "scan_id": scan_id}

    # ── Detection tools ───────────────────────────────────────────────────────

    if api_path == "/detectincidents":
        raw = incident_detector.lambda_handler({
            **event_base,
            "lookback_minutes": params.get("lookback_minutes", 60),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/rundiagnostics":
        raw = diagnostic_runner.lambda_handler({
            **event_base,
            "resource_id":    params.get("resource_id", ""),
            "resource_type":  params.get("resource_type", ""),
            "lookback_hours": params.get("lookback_hours", 4),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/getcloudwatchmetrics":
        return _get_cloudwatch_metrics(params, session)

    elif api_path == "/getrecentlogs":
        return _get_recent_logs(params, session)

    # ── Remediation tools ─────────────────────────────────────────────────────

    elif api_path == "/restartecsservice":
        return auto_healer.lambda_handler({
            **event_base,
            "action":      "restart_ecs_tasks",
            "cluster":     params.get("cluster"),
            "service":     params.get("service"),
            "approved_by": params.get("approved_by", ""),
            "reason":      params.get("reason", ""),
        }, None, session=session)

    elif api_path == "/rebootec2instance":
        return auto_healer.lambda_handler({
            **event_base,
            "action":      "reboot_ec2",
            "resource_id": params.get("instance_id"),
            "approved_by": params.get("approved_by", ""),
            "reason":      params.get("reason", ""),
        }, None, session=session)

    elif api_path == "/scaleasg":
        return auto_healer.lambda_handler({
            **event_base,
            "action":           "scale_asg",
            "resource_id":      params.get("asg_name"),
            "desired_capacity": params.get("desired_capacity", 0),
            "approved_by":      params.get("approved_by", ""),
            "reason":           params.get("reason", ""),
        }, None, session=session)

    # ── Reporting tools ───────────────────────────────────────────────────────

    elif api_path == "/escalatetohuman":
        return _escalate(params, account_id, account_name)

    elif api_path == "/saveincidentreport":
        return _save_report(params, account_id, account_name)

    else:
        logger.error(f"No route matched: '{api_path}'")
        return {"error": f"Unknown api_path: '{api_path}'", "success": False}


# ── Tool Implementations ──────────────────────────────────────────────────────

def _get_cloudwatch_metrics(params, session):
    """Retrieve specific CloudWatch metrics from the target account."""
    from datetime import timedelta
    cw = session.client("cloudwatch")

    namespace      = params.get("namespace", "AWS/EC2")
    metric_name    = params.get("metric_name", "CPUUtilization")
    resource_id    = params.get("resource_id", "")
    dimension_name = params.get("dimension_name", "InstanceId")
    lookback_hours = int(params.get("lookback_hours", 4))

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    try:
        pts = cw.get_metric_statistics(
            Namespace   = namespace,
            MetricName  = metric_name,
            Dimensions  = [{"Name": dimension_name, "Value": resource_id}],
            StartTime   = start_time,
            EndTime     = end_time,
            Period      = 300,
            Statistics  = ["Average", "Maximum", "Minimum"],
        )

        datapoints = sorted(pts.get("Datapoints", []), key=lambda x: x["Timestamp"])
        formatted  = [{
            "timestamp": d["Timestamp"].isoformat(),
            "average":   round(d.get("Average", 0), 2),
            "maximum":   round(d.get("Maximum", 0), 2),
            "minimum":   round(d.get("Minimum", 0), 2),
        } for d in datapoints]

        return {
            "namespace":   namespace,
            "metric_name": metric_name,
            "resource_id": resource_id,
            "datapoints":  formatted,
            "count":       len(formatted),
        }
    except Exception as e:
        logger.error(f"CloudWatch metrics failed: {e}")
        return {"error": str(e), "datapoints": []}


def _get_recent_logs(params, session):
    """Retrieve recent log events from a CloudWatch Log Group in the target account."""
    cw_logs     = session.client("logs")
    lg_name     = params.get("log_group_name", "")
    pattern     = params.get("filter_pattern", "ERROR")
    lookback_min = int(params.get("lookback_minutes", 30))
    limit        = int(params.get("limit", 20))

    if not lg_name:
        return {"error": "log_group_name is required", "events": []}

    from datetime import timedelta
    start_ms = int(
        (datetime.now(timezone.utc) - timedelta(minutes=lookback_min)).timestamp() * 1000
    )

    try:
        resp   = cw_logs.filter_log_events(
            logGroupName  = lg_name,
            startTime     = start_ms,
            filterPattern = pattern,
            limit         = limit,
        )
        events = [{
            "timestamp": datetime.fromtimestamp(
                e["timestamp"] / 1000, tz=timezone.utc
            ).isoformat(),
            "message": e.get("message", "")[:500],
        } for e in resp.get("events", [])]

        return {
            "log_group_name": lg_name,
            "filter_pattern": pattern,
            "events":         events,
            "count":          len(events),
        }
    except Exception as e:
        logger.error(f"Log retrieval failed: {e}")
        return {"error": str(e), "events": []}


def _escalate(params, account_id, account_name):
    """Send an incident alert to the team via SNS, Teams, and Slack."""
    if not ALERT_TOPIC_ARN:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}

    severity = params.get("severity", "HIGH")
    title    = params.get("title", "Incident Alert")

    message = {
        "source":             "IncidentAgent",
        "severity":           severity,
        "title":              title,
        "incident_summary":   params.get("incident_summary", ""),
        "affected_resources": params.get("affected_resources", ""),
        "root_cause_theory":  params.get("root_cause_theory", ""),
        "recommended_action": params.get("recommended_action", ""),
        "actions_taken":      params.get("actions_taken", ""),
        "escalated_at":       datetime.now(timezone.utc).isoformat(),
        "account_id":         account_id,
        "account_name":       account_name,
    }

    try:
        resp = sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[{severity}][{account_name or account_id}] Incident Agent: {title}",
            Message  = json.dumps(message, indent=2),
        )

        notify_teams(
            title          = title,
            severity       = severity,
            description    = params.get("incident_summary", params.get("situation", "")),
            resource_id    = params.get("affected_resources", ""),
            recommendation = params.get("recommended_action", ""),
            agent_name     = "governance-incident-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_slack(
            title          = title,
            severity       = severity,
            description    = params.get("incident_summary", params.get("situation", "")),
            resource_id    = params.get("affected_resources", ""),
            recommendation = params.get("recommended_action", ""),
            agent_name     = "governance-incident-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        _notify_orchestrator(
            source         = "incident-agent",
            event_type     = "scan_complete",
            severity       = severity,
            scan_id        = params.get("scan_id", ""),
            summary        = params.get("incident_summary", "Incident scan complete"),
            critical_count = 1 if severity == "CRITICAL" else 0,
            account_id     = account_id,
            account_name   = account_name,
            payload        = {"title": title},
        )

        return {
            "success":      True,
            "message_id":   resp.get("MessageId", ""),
            "escalated_at": message["escalated_at"],
        }
    except Exception as e:
        logger.error(f"Escalation failed: {e}")
        return {"success": False, "message": str(e)}


def _notify_orchestrator(source, event_type, severity, scan_id,
                         summary, critical_count=0, high_count=0,
                         account_id="", account_name="", payload=None):
    if not ORCHESTRATOR_TOPIC_ARN:
        return
    try:
        sns.publish(
            TopicArn = ORCHESTRATOR_TOPIC_ARN,
            Subject  = f"[{severity}][{account_name or account_id}] {source} scan complete",
            Message  = json.dumps({
                "source":          source,
                "event_type":      event_type,
                "severity":        severity,
                "scan_id":         scan_id,
                "summary":         summary,
                "critical_count":  critical_count,
                "high_count":      high_count,
                "requires_action": critical_count > 0,
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "account_id":      account_id,
                "account_name":    account_name,
                "payload":         payload or {},
            }),
        )
    except Exception as e:
        logger.error(f"Failed to notify orchestrator: {e}")


def _save_report(params, account_id, account_name):
    """Persist the incident report to DynamoDB."""
    try:
        scan_id        = params.get("scan_id", f"incident-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
        critical_count = 1 if params.get("severity") == "CRITICAL" else 0
        high_count     = 1 if params.get("severity") == "HIGH"     else 0

        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":            scan_id,
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "agent":              "incident-agent",
            "severity":           params.get("severity", ""),
            "title":              params.get("title", ""),
            "incident_summary":   params.get("incident_summary", ""),
            "root_cause":         params.get("root_cause", ""),
            "affected_resources": params.get("affected_resources", ""),
            "timeline":           params.get("timeline", ""),
            "actions_taken":      params.get("actions_taken", ""),
            "resolution":         params.get("resolution", ""),
            "prevention":         params.get("prevention", ""),
            "duration_minutes":   str(params.get("duration_minutes", 0)),
            "account_id":         account_id,
            "account_name":       account_name,
            "ttl":                int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
        })

        _notify_orchestrator(
            source         = "governance-incident-agent",
            event_type     = "scan_complete",
            severity       = params.get("severity", ""),
            scan_id        = scan_id,
            summary        = params.get("incident_summary", "Incident scan complete"),
            critical_count = critical_count,
            high_count     = high_count,
            account_id     = account_id,
            account_name   = account_name,
            payload        = {"title": params.get("title", "")},
        )

        notify_teams_scan_complete(
            agent_name     = "governance-incident-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("incident_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = account_name,
        )
        notify_slack_scan_complete(
            agent_name     = "governance-incident-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("incident_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = account_name,
        )

        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"Save report failed: {e}")
        return {"success": False, "message": str(e)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _enrich(raw):
    findings = raw.get("findings", [])
    return {
        **raw,
        "summary": {
            **raw.get("summary", {}),
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
        }
    }


def _extract_parameters(event):
    params = {}
    try:
        body    = event.get("requestBody", {})
        content = body.get("content", {}).get("application/json", {})
        for prop in content.get("properties", []):
            params[prop["name"]] = prop.get("value")
        for param in event.get("parameters", []):
            params[param["name"]] = param.get("value")
    except Exception as e:
        logger.warning(f"Parameter extraction error: {e}")
    return params
