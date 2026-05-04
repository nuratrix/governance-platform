"""
Cost Agent - Bedrock Action Handler — Multi-Account Edition
Extracts account_id from promptSessionAttributes and includes it
in all findings, notifications, and DynamoDB records.
Note: Cost Explorer is global (governance account only); EC2/RDS/S3 checkers
use cross-account sessions for scanning member accounts.
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

import ec2_cost_checker
import rds_cost_checker
import s3_cost_checker
import reservations_checker
from utils import get_or_assume_session
from teams_notifier import notify_teams, notify_teams_scan_complete
from slack_notifier import notify_slack, notify_slack_scan_complete

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns      = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
ce       = boto3.client("ce")   # Cost Explorer — governance account only

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

    # EC2 client scoped to target account for remediation
    ec2_session = session.client("ec2")

    api_path_normalized = "/" + api_path.strip().strip("/").lower()
    logger.info(f"Routing: {action_group} → {api_path_normalized} account={account_id}")

    try:
        result = _route(api_path_normalized, parameters, session, ec2_session, account_id, account_name)
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


def _route(api_path, params, session, ec2_client, account_id, account_name):
    scan_id = f"cost-{account_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    event_base = {"account_id": account_id, "account_name": account_name}

    if api_path == "/checkec2costs":
        raw = ec2_cost_checker.lambda_handler({
            **event_base, "scan_id": scan_id,
            "lookback_days": params.get("lookback_days", 14),
            "cpu_threshold": params.get("cpu_threshold", 5.0),
            "include_stopped": params.get("include_stopped", True),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/checkrdscosts":
        raw = rds_cost_checker.lambda_handler({
            **event_base, "scan_id": scan_id,
            "lookback_days": params.get("lookback_days", 14),
            "connection_threshold": params.get("connection_threshold", 1),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/checks3costs":
        raw = s3_cost_checker.lambda_handler({
            **event_base, "scan_id": scan_id,
            "min_size_gb": params.get("min_size_gb", 1.0),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/checkreservations":
        raw = reservations_checker.lambda_handler({
            **event_base, "scan_id": scan_id,
            "lookback_days": params.get("lookback_days", 30),
            "min_saving_threshold": params.get("min_saving_threshold", 50),
        }, None, session=session)
        return _enrich(raw)

    elif api_path == "/getcostexplorerdata":
        return _get_cost_explorer_data(params, account_id)

    elif api_path == "/stopec2instance":
        return _stop_ec2_instance(params, ec2_client, account_id)

    elif api_path == "/deleteebsvolume":
        return _delete_ebs_volume(params, ec2_client, account_id)

    elif api_path == "/escalatetohuman":
        return _escalate(params, account_id, account_name)

    elif api_path == "/savecostreport":
        return _save_report(params, account_id, account_name)

    else:
        return {"error": f"Unknown api_path: '{api_path}'", "success": False}


def _get_cost_explorer_data(params, account_id):
    """Cost Explorer is always queried from the governance account (global service)."""
    try:
        granularity  = params.get("granularity", "MONTHLY")
        lookback     = int(params.get("lookback_days", 30))
        group_by_key = params.get("group_by", "SERVICE")

        from datetime import timedelta
        end   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start = (datetime.now(timezone.utc) - timedelta(days=lookback)).strftime("%Y-%m-%d")

        kwargs = {
            "TimePeriod":  {"Start": start, "End": end},
            "Granularity": granularity,
            "Metrics":     ["UnblendedCost"],
            "GroupBy":     [{"Type": "DIMENSION", "Key": group_by_key}],
        }

        if account_id and account_id != GOVERNANCE_ACCOUNT_ID:
            kwargs["Filter"] = {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account_id]}}

        resp = ce.get_cost_and_usage(**kwargs)
        breakdown, total_cost = [], 0.0
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                total_cost += cost
                breakdown.append({"group": group["Keys"][0], "cost": round(cost, 2),
                                   "period": period["TimePeriod"]["Start"]})
        breakdown.sort(key=lambda x: x["cost"], reverse=True)
        return {"total_cost": round(total_cost, 2), "currency": "USD",
                "account_id": account_id, "breakdown": breakdown[:20]}
    except Exception as e:
        logger.error(f"Cost Explorer failed: {e}")
        return {"error": str(e), "total_cost": 0, "breakdown": []}


def _stop_ec2_instance(params, ec2_client, account_id):
    instance_id = params.get("instance_id")
    reason      = params.get("reason", "Stopped by Cost Agent")
    approved_by = params.get("approved_by")

    if not instance_id:
        return {"success": False, "message": "instance_id is required"}
    if not approved_by:
        return {"success": False,
                "message": "approved_by is required. Call escalate_to_human first."}

    try:
        desc           = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance       = desc["Reservations"][0]["Instances"][0]
        previous_state = instance["State"]["Name"]
        instance_type  = instance["InstanceType"]

        if previous_state == "stopped":
            return {"success": True, "message": f"{instance_id} is already stopped",
                    "previous_state": previous_state, "new_state": "stopped"}

        ec2_client.stop_instances(InstanceIds=[instance_id])
        _audit_log("STOP_EC2", f"[{account_id}] Stopped {instance_id} ({instance_type}). Reason: {reason}. Approved: {approved_by}")
        return {"success": True, "message": f"{instance_id} is stopping",
                "previous_state": previous_state, "new_state": "stopping"}
    except Exception as e:
        logger.error(f"Stop instance failed: {e}")
        return {"success": False, "message": str(e)}


def _delete_ebs_volume(params, ec2_client, account_id):
    volume_id             = params.get("volume_id")
    reason                = params.get("reason", "Deleted by Cost Agent")
    create_snapshot_first = params.get("create_snapshot_first", True)

    if not volume_id:
        return {"success": False, "message": "volume_id is required"}
    try:
        vol = ec2_client.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
        if vol["State"] == "in-use":
            return {"success": False, "message": f"{volume_id} is attached. Will not delete."}

        size_gb, vol_type = vol["Size"], vol["VolumeType"]
        snapshot_id = None
        if create_snapshot_first and size_gb >= 20:
            snap = ec2_client.create_snapshot(VolumeId=volume_id,
                                              Description=f"Safety snapshot — {reason}")
            snapshot_id = snap["SnapshotId"]
            waiter = ec2_client.get_waiter("snapshot_completed")
            waiter.wait(SnapshotIds=[snapshot_id], WaiterConfig={"MaxAttempts": 20, "Delay": 15})

        ec2_client.delete_volume(VolumeId=volume_id)
        _audit_log("DELETE_EBS", f"[{account_id}] Deleted {volume_id} ({size_gb}GB). Snapshot: {snapshot_id}")
        return {"success": True, "message": f"{volume_id} deleted",
                "snapshot_id": snapshot_id or "none", "volume_size_gb": size_gb}
    except Exception as e:
        logger.error(f"Delete volume failed: {e}")
        return {"success": False, "message": str(e)}


def _escalate(params, account_id, account_name):
    if not ALERT_TOPIC_ARN:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}
    severity = params.get("severity", "MEDIUM")
    saving   = params.get("estimated_monthly_saving", 0)
    try:
        resp = sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[{severity}][{account_name or account_id}] Cost Agent: {params.get('title')} — ${saving:.0f}/month",
            Message  = json.dumps({**params, "account_id": account_id, "account_name": account_name}, indent=2),
        )
        notify_teams(
            title=params.get("title",""), severity=severity,
            description=params.get("incident_summary", params.get("situation","")),
            resource_id=params.get("affected_resources",""),
            recommendation=params.get("recommended_action",""),
            agent_name="governance-cost-agent",
            actions_taken=params.get("actions_taken",""), scan_id=params.get("scan_id",""),
            account_id=account_id, account_name=account_name,
        )
        notify_slack(
            title=params.get("title",""), severity=severity,
            description=params.get("incident_summary", params.get("situation","")),
            resource_id=params.get("affected_resources",""),
            recommendation=params.get("recommended_action",""),
            agent_name="governance-cost-agent",
            actions_taken=params.get("actions_taken",""), scan_id=params.get("scan_id",""),
            account_id=account_id, account_name=account_name,
        )
        _audit_log("ESCALATION", f"[{account_id}] {severity}: {params.get('title')} — ${saving:.0f}/month")
        return {"success": True, "message_id": resp.get("MessageId", "")}
    except Exception as e:
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
                "source": source, "event_type": event_type, "severity": severity,
                "scan_id": scan_id, "summary": summary,
                "critical_count": critical_count, "high_count": high_count,
                "requires_action": critical_count > 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "account_id": account_id, "account_name": account_name,
                "payload": payload or {},
            }),
        )
    except Exception as e:
        logger.error(f"Failed to notify orchestrator: {e}")


def _save_report(params, account_id, account_name):
    try:
        scan_id        = params.get("scan_id", f"cost-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
        critical_count = sum(1 for f in params.get("critical_findings", ""))
        high_count     = sum(1 for f in params.get("high_findings", ""))
        saving         = float(params.get("total_potential_saving", 0))
        table          = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":                scan_id,
            "timestamp":              datetime.now(timezone.utc).isoformat(),
            "agent":                  "cost-agent",
            "total_potential_saving": str(saving),
            "executive_summary":      params.get("executive_summary", ""),
            "top_recommendations":    params.get("top_recommendations", ""),
            "actions_taken":          params.get("actions_taken", ""),
            "account_id":             account_id,
            "account_name":           account_name,
            "ttl":                    int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })

        _notify_orchestrator(
            source="governance-cost-agent", event_type="scan_complete",
            severity="HIGH" if saving > 500 else "LOW",
            scan_id=scan_id,
            summary=params.get("executive_summary", f"Cost scan complete. Potential saving: ${saving:.0f}/month"),
            account_id=account_id, account_name=account_name,
            payload={"total_potential_saving": saving},
        )

        notify_teams_scan_complete(
            agent_name="governance-cost-agent",
            severity="CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count=critical_count, high_count=high_count,
            summary=params.get("executive_summary", ""), scan_id=scan_id,
            account_id=account_id, account_name=account_name,
        )
        notify_slack_scan_complete(
            agent_name="governance-cost-agent",
            severity="CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count=critical_count, high_count=high_count,
            summary=params.get("executive_summary", ""), scan_id=scan_id,
            account_id=account_id, account_name=account_name,
        )

        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"Save report failed: {e}")
        return {"success": False, "message": str(e)}


def _enrich(raw):
    findings     = raw.get("findings", [])
    total_saving = sum(f.get("estimated_monthly_saving", 0) for f in findings)
    return {**raw, "summary": {**raw.get("summary", {}),
        "total_findings": len(findings),
        "total_potential_saving": round(total_saving, 2)}}


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


def _audit_log(action_type, detail):
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":     f"action-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "agent":       "cost-agent",
            "action_type": action_type,
            "detail":      detail,
            "ttl":         int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
        })
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")
