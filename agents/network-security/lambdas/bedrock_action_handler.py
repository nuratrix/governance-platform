"""
Network Security Agent - Bedrock Action Handler
Routes all Bedrock Agent tool calls to the appropriate Lambda checker
or performs inline actions (escalation, report saving).
"""

import json
import logging
import os
import boto3
from utils import get_or_assume_session
from datetime import datetime, timezone
from teams_notifier import notify_teams_scan_complete

import vpc_checker
import nacl_checker
import dns_checker

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info(f"Action handler event: {json.dumps(event)}")

    api_path   = event.get("apiPath", "")
    parameters = _parse_parameters(event)
    session    = get_or_assume_session(
        parameters.get("account_id", ""),
        os.environ.get("GOVERNANCE_ACCOUNT_ID", "")
    )

    try:
        result = _route(api_path, parameters, session)
    except Exception as e:
        logger.error(f"Route error for {api_path}: {e}", exc_info=True)
        result = {"error": str(e)}

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", ""),
            "apiPath":     api_path,
            "httpMethod":  event.get("httpMethod", "POST"),
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(result)
                }
            }
        }
    }


# ─── Router ───────────────────────────────────────────────────────────────────

def _route(api_path, params, session):
    account_id   = params.get("account_id", "")
    account_name = params.get("account_name", "")
    scan_id      = params.get("scan_id", f"scan-{int(datetime.now(timezone.utc).timestamp())}")

    base_event = {
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
    }

    if api_path == "/checkvpc":
        return vpc_checker.lambda_handler(base_event, None, session=session)

    if api_path == "/checksecuritygroups":
        return nacl_checker.lambda_handler(base_event, None, session=session)

    if api_path == "/checkdns":
        return dns_checker.lambda_handler(base_event, None, session=session)

    if api_path == "/escalatetohuman":
        return _escalate(params)

    if api_path == "/savenetworkreport":
        return _save_report(params, scan_id, account_id)

    return {"error": f"Unknown apiPath: {api_path}"}


# ─── Cross-account session ────────────────────────────────────────────────────


# ─── Inline actions ───────────────────────────────────────────────────────────

def _escalate(params):
    sns   = boto3.client("sns")
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}

    severity = params.get("severity", "HIGH")
    title    = params.get("title", "Network security finding")
    message  = (
        f"[{severity}] {title}\n\n"
        f"Summary: {params.get('finding_summary', '')}\n"
        f"Affected resource: {params.get('resource_id', 'N/A')}\n"
        f"Region: {params.get('region', 'N/A')}\n\n"
        f"Recommended action: {params.get('recommended_action', '')}\n"
        f"Agent reasoning: {params.get('agent_reasoning', '')}"
    )

    try:
        resp = sns.publish(TopicArn=topic, Subject=f"[Network Security] {title}", Message=message)
        return {"success": True, "message_id": resp["MessageId"], "escalated_at": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")
        return {"success": False, "message": str(e)}


def _save_report(params, scan_id, account_id):
    table_name = os.environ.get("FINDINGS_TABLE", "")
    if not table_name:
        return {"success": False, "message": "FINDINGS_TABLE not configured"}

    dynamodb = boto3.resource("dynamodb")
    table    = dynamodb.Table(table_name)

    item = {
        "scan_id":           scan_id,
        "account_id":        account_id,
        "account_name":      params.get("account_name", ""),
        "agent":             "governance-network-security-agent",
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "total_findings":    params.get("total_findings", 0),
        "critical_findings": params.get("critical_findings", 0),
        "high_findings":     params.get("high_findings", 0),
        "executive_summary": params.get("executive_summary", ""),
        "top_findings":      params.get("top_findings", ""),
        "actions_taken":     params.get("actions_taken", ""),
        "escalations":       params.get("escalations", ""),
        "ttl":               int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
    }

    try:
        table.put_item(Item=item)
        critical_count = int(params.get("critical_findings", 0))
        high_count     = int(params.get("high_findings", 0))
        notify_teams_scan_complete(
            agent_name     = "governance-network-security-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("executive_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = params.get("account_name", ""),
        )
        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"DynamoDB put failed: {e}")
        return {"success": False, "message": str(e)}


# ─── Parameter parsing ────────────────────────────────────────────────────────

def _parse_parameters(event):
    params = {}
    content = event.get("requestBody", {}).get("content", {}).get("application/json", {})
    # Bedrock Agents send request body fields as a "properties" array
    for prop in content.get("properties", []):
        params[prop["name"]] = prop.get("value")
    # Fallback: direct Lambda invocations may send a raw "body" string
    if not params:
        body = content.get("body")
        if body:
            try:
                params.update(json.loads(body) if isinstance(body, str) else body)
            except (json.JSONDecodeError, TypeError):
                pass

    for p in event.get("parameters", []):
        params[p["name"]] = p["value"]

    session_attrs = event.get("sessionAttributes", {})
    for key in ("account_id", "account_name", "scan_id"):
        if key in session_attrs and key not in params:
            params[key] = session_attrs[key]

    return params
