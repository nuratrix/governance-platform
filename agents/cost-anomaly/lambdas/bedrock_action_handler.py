"""
Cost Anomaly Agent - Bedrock Action Handler
Routes all Bedrock Agent tool calls to the appropriate Lambda checker
or performs inline actions (escalation, report saving).
"""

import json
import logging
import os
import boto3
from utils import get_or_assume_session
from datetime import datetime, timezone

import anomaly_detector
import root_cause_analyzer
import utils

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
    days_back    = int(params.get("days_back", 7))

    base_event = {
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
        "days_back":    days_back,
    }

    if api_path == "/checkanomalies":
        return anomaly_detector.lambda_handler(base_event, None)

    if api_path == "/analyzerootcauses":
        return root_cause_analyzer.lambda_handler(
            {**base_event, "compare_days": int(params.get("compare_days", 14))},
            None
        )

    if api_path == "/escalatetohuman":
        return _escalate(params)

    if api_path == "/saveanomalyreport":
        return _save_report(params, scan_id, account_id)

    return {"error": f"Unknown apiPath: {api_path}"}



# ─── Inline actions ───────────────────────────────────────────────────────────

def _escalate(params):
    sns   = boto3.client("sns")
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}

    severity = params.get("severity", "HIGH")
    title    = params.get("title", "Cost anomaly escalation")
    message  = (
        f"[{severity}] {title}\n\n"
        f"Summary: {params.get('finding_summary', '')}\n"
        f"Anomaly ID: {params.get('anomaly_id', 'N/A')}\n"
        f"Total unexpected spend: ${params.get('total_impact_usd', 0):.2f}\n"
        f"Root causes: {params.get('root_causes', 'Not yet determined')}\n\n"
        f"Recommended action: {params.get('recommended_action', '')}\n"
        f"Agent reasoning: {params.get('agent_reasoning', '')}"
    )

    try:
        resp = sns.publish(TopicArn=topic, Subject=f"[Cost Anomaly] {title}", Message=message)
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
        "PK":               f"REPORT#{scan_id}",
        "SK":               "COST_ANOMALY",
        "scan_id":          scan_id,
        "account_id":       account_id,
        "agent":            "cost-anomaly",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "total_anomalies":           params.get("total_anomalies", 0),
        "total_unexpected_spend_usd": params.get("total_unexpected_spend_usd", 0),
        "executive_summary":         params.get("executive_summary", ""),
        "top_findings":              params.get("top_findings", ""),
        "actions_taken":             params.get("actions_taken", ""),
        "escalations":               params.get("escalations", ""),
    }

    try:
        table.put_item(Item=item)
        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"DynamoDB put failed: {e}")
        return {"success": False, "message": str(e)}


# ─── Parameter parsing ────────────────────────────────────────────────────────

def _parse_parameters(event):
    """Extract parameters from Bedrock's various input formats."""
    params = {}

    # Format 1: requestBody (API schema format)
    body = event.get("requestBody", {}).get("content", {}).get("application/json", {}).get("body")
    if body:
        try:
            params.update(json.loads(body) if isinstance(body, str) else body)
        except (json.JSONDecodeError, TypeError):
            pass

    # Format 2: flat parameters list
    for p in event.get("parameters", []):
        params[p["name"]] = p["value"]

    # Format 3: sessionAttributes
    session_attrs = event.get("sessionAttributes", {})
    for key in ("account_id", "account_name", "scan_id"):
        if key in session_attrs and key not in params:
            params[key] = session_attrs[key]

    return params
