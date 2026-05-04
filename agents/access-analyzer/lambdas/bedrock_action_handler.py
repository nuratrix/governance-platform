"""
IAM Access Analyzer Agent - Bedrock Action Handler
"""

import json
import logging
import os
import boto3
from utils import get_or_assume_session
from datetime import datetime, timezone

import access_analyzer_checker
import unused_permissions_checker

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
            "actionGroup":  event.get("actionGroup", ""),
            "apiPath":      api_path,
            "httpMethod":   event.get("httpMethod", "POST"),
            "httpStatusCode": 200,
            "responseBody": {"application/json": {"body": json.dumps(result)}}
        }
    }


def _route(api_path, params, session):
    account_id   = params.get("account_id", "")
    account_name = params.get("account_name", "")
    scan_id      = params.get("scan_id", f"scan-{int(datetime.now(timezone.utc).timestamp())}")
    base_event   = {"scan_id": scan_id, "account_id": account_id, "account_name": account_name}

    if api_path == "/checkaccessanalyzer":
        return access_analyzer_checker.lambda_handler(base_event, None, session=session)
    if api_path == "/checkunusedpermissions":
        return unused_permissions_checker.lambda_handler(base_event, None, session=session)
    if api_path == "/escalatetohuman":
        return _escalate(params)
    if api_path == "/saveiamreport":
        return _save_report(params, scan_id, account_id)
    return {"error": f"Unknown apiPath: {api_path}"}



def _escalate(params):
    sns   = boto3.client("sns")
    topic = os.environ.get("ALERT_TOPIC_ARN", "")
    if not topic:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}
    severity = params.get("severity", "HIGH")
    title    = params.get("title", "IAM Access Analyzer finding")
    message  = (
        f"[{severity}] {title}\n\n"
        f"Summary: {params.get('finding_summary', '')}\n"
        f"Resource: {params.get('resource_id', 'N/A')}\n\n"
        f"Recommended action: {params.get('recommended_action', '')}\n"
        f"Agent reasoning: {params.get('agent_reasoning', '')}"
    )
    try:
        resp = sns.publish(TopicArn=topic, Subject=f"[IAM/Access Analyzer] {title}", Message=message)
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
        "PK":                 f"REPORT#{scan_id}",
        "SK":                 "IAM_ACCESS_ANALYZER",
        "scan_id":            scan_id,
        "account_id":         account_id,
        "agent":              "access-analyzer",
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "total_findings":     params.get("total_findings", 0),
        "public_exposures":   params.get("public_exposures", 0),
        "unused_credentials": params.get("unused_credentials", 0),
        "executive_summary":  params.get("executive_summary", ""),
        "top_findings":       params.get("top_findings", ""),
        "escalations":        params.get("escalations", ""),
    }
    try:
        table.put_item(Item=item)
        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"DynamoDB put failed: {e}")
        return {"success": False, "message": str(e)}


def _parse_parameters(event):
    params = {}
    body = event.get("requestBody", {}).get("content", {}).get("application/json", {}).get("body")
    if body:
        try:
            params.update(json.loads(body) if isinstance(body, str) else body)
        except (json.JSONDecodeError, TypeError):
            pass
    for p in event.get("parameters", []):
        params[p["name"]] = p["value"]
    for key in ("account_id", "account_name", "scan_id"):
        if key in event.get("sessionAttributes", {}) and key not in params:
            params[key] = event["sessionAttributes"][key]
    return params
