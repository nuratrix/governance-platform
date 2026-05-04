"""
Infrastructure Agent - Bedrock Action Handler — Multi-Account Edition
Extracts account_id from promptSessionAttributes and includes it
in all findings, notifications, and DynamoDB records.
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

import ec2_checker
import rds_checker
import network_checker
import tagging_checker
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
    scan_id    = f"infra-{account_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    event_base = {"scan_id": scan_id, "account_id": account_id, "account_name": account_name}

    if api_path == "/checkec2":
        return _enrich(ec2_checker.lambda_handler(event_base, None, session=session))

    elif api_path == "/checkrds":
        return _enrich(rds_checker.lambda_handler(event_base, None, session=session))

    elif api_path == "/checknetwork":
        return _enrich(network_checker.lambda_handler(event_base, None, session=session))

    elif api_path == "/checktagging":
        return _enrich(tagging_checker.lambda_handler(event_base, None, session=session))

    elif api_path == "/escalatetohuman":
        return _escalate(params, account_id, account_name)

    elif api_path == "/saveinfrareport":
        return _save_report(params, account_id, account_name)

    else:
        logger.error(f"No route matched: '{api_path}'")
        return {"error": f"Unknown api_path: '{api_path}'", "success": False}


def _enrich(raw):
    findings = raw.get("findings", [])
    return {
        **raw,
        "summary": {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low":      sum(1 for f in findings if f.get("severity") == "LOW"),
        }
    }


def _escalate(params, account_id, account_name):
    if not ALERT_TOPIC_ARN:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}
    try:
        resp = sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[{params.get('severity')}][{account_name or account_id}] Infra Agent: {params.get('title')}",
            Message  = json.dumps({**params, "account_id": account_id, "account_name": account_name}, indent=2),
        )

        notify_teams(
            title          = params.get("title", ""),
            severity       = params.get("severity", "HIGH"),
            description    = params.get("incident_summary", params.get("situation", "")),
            resource_id    = params.get("affected_resources", ""),
            recommendation = params.get("recommended_action", ""),
            agent_name     = "governance-infrastructure-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_slack(
            title          = params.get("title", ""),
            severity       = params.get("severity", "HIGH"),
            description    = params.get("incident_summary", params.get("situation", "")),
            resource_id    = params.get("affected_resources", ""),
            recommendation = params.get("recommended_action", ""),
            agent_name     = "governance-infrastructure-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        return {"success": True, "message_id": resp["MessageId"]}
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
    try:
        scan_id        = params.get("scan_id", f"infra-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
        critical_count = sum(1 for f in params.get("critical_findings", ""))
        high_count     = sum(1 for f in params.get("high_findings", ""))

        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":           scan_id,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "agent":             "infrastructure-agent",
            "risk_score":        str(params.get("risk_score", 0)),
            "executive_summary": params.get("executive_summary", ""),
            "actions_taken":     params.get("actions_taken", ""),
            "recommendations":   params.get("recommendations", ""),
            "account_id":        account_id,
            "account_name":      account_name,
            "ttl":               int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })

        _notify_orchestrator(
            source         = "governance-infrastructure-agent",
            event_type     = "scan_complete",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            scan_id        = scan_id,
            summary        = params.get("executive_summary", "Infrastructure scan complete"),
            critical_count = critical_count,
            high_count     = high_count,
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_teams_scan_complete(
            agent_name     = "governance-infrastructure-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("executive_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_slack_scan_complete(
            agent_name     = "governance-infrastructure-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("executive_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = account_name,
        )

        return {"success": True, "scan_id": scan_id}
    except Exception as e:
        logger.error(f"Save report failed: {e}")
        return {"success": False, "message": str(e)}


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
