"""
Bedrock Agent - Action Group Handler — Multi-Account Edition
Extracts account_id from promptSessionAttributes and passes a cross-account
boto3 session to every checker so scans run in the correct member account.
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

from build_finding import build_finding
from utils import get_or_assume_session
import iam_checker
import s3_checker
import sg_checker
import cloudtrail_checker
import guardduty_checker
import kms_secrets_checker
import eks_checker
import ecr_checker
import lambda_security_checker
import rds_security_checker
import ssm_checker
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
    logger.info(f"Bedrock Agent invocation: {json.dumps(event)}")

    action_group = event.get("actionGroup", "")
    api_path     = event.get("apiPath", "")
    parameters   = _extract_parameters(event)

    # ── Multi-Account: pull account context from session ──────────────────────
    session_attrs = event.get("sessionAttributes", {})
    prompt_attrs  = event.get("promptSessionAttributes", {})
    account_id    = prompt_attrs.get("account_id", session_attrs.get("account_id", GOVERNANCE_ACCOUNT_ID))
    account_name  = prompt_attrs.get("account_name", session_attrs.get("account_name", ""))
    reader_role   = prompt_attrs.get("reader_role", "governance-platform-reader")

    logger.info(f"Routing: actionGroup={action_group}, apiPath={api_path}, account={account_id}")

    # Build a boto3 session scoped to the target account
    try:
        session = get_or_assume_session(
            account_id            = account_id,
            governance_account_id = GOVERNANCE_ACCOUNT_ID,
            role_name             = reader_role,
        )
    except Exception as e:
        logger.error(f"Could not assume role for account {account_id}: {e}")
        session = boto3.Session()   # fall back to default session

    try:
        result = _route(action_group, api_path, parameters, session,
                        account_id, account_name)
    except Exception as e:
        logger.error(f"Action handler error: {e}")
        result = {"error": str(e), "success": False}

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "apiPath":     api_path,
            "httpMethod":  event.get("httpMethod", "POST"),
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {"body": json.dumps(result)}
            }
        }
    }


def _route(action_group, api_path, params, session, account_id, account_name):
    # ── IAM ───────────────────────────────────────────────────────────────────
    if api_path == "/checkiam":
        raw = iam_checker.lambda_handler(
            {"scan_id": _scan_id(), "focus_area": params.get("focus_area"),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── S3 ────────────────────────────────────────────────────────────────────
    elif api_path == "/checks3":
        raw = s3_checker.lambda_handler(
            {"scan_id": _scan_id(), "bucket_name": params.get("bucket_name"),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── Security Groups ───────────────────────────────────────────────────────
    elif api_path == "/checksecuritygroups":
        raw = sg_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "security_group_id": params.get("security_group_id"),
             "vpc_id": params.get("vpc_id"),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── GuardDuty ─────────────────────────────────────────────────────────────
    elif api_path == "/checkguardduty":
        raw = guardduty_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "severity_filter": params.get("severity_filter", "MEDIUM"),
             "days_back": int(params.get("days_back", 7)),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── CloudTrail config audit ───────────────────────────────────────────────
    elif api_path == "/checkcloudtrail":
        raw = cloudtrail_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── CloudTrail event lookup ───────────────────────────────────────────────
    elif api_path == "/getcloudtrailevents":
        return _get_cloudtrail_events(
            lookup_type  = params.get("lookup_type", "username"),
            lookup_value = params.get("lookup_value", ""),
            hours_back   = int(params.get("hours_back", 24)),
            session      = session,
        )

    # ── KMS / Secrets Manager ─────────────────────────────────────────────────
    elif api_path == "/checkkms":
        raw = kms_secrets_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── Remediation: remove SG rule ───────────────────────────────────────────
    elif api_path == "/remediatesecuritygroup":
        return _remediate_sg(params, session, account_id)

    # ── Remediation: disable IAM key ──────────────────────────────────────────
    elif api_path == "/disableiamaccesskey":
        return _disable_access_key(params, session, account_id)

    # ── EKS ───────────────────────────────────────────────────────────────────
    elif api_path == "/checkeks":
        raw = eks_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── ECR ───────────────────────────────────────────────────────────────────
    elif api_path == "/checkecr":
        raw = ecr_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── Lambda Security ───────────────────────────────────────────────────────
    elif api_path == "/checklambdasecurity":
        raw = lambda_security_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── RDS Security ──────────────────────────────────────────────────────────
    elif api_path == "/checkrdssecurity":
        raw = rds_security_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── SSM ───────────────────────────────────────────────────────────────────
    elif api_path == "/checkssm":
        raw = ssm_checker.lambda_handler(
            {"scan_id": _scan_id(),
             "account_id": account_id, "account_name": account_name},
            None, session=session)
        return _enrich_response(raw)

    # ── Escalation ────────────────────────────────────────────────────────────
    elif api_path == "/escalatetohuman":
        return _escalate(params, account_id, account_name)

    # ── Save report ───────────────────────────────────────────────────────────
    elif api_path == "/savescanreport":
        return _save_report(params, account_id, account_name)

    else:
        return {"error": f"Unknown api_path: {api_path}"}


# ── Tool Implementations ──────────────────────────────────────────────────────

def _get_cloudtrail_events(lookup_type, lookup_value, hours_back, session):
    from datetime import timedelta
    try:
        ct_client  = session.client("cloudtrail")
        start_time = datetime.now(timezone.utc) - timedelta(hours=min(hours_back, 168))
        attribute_key_map = {
            "username":      "Username",
            "resource_name": "ResourceName",
            "event_name":    "EventName",
            "access_key_id": "AccessKeyId",
        }
        attribute_key = attribute_key_map.get(lookup_type, "Username")
        paginator = ct_client.get_paginator("lookup_events")
        events = []
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": attribute_key, "AttributeValue": lookup_value}],
            StartTime=start_time,
            PaginationConfig={"MaxItems": 100}
        ):
            for event in page.get("Events", []):
                events.append({
                    "event_time": event.get("EventTime", "").isoformat() if event.get("EventTime") else "",
                    "event_name": event.get("EventName", ""),
                    "username":   event.get("Username", ""),
                    "source_ip":  json.loads(event.get("CloudTrailEvent", "{}")).get("sourceIPAddress", ""),
                    "user_agent": json.loads(event.get("CloudTrailEvent", "{}")).get("userAgent", ""),
                    "resources":  [r.get("ResourceName", "") for r in event.get("Resources", [])],
                })
        return {"events": events, "total_events": len(events)}
    except Exception as e:
        logger.error(f"CloudTrail lookup failed: {e}")
        return {"error": str(e), "events": [], "total_events": 0}


def _remediate_sg(params, session, account_id):
    ec2_client = session.client("ec2")
    sg_id    = params.get("security_group_id")
    protocol = params.get("protocol", "tcp")
    cidr     = params.get("cidr", "0.0.0.0/0")
    reason   = params.get("reason", "Removed by Security Agent")

    try:
        ip_permission = {
            "IpProtocol": protocol,
            "FromPort":   int(params.get("from_port", 0)),
            "ToPort":     int(params.get("to_port", 65535)),
            "IpRanges":   [{"CidrIp": cidr, "Description": f"Removed: {reason}"}],
        }
        ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[ip_permission])
        _audit_log("REMEDIATION",
                   f"[{account_id}] Removed SG rule from {sg_id}: {protocol} {cidr} "
                   f"ports {params.get('from_port')}-{params.get('to_port')}. Reason: {reason}")
        return {
            "success":      True,
            "message":      f"Successfully removed rule from {sg_id}",
            "action_taken": f"Revoked {protocol} port {params.get('from_port')}-{params.get('to_port')} from {cidr} on {sg_id}",
        }
    except Exception as e:
        logger.error(f"SG remediation failed: {e}")
        return {"success": False, "message": str(e)}


def _disable_access_key(params, session, account_id):
    iam_client    = session.client("iam")
    username      = params.get("username")
    access_key_id = params.get("access_key_id")
    reason        = params.get("reason", "Disabled by Security Agent")

    try:
        iam_client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status="Inactive")
        _audit_log("REMEDIATION",
                   f"[{account_id}] Disabled access key {access_key_id} for user {username}. Reason: {reason}")
        return {
            "success":         True,
            "message":         f"Access key {access_key_id} for {username} has been disabled",
            "previous_status": "Active",
            "new_status":      "Inactive",
        }
    except Exception as e:
        logger.error(f"Key disable failed: {e}")
        return {"success": False, "message": str(e)}


def _escalate(params, account_id, account_name):
    if not ALERT_TOPIC_ARN:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}

    severity  = params.get("severity", "HIGH")
    title     = params.get("title", "Security Finding")
    summary   = params.get("finding_summary", "")
    action    = params.get("recommended_action", "")
    resources = params.get("affected_resources", [])
    reasoning = params.get("agent_reasoning", "")

    message = {
        "source":             "SecurityAgent-Bedrock",
        "severity":           severity,
        "title":              title,
        "finding_summary":    summary,
        "recommended_action": action,
        "affected_resources": resources,
        "agent_reasoning":    reasoning,
        "escalated_at":       datetime.now(timezone.utc).isoformat(),
        # ── Multi-Account ──────────────────────────────────────────────────
        "account_id":         account_id,
        "account_name":       account_name,
    }

    try:
        resp = sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[{severity}][{account_name or account_id}] Security Agent: {title}",
            Message  = json.dumps(message, indent=2),
        )

        notify_teams(
            title          = title,
            severity       = severity,
            description    = params.get("incident_summary", params.get("situation", summary)),
            resource_id    = str(resources),
            recommendation = action,
            agent_name     = "governance-security-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_slack(
            title          = title,
            severity       = severity,
            description    = params.get("incident_summary", params.get("situation", summary)),
            resource_id    = str(resources),
            recommendation = action,
            agent_name     = "governance-security-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        _audit_log("ESCALATION", f"[{account_id}] {severity}: {title} — {summary}")
        return {"success": True, "message_id": resp.get("MessageId", ""),
                "escalated_at": message["escalated_at"]}
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
                "source":         source,
                "event_type":     event_type,
                "severity":       severity,
                "scan_id":        scan_id,
                "summary":        summary,
                "critical_count": critical_count,
                "high_count":     high_count,
                "requires_action": critical_count > 0,
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "account_id":     account_id,
                "account_name":   account_name,
                "payload":        payload or {},
            }),
        )
        logger.info(f"Orchestrator notified: {source} {event_type} account={account_id}")
    except Exception as e:
        logger.error(f"Failed to notify orchestrator: {e}")


def _save_report(params, account_id, account_name):
    scan_id = params.get("scan_id", _scan_id())
    try:
        critical_count = sum(1 for f in params.get("critical_findings", ""))
        high_count     = sum(1 for f in params.get("high_findings", ""))
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":           scan_id,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "agent":             "governance-security-agent",
            "risk_score":        str(params.get("risk_score", 0)),
            "executive_summary": params.get("executive_summary", ""),
            "findings":          json.dumps(params.get("findings", [])),
            "actions_taken":     json.dumps(params.get("actions_taken", [])),
            "escalations":       json.dumps(params.get("escalations", [])),
            "recommendations":   json.dumps(params.get("recommendations", [])),
            "source":            "bedrock-agent",
            # ── Multi-Account ──────────────────────────────────────────────
            "account_id":        account_id,
            "account_name":      account_name,
            "ttl":               int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })

        _notify_orchestrator(
            source         = "governance-security-agent",
            event_type     = "scan_complete",
            severity       = "CRITICAL" if critical_count > 0 else "LOW",
            scan_id        = scan_id,
            summary        = params.get("executive_summary", "Security scan complete"),
            critical_count = critical_count,
            high_count     = high_count,
            account_id     = account_id,
            account_name   = account_name,
            payload        = {"risk_score": params.get("risk_score", 0)},
        )

        notify_teams_scan_complete(
            agent_name     = "governance-security-agent",
            severity       = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "LOW",
            critical_count = critical_count,
            high_count     = high_count,
            summary        = params.get("executive_summary", ""),
            scan_id        = scan_id,
            account_id     = account_id,
            account_name   = account_name,
        )

        notify_slack_scan_complete(
            agent_name     = "governance-security-agent",
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


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _enrich_response(raw):
    findings = raw.get("findings", [])
    summary  = {
        "total":    len(findings),
        "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
        "high":     len([f for f in findings if f.get("severity") == "HIGH"]),
        "medium":   len([f for f in findings if f.get("severity") == "MEDIUM"]),
        "low":      len([f for f in findings if f.get("severity") == "LOW"]),
    }
    return {**raw, "summary": summary}


def _scan_id():
    return f"agent-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"


def _audit_log(action_type, detail):
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":     f"action-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "detail":      detail,
            "source":      "bedrock-agent",
            "ttl":         int(datetime.now(timezone.utc).timestamp()) + (365 * 86400),
        })
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")
