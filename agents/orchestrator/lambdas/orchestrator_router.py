"""
Orchestrator Agent - SNS Router Lambda — Multi-Account Edition
Receives SNS notifications from all sub-agents, enriches them with
account context, then invokes the Bedrock Orchestrator Agent.

Message format published by each sub-agent's action handler:
{
    "source":          "security-agent" | "cost-agent" | ...,
    "event_type":      "scan_complete" | "critical_finding" | "remediation_taken",
    "severity":        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "scan_id":         "security-20250324-060012",
    "summary":         "Plain English description of what happened",
    "critical_count":  2,
    "high_count":      4,
    "requires_action": true,
    "account_id":      "123456789012",
    "account_name":    "production",
    "payload":         { ... agent-specific data ... }
}
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")
dynamodb              = boto3.resource("dynamodb")
sns                   = boto3.client("sns")

AGENT_ID        = os.environ["BEDROCK_AGENT_ID"]
AGENT_ALIAS_ID  = os.environ["BEDROCK_AGENT_ALIAS_ID"]
FINDINGS_TABLE  = os.environ.get("FINDINGS_TABLE", "governance-platform-findings")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")


def lambda_handler(event, context):
    """
    Entry point — triggered by SNS subscription on the orchestrator topic.
    Each sub-agent publishes here when it completes a scan or detects a
    critical finding.
    """
    for record in event.get("Records", []):
        try:
            raw     = record["Sns"]["Message"]
            message = json.loads(raw)
            _handle_agent_message(message)
        except Exception as e:
            logger.error(f"Failed to process SNS record: {e}", exc_info=True)


def _handle_agent_message(message):
    source       = message.get("source", "unknown")
    event_type   = message.get("event_type", "unknown")
    severity     = message.get("severity", "LOW")
    scan_id      = message.get("scan_id", "unknown")
    summary      = message.get("summary", "")
    critical     = int(message.get("critical_count", 0))
    high         = int(message.get("high_count", 0))
    account_id   = message.get("account_id", "")
    account_name = message.get("account_name", "")

    logger.info(
        f"Received from {source} (account={account_id}): event_type={event_type} "
        f"severity={severity} critical={critical} high={high}"
    )

    # Always store the notification so Bedrock Agent can query DynamoDB
    _store_notification(message)

    # Only invoke the Bedrock Orchestrator Agent when coordination is needed
    should_invoke = (
        event_type == "critical_finding"
        or (event_type == "scan_complete" and critical > 0)
        or event_type == "remediation_taken"
        or severity == "CRITICAL"
    )

    if not should_invoke:
        logger.info(
            f"No orchestration needed for {source} (account={account_id}) — "
            f"{event_type} with no critical findings"
        )
        return

    prompt     = _build_prompt(source, event_type, severity, scan_id, summary,
                               critical, high, account_id, account_name)
    session_id = f"orch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    logger.info(f"Invoking Orchestrator Agent — session={session_id} account={account_id}")

    try:
        response = bedrock_agent_runtime.invoke_agent(
            agentId      = AGENT_ID,
            agentAliasId = AGENT_ALIAS_ID,
            sessionId    = session_id,
            inputText    = prompt,
            sessionState = {
                "promptSessionAttributes": {
                    "source":       source,
                    "event_type":   event_type,
                    "severity":     severity,
                    "scan_id":      scan_id,
                    "account_id":   account_id,
                    "account_name": account_name,
                    "timestamp":    datetime.now(timezone.utc).isoformat(),
                }
            }
        )
        completion = _collect_response(response)
        logger.info(f"Orchestrator session {session_id} complete")
        _store_orchestration_result(
            session_id, source, event_type, prompt, completion,
            account_id, account_name
        )

    except Exception as e:
        logger.error(f"Orchestrator Agent invocation failed: {e}", exc_info=True)
        _send_failure_alert(source, event_type, str(e), account_id, account_name)


def _build_prompt(source, event_type, severity, scan_id, summary,
                  critical, high, account_id, account_name):
    """Build a targeted prompt based on what the sub-agent reported."""
    account_label = f" in account {account_name or account_id}" if account_id else ""

    if event_type == "critical_finding":
        return (
            f"URGENT: {source} has detected a {severity} severity finding{account_label} "
            f"(scan_id: {scan_id}). Summary: {summary}. "
            f"Use query_agent_findings with account_id={account_id!r} to check if other "
            f"agents have related findings from the last 24 hours. "
            f"Determine if cross-agent coordination is needed — for example, "
            f"a CRITICAL security finding may need the incident agent notified. "
            f"Check for conflicts between agent recommendations. "
            f"Produce an executive summary and save it with save_coordination_report."
        )

    elif event_type == "scan_complete":
        return (
            f"The {source} has completed its scan{account_label} (scan_id: {scan_id}). "
            f"Results: {critical} critical, {high} high severity findings. "
            f"Summary: {summary}. "
            f"Use query_agent_findings with account_id={account_id!r} to pull recent "
            f"findings from all agents for this account. "
            f"Identify patterns and conflicts — for example, does the cost agent want "
            f"to stop an instance the security agent flagged as compromised? "
            f"Produce a cross-agent summary and save it with save_coordination_report."
        )

    elif event_type == "remediation_taken":
        return (
            f"The {source} has taken a remediation action{account_label} (scan_id: {scan_id}). "
            f"Summary: {summary}. "
            f"Check if this action may impact other agents. For example, stopping "
            f"an EC2 instance may affect the incident agent's active investigation. "
            f"Save the coordination report."
        )

    else:
        return (
            f"Received notification from {source}{account_label}: {event_type}. "
            f"Severity: {severity}. Summary: {summary}. "
            f"Review, correlate with other agent findings, and save coordination report."
        )


def _collect_response(response):
    completion = ""
    for event in response.get("completion", []):
        if "chunk" in event:
            chunk = event["chunk"]
            if "bytes" in chunk:
                completion += chunk["bytes"].decode("utf-8")
    return completion


def _store_notification(message):
    """Store every agent notification for the Bedrock Agent to query later."""
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":    f"notify-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')}",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "agent":      "orchestrator",
            "event_type": message.get("event_type", "unknown"),
            "source":     message.get("source", "unknown"),
            "severity":   message.get("severity", "LOW"),
            "summary":    message.get("summary", ""),
            "account_id": message.get("account_id", ""),
            "account_name": message.get("account_name", ""),
            "payload":    json.dumps(message.get("payload", {})),
            "ttl":        int(datetime.now(timezone.utc).timestamp()) + (30 * 86400),
        })
    except Exception as e:
        logger.warning(f"Failed to store notification: {e}")


def _store_orchestration_result(session_id, source, event_type, prompt, completion,
                                 account_id, account_name):
    """Store the Orchestrator's coordination response in DynamoDB."""
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":      session_id,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "agent":        "orchestrator",
            "event_type":   "orchestration_complete",
            "source":       source,
            "trigger":      event_type,
            "prompt":       prompt[:1000],
            "completion":   completion[:2000],
            "account_id":   account_id,
            "account_name": account_name,
            "ttl":          int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })
    except Exception as e:
        logger.warning(f"Failed to store orchestration result: {e}")


def _send_failure_alert(source, event_type, error, account_id, account_name):
    """Alert humans if the Orchestrator itself fails."""
    if not ALERT_TOPIC_ARN:
        return
    try:
        sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[ERROR][{account_name or account_id}] Orchestrator Agent failed to process notification",
            Message  = json.dumps({
                "error":        error,
                "source":       source,
                "event_type":   event_type,
                "account_id":   account_id,
                "account_name": account_name,
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            }, indent=2),
        )
    except Exception as e:
        logger.error(f"Failed to send failure alert: {e}")
