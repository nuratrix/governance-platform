"""
Orchestrator Agent - Bedrock Action Handler — Multi-Account Edition
Routes Bedrock Agent tool calls for cross-agent coordination,
conflict resolution, findings queries and report generation.

Multi-account changes:
  - query_agent_findings uses account-agent-timestamp-index GSI when account_id provided
  - detect_conflicts scopes resource_map to per-account keys (no cross-account false positives)
  - get_platform_health groups by (agent, account_id)
  - invoke_agent passes account_id in promptSessionAttributes to sub-agents
  - save_coordination_report stores account_id and account_name
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone, timedelta
from boto3.dynamodb.conditions import Key, Attr
import conflict_rules
from teams_notifier import notify_teams, notify_teams_scan_complete
from slack_notifier import notify_slack, notify_slack_scan_complete

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sns      = boto3.client("sns")
bedrock  = boto3.client("bedrock-agent-runtime")

FINDINGS_TABLE  = os.environ.get("FINDINGS_TABLE", "governance-platform-findings")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")

# Sub-agent alias ARNs — Orchestrator uses these to invoke agents on demand
SECURITY_AGENT_ID        = os.environ.get("SECURITY_AGENT_ID", "")
SECURITY_AGENT_ALIAS_ID  = os.environ.get("SECURITY_AGENT_ALIAS_ID", "")
COST_AGENT_ID            = os.environ.get("COST_AGENT_ID", "")
COST_AGENT_ALIAS_ID      = os.environ.get("COST_AGENT_ALIAS_ID", "")
INFRA_AGENT_ID           = os.environ.get("INFRA_AGENT_ID", "")
INFRA_AGENT_ALIAS_ID     = os.environ.get("INFRA_AGENT_ALIAS_ID", "")
COMPLIANCE_AGENT_ID      = os.environ.get("COMPLIANCE_AGENT_ID", "")
COMPLIANCE_AGENT_ALIAS_ID = os.environ.get("COMPLIANCE_AGENT_ALIAS_ID", "")
INCIDENT_AGENT_ID        = os.environ.get("INCIDENT_AGENT_ID", "")
INCIDENT_AGENT_ALIAS_ID  = os.environ.get("INCIDENT_AGENT_ALIAS_ID", "")


def lambda_handler(event, context):
    logger.info(f"RAW EVENT: {json.dumps(event)}")

    action_group = event.get("actionGroup", "")
    api_path     = event.get("apiPath", "")
    http_method  = event.get("httpMethod", "POST")
    parameters   = _extract_parameters(event)

    # ── Multi-Account: pull account context ───────────────────────────────
    session_attrs = event.get("sessionAttributes", {})
    prompt_attrs  = event.get("promptSessionAttributes", {})
    account_id    = prompt_attrs.get("account_id", session_attrs.get("account_id", ""))
    account_name  = prompt_attrs.get("account_name", session_attrs.get("account_name", ""))

    api_path_normalized = "/" + api_path.strip().strip("/").lower()
    logger.info(f"Routing: {action_group} → {api_path_normalized} account={account_id}")

    try:
        result = _route(api_path_normalized, parameters, account_id, account_name)
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


def _route(api_path, params, account_id, account_name):

    if api_path == "/queryagentfindings":
        return _query_agent_findings(params, account_id)

    elif api_path == "/detectconflicts":
        return _detect_conflicts(params, account_id)

    elif api_path == "/invokeagent":
        return _invoke_agent(params, account_id, account_name)

    elif api_path == "/getplatformhealth":
        return _get_platform_health(params, account_id)

    elif api_path == "/escalatetohuman":
        return _escalate(params, account_id, account_name)

    elif api_path == "/savecoordinationreport":
        return _save_report(params, account_id, account_name)

    else:
        logger.error(f"No route matched: '{api_path}'")
        return {"error": f"Unknown api_path: '{api_path}'", "success": False}


# ── Tool Implementations ──────────────────────────────────────────────────────

def _query_agent_findings(params, caller_account_id):
    """
    Query DynamoDB for recent findings from one or all agents.
    When account_id is provided (from params or caller context), uses the
    account-agent-timestamp-index GSI for efficient per-account queries.
    """
    agent_filter  = params.get("agent_filter", "")
    hours_back    = int(params.get("hours_back", 24))
    severity      = params.get("severity_filter", "")
    event_type    = params.get("event_type", "")
    # Allow explicit account_id in params to override caller context
    account_id    = params.get("account_id", caller_account_id)

    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

    try:
        table = dynamodb.Table(FINDINGS_TABLE)

        if account_id:
            # Use account-agent-timestamp-index GSI: partition=account_id, range=timestamp
            filter_expr = None
            if agent_filter:
                filter_expr = Attr("agent").eq(agent_filter)
            if severity:
                cond = Attr("severity").eq(severity)
                filter_expr = (filter_expr & cond) if filter_expr else cond
            if event_type:
                cond = Attr("event_type").eq(event_type)
                filter_expr = (filter_expr & cond) if filter_expr else cond

            query_kwargs = dict(
                IndexName              = "account-agent-timestamp-index",
                KeyConditionExpression = Key("account_id").eq(account_id) & Key("timestamp").gte(since),
                Limit                  = 100,
            )
            if filter_expr:
                query_kwargs["FilterExpression"] = filter_expr
            resp = table.query(**query_kwargs)

        elif agent_filter:
            # No account filter — use original agent-timestamp-index GSI
            resp = table.query(
                IndexName              = "agent-timestamp-index",
                KeyConditionExpression = Key("agent").eq(agent_filter) & Key("timestamp").gte(since),
                Limit                  = 50,
            )

        else:
            # Full scan with timestamp filter
            filter_expr = Attr("timestamp").gte(since)
            if severity:
                filter_expr = filter_expr & Attr("severity").eq(severity)
            if event_type:
                filter_expr = filter_expr & Attr("event_type").eq(event_type)
            resp = table.scan(FilterExpression=filter_expr, Limit=100)

        items = resp.get("Items", [])

        # Group by agent for easier Orchestrator reasoning
        by_agent = {}
        for item in items:
            agent = item.get("agent", "unknown")
            if agent not in by_agent:
                by_agent[agent] = []
            by_agent[agent].append({
                "scan_id":    item.get("scan_id"),
                "timestamp":  item.get("timestamp"),
                "event_type": item.get("event_type"),
                "severity":   item.get("severity"),
                "summary":    item.get("summary", item.get("title", "")),
                "account_id": item.get("account_id", ""),
            })

        return {
            "total_items":    len(items),
            "hours_back":     hours_back,
            "agent_filter":   agent_filter or "all",
            "account_filter": account_id or "all",
            "by_agent":       by_agent,
            "agents_found":   list(by_agent.keys()),
        }

    except Exception as e:
        logger.error(f"Query findings failed: {e}")
        return {"error": str(e), "total_items": 0, "by_agent": {}}


def _detect_conflicts(params, caller_account_id):
    """
    Identify and deterministically resolve conflicts between agent
    recommendations on the same resource.
 
    Resolution is rule-based. No model call is made in this path. Pairs the
    rules cannot decide are returned in adjudication_queue for the
    Orchestrator's model to reason about.
    """
    hours_back = int(params.get("hours_back", 48))
    account_id = params.get("account_id", caller_account_id)
    kind_filter = params.get("kind_filter", "")   # optional: conflict|suppression|serialize|adjudicate
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
 
    try:
        table = dynamodb.Table(FINDINGS_TABLE)  # noqa: F821 — module-level in the handler
 
        if account_id:
            resp = table.query(
                IndexName="account-agent-timestamp-index",
                KeyConditionExpression=Key("account_id").eq(account_id) & Key("timestamp").gte(since),
                Limit=500,
            )
        else:
            resp = table.scan(
                FilterExpression=Attr("timestamp").gte(since),
                Limit=500,
            )
 
        items = resp.get("Items", [])
 
        # Page the query — a busy account will exceed one page and silently
        # under-report conflicts otherwise.
        while "LastEvaluatedKey" in resp and len(items) < 2000:
            if account_id:
                resp = table.query(
                    IndexName="account-agent-timestamp-index",
                    KeyConditionExpression=Key("account_id").eq(account_id) & Key("timestamp").gte(since),
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                    Limit=500,
                )
            else:
                resp = table.scan(
                    FilterExpression=Attr("timestamp").gte(since),
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                    Limit=500,
                )
            items.extend(resp.get("Items", []))
 
        result = conflict_rules.resolve(items)
 
        if result["skipped_unclassified"]:
            logger.warning(
                "%d findings skipped — missing or invalid recommended_action. "
                "Conflict coverage is incomplete for this window.",
                result["skipped_unclassified"],
            )
 
        payload = {
            "conflicts_found":        len(result["conflicts"]),
            "conflicts":              result["conflicts"],
            "suppressions_found":     len(result["suppressions"]),
            "suppressions":           result["suppressions"],
            "serialisations_found":   len(result["serialisations"]),
            "serialisations":         result["serialisations"],
            "adjudication_required":  len(result["adjudication_queue"]),
            "adjudication_queue":     result["adjudication_queue"],
            "resources_checked":      result["resources_checked"],
            "findings_active":        result["findings_active"],
            "skipped_stale":          result["skipped_stale"],
            "skipped_unclassified":   result["skipped_unclassified"],
            "hours_back":             hours_back,
            "account_filter":         account_id or "all",
            "resolution_mode":        "deterministic",
        }
 
        if kind_filter:
            keep = {
                "conflict":    ["conflicts"],
                "suppression": ["suppressions"],
                "serialize":   ["serialisations"],
                "adjudicate":  ["adjudication_queue"],
            }.get(kind_filter, [])
            for k in ["conflicts", "suppressions", "serialisations", "adjudication_queue"]:
                if k not in keep:
                    payload[k] = []
 
        return payload
 
    except Exception as e:
        logger.error(f"Conflict detection failed: {e}", exc_info=True)
        return {
            "error": str(e),
            "conflicts_found": 0, "conflicts": [],
            "adjudication_required": 0, "adjudication_queue": [],
        }
 
def _invoke_agent(params, caller_account_id, caller_account_name):
    """
    Invoke a specific sub-agent on demand.
    Passes account_id in promptSessionAttributes so the sub-agent scans
    the correct account rather than defaulting to the governance account.
    """
    agent_name   = params.get("agent_name", "")
    prompt       = params.get("prompt", "")
    account_id   = params.get("account_id", caller_account_id)
    account_name = params.get("account_name", caller_account_name)

    if not agent_name or not prompt:
        return {"success": False, "message": "agent_name and prompt are required"}

    agent_map = {
        "security-agent":   (SECURITY_AGENT_ID,    SECURITY_AGENT_ALIAS_ID),
        "cost-agent":       (COST_AGENT_ID,         COST_AGENT_ALIAS_ID),
        "infra-agent":      (INFRA_AGENT_ID,        INFRA_AGENT_ALIAS_ID),
        "compliance-agent": (COMPLIANCE_AGENT_ID,   COMPLIANCE_AGENT_ALIAS_ID),
        "incident-agent":   (INCIDENT_AGENT_ID,     INCIDENT_AGENT_ALIAS_ID),
    }

    if agent_name not in agent_map:
        return {
            "success": False,
            "message": f"Unknown agent: {agent_name}. Valid agents: {list(agent_map.keys())}",
        }

    agent_id, alias_id = agent_map[agent_name]
    if not agent_id or not alias_id:
        return {
            "success": False,
            "message": (
                f"Agent {agent_name} IDs not configured. "
                "Set the environment variables in the Orchestrator Lambda."
            ),
        }

    session_id = f"orch-invoke-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    try:
        response = bedrock.invoke_agent(
            agentId      = agent_id,
            agentAliasId = alias_id,
            sessionId    = session_id,
            inputText    = prompt,
            sessionState = {
                "promptSessionAttributes": {
                    "account_id":   account_id,
                    "account_name": account_name,
                }
            },
        )
        completion = ""
        for event in response.get("completion", []):
            if "chunk" in event and "bytes" in event["chunk"]:
                completion += event["chunk"]["bytes"].decode("utf-8")

        return {
            "success":    True,
            "agent_name": agent_name,
            "session_id": session_id,
            "account_id": account_id,
            "completion": completion[:2000],
        }

    except Exception as e:
        logger.error(f"Agent invocation failed for {agent_name}: {e}")
        return {"success": False, "message": str(e)}


def _get_platform_health(params, caller_account_id):
    """
    Summarise overall platform health.
    When account_id is provided, scopes to that account.
    When empty, aggregates across all accounts with per-account breakdown.
    """
    hours_back = int(params.get("hours_back", 24))
    account_id = params.get("account_id", caller_account_id)
    since      = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

    try:
        table = dynamodb.Table(FINDINGS_TABLE)

        if account_id:
            resp = table.query(
                IndexName              = "account-agent-timestamp-index",
                KeyConditionExpression = Key("account_id").eq(account_id) & Key("timestamp").gte(since),
                Limit                  = 500,
            )
        else:
            resp = table.scan(
                FilterExpression = Attr("timestamp").gte(since),
                Limit            = 500,
            )
        items = resp.get("Items", [])

        # Aggregate counts by (agent, account_id)
        health      = {}    # { agent: { CRITICAL:0, HIGH:0, ... } }
        by_account  = {}    # { account_id: { CRITICAL:0, HIGH:0, ... } }

        for item in items:
            agent    = item.get("agent", "unknown")
            severity = item.get("severity", "LOW")
            acct     = item.get("account_id", "unknown")
            if agent == "orchestrator":
                continue

            if agent not in health:
                health[agent] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "last_seen": ""}
            health[agent][severity] = health[agent].get(severity, 0) + 1
            ts = item.get("timestamp", "")
            if ts > health[agent]["last_seen"]:
                health[agent]["last_seen"] = ts

            if acct not in by_account:
                by_account[acct] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            by_account[acct][severity] = by_account[acct].get(severity, 0) + 1

        total_critical = sum(v.get("CRITICAL", 0) for v in health.values())
        total_high     = sum(v.get("HIGH", 0)     for v in health.values())
        overall_status = (
            "CRITICAL" if total_critical > 0
            else "DEGRADED" if total_high > 5
            else "WARNING"  if total_high > 0
            else "HEALTHY"
        )

        return {
            "overall_status":   overall_status,
            "total_critical":   total_critical,
            "total_high":       total_high,
            "by_agent":         health,
            "by_account":       by_account,
            "account_filter":   account_id or "all",
            "hours_back":       hours_back,
            "agents_reporting": list(health.keys()),
        }

    except Exception as e:
        logger.error(f"Platform health check failed: {e}")
        return {"error": str(e), "overall_status": "UNKNOWN"}


def _escalate(params, account_id, account_name):
    """Send a cross-agent coordination alert to the team."""
    if not ALERT_TOPIC_ARN:
        return {"success": False, "message": "ALERT_TOPIC_ARN not configured"}

    severity = params.get("severity", "HIGH")
    title    = params.get("title", "Orchestrator Alert")

    message = {
        "source":             "orchestrator",
        "severity":           severity,
        "title":              title,
        "situation":          params.get("situation", ""),
        "agents_involved":    params.get("agents_involved", ""),
        "conflicts":          params.get("conflicts", ""),
        "recommended_action": params.get("recommended_action", ""),
        "escalated_at":       datetime.now(timezone.utc).isoformat(),
        "account_id":         account_id,
        "account_name":       account_name,
    }

    try:
        resp = sns.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[{severity}][{account_name or account_id or 'platform'}] Orchestrator: {title}",
            Message  = json.dumps(message, indent=2),
        )

        notify_teams(
            title          = title,
            severity       = severity,
            description    = params.get("incident_summary", params.get("situation", "")),
            resource_id    = params.get("affected_resources", ""),
            recommendation = params.get("recommended_action", ""),
            agent_name     = "governance-orchestrator-agent",
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
            agent_name     = "governance-orchestrator-agent",
            actions_taken  = params.get("actions_taken", ""),
            scan_id        = params.get("scan_id", ""),
            account_id     = account_id,
            account_name   = account_name,
        )

        return {
            "success":      True,
            "message_id":   resp.get("MessageId", ""),
            "escalated_at": message["escalated_at"],
        }
    except Exception as e:
        logger.error(f"Escalation failed: {e}")
        return {"success": False, "message": str(e)}


def _save_report(params, account_id, account_name):
    """Save the coordination report to DynamoDB."""
    try:
        table   = dynamodb.Table(FINDINGS_TABLE)
        scan_id = params.get("scan_id",
                             f"orch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")

        table.put_item(Item={
            "scan_id":           scan_id,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "agent":             "orchestrator",
            "event_type":        "coordination_report",
            "trigger_agent":     params.get("trigger_agent", ""),
            "trigger_event":     params.get("trigger_event", ""),
            "platform_status":   params.get("platform_status", ""),
            "conflicts_found":   params.get("conflicts_found", ""),
            "actions_taken":     params.get("actions_taken", ""),
            "agents_invoked":    params.get("agents_invoked", ""),
            "executive_summary": params.get("executive_summary", ""),
            "account_id":        account_id,
            "account_name":      account_name,
            "ttl":               int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })

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
