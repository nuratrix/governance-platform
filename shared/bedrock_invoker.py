"""
shared/bedrock_invoker.py

SQS-triggered Lambda that calls bedrock_agent_runtime.invoke_agent for
exactly ONE account per invocation. Consumed from the per-agent
bedrock-invoke-queue (batch_size=1).

Each SQS message is produced by bedrock_agent_trigger.lambda_handler and
contains everything this Lambda needs — no env-var lookups for agent IDs
or prompts, making this function stateless and reusable across all agents.

Expected SQS message body (JSON):
  {
    "account_id":            "123456789012",
    "account_name":          "prod-account",
    "reader_role":           "governance-platform-reader",
    "agent_id":              "XXXXXXXXXX",
    "alias_id":              "YYYYYYYYYY",
    "full_prompt":           "RULES REFERENCE\\n...\\nTASK: Run a full scan.",
    "scan_type":             "full",
    "triggered_by":          "scheduled",
    "rules_mode":            "inline",
    "governance_account_id": "999999999999"
  }

Environment variables (from local.lambda_env):
  ALERT_TOPIC_ARN  – SNS topic for failure alerts
  AWS_REGION       – set automatically by Lambda runtime
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")


def lambda_handler(event, context):
    results = []
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Malformed SQS record: {e}")
            continue

        result = _invoke_for_account(body)
        results.append(result)

    successes = sum(1 for r in results if r.get("success"))
    logger.info(f"bedrock_invoker: {successes}/{len(results)} invocations succeeded")
    return {"statusCode": 200, "successes": successes, "total": len(results)}


def _invoke_for_account(body: dict) -> dict:
    account_id   = body.get("account_id", "")
    account_name = body.get("account_name", account_id)
    reader_role  = body.get("reader_role", "governance-platform-reader")
    agent_id     = body.get("agent_id", "")
    alias_id     = body.get("alias_id", "")
    full_prompt  = body.get("full_prompt", "Run a full scan.")
    scan_type    = body.get("scan_type", "full")
    triggered_by = body.get("triggered_by", "scheduled")
    rules_mode   = body.get("rules_mode", "inline")
    gov_account  = body.get("governance_account_id", "")

    if not agent_id or not alias_id:
        logger.error(f"Missing agent_id or alias_id for account {account_id}")
        return {"success": False, "account_id": account_id, "error": "missing agent_id/alias_id"}

    session_id = (
        f"invoker-{account_id}-"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    )

    session_state = {
        "sessionAttributes": {
            "account_id":            account_id,
            "account_name":          account_name,
            "reader_role":           reader_role,
            "governance_account_id": gov_account,
            "scan_type":             scan_type,
        },
        "promptSessionAttributes": {
            "scan_type":             scan_type,
            "triggered_by":          triggered_by,
            "rules_mode":            rules_mode,
            "timestamp":             datetime.now(timezone.utc).isoformat(),
            "account_id":            account_id,
            "account_name":          account_name,
            "reader_role":           reader_role,
            "governance_account_id": gov_account,
        },
    }

    logger.info(
        f"Invoking Bedrock agent for account={account_id} ({account_name}) "
        f"agent_id={agent_id} session={session_id}"
    )

    bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")
    try:
        response   = bedrock_agent_runtime.invoke_agent(
            agentId      = agent_id,
            agentAliasId = alias_id,
            sessionId    = session_id,
            inputText    = full_prompt,
            sessionState = session_state,
        )
        completion = _collect_response(response)
        logger.info(f"Session {session_id} complete for account {account_id}")
        return {
            "success":    True,
            "account_id": account_id,
            "session_id": session_id,
            "completion": completion[:300],
        }
    except Exception as e:
        logger.error(
            f"invoke_agent failed for account {account_id}: {e}", exc_info=True
        )
        _send_failure_alert(agent_id, session_id, account_id, str(e))
        return {"success": False, "account_id": account_id, "error": str(e)}


def _collect_response(response) -> str:
    completion = ""
    try:
        for event in response.get("completion", []):
            if "chunk" in event and "bytes" in event["chunk"]:
                completion += event["chunk"]["bytes"].decode("utf-8")
    except Exception as e:
        logger.warning(f"Response stream ended early: {e}")
    return completion


def _send_failure_alert(agent_id: str, session_id: str, account_id: str, error: str):
    if not ALERT_TOPIC_ARN:
        return
    try:
        sns = boto3.client("sns")
        sns.publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject=f"[ERROR] Bedrock invoker failed for account {account_id}",
            Message=json.dumps({
                "agent_id":   agent_id,
                "session_id": session_id,
                "account_id": account_id,
                "error":      error,
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }, indent=2),
        )
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
