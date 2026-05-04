"""
shared/bedrock_agent_trigger.py

Publishes one SQS message per managed account so that bedrock_invoker
Lambdas can call invoke_agent in parallel (one account per invocation).

Previously this Lambda called invoke_agent in a sequential for-loop,
which hit the 900-second Lambda ceiling at ~5 accounts. Now it is a
pure publisher: it resolves the agent, builds the prompt, reads the
account list, and enqueues — nothing more.

Environment variables:
  BEDROCK_INVOKE_QUEUE_URL  – SQS queue consumed by lambda_bedrock_invoker
  BEDROCK_AGENT_ID          – Bedrock agent ID (or resolved via BEDROCK_AGENT_NAME)
  BEDROCK_AGENT_ALIAS_ID    – Bedrock agent alias ID
  BEDROCK_AGENT_NAME        – used when agent_id is not known at deploy time
  DEFAULT_PROMPT            – default scan prompt
  RULES_MODE                – inline | kb | none
  RULES_BUCKET              – S3 bucket for inline rules
  KNOWLEDGE_BASE_ID         – Bedrock KB ID (when RULES_MODE=kb)
  GOVERNANCE_ACCOUNT_ID     – always scanned
  ACCOUNT_REGISTRY_TABLE    – DynamoDB table for live account list
  MEMBER_ACCOUNTS_JSON      – fallback static JSON list
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3                    = boto3.client("s3")
bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")
sqs                   = boto3.client("sqs")
dynamodb              = boto3.resource("dynamodb")

RULES_MODE              = os.environ.get("RULES_MODE", "inline").lower()
RULES_BUCKET            = os.environ.get("RULES_BUCKET", "")
KNOWLEDGE_BASE_ID       = os.environ.get("KNOWLEDGE_BASE_ID", "")
AGENT_ID                = os.environ.get("BEDROCK_AGENT_ID", "")
AGENT_ALIAS_ID          = os.environ.get("BEDROCK_AGENT_ALIAS_ID", "")
AGENT_NAME              = os.environ.get("BEDROCK_AGENT_NAME", "")
DEFAULT_PROMPT          = os.environ.get("DEFAULT_PROMPT", "Run a full scan.")
GOVERNANCE_ACCOUNT_ID   = os.environ.get("GOVERNANCE_ACCOUNT_ID", "")
ACCOUNT_REGISTRY_TABLE  = os.environ.get("ACCOUNT_REGISTRY_TABLE", "")
MEMBER_ACCOUNTS_JSON    = os.environ.get("MEMBER_ACCOUNTS_JSON", "[]")
BEDROCK_INVOKE_QUEUE_URL = os.environ.get("BEDROCK_INVOKE_QUEUE_URL", "")

RULES_KEY_MAP = {
    "governance-security-agent":       "security/security_rules.md",
    "governance-compliance-agent":     "compliance/compliance_rules.md",
    "governance-cost-agent":           "cost/cost_rules.md",
    "governance-incident-agent":       "incident/incident_rules.md",
    "governance-infrastructure-agent": "infrastructure/infrastructure_rules.md",
    "governance-orchestrator-agent":   "orchestrator/orchestrator_rules.md",
}


def lambda_handler(event, context):
    prompt       = event.get("prompt")       or DEFAULT_PROMPT
    scan_type    = event.get("scan_type",    "full")
    triggered_by = event.get("triggered_by", "scheduled")
    agent_id     = event.get("agent_id")     or AGENT_ID
    alias_id     = event.get("alias_id")     or AGENT_ALIAS_ID

    if not BEDROCK_INVOKE_QUEUE_URL:
        logger.error("BEDROCK_INVOKE_QUEUE_URL is not set — cannot fan out")
        return {"success": False, "message": "BEDROCK_INVOKE_QUEUE_URL not configured"}

    logger.info(f"RULES_MODE={RULES_MODE} agent={AGENT_NAME}")

    agent_id, alias_id = _resolve_agent(agent_id)
    if not agent_id or not alias_id:
        return {"success": False, "message": "Could not determine agent_id or alias_id"}

    rules_context = _load_rules(prompt)
    full_prompt   = _build_prompt(prompt, rules_context)

    accounts = _get_accounts_to_scan()
    logger.info(f"Publishing {len(accounts)} account(s) to Bedrock invoke queue")

    published = 0
    for account in accounts:
        try:
            sqs.send_message(
                QueueUrl=BEDROCK_INVOKE_QUEUE_URL,
                MessageBody=json.dumps({
                    "account_id":           account["account_id"],
                    "account_name":         account.get("name", account["account_id"]),
                    "reader_role":          account.get("reader_role", "governance-platform-reader"),
                    "agent_id":             agent_id,
                    "alias_id":             alias_id,
                    "full_prompt":          full_prompt,
                    "scan_type":            scan_type,
                    "triggered_by":         triggered_by,
                    "rules_mode":           RULES_MODE,
                    "governance_account_id": GOVERNANCE_ACCOUNT_ID,
                }),
            )
            published += 1
        except Exception as e:
            logger.error(f"Failed to enqueue account {account['account_id']}: {e}")

    logger.info(f"bedrock_agent_trigger: published {published}/{len(accounts)} accounts")
    return {"success": True, "published": published, "total_accounts": len(accounts)}


# ── Account discovery ─────────────────────────────────────────────────────────

def _get_accounts_to_scan() -> list:
    if ACCOUNT_REGISTRY_TABLE:
        try:
            table    = dynamodb.Table(ACCOUNT_REGISTRY_TABLE)
            resp     = table.scan()
            accounts = resp.get("Items", [])
            if accounts:
                logger.info(f"Loaded {len(accounts)} accounts from DynamoDB registry")
                return accounts
        except Exception as e:
            logger.warning(f"Could not load accounts from DynamoDB: {e}")

    try:
        env_accounts = json.loads(MEMBER_ACCOUNTS_JSON)
        if env_accounts:
            governance = {
                "account_id":  GOVERNANCE_ACCOUNT_ID,
                "name":        "governance-account",
                "reader_role": "self",
            }
            all_accounts = [governance] + [
                a for a in env_accounts
                if a.get("account_id") != GOVERNANCE_ACCOUNT_ID
            ]
            logger.info(f"Loaded {len(all_accounts)} accounts from MEMBER_ACCOUNTS_JSON")
            return all_accounts
    except Exception as e:
        logger.warning(f"Could not parse MEMBER_ACCOUNTS_JSON: {e}")

    logger.info("No member accounts configured — scanning governance account only")
    return [{"account_id": GOVERNANCE_ACCOUNT_ID, "name": "governance-account", "reader_role": "self"}]


# ── Rules loading ─────────────────────────────────────────────────────────────

def _load_rules(prompt):
    if RULES_MODE == "none":
        return ""
    elif RULES_MODE == "inline":
        return _load_inline_rules()
    elif RULES_MODE in ("kb", "pinecone", "knowledge_base"):
        return _load_kb_rules(prompt)
    else:
        logger.warning(f"Unknown RULES_MODE '{RULES_MODE}' — falling back to inline")
        return _load_inline_rules()


def _load_inline_rules():
    if not RULES_BUCKET:
        return ""
    rules_key = RULES_KEY_MAP.get(AGENT_NAME, "")
    if not rules_key:
        return ""
    try:
        response = s3.get_object(Bucket=RULES_BUCKET, Key=rules_key)
        content  = response["Body"].read().decode("utf-8")
        if len(content) > 80000:
            content = content[:80000]
        return content
    except Exception as e:
        logger.error(f"Failed to load inline rules: {e}")
        return ""


def _load_kb_rules(prompt):
    if not KNOWLEDGE_BASE_ID:
        return _load_inline_rules()
    search_query = f"{AGENT_NAME} rules {prompt[:200]}"
    try:
        response = bedrock_agent_runtime.retrieve(
            knowledgeBaseId = KNOWLEDGE_BASE_ID,
            retrievalQuery  = {"text": search_query},
            retrievalConfiguration = {
                "vectorSearchConfiguration": {
                    "numberOfResults":    10,
                    "overrideSearchType": "HYBRID",
                }
            }
        )
        results = response.get("retrievalResults", [])
        if not results:
            return _load_inline_rules()
        chunks = [
            item["content"]["text"]
            for item in results
            if item.get("content", {}).get("text") and item.get("score", 0) > 0.3
        ]
        return "\n\n---\n\n".join(chunks)
    except Exception as e:
        logger.error(f"KB query failed: {e} — falling back to inline")
        return _load_inline_rules()


def _build_prompt(original_prompt, rules_context):
    if not rules_context:
        return original_prompt
    return (
        "RULES REFERENCE\n"
        "Use these rules to determine severity, auto-remediation eligibility "
        "and recommended actions for every finding:\n\n"
        f"{rules_context}\n\n"
        "---\n\n"
        f"TASK: {original_prompt}"
    )


# ── Agent resolution ──────────────────────────────────────────────────────────

def _resolve_agent(known_agent_id=None):
    bedrock_agent = boto3.client("bedrock-agent")
    agent_id      = known_agent_id or AGENT_ID

    if not agent_id and AGENT_NAME:
        try:
            agents = bedrock_agent.list_agents()["agentSummaries"]
            match  = next((a for a in agents if a["agentName"] == AGENT_NAME), None)
            if match:
                agent_id = match["agentId"]
        except Exception as e:
            logger.error(f"Failed to list agents: {e}")
            return None, None

    if not agent_id:
        return None, None

    try:
        aliases    = bedrock_agent.list_agent_aliases(agentId=agent_id)["agentAliasSummaries"]
        live_alias = next((a for a in aliases if a["agentAliasName"].endswith("agent-live")), None)
        if not live_alias and aliases:
            live_alias = aliases[0]
        if live_alias:
            return agent_id, live_alias["agentAliasId"]
    except Exception as e:
        logger.error(f"Failed to resolve alias: {e}")

    return agent_id, None
