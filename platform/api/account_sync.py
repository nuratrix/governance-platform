"""
platform/api/account_sync.py

Syncs all active AWS Organizations accounts into the account_registry DynamoDB table.
Triggered hourly by EventBridge. The bedrock_agent_trigger Lambda reads from this
table at scan time — so all accounts are discovered automatically without any
per-account configuration.

Environment variables:
  ACCOUNT_REGISTRY_TABLE  — DynamoDB table name
  GOVERNANCE_ACCOUNT_ID   — excluded from the member list (scanned via governance role)
  READER_ROLE_NAME        — IAM role name deployed in each member account (default: governance-platform-reader)
  DEFAULT_ENV             — env tag applied to auto-discovered accounts (default: production)
"""

import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACCOUNT_REGISTRY_TABLE = os.environ.get("ACCOUNT_REGISTRY_TABLE", "")
GOVERNANCE_ACCOUNT_ID  = os.environ.get("GOVERNANCE_ACCOUNT_ID", "")
READER_ROLE_NAME       = os.environ.get("READER_ROLE_NAME", "governance-platform-reader")
DEFAULT_ENV            = os.environ.get("DEFAULT_ENV", "production")

dynamodb = boto3.resource("dynamodb")
org      = boto3.client("organizations")


def lambda_handler(event, context):
    if not ACCOUNT_REGISTRY_TABLE:
        logger.error("ACCOUNT_REGISTRY_TABLE not configured")
        return {"success": False, "message": "ACCOUNT_REGISTRY_TABLE not configured"}

    try:
        accounts = _list_org_accounts()
    except Exception as e:
        logger.error(f"organizations:ListAccounts failed: {e}")
        return {"success": False, "message": str(e)}

    table  = dynamodb.Table(ACCOUNT_REGISTRY_TABLE)
    synced = 0
    now    = datetime.now(timezone.utc).isoformat()

    for acct in accounts:
        if acct.get("Status") != "ACTIVE":
            continue
        if acct["Id"] == GOVERNANCE_ACCOUNT_ID:
            continue
        try:
            table.put_item(Item={
                "account_id":  acct["Id"],
                "name":        acct["Name"],
                "env":         DEFAULT_ENV,
                "reader_role": READER_ROLE_NAME,
                "role_arn":    f"arn:aws:iam::{acct['Id']}:role/{READER_ROLE_NAME}",
                "email":       acct.get("Email", ""),
                "updated_at":  now,
                "source":      "organizations-sync",
            })
            synced += 1
        except Exception as e:
            logger.error(f"Failed to upsert account {acct['Id']}: {e}")

    logger.info(f"account_sync: synced {synced} of {len(accounts)} org accounts")
    return {"success": True, "synced": synced, "total": len(accounts)}


def _list_org_accounts():
    accounts  = []
    paginator = org.get_paginator("list_accounts")
    for page in paginator.paginate():
        accounts.extend(page["Accounts"])
    return accounts
