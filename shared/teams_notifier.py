"""
Microsoft Teams Integration — Multi-Account Edition
Added account_id and account_name fields to all Adaptive Card payloads so
operators can immediately see which account generated the finding.
"""

import json
import boto3
import urllib.request
import urllib.error
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()

TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")
TEAMS_SECRET_ARN  = os.environ.get("TEAMS_SECRET_ARN", "")

_cached_webhook_url = None


def _get_webhook_url():
    global _cached_webhook_url
    if TEAMS_WEBHOOK_URL:
        return TEAMS_WEBHOOK_URL
    if _cached_webhook_url:
        return _cached_webhook_url
    if not TEAMS_SECRET_ARN:
        logger.warning("Neither TEAMS_WEBHOOK_URL nor TEAMS_SECRET_ARN is set")
        return ""
    try:
        sm     = boto3.client("secretsmanager")
        secret = sm.get_secret_value(SecretId=TEAMS_SECRET_ARN)
        value  = secret.get("SecretString", "")
        try:
            parsed = json.loads(value)
            url    = parsed.get("url", parsed.get("webhook_url", value))
        except json.JSONDecodeError:
            url = value.strip()
        _cached_webhook_url = url
        logger.info("Teams webhook URL loaded from Secrets Manager")
        return url
    except Exception as e:
        logger.error(f"Failed to fetch Teams webhook URL: {e}")
        return ""


def notify_teams(title, severity, description, resource_id="",
                 recommendation="", agent_name="", actions_taken="",
                 scan_id="",
                 account_id="", account_name=""):   # ← Multi-Account fields
    """Send an Adaptive Card notification to Microsoft Teams."""
    webhook_url = _get_webhook_url()
    if not webhook_url:
        return False

    theme_color = {
        "CRITICAL": "B52B2B", "HIGH": "C05A00",
        "MEDIUM":   "C4900A", "LOW":  "1E7E4E",
    }.get(severity, "1B4F8A")

    severity_icon = {
        "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM":   "🟡", "LOW":  "🟢",
    }.get(severity, "🔵")

    # Build account label for the message header
    account_label = account_name or account_id
    header_text   = f"{severity_icon} **{severity}** — {title}"
    if account_label:
        header_text = f"{severity_icon} **[{account_label}]** **{severity}** — {title}"

    # Build FactSet entries
    facts = [f for f in [
        {"title": "Agent",        "value": agent_name}   if agent_name   else None,
        # ── Multi-Account: account facts ────────────────────────────────────
        {"title": "Account ID",   "value": account_id}   if account_id   else None,
        {"title": "Account Name", "value": account_name} if account_name else None,
        {"title": "Resource",     "value": resource_id}  if resource_id  else None,
        {"title": "Scan ID",      "value": scan_id}      if scan_id      else None,
        {"title": "Time",         "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
    ] if f is not None]

    body = [
        {
            "type":   "TextBlock",
            "text":   header_text,
            "size":   "Medium",
            "weight": "Bolder",
            "color":  "Attention" if severity in ("CRITICAL", "HIGH") else
                      "Warning"   if severity == "MEDIUM" else "Good",
            "wrap":   True,
        },
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "text": description, "wrap": True},
    ]

    if recommendation:
        body.append({
            "type":  "TextBlock",
            "text":  f"**Recommendation:** {recommendation}",
            "wrap":  True,
            "color": "Accent",
        })
    if actions_taken:
        body.append({
            "type": "TextBlock",
            "text": f"**Actions taken:** {actions_taken}",
            "wrap": True,
        })

    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body":    body,
            }
        }]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url     = webhook_url,
            data    = data,
            method  = "POST",
            headers = {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"Teams notification sent: {title}")
            return resp.getcode() == 202
    except Exception as e:
        logger.error(f"Teams notification failed: {e}")
        return False


def notify_teams_scan_complete(agent_name, severity, critical_count,
                                high_count, summary, scan_id,
                                account_id="", account_name=""):   # ← Multi-Account
    if severity not in ("CRITICAL", "HIGH"):
        return False

    account_label = account_name or account_id
    title = f"{agent_name} scan complete — {critical_count} critical, {high_count} high"
    if account_label:
        title = f"[{account_label}] {title}"

    return notify_teams(
        title          = title,
        severity       = severity,
        description    = summary,
        agent_name     = agent_name,
        scan_id        = scan_id,
        recommendation = "Review findings in DynamoDB and address critical items within SLA.",
        account_id     = account_id,
        account_name   = account_name,
    )
