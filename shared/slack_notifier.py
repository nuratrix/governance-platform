"""
Slack Integration — Multi-Account Edition
Added account_id and account_name fields to all Block Kit payloads so
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

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
SLACK_SECRET_ARN  = os.environ.get("SLACK_SECRET_ARN", "")

_cached_webhook_url = None


def _get_webhook_url():
    global _cached_webhook_url
    if SLACK_WEBHOOK_URL:
        return SLACK_WEBHOOK_URL
    if _cached_webhook_url:
        return _cached_webhook_url
    if not SLACK_SECRET_ARN:
        logger.warning("Neither SLACK_WEBHOOK_URL nor SLACK_SECRET_ARN is set")
        return ""
    try:
        sm     = boto3.client("secretsmanager")
        secret = sm.get_secret_value(SecretId=SLACK_SECRET_ARN)
        value  = secret.get("SecretString", "")
        try:
            parsed = json.loads(value)
            url    = parsed.get("url", parsed.get("webhook_url", value))
        except json.JSONDecodeError:
            url = value.strip()
        _cached_webhook_url = url
        return url
    except Exception as e:
        logger.error(f"Failed to fetch Slack webhook URL: {e}")
        return ""


def notify_slack(title, severity, description, resource_id="",
                 recommendation="", agent_name="", actions_taken="",
                 scan_id="",
                 account_id="", account_name=""):   # ← Multi-Account fields
    """Send a Block Kit notification to Slack."""
    webhook_url = _get_webhook_url()
    if not webhook_url:
        return False

    color = {
        "CRITICAL": "#B52B2B", "HIGH": "#C05A00",
        "MEDIUM": "#C4900A",   "LOW":  "#1E7E4E",
    }.get(severity, "#1B4F8A")

    icon = {
        "CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:",
        "MEDIUM": ":large_yellow_circle:", "LOW": ":large_green_circle:",
    }.get(severity, ":large_blue_circle:")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build account label for the message header
    account_label = account_name or account_id
    header_text   = f"{icon} {severity}: {title}"
    if account_label:
        header_text = f"{icon} [{account_label}] {severity}: {title}"

    fields = [f for f in [
        {"type": "mrkdwn", "text": f"*Agent:*\n{agent_name}"}                        if agent_name    else None,
        {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"}                        if severity      else None,
        # ── Multi-Account: account fields ───────────────────────────────────
        {"type": "mrkdwn", "text": f"*Account:*\n`{account_id}`"}                     if account_id    else None,
        {"type": "mrkdwn", "text": f"*Account Name:*\n{account_name}"}                if account_name  else None,
        {"type": "mrkdwn", "text": f"*Resource:*\n`{resource_id}`"}                   if resource_id   else None,
        {"type": "mrkdwn", "text": f"*Time:*\n{timestamp}"}                           if timestamp     else None,
        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"}                        if scan_id       else None,
        {"type": "mrkdwn", "text": f"*Actions Taken:*\n{actions_taken}"}              if actions_taken else None,
    ] if f is not None]

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header_text, "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": description}},
        {"type": "divider"},
        {"type": "section", "fields": fields},
    ]

    if recommendation:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f":bulb: *Recommendation*\n{recommendation}"},
        })

    blocks.append({
        "type": "actions",
        "elements": [{
            "type":  "button",
            "text":  {"type": "plain_text", "text": "View in DynamoDB", "emoji": True},
            "url":   "https://console.aws.amazon.com/dynamodbv2/home?region=us-east-1",
            "style": "primary",
        }]
    })

    payload = {"attachments": [{"color": color, "blocks": blocks}]}
    return _send(webhook_url, payload, title)


def notify_slack_scan_complete(agent_name, severity, critical_count,
                                high_count, summary, scan_id,
                                account_id="", account_name=""):   # ← Multi-Account
    if severity not in ("CRITICAL", "HIGH"):
        return False

    icon        = ":red_circle:" if severity == "CRITICAL" else ":large_orange_circle:"
    webhook_url = _get_webhook_url()
    if not webhook_url:
        return False

    account_label = account_name or account_id
    header_text   = f"{icon} {agent_name} scan complete"
    if account_label:
        header_text = f"{icon} [{account_label}] {agent_name} scan complete"

    fields = [
        {"type": "mrkdwn", "text": f"*Critical:*\n{critical_count}"},
        {"type": "mrkdwn", "text": f"*High:*\n{high_count}"},
        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
        {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"},
    ]
    if account_id:
        fields.insert(0, {"type": "mrkdwn", "text": f"*Account:*\n`{account_id}`"})
    if account_name:
        fields.insert(1, {"type": "mrkdwn", "text": f"*Account Name:*\n{account_name}"})

    payload = {
        "attachments": [{
            "color": "#B52B2B" if severity == "CRITICAL" else "#C05A00",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": header_text, "emoji": True}},
                {"type": "section", "fields": fields},
                {"type": "section", "text": {"type": "mrkdwn", "text": summary[:500] if summary else "Scan complete."}},
            ]
        }]
    }

    return _send(webhook_url, payload, f"{agent_name} scan complete")


def _send(webhook_url, payload, title):
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url     = webhook_url,
            data    = data,
            method  = "POST",
            headers = {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body   = resp.read().decode("utf-8")
            status = resp.getcode()
            if status == 200 and body == "ok":
                logger.info(f"Slack notification sent: {title}")
                return True
            logger.warning(f"Slack returned HTTP {status}: {body}")
            return False
    except urllib.error.HTTPError as e:
        logger.error(f"Slack HTTP error {e.code}: {e.read().decode()}")
        return False
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
        return False
