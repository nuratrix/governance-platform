"""
Security Agent - Main Orchestrator — Multi-Account Edition
Passes account_id through to all sub-checkers and includes account_id
in DynamoDB findings and SNS notifications.
"""

import json
import boto3
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client("lambda")
sns_client    = boto3.client("sns")
dynamodb      = boto3.resource("dynamodb")

FINDINGS_TABLE         = os.environ.get("FINDINGS_TABLE", "governance-platform-findings")
ALERT_TOPIC_ARN        = os.environ.get("ALERT_TOPIC_ARN", "")
ORCHESTRATOR_TOPIC_ARN = os.environ.get("ORCHESTRATOR_TOPIC_ARN", "")
GOVERNANCE_ACCOUNT_ID  = os.environ.get("GOVERNANCE_ACCOUNT_ID", "")

SUB_AGENTS = {
    "iam":        os.environ.get("IAM_CHECKER_FN",  "governance-security-iam-checker"),
    "s3":         os.environ.get("S3_CHECKER_FN",   "governance-security-s3-checker"),
    "sg":         os.environ.get("SG_CHECKER_FN",   "governance-security-sg-checker"),
    "cloudtrail": os.environ.get("CT_CHECKER_FN",   "governance-security-cloudtrail-checker"),
    "guardduty":  os.environ.get("GD_CHECKER_FN",   "governance-security-guardduty-checker"),
    "kms":        os.environ.get("KMS_CHECKER_FN",  "governance-security-kms-checker"),
}

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def lambda_handler(event, context):
    logger.info(f"Security Agent Orchestrator triggered: {json.dumps(event)}")

    scan_type    = event.get("scan_type", "full")
    targets      = event.get("targets", list(SUB_AGENTS.keys()))
    triggered_by = event.get("triggered_by", "scheduled")
    # ── Multi-Account ───────────────────────────────────────────────────────
    account_id   = event.get("account_id", GOVERNANCE_ACCOUNT_ID)
    account_name = event.get("account_name", "governance-account")

    scan_id = f"scan-{account_id}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    logger.info(f"Starting scan_id={scan_id} account={account_id} targets={targets}")

    all_findings = []
    errors       = []

    for agent_key in targets:
        fn_name = SUB_AGENTS.get(agent_key)
        if not fn_name:
            logger.warning(f"Unknown agent key: {agent_key}")
            continue
        try:
            resp    = lambda_client.invoke(
                FunctionName  = fn_name,
                InvocationType = "RequestResponse",
                Payload       = json.dumps({
                    "scan_id":      scan_id,
                    "account_id":   account_id,
                    "account_name": account_name,
                }),
            )
            payload = json.loads(resp["Payload"].read())
            if resp.get("FunctionError"):
                errors.append({"agent": agent_key, "error": payload})
                logger.error(f"Sub-agent {agent_key} error: {payload}")
            else:
                findings = payload.get("findings", [])
                all_findings.extend(findings)
                logger.info(f"Agent {agent_key} returned {len(findings)} findings")
        except Exception as e:
            errors.append({"agent": agent_key, "error": str(e)})
            logger.error(f"Failed to invoke {agent_key}: {e}")

    all_findings     = _deduplicate(all_findings)
    risk_score       = _calculate_risk_score(all_findings)
    critical_findings = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high_findings    = [f for f in all_findings if f.get("severity") == "HIGH"]

    _persist_findings(scan_id, all_findings, risk_score, account_id, account_name)
    remediated = _auto_remediate(all_findings)

    if critical_findings or high_findings:
        _send_alert(scan_id, critical_findings, high_findings, risk_score, account_id, account_name)

    _notify_orchestrator(scan_id, all_findings, risk_score, errors, account_id, account_name)

    return {
        "scan_id":        scan_id,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "triggered_by":   triggered_by,
        "account_id":     account_id,
        "account_name":   account_name,
        "risk_score":     risk_score,
        "total_findings": len(all_findings),
        "critical":       len(critical_findings),
        "high":           len(high_findings),
        "medium":         len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
        "low":            len([f for f in all_findings if f.get("severity") == "LOW"]),
        "auto_remediated": remediated,
        "errors":         errors,
        "findings":       all_findings,
    }


def _deduplicate(findings):
    seen, unique = set(), []
    for f in findings:
        key = f"{f.get('rule_id')}-{f.get('resource_id')}-{f.get('account_id', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _calculate_risk_score(findings):
    if not findings:
        return 0
    total       = sum(SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 0) for f in findings)
    max_possible = len(findings) * SEVERITY_WEIGHTS["CRITICAL"]
    return round((total / max_possible) * 100, 1) if max_possible > 0 else 0


def _persist_findings(scan_id, findings, risk_score, account_id, account_name):
    try:
        table = dynamodb.Table(FINDINGS_TABLE)
        table.put_item(Item={
            "scan_id":        scan_id,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "agent":          "governance-security-agent",
            "risk_score":     str(risk_score),
            "total_findings": len(findings),
            "findings":       json.dumps(findings),
            "account_id":     account_id,
            "account_name":   account_name,
            "ttl":            int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })
    except Exception as e:
        logger.error(f"Failed to persist findings: {e}")


def _auto_remediate(findings):
    remediated = []
    ec2 = boto3.client("ec2")
    for finding in findings:
        if finding.get("severity") not in ("LOW",):
            continue
        if finding.get("auto_remediable") and finding.get("remediation_action"):
            action = finding["remediation_action"]
            try:
                if action["type"] == "revoke_sg_rule":
                    ec2.revoke_security_group_ingress(
                        GroupId=action["group_id"],
                        IpPermissions=action["ip_permissions"],
                    )
                    remediated.append(finding["rule_id"])
                    finding["status"] = "REMEDIATED"
            except Exception as e:
                logger.warning(f"Auto-remediation failed for {finding['rule_id']}: {e}")
    return remediated


def _send_alert(scan_id, critical, high, risk_score, account_id, account_name):
    if not ALERT_TOPIC_ARN:
        return
    account_label = account_name or account_id
    try:
        sns_client.publish(
            TopicArn = ALERT_TOPIC_ARN,
            Subject  = f"[SECURITY ALERT][{account_label}] Risk Score {risk_score} - {len(critical)} Critical",
            Message  = json.dumps({
                "scan_id":        scan_id,
                "risk_score":     risk_score,
                "account_id":     account_id,
                "account_name":   account_name,
                "critical_count": len(critical),
                "high_count":     len(high),
                "critical_findings": critical[:5],
            }, indent=2),
        )
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")


def _notify_orchestrator(scan_id, findings, risk_score, errors, account_id, account_name):
    if not ORCHESTRATOR_TOPIC_ARN:
        return
    try:
        sns_client.publish(
            TopicArn = ORCHESTRATOR_TOPIC_ARN,
            Subject  = "SecurityAgent:ScanComplete",
            Message  = json.dumps({
                "agent":          "security",
                "scan_id":        scan_id,
                "risk_score":     risk_score,
                "total_findings": len(findings),
                "needs_attention": risk_score > 50,
                "account_id":     account_id,
                "account_name":   account_name,
                "errors":         errors,
            }),
            MessageAttributes={
                "agent":      {"DataType": "String", "StringValue": "security"},
                "event":      {"DataType": "String", "StringValue": "scan_complete"},
                "account_id": {"DataType": "String", "StringValue": account_id},
            },
        )
    except Exception as e:
        logger.error(f"Failed to notify orchestrator: {e}")
