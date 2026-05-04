"""
Cost Anomaly Agent - Anomaly Detector
Pulls active cost anomalies from AWS Cost Anomaly Detection service
and evaluates their impact and affected dimensions.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Anomaly impact thresholds (USD)
CRITICAL_IMPACT = 1000
HIGH_IMPACT     = 250
MEDIUM_IMPACT   = 50


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    days_back    = int(event.get("days_back", 7))
    logger.info(f"Anomaly Detector starting scan_id={scan_id} account={account_id}")

    # Cost Explorer is a global service — always uses governance account credentials
    ce = boto3.client("ce", region_name="us-east-1")

    findings = []
    findings.extend(_check_active_anomalies(ce, days_back, account_id, account_name))
    findings.extend(_check_anomaly_monitors(ce, account_id, account_name))
    findings.extend(_check_anomaly_subscriptions(ce, account_id, account_name))

    logger.info(f"Anomaly Detector complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_active_anomalies(ce, days_back, account_id, account_name):
    findings = []
    try:
        end   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")

        paginator = ce.get_paginator("get_anomalies")
        for page in paginator.paginate(
            DateInterval={"StartDate": start, "EndDate": end},
            Feedback="PLANNED_ACTIVITY"   # exclude already-acknowledged planned spend
        ):
            for anomaly in page.get("Anomalies", []):
                impact      = anomaly.get("Impact", {})
                total_impact = float(impact.get("TotalImpact", 0))
                max_impact   = float(impact.get("MaxImpact", 0))
                anomaly_id   = anomaly.get("AnomalyId", "")
                start_date   = anomaly.get("AnomalyStartDate", "")
                end_date     = anomaly.get("AnomalyEndDate", "ongoing")

                root_causes  = anomaly.get("RootCauses", [])
                rc_summary   = "; ".join(
                    f"{rc.get('Service','?')} / {rc.get('UsageType','?')} in {rc.get('Region','?')}"
                    for rc in root_causes[:3]
                )

                if total_impact >= CRITICAL_IMPACT:
                    severity = "CRITICAL"
                elif total_impact >= HIGH_IMPACT:
                    severity = "HIGH"
                elif total_impact >= MEDIUM_IMPACT:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                findings.append(build_finding(
                    rule_id="COST-ANO-001", severity=severity,
                    resource_type="AWS::CostExplorer::Anomaly",
                    resource_id=anomaly_id,
                    title=f"Cost anomaly detected: ${total_impact:.2f} unexpected spend ({start_date} → {end_date})",
                    description=(
                        f"AWS Cost Anomaly Detection identified unexpected spend of "
                        f"${total_impact:.2f} total (peak ${max_impact:.2f}/day). "
                        f"Root causes: {rc_summary or 'not yet determined'}."
                    ),
                    recommendation=(
                        "Investigate the root cause services and usage types immediately. "
                        "Check for unauthorised resource creation, runaway auto-scaling, or "
                        "misconfigured data transfer. Mark as feedback in Cost Explorer once resolved."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"anomaly_id": anomaly_id, "total_impact_usd": total_impact,
                           "root_causes": root_causes}
                ))
    except Exception as e:
        logger.error(f"Anomaly fetch failed: {e}")
    return findings


def _check_anomaly_monitors(ce, account_id, account_name):
    """Verify at least one anomaly monitor is configured."""
    findings = []
    try:
        resp     = ce.get_anomaly_monitors()
        monitors = resp.get("AnomalyMonitors", [])
        if not monitors:
            findings.append(build_finding(
                rule_id="COST-ANO-002", severity="HIGH",
                resource_type="AWS::CostExplorer::AnomalyMonitor",
                resource_id="no-monitor",
                title="No AWS Cost Anomaly Detection monitors configured",
                description=(
                    "No cost anomaly monitors are set up. AWS Cost Anomaly Detection "
                    "cannot alert on unexpected spend without at least one monitor."
                ),
                recommendation=(
                    "Create an anomaly monitor in Cost Explorer → Cost Anomaly Detection. "
                    "Start with an AWS services monitor, then add linked-account monitors "
                    "for multi-account environments."
                ),
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.error(f"Anomaly monitor check failed: {e}")
    return findings


def _check_anomaly_subscriptions(ce, account_id, account_name):
    """Verify alert subscriptions are configured so anomalies trigger notifications."""
    findings = []
    try:
        resp          = ce.get_anomaly_subscriptions()
        subscriptions = resp.get("AnomalySubscriptions", [])
        if not subscriptions:
            findings.append(build_finding(
                rule_id="COST-ANO-003", severity="MEDIUM",
                resource_type="AWS::CostExplorer::AnomalySubscription",
                resource_id="no-subscription",
                title="No Cost Anomaly Detection alert subscriptions configured",
                description=(
                    "Anomaly monitors exist but no subscriptions are set up. "
                    "Anomalies will be detected but no one will be alerted."
                ),
                recommendation=(
                    "Create an anomaly subscription with an SNS topic or email address "
                    "and set a sensible threshold (e.g. $50 absolute impact)."
                ),
                account_id=account_id, account_name=account_name,
            ))
        else:
            for sub in subscriptions:
                threshold = sub.get("Threshold", 0)
                if threshold == 0:
                    findings.append(build_finding(
                        rule_id="COST-ANO-003b", severity="LOW",
                        resource_type="AWS::CostExplorer::AnomalySubscription",
                        resource_id=sub.get("SubscriptionArn", ""),
                        title=f"Cost anomaly subscription '{sub.get('SubscriptionName')}' alerts on every anomaly (threshold=$0)",
                        description="Zero threshold means every small fluctuation triggers an alert, causing alert fatigue.",
                        recommendation="Set a minimum threshold of $25-$50 to reduce noise while catching significant anomalies.",
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"Anomaly subscription check failed: {e}")
    return findings


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    # Cost Explorer is a global governance-account service — no cross-account session needed
    ce = boto3.client("ce", region_name="us-east-1")
    findings = []
    findings.extend(_check_active_anomalies(ce, 7, account_id, ""))
    findings.extend(_check_anomaly_monitors(ce, account_id, ""))
    findings.extend(_check_anomaly_subscriptions(ce, account_id, ""))
    return findings
