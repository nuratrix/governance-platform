"""
Cost Anomaly Agent - Root Cause Analyzer
Pulls per-service, per-account, and per-region cost breakdowns to help
identify the root cause of unexpected spend spikes detected by anomaly detection.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Minimum spend increase (USD/day) to flag as a root cause contributor
SPIKE_THRESHOLD = 10.0


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    days_back    = int(event.get("days_back", 7))
    compare_days = int(event.get("compare_days", 14))  # baseline window before the spike window
    logger.info(f"Root Cause Analyzer starting scan_id={scan_id} account={account_id}")

    ce = boto3.client("ce", region_name="us-east-1")

    findings = []
    findings.extend(_check_service_spend_spikes(ce, days_back, compare_days, account_id, account_name))
    findings.extend(_check_linked_account_spikes(ce, days_back, compare_days, account_id, account_name))
    findings.extend(_check_region_spend_spikes(ce, days_back, compare_days, account_id, account_name))

    logger.info(f"Root Cause Analyzer complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _date_range(days_back, offset=0):
    """Return (start, end) YYYY-MM-DD strings for a window ending `offset` days ago."""
    now   = datetime.now(timezone.utc)
    end   = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
    start = (now - timedelta(days=offset + days_back)).strftime("%Y-%m-%d")
    return start, end


def _get_cost_by_dimension(ce, start, end, group_by_key):
    """Return dict of {dimension_value: total_cost_usd}."""
    totals = {}
    try:
        paginator = ce.get_paginator("get_cost_and_usage")
        for page in paginator.paginate(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": group_by_key}]
        ):
            for result_by_time in page.get("ResultsByTime", []):
                for group in result_by_time.get("Groups", []):
                    key  = group["Keys"][0]
                    cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    totals[key] = totals.get(key, 0.0) + cost
    except Exception as e:
        logger.warning(f"get_cost_and_usage ({group_by_key}) failed: {e}")
    return totals


# ─── Checks ───────────────────────────────────────────────────────────────────

def _check_service_spend_spikes(ce, days_back, compare_days, account_id, account_name):
    """Compare current-window service spend against baseline to find spikes."""
    findings = []
    try:
        spike_start,    spike_end    = _date_range(days_back)
        baseline_start, baseline_end = _date_range(compare_days, offset=days_back)

        current  = _get_cost_by_dimension(ce, spike_start, spike_end, "SERVICE")
        baseline = _get_cost_by_dimension(ce, baseline_start, baseline_end, "SERVICE")

        # Normalise to per-day averages for a fair comparison
        current_daily  = {k: v / days_back  for k, v in current.items()}
        baseline_daily = {k: v / compare_days for k, v in baseline.items()}

        for service, cur_daily in current_daily.items():
            base_daily  = baseline_daily.get(service, 0.0)
            delta_daily = cur_daily - base_daily

            if delta_daily < SPIKE_THRESHOLD:
                continue

            pct_change = ((delta_daily - base_daily) / base_daily * 100) if base_daily > 0 else 9999.0

            if pct_change >= 200 or delta_daily >= 100:
                severity = "CRITICAL"
            elif pct_change >= 100 or delta_daily >= 50:
                severity = "HIGH"
            elif pct_change >= 50 or delta_daily >= SPIKE_THRESHOLD:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            findings.append(build_finding(
                rule_id="COST-RCA-001", severity=severity,
                resource_type="AWS::CostExplorer::ServiceSpike",
                resource_id=service,
                title=f"Spend spike detected for {service}: +${delta_daily:.2f}/day ({pct_change:.0f}% increase)",
                description=(
                    f"Service '{service}' averaged ${cur_daily:.2f}/day over the last {days_back} days "
                    f"versus ${base_daily:.2f}/day in the prior {compare_days}-day baseline — "
                    f"an increase of ${delta_daily:.2f}/day ({pct_change:.0f}%). "
                    f"Total unexpected spend this window: ~${delta_daily * days_back:.2f}."
                ),
                recommendation=(
                    f"Investigate new or changed resources in {service}. "
                    "Open Cost Explorer → Filter by SERVICE, set the date to the spike window, "
                    "then group by USAGE_TYPE and RESOURCE_ID to pinpoint the specific resource."
                ),
                account_id=account_id, account_name=account_name,
                extra={
                    "service": service,
                    "current_daily_usd": round(cur_daily, 2),
                    "baseline_daily_usd": round(base_daily, 2),
                    "delta_daily_usd": round(delta_daily, 2),
                    "pct_change": round(pct_change, 1),
                    "spike_window_days": days_back,
                }
            ))
    except Exception as e:
        logger.error(f"Service spike check failed: {e}")
    return findings


def _check_linked_account_spikes(ce, days_back, compare_days, account_id, account_name):
    """Flag linked accounts whose spend has increased significantly."""
    findings = []
    try:
        spike_start,    spike_end    = _date_range(days_back)
        baseline_start, baseline_end = _date_range(compare_days, offset=days_back)

        current  = _get_cost_by_dimension(ce, spike_start, spike_end, "LINKED_ACCOUNT")
        baseline = _get_cost_by_dimension(ce, baseline_start, baseline_end, "LINKED_ACCOUNT")

        current_daily  = {k: v / days_back  for k, v in current.items()}
        baseline_daily = {k: v / compare_days for k, v in baseline.items()}

        for acct, cur_daily in current_daily.items():
            # Skip the governance account itself — we care about member accounts
            if acct == account_id:
                continue
            base_daily  = baseline_daily.get(acct, 0.0)
            delta_daily = cur_daily - base_daily

            if delta_daily < SPIKE_THRESHOLD:
                continue

            pct_change = ((delta_daily - base_daily) / base_daily * 100) if base_daily > 0 else 9999.0

            severity = "HIGH" if (pct_change >= 100 or delta_daily >= 50) else "MEDIUM"

            findings.append(build_finding(
                rule_id="COST-RCA-002", severity=severity,
                resource_type="AWS::Organizations::Account",
                resource_id=acct,
                title=f"Linked account {acct} spend spike: +${delta_daily:.2f}/day ({pct_change:.0f}%)",
                description=(
                    f"AWS account {acct} averaged ${cur_daily:.2f}/day over the last {days_back} days "
                    f"versus ${base_daily:.2f}/day in the prior baseline — "
                    f"an increase of ${delta_daily:.2f}/day. "
                    f"Investigate resources recently created or modified in this account."
                ),
                recommendation=(
                    "Switch to the affected account in Cost Explorer and filter by SERVICE. "
                    "Check CloudTrail for recent CreateResource or RunInstances events. "
                    "Ensure the account has appropriate budget alerts and SCPs."
                ),
                account_id=account_id, account_name=account_name,
                extra={
                    "linked_account_id": acct,
                    "current_daily_usd": round(cur_daily, 2),
                    "baseline_daily_usd": round(base_daily, 2),
                    "delta_daily_usd": round(delta_daily, 2),
                    "pct_change": round(pct_change, 1),
                }
            ))
    except Exception as e:
        logger.error(f"Linked account spike check failed: {e}")
    return findings


def _check_region_spend_spikes(ce, days_back, compare_days, account_id, account_name):
    """Flag regions with unexpected spend increases — useful for detecting region-sprawl."""
    findings = []
    try:
        spike_start,    spike_end    = _date_range(days_back)
        baseline_start, baseline_end = _date_range(compare_days, offset=days_back)

        current  = _get_cost_by_dimension(ce, spike_start, spike_end, "REGION")
        baseline = _get_cost_by_dimension(ce, baseline_start, baseline_end, "REGION")

        current_daily  = {k: v / days_back  for k, v in current.items()}
        baseline_daily = {k: v / compare_days for k, v in baseline.items()}

        for region, cur_daily in current_daily.items():
            if region in ("NoRegion", "global"):
                continue
            base_daily  = baseline_daily.get(region, 0.0)
            delta_daily = cur_daily - base_daily

            if delta_daily < SPIKE_THRESHOLD:
                continue

            # New regions (no baseline) are always worth flagging
            new_region  = base_daily == 0.0
            pct_change  = 9999.0 if new_region else ((delta_daily / base_daily) * 100)
            severity    = "HIGH" if new_region else ("MEDIUM" if pct_change >= 100 else "LOW")

            findings.append(build_finding(
                rule_id="COST-RCA-003", severity=severity,
                resource_type="AWS::CostExplorer::RegionSpike",
                resource_id=region,
                title=(
                    f"{'New region' if new_region else 'Spend spike'} detected in {region}: "
                    f"+${delta_daily:.2f}/day"
                ),
                description=(
                    f"Region '{region}' is generating ${cur_daily:.2f}/day in spend "
                    f"(baseline was ${base_daily:.2f}/day). "
                    + ("This region had no prior spend — it may be newly enabled or an anomaly." if new_region
                       else f"That is a {pct_change:.0f}% increase over the baseline period.")
                ),
                recommendation=(
                    f"Review all resources in region {region}. "
                    "Use Cost Explorer → Filter by REGION, group by SERVICE, to identify the top services. "
                    + ("If this region should not be used, apply an SCP to deny resource creation there."
                       if new_region else
                       "Check for unintended cross-region data transfer or resource replication.")
                ),
                account_id=account_id, account_name=account_name,
                extra={
                    "region": region,
                    "current_daily_usd": round(cur_daily, 2),
                    "baseline_daily_usd": round(base_daily, 2),
                    "delta_daily_usd": round(delta_daily, 2),
                    "new_region": new_region,
                }
            ))
    except Exception as e:
        logger.error(f"Region spike check failed: {e}")
    return findings


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    # Cost Explorer is a global governance-account service — no cross-account session needed
    ce = boto3.client("ce", region_name="us-east-1")
    findings = []
    findings.extend(_check_service_spend_spikes(ce, 7, 14, account_id, ""))
    findings.extend(_check_linked_account_spikes(ce, 7, 14, account_id, ""))
    findings.extend(_check_region_spend_spikes(ce, 7, 14, account_id, ""))
    return findings
