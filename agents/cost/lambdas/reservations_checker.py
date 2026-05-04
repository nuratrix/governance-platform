"""
Cost Agent - Reservations Checker (Multi-Account Edition)
Analyses Reserved Instance and Savings Plan coverage, utilisation,
and identifies on-demand spend that could be covered by reservations.
Rules: COST-RI-001 through COST-RI-005

Note: Cost Explorer is a global governance-account service. For member
accounts a LINKED_ACCOUNT filter is applied rather than assuming a role.
The `session` parameter is accepted but CE calls always use the governance
account. The `account_id` filter scopes CE data to the target account.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id              = event.get("scan_id", "manual")
    account_id           = event.get("account_id", "")
    account_name         = event.get("account_name", "")
    lookback_days        = int(event.get("lookback_days", 30))
    min_saving_threshold = float(event.get("min_saving_threshold", 50))

    # Cost Explorer is governance-account only — always use the local client.
    # For member accounts we apply a LINKED_ACCOUNT filter on all CE calls.
    ce = boto3.client("ce")

    # For expiring RI check we need EC2 from the target account
    s   = session or boto3
    ec2 = s.client("ec2")

    logger.info(f"Reservations check for {account_id} — lookback={lookback_days}d")

    findings = []
    findings += _check_ri_coverage(ce, lookback_days, min_saving_threshold, account_id, account_name)
    findings += _check_ri_utilisation(ce, account_id, account_name)
    findings += _check_expiring_reservations(ec2, account_id, account_name)
    findings += _check_savings_plan_coverage(ce, lookback_days, account_id, account_name)
    findings += _get_ri_recommendations(ce, min_saving_threshold, account_id, account_name)

    for f in findings:
        f["region"] = "global"
    total_saving    = sum(f.get("estimated_monthly_saving", 0) for f in findings)
    coverage_pct    = _get_ri_coverage_percentage(ce, lookback_days, account_id)
    utilisation_pct = _get_ri_utilisation_percentage(ce, account_id)
    expiring        = len([f for f in findings if "COST-RI-003" in f.get("rule_id", "")])

    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
        "summary": {
            "total_findings":            len(findings),
            "total_potential_saving":    round(total_saving, 2),
            "ri_coverage_percentage":    round(coverage_pct, 1),
            "ri_utilisation_percentage": round(utilisation_pct, 1),
            "expiring_reservations":     expiring,
        }
    }


def _account_filter(account_id):
    """Build a CE filter for a specific linked account."""
    if not account_id:
        return None
    return {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account_id]}}


def _get_ri_coverage_percentage(ce, lookback_days, account_id):
    try:
        end    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start  = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        kwargs = {"TimePeriod": {"Start": start, "End": end}, "Granularity": "MONTHLY"}
        filt   = _account_filter(account_id)
        if filt:
            kwargs["Filter"] = filt
        resp   = ce.get_reservation_coverage(**kwargs)
        totals = resp.get("Total", {})
        return float(totals.get("CoverageHours", {}).get("CoverageHoursPercentage", 0))
    except Exception as e:
        logger.warning(f"Could not get RI coverage: {e}")
        return 0.0


def _get_ri_utilisation_percentage(ce, account_id):
    try:
        end    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start  = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        kwargs = {"TimePeriod": {"Start": start, "End": end}, "Granularity": "MONTHLY"}
        filt   = _account_filter(account_id)
        if filt:
            kwargs["Filter"] = filt
        resp  = ce.get_reservation_utilization(**kwargs)
        total = resp.get("Total", {})
        return float(total.get("UtilizationPercentage", 0))
    except Exception as e:
        logger.warning(f"Could not get RI utilisation: {e}")
        return 0.0


def _check_ri_coverage(ce, lookback_days, min_saving_threshold, account_id, account_name):
    findings = []
    try:
        end    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start  = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        kwargs = {
            "TimePeriod":  {"Start": start, "End": end},
            "Granularity": "MONTHLY",
            "GroupBy":     [{"Type": "DIMENSION", "Key": "SERVICE"}],
        }
        filt = _account_filter(account_id)
        if filt:
            kwargs["Filter"] = filt
        resp = ce.get_reservation_coverage(**kwargs)

        for group in resp.get("ResultsByTime", [{}])[-1].get("Groups", []):
            service        = group["Keys"][0]
            coverage       = group.get("Coverage", {})
            pct            = float(coverage.get("CoverageHours", {}).get("CoverageHoursPercentage", 100))
            on_demand_cost = float(coverage.get("CoverageCost", {}).get("OnDemandCost", 0))
            monthly_cost   = on_demand_cost * (30 / lookback_days)
            saving         = monthly_cost * 0.35

            if pct < 50 and saving >= min_saving_threshold:
                severity = "HIGH" if pct < 20 else "MEDIUM"
                findings.append({
                    **build_finding(
                        rule_id        = "COST-RI-001",
                        severity       = severity,
                        resource_type  = "AWS::CostExplorer::ReservationCoverage",
                        resource_id    = service,
                        title          = f"Low RI coverage for {service} — {pct:.0f}% covered",
                        description    = (
                            f"{service} has {pct:.0f}% RI coverage. Monthly on-demand cost: ${monthly_cost:.2f}."
                        ),
                        recommendation = (
                            f"Purchase RIs or a Savings Plan for {service}. "
                            f"Estimated saving: ${saving:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(saving, 2),
                    "coverage_percentage":      round(pct, 1),
                    "payment_option":           "NO_UPFRONT",
                    "term":                     "ONE_YEAR",
                })

    except Exception as e:
        logger.error(f"RI coverage check failed: {e}")
    return findings


def _check_ri_utilisation(ce, account_id, account_name):
    findings = []
    try:
        end    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start  = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        kwargs = {
            "TimePeriod":  {"Start": start, "End": end},
            "Granularity": "MONTHLY",
            "GroupBy":     [{"Type": "DIMENSION", "Key": "SUBSCRIPTION_ID"}],
        }
        filt = _account_filter(account_id)
        if filt:
            kwargs["Filter"] = filt
        resp = ce.get_reservation_utilization(**kwargs)

        for group in resp.get("ResultsByTime", [{}])[-1].get("Groups", []):
            sub_id      = group["Keys"][0]
            utilisation = group.get("Utilization", {})
            pct         = float(utilisation.get("UtilizationPercentage", 100))
            unused_cost = (
                float(utilisation.get("UnusedAmortizedUpfrontFeeForBillingPeriod", 0)) +
                float(utilisation.get("UnusedRecurringFee", 0))
            )

            if pct < 80 and unused_cost > 20:
                findings.append({
                    **build_finding(
                        rule_id        = "COST-RI-002",
                        severity       = "MEDIUM",
                        resource_type  = "AWS::CostExplorer::ReservationUtilization",
                        resource_id    = sub_id,
                        title          = f"Underutilised reservation — {pct:.0f}% utilised",
                        description    = (
                            f"Reserved Instance {sub_id} is {pct:.0f}% utilised. "
                            f"Wasted spend: ${unused_cost:.2f}/month."
                        ),
                        recommendation = (
                            "Sell on the AWS Marketplace or modify to match current usage. "
                            f"Wasted spend: ${unused_cost:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(unused_cost, 2),
                    "payment_option": "",
                    "term":           "",
                })

    except Exception as e:
        logger.error(f"RI utilisation check failed: {e}")
    return findings


def _check_expiring_reservations(ec2, account_id, account_name):
    findings = []
    try:
        resp = ec2.describe_reserved_instances(
            Filters=[{"Name": "state", "Values": ["active"]}]
        )
        now = datetime.now(timezone.utc)
        for ri in resp.get("ReservedInstances", []):
            end_date = ri.get("End")
            if not end_date:
                continue
            end_date  = end_date.replace(tzinfo=timezone.utc)
            days_left = (end_date - now).days

            if days_left <= 60:
                severity = "HIGH" if days_left <= 30 else "MEDIUM"
                findings.append({
                    **build_finding(
                        rule_id        = "COST-RI-003",
                        severity       = severity,
                        resource_type  = "AWS::EC2::ReservedInstances",
                        resource_id    = ri["ReservedInstancesId"],
                        title          = f"Reservation expiring in {days_left} days — {ri['InstanceType']}",
                        description    = (
                            f"RI {ri['ReservedInstancesId']} ({ri['InstanceCount']}x {ri['InstanceType']}) "
                            f"expires in {days_left} days on {end_date.strftime('%Y-%m-%d')}."
                        ),
                        recommendation = (
                            "Renew if still needed. On-demand pricing is 30-60% more expensive."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": 0,
                    "days_until_expiry":        days_left,
                    "expiry_date":              end_date.strftime("%Y-%m-%d"),
                    "payment_option":           ri.get("OfferingType", ""),
                    "term":                     "",
                })

    except Exception as e:
        logger.error(f"Expiring reservations check failed: {e}")
    return findings


def _check_savings_plan_coverage(ce, lookback_days, account_id, account_name):
    findings = []
    try:
        end    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        start  = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
        kwargs = {"TimePeriod": {"Start": start, "End": end}, "Granularity": "MONTHLY"}
        filt   = _account_filter(account_id)
        if filt:
            kwargs["Filter"] = filt
        resp = ce.get_savings_plans_coverage(**kwargs)

        for period in resp.get("SavingsPlansCoverages", []):
            coverage       = period.get("Coverage", {})
            pct            = float(coverage.get("CoveragePercentage", 100))
            on_demand_cost = float(coverage.get("OnDemandCost", 0))
            monthly_cost   = on_demand_cost * (30 / lookback_days)
            saving         = monthly_cost * 0.20

            if pct < 60 and saving > 50:
                findings.append({
                    **build_finding(
                        rule_id        = "COST-RI-004",
                        severity       = "MEDIUM",
                        resource_type  = "AWS::CostExplorer::SavingsPlanCoverage",
                        resource_id    = "account",
                        title          = f"Low Savings Plan coverage — {pct:.0f}% of eligible spend covered",
                        description    = (
                            f"Only {pct:.0f}% of eligible compute spend is covered by Savings Plans. "
                            f"On-demand eligible spend: ~${monthly_cost:.2f}/month."
                        ),
                        recommendation = (
                            "Purchase a Compute Savings Plan. "
                            f"Estimated saving: ${saving:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(saving, 2),
                    "coverage_percentage":      round(pct, 1),
                    "payment_option":           "NO_UPFRONT",
                    "term":                     "ONE_YEAR",
                })

    except Exception as e:
        logger.warning(f"Savings Plan coverage check failed: {e}")
    return findings


def _get_ri_recommendations(ce, min_saving_threshold, account_id, account_name):
    findings = []
    try:
        kwargs = {
            "Service":               "Amazon EC2",
            "LookbackPeriodInDays":  "THIRTY_DAYS",
            "TermInYears":           "ONE_YEAR",
            "PaymentOption":         "NO_UPFRONT",
        }
        if account_id:
            kwargs["AccountId"] = account_id
            kwargs["AccountScope"] = "LINKED"

        resp = ce.get_reservation_purchase_recommendation(**kwargs)

        for rec in resp.get("Recommendations", []):
            summary          = rec.get("RecommendationSummary", {})
            estimated_saving = float(summary.get("EstimatedMonthlySavingsAmount", 0))
            if estimated_saving < min_saving_threshold:
                continue

            for detail in rec.get("RecommendationDetails", [])[:3]:
                ec2_details   = detail.get("InstanceDetails", {}).get("EC2InstanceDetails", {})
                instance_type = ec2_details.get("InstanceType", "unknown")
                region        = ec2_details.get("Region", "")
                recommended   = int(detail.get("RecommendedNumberOfInstancesToPurchase", 0))
                detail_saving = float(detail.get("EstimatedMonthlySavingsAmount", 0))

                if detail_saving < 10:
                    continue

                findings.append({
                    **build_finding(
                        rule_id        = "COST-RI-005",
                        severity       = "LOW",
                        resource_type  = "AWS::CostExplorer::RIRecommendation",
                        resource_id    = f"{instance_type}-{region}",
                        title          = f"RI purchase recommended — {recommended}x {instance_type} in {region}",
                        description    = (
                            f"AWS recommends {recommended} RI(s) of type {instance_type} in {region}."
                        ),
                        recommendation = (
                            f"Purchase {recommended}x {instance_type} 1-year No Upfront RI in {region}. "
                            f"Estimated saving: ${detail_saving:.2f}/month."
                        ),
                        auto_remediable = False,
                        account_id=account_id, account_name=account_name,
                    ),
                    "estimated_monthly_saving": round(detail_saving, 2),
                    "recommended_count":        recommended,
                    "instance_type":            instance_type,
                    "region":                   region,
                    "payment_option":           "NO_UPFRONT",
                    "term":                     "ONE_YEAR",
                })

    except Exception as e:
        logger.warning(f"RI recommendations failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    # Cost Explorer is a global governance-account service
    ce = boto3.client("ce")
    session = _get_session(account_id)
    ec2 = session.client("ec2", region_name=region)
    findings = []
    findings.extend(_check_ri_coverage(ce, 30, 50.0, account_id, ""))
    findings.extend(_check_ri_utilisation(ce, account_id, ""))
    findings.extend(_check_expiring_reservations(ec2, account_id, ""))
    findings.extend(_check_savings_plan_coverage(ce, 30, account_id, ""))
    findings.extend(_get_ri_recommendations(ce, 50.0, account_id, ""))
    return findings
