"""
Backup & DR Agent - Backup Plan Checker
Audits AWS Backup plans, vaults, and coverage to ensure critical resources
have appropriate backup policies with sufficient retention and frequency.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Minimum backup frequency (hours) and retention (days) thresholds
MIN_DAILY_BACKUP_RETENTION_DAYS = 7
MIN_MONTHLY_BACKUP_RETENTION_DAYS = 30


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    findings = []
    for region in get_scan_regions(session):
        backup = session.client("backup", region_name=region) if session else boto3.client("backup", region_name=region)
        ec2    = session.client("ec2", region_name=region)    if session else boto3.client("ec2", region_name=region)
        region_findings = []
        region_findings.extend(_check_backup_plans_exist(backup, account_id, account_name))
        region_findings.extend(_check_plan_retention(backup, account_id, account_name))
        region_findings.extend(_check_unprotected_resources(backup, ec2, account_id, account_name))
        region_findings.extend(_check_cross_region_backup(backup, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Backup Plan Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_backup_plans_exist(backup, account_id, account_name):
    findings = []
    try:
        resp  = backup.list_backup_plans()
        plans = resp.get("BackupPlansList", [])
        if not plans:
            findings.append(build_finding(
                rule_id="BDR-001", severity="CRITICAL",
                resource_type="AWS::Backup::BackupPlan",
                resource_id="no-backup-plan",
                title="No AWS Backup plans configured in this account",
                description=(
                    "No AWS Backup plans are configured. Without backup plans, "
                    "EC2 instances, RDS databases, EFS file systems, and DynamoDB tables "
                    "have no automated backup protection. This is a critical DR gap."
                ),
                recommendation=(
                    "Create AWS Backup plans immediately. At minimum, configure:\n"
                    "1. Daily backups with 7-day retention for all production resources\n"
                    "2. Weekly backups with 30-day retention for compliance\n"
                    "3. Monthly backups with 1-year retention for regulated workloads\n"
                    "Use resource tags (e.g. Backup=required) to automatically assign resources."
                ),
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.error(f"Backup plan existence check failed: {e}")
    return findings


def _check_plan_retention(backup, account_id, account_name):
    """Flag backup rules with insufficient retention periods."""
    findings = []
    try:
        resp  = backup.list_backup_plans()
        plans = resp.get("BackupPlansList", [])
        for plan_meta in plans:
            plan_id   = plan_meta["BackupPlanId"]
            plan_name = plan_meta.get("BackupPlanName", plan_id)
            try:
                plan_detail = backup.get_backup_plan(BackupPlanId=plan_id)
                rules       = plan_detail.get("BackupPlan", {}).get("Rules", [])
                for rule in rules:
                    rule_name       = rule.get("RuleName", "unnamed")
                    lifecycle        = rule.get("Lifecycle", {})
                    delete_after     = lifecycle.get("DeleteAfterDays", 0)
                    schedule         = rule.get("ScheduleExpression", "")
                    is_daily         = "* * ? *" in schedule or "0 * ? *" in schedule

                    min_retention    = MIN_DAILY_BACKUP_RETENTION_DAYS if is_daily else MIN_MONTHLY_BACKUP_RETENTION_DAYS

                    if delete_after and delete_after < min_retention:
                        findings.append(build_finding(
                            rule_id="BDR-002", severity="HIGH",
                            resource_type="AWS::Backup::BackupPlan",
                            resource_id=f"{plan_name}/{rule_name}",
                            title=f"Backup plan '{plan_name}' rule '{rule_name}' retains backups only {delete_after} days",
                            description=(
                                f"Backup plan '{plan_name}' rule '{rule_name}' has a retention of "
                                f"only {delete_after} days. The recommended minimum is {min_retention} days "
                                f"for {'daily' if is_daily else 'non-daily'} backups. "
                                "Short retention periods increase recovery point objective (RPO) risk."
                            ),
                            recommendation=(
                                f"Increase the DeleteAfterDays for rule '{rule_name}' "
                                f"to at least {min_retention} days. "
                                "For regulated workloads, align with compliance requirements "
                                "(e.g. HIPAA: 6 years, PCI-DSS: 1 year)."
                            ),
                            account_id=account_id, account_name=account_name,
                            extra={"plan_id": plan_id, "plan_name": plan_name, "rule_name": rule_name,
                                   "delete_after_days": delete_after}
                        ))
            except Exception as e:
                logger.warning(f"Could not get plan detail for {plan_id}: {e}")
    except Exception as e:
        logger.error(f"Backup retention check failed: {e}")
    return findings


def _check_unprotected_resources(backup, ec2, account_id, account_name):
    """Check for EC2 instances not covered by any backup plan."""
    findings = []
    try:
        # Get all protected resources
        protected_arns = set()
        paginator = backup.get_paginator("list_protected_resources")
        for page in paginator.paginate():
            for resource in page.get("Results", []):
                protected_arns.add(resource.get("ResourceArn", ""))

        # Check EC2 instances
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        ).get("Reservations", [])

        unprotected = []
        for res in reservations:
            for inst in res.get("Instances", []):
                inst_id  = inst["InstanceId"]
                region   = "us-east-1"  # simplified; full implementation would use region from ARN
                arn      = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
                tags     = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                env_tag  = tags.get("Environment", tags.get("Env", "")).lower()
                name_tag = tags.get("Name", inst_id)

                if arn not in protected_arns and env_tag in ("production", "prod", "staging"):
                    unprotected.append((inst_id, name_tag, env_tag))

        if unprotected:
            resource_list = ", ".join(f"{name} ({inst_id})" for inst_id, name, _ in unprotected[:10])
            findings.append(build_finding(
                rule_id="BDR-003", severity="HIGH",
                resource_type="AWS::EC2::Instance",
                resource_id="unprotected-instances",
                title=f"{len(unprotected)} production/staging EC2 instance(s) not covered by AWS Backup",
                description=(
                    f"{len(unprotected)} EC2 instances tagged as production or staging "
                    f"are not protected by any AWS Backup plan. "
                    f"Instances: {resource_list}"
                    + (f" (and {len(unprotected) - 10} more)" if len(unprotected) > 10 else "") + "."
                ),
                recommendation=(
                    "Add these instances to a backup plan. "
                    "The easiest approach is to tag them with Backup=required and create a "
                    "backup plan that uses a tag-based resource assignment. "
                    "Alternatively, create specific backup selections per resource ARN."
                ),
                account_id=account_id, account_name=account_name,
                extra={"unprotected_count": len(unprotected),
                       "unprotected_instances": [i for i, _, _ in unprotected[:20]]}
            ))
    except Exception as e:
        logger.error(f"Unprotected resources check failed: {e}")
    return findings


def _check_cross_region_backup(backup, account_id, account_name):
    """Flag if no backup plans have cross-region copy rules configured."""
    findings = []
    try:
        resp  = backup.list_backup_plans()
        plans = resp.get("BackupPlansList", [])
        has_cross_region = False

        for plan_meta in plans:
            plan_id = plan_meta["BackupPlanId"]
            try:
                plan_detail = backup.get_backup_plan(BackupPlanId=plan_id)
                for rule in plan_detail.get("BackupPlan", {}).get("Rules", []):
                    if rule.get("CopyActions"):
                        has_cross_region = True
                        break
            except Exception:
                pass
            if has_cross_region:
                break

        if plans and not has_cross_region:
            findings.append(build_finding(
                rule_id="BDR-004", severity="MEDIUM",
                resource_type="AWS::Backup::BackupPlan",
                resource_id="no-cross-region-copy",
                title="No backup plans configured with cross-region copy rules",
                description=(
                    "None of the existing backup plans include cross-region copy actions. "
                    "Cross-region backup copies are essential for disaster recovery — "
                    "a regional outage would make same-region backups inaccessible."
                ),
                recommendation=(
                    "Add CopyActions to your backup plan rules to copy backups to a "
                    "secondary region (e.g. if primary is us-east-1, copy to us-west-2). "
                    "Ensure the destination vault exists and has appropriate permissions."
                ),
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.error(f"Cross-region backup check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    backup = session.client("backup", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    findings.extend(_check_backup_plans_exist(backup, account_id, ""))
    findings.extend(_check_plan_retention(backup, account_id, ""))
    findings.extend(_check_unprotected_resources(backup, ec2, account_id, ""))
    findings.extend(_check_cross_region_backup(backup, account_id, ""))
    return findings
