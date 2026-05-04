"""
IAM Access Analyzer Agent - Access Analyzer Checker
Audits IAM Access Analyzer findings: external access to S3, KMS, SQS, etc.,
and verifies analyzers are deployed in each active region.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Finding types that represent high-risk external access
HIGH_RISK_TYPES = {
    "AWS::S3::Bucket",
    "AWS::KMS::Key",
    "AWS::SecretsManager::Secret",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Lambda::LayerVersion",
    "AWS::SQS::Queue",
    "AWS::SNS::Topic",
}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    findings = []
    for region in get_scan_regions(session):
        aa = session.client("accessanalyzer", region_name=region) if session \
            else boto3.client("accessanalyzer", region_name=region)
        region_findings = []
        region_findings.extend(_check_analyzer_exists(aa, region, account_id, account_name))
        region_findings.extend(_check_active_findings(aa, region, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Access Analyzer Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_analyzer_exists(aa, region, account_id, account_name):
    """Verify at least one ACCOUNT or ORGANIZATION analyzer is active in this region."""
    findings = []
    try:
        resp      = aa.list_analyzers()
        analyzers = [a for a in resp.get("analyzers", []) if a.get("status") == "ACTIVE"]

        if not analyzers:
            findings.append(build_finding(
                rule_id="IAM-AA-001", severity="HIGH",
                resource_type="AWS::AccessAnalyzer::Analyzer",
                resource_id=f"{region}/no-analyzer",
                title=f"No active IAM Access Analyzer in {region}",
                description=(
                    f"Region {region} has no active AWS IAM Access Analyzer. "
                    "Without an analyzer, external resource access (S3 buckets, KMS keys, "
                    "IAM roles, Lambda functions) will not be automatically audited."
                ),
                recommendation=(
                    f"Create an IAM Access Analyzer in {region}. "
                    "Use the ORGANIZATION type if you have AWS Organizations enabled "
                    "to also detect cross-account access within the org. "
                    "Go to IAM → Access analyzer → Create analyzer."
                ),
                account_id=account_id, account_name=account_name,
                extra={"region": region}
            ))
    except Exception as e:
        logger.error(f"Analyzer check failed in {region}: {e}")
    return findings


def _check_active_findings(aa, region, account_id, account_name):
    """Pull all active (unresolved) Access Analyzer findings and convert to platform findings."""
    findings = []
    try:
        analyzers = [a for a in aa.list_analyzers().get("analyzers", [])
                     if a.get("status") == "ACTIVE"]

        for analyzer in analyzers:
            arn = analyzer["arn"]
            paginator = aa.get_paginator("list_findings")
            for page in paginator.paginate(
                analyzerArn=arn,
                filter={"status": {"eq": ["ACTIVE"]}}
            ):
                for finding in page.get("findings", []):
                    _convert_finding(finding, arn, region, account_id, account_name, findings)

    except Exception as e:
        logger.error(f"Active findings check failed in {region}: {e}")
    return findings


def _convert_finding(finding, analyzer_arn, region, account_id, account_name, out):
    finding_id    = finding.get("id", "")
    resource_type = finding.get("resourceType", "")
    resource      = finding.get("resource", "")
    principal     = finding.get("principal", {})
    condition     = finding.get("condition", {})
    action        = finding.get("action", [])
    is_public     = finding.get("isPublic", False)
    status        = finding.get("status", "ACTIVE")

    if status != "ACTIVE":
        return

    # Determine severity
    if is_public and resource_type in HIGH_RISK_TYPES:
        severity = "CRITICAL"
    elif is_public:
        severity = "HIGH"
    elif resource_type in HIGH_RISK_TYPES:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    principal_str = ", ".join(f"{k}={v}" for k, v in principal.items()) if principal else "unknown"
    action_str    = ", ".join(action[:5]) if action else "unknown"
    cond_str      = str(condition) if condition else "none"

    out.append(build_finding(
        rule_id="IAM-AA-002", severity=severity,
        resource_type=resource_type,
        resource_id=f"{region}/{resource}",
        title=f"{'Public' if is_public else 'External'} access to {resource_type} {resource} ({region})",
        description=(
            f"IAM Access Analyzer detected {'public' if is_public else 'external'} access "
            f"to {resource_type} resource '{resource}' in {region}. "
            f"Principal: {principal_str}. "
            f"Actions allowed: {action_str}. "
            f"Conditions: {cond_str}."
        ),
        recommendation=(
            f"Review the resource policy for {resource} and remove the external principal "
            f"if the access is not intentional. "
            "Archive this finding in Access Analyzer after verifying it is intentional, "
            "so it does not appear in future reports. "
            "Use IAM policy conditions to restrict access to specific VPCs or organisations."
        ),
        account_id=account_id, account_name=account_name,
        extra={
            "finding_id": finding_id,
            "analyzer_arn": analyzer_arn,
            "resource": resource,
            "resource_type": resource_type,
            "is_public": is_public,
            "principal": principal,
            "actions": action[:10],
            "region": region,
        }
    ))


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    aa = session.client("accessanalyzer", region_name=region)
    findings.extend(_check_analyzer_exists(aa, region, account_id, ""))
    findings.extend(_check_active_findings(aa, region, account_id, ""))
    return findings
