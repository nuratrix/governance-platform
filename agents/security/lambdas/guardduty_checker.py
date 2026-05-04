"""
Security Agent - GuardDuty Checker — Multi-Account Edition
Accepts an optional boto3 session for cross-account scanning.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"GuardDuty Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        gd = (session or boto3).client("guardduty", region_name=region)
        region_findings = []
        try:
            detectors = gd.list_detectors()["DetectorIds"]
            if not detectors:
                region_findings.append(build_finding(
                    rule_id="SEC-GD-001", severity="CRITICAL",
                    resource_type="AWS::GuardDuty::Detector", resource_id="account",
                    title="GuardDuty is not enabled in this region",
                    description="Amazon GuardDuty is not configured. Threat detection is disabled.",
                    recommendation="Enable GuardDuty in all active regions.",
                    account_id=account_id, account_name=account_name,
                ))
            else:
                for detector_id in detectors:
                    region_findings.extend(_check_detector_status(gd, detector_id, account_id, account_name))
                    region_findings.extend(_check_active_findings(gd, detector_id, account_id, account_name))
                    region_findings.extend(_check_s3_protection(gd, detector_id, account_id, account_name))
        except Exception as e:
            logger.error(f"GuardDuty check failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"GuardDuty Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_detector_status(gd, detector_id, account_id, account_name):
    findings = []
    try:
        detector = gd.get_detector(DetectorId=detector_id)
        if detector.get("Status") != "ENABLED":
            findings.append(build_finding(
                rule_id="SEC-GD-001", severity="CRITICAL",
                resource_type="AWS::GuardDuty::Detector", resource_id=detector_id,
                title=f"GuardDuty detector {detector_id} is not ENABLED",
                description=f"Detector status: {detector.get('Status')}.",
                recommendation="Enable the GuardDuty detector.",
                account_id=account_id, account_name=account_name,
            ))
        freq = detector.get("FindingPublishingFrequency", "")
        if freq == "SIX_HOURS":
            findings.append(build_finding(
                rule_id="SEC-GD-001b", severity="LOW",
                resource_type="AWS::GuardDuty::Detector", resource_id=detector_id,
                title="GuardDuty finding frequency is set to 6 hours",
                description="Findings may take up to 6 hours to appear.",
                recommendation="Change finding frequency to FIFTEEN_MINUTES.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.error(f"Could not check detector {detector_id}: {e}")
    return findings


def _check_active_findings(gd, detector_id, account_id, account_name):
    findings = []
    try:
        since       = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        finding_ids = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                    "updatedAt":        {"GreaterThanOrEqual": since},
                }
            },
            SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
            MaxResults=50,
        )["FindingIds"]

        if not finding_ids:
            return findings

        for gd_finding in gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)["Findings"]:
            sev_score = gd_finding.get("Severity", 0)
            severity  = _map_severity(sev_score)
            if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                findings.append(build_finding(
                    rule_id="SEC-GD-002", severity=severity,
                    resource_type="AWS::GuardDuty::Finding",
                    resource_id=gd_finding.get("Id", "unknown"),
                    title=f"GuardDuty: {gd_finding.get('Title', 'Unknown threat')}",
                    description=gd_finding.get("Description", "GuardDuty detected a threat."),
                    recommendation=f"Investigate finding {gd_finding.get('Id')}. Type: {gd_finding.get('Type', 'Unknown')}",
                    account_id=account_id, account_name=account_name,
                    extra={
                        "guardduty_type":     gd_finding.get("Type"),
                        "guardduty_severity": sev_score,
                        "region":             gd_finding.get("Region"),
                    },
                ))
    except Exception as e:
        logger.error(f"Could not retrieve GuardDuty findings for {detector_id}: {e}")
    return findings


def _check_s3_protection(gd, detector_id, account_id, account_name):
    findings = []
    try:
        features  = gd.get_detector(DetectorId=detector_id).get("Features", [])
        s3_feature = next((f for f in features if f.get("Name") == "S3_DATA_EVENTS"), None)
        if not s3_feature or s3_feature.get("Status") != "ENABLED":
            findings.append(build_finding(
                rule_id="SEC-GD-003", severity="MEDIUM",
                resource_type="AWS::GuardDuty::Detector", resource_id=detector_id,
                title="GuardDuty S3 Protection is not enabled",
                description="GuardDuty is not monitoring S3 data events.",
                recommendation="Enable S3 Protection in GuardDuty settings.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check S3 protection for {detector_id}: {e}")
    return findings


def _map_severity(score):
    if score >= 7.0: return "CRITICAL"
    elif score >= 4.0: return "HIGH"
    elif score >= 1.0: return "MEDIUM"
    return "LOW"


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    gd = session.client("guardduty", region_name=region)
    findings = []
    try:
        detectors = gd.list_detectors()["DetectorIds"]
        if not detectors:
            from build_finding import build_finding
            findings.append(build_finding(
                rule_id="SEC-GD-001", severity="CRITICAL",
                resource_type="AWS::GuardDuty::Detector", resource_id="account",
                title="GuardDuty is not enabled in this region",
                description="Amazon GuardDuty is not configured. Threat detection is disabled.",
                recommendation="Enable GuardDuty in all active regions.",
                account_id=account_id, account_name="",
            ))
            return findings
        for detector_id in detectors:
            findings.extend(_check_detector_status(gd, detector_id, account_id, ""))
            findings.extend(_check_active_findings(gd, detector_id, account_id, ""))
            findings.extend(_check_s3_protection(gd, detector_id, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"GuardDuty run_checks failed: {e}")
    return findings
