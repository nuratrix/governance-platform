"""
Security Agent - CloudTrail Checker — Multi-Account Edition
Accepts an optional boto3 session for cross-account scanning.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"CloudTrail Checker starting for scan_id={scan_id} account={account_id}")

    s3 = (session or boto3).client("s3")  # S3 is global

    findings = []
    for region in get_scan_regions(session):
        ct = (session or boto3).client("cloudtrail", region_name=region)
        region_findings = []
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            if not trails:
                region_findings.append(build_finding(
                    rule_id="SEC-CT-001", severity="CRITICAL",
                    resource_type="AWS::CloudTrail::Trail", resource_id="account",
                    title="No CloudTrail trails configured in this account/region",
                    description="CloudTrail is not enabled. All API activity is unlogged.",
                    recommendation="Create a multi-region CloudTrail trail.",
                    account_id=account_id, account_name=account_name,
                ))
            else:
                has_multi_region = False
                for trail in trails:
                    trail_name = trail["Name"]
                    region_findings.extend(_check_multi_region(trail, account_id, account_name))
                    region_findings.extend(_check_log_validation(trail, account_id, account_name))
                    region_findings.extend(_check_encryption(trail, account_id, account_name))
                    region_findings.extend(_check_cloudwatch_logs(trail, account_id, account_name))
                    region_findings.extend(_check_s3_bucket_access(s3, trail, account_id, account_name))
                    region_findings.extend(_check_management_events(ct, trail, trail_name, account_id, account_name))
                    if trail.get("IsMultiRegionTrail"):
                        has_multi_region = True

                if not has_multi_region:
                    region_findings.append(build_finding(
                        rule_id="SEC-CT-001b", severity="HIGH",
                        resource_type="AWS::CloudTrail::Trail", resource_id="account",
                        title="No multi-region CloudTrail trail found",
                        description="All existing trails are single-region.",
                        recommendation="Enable a multi-region CloudTrail trail.",
                        account_id=account_id, account_name=account_name,
                    ))
        except Exception as e:
            logger.error(f"CloudTrail check failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"CloudTrail Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_multi_region(trail, account_id, account_name):
    if not trail.get("IsMultiRegionTrail"):
        return [build_finding(
            rule_id="SEC-CT-001", severity="HIGH",
            resource_type="AWS::CloudTrail::Trail", resource_id=trail["TrailARN"],
            title=f"Trail '{trail['Name']}' is not multi-region",
            description="Single-region trails miss API activity in other regions.",
            recommendation="Convert to a multi-region trail.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_log_validation(trail, account_id, account_name):
    if not trail.get("LogFileValidationEnabled"):
        return [build_finding(
            rule_id="SEC-CT-002", severity="MEDIUM",
            resource_type="AWS::CloudTrail::Trail", resource_id=trail["TrailARN"],
            title=f"Trail '{trail['Name']}' does not have log file validation enabled",
            description="Without log file validation, log tampering cannot be detected.",
            recommendation="Enable log file validation on the trail.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_encryption(trail, account_id, account_name):
    if not trail.get("KMSKeyId"):
        return [build_finding(
            rule_id="SEC-CT-003", severity="MEDIUM",
            resource_type="AWS::CloudTrail::Trail", resource_id=trail["TrailARN"],
            title=f"Trail '{trail['Name']}' is not encrypted with KMS",
            description="CloudTrail logs are not encrypted with a customer-managed KMS key.",
            recommendation="Configure a KMS CMK for CloudTrail log encryption.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_cloudwatch_logs(trail, account_id, account_name):
    if not trail.get("CloudWatchLogsLogGroupArn"):
        return [build_finding(
            rule_id="SEC-CT-004", severity="MEDIUM",
            resource_type="AWS::CloudTrail::Trail", resource_id=trail["TrailARN"],
            title=f"Trail '{trail['Name']}' is not delivering logs to CloudWatch",
            description="Without CloudWatch integration, real-time alerting on API activity is not possible.",
            recommendation="Configure CloudTrail to deliver logs to a CloudWatch Logs group.",
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_s3_bucket_access(s3, trail, account_id, account_name):
    findings    = []
    bucket_name = trail.get("S3BucketName")
    if not bucket_name:
        return findings
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        if not all([config.get("BlockPublicAcls"), config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"), config.get("RestrictPublicBuckets")]):
            findings.append(build_finding(
                rule_id="SEC-CT-005", severity="CRITICAL",
                resource_type="AWS::S3::Bucket", resource_id=bucket_name,
                title=f"CloudTrail S3 bucket '{bucket_name}' is not fully blocking public access",
                description="The CloudTrail log bucket could be publicly accessible.",
                recommendation="Enable all public access block settings on the CloudTrail S3 bucket.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check CloudTrail S3 bucket {bucket_name}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ct = session.client("cloudtrail", region_name=region)
    s3 = session.client("s3")
    findings = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        if not trails:
            from build_finding import build_finding
            findings.append(build_finding(
                rule_id="SEC-CT-001", severity="CRITICAL",
                resource_type="AWS::CloudTrail::Trail", resource_id="account",
                title="No CloudTrail trails configured in this account/region",
                description="CloudTrail is not enabled. All API activity is unlogged.",
                recommendation="Create a multi-region CloudTrail trail.",
                account_id=account_id, account_name="",
            ))
            return findings
        for trail in trails:
            trail_name = trail["Name"]
            findings.extend(_check_multi_region(trail, account_id, ""))
            findings.extend(_check_log_validation(trail, account_id, ""))
            findings.extend(_check_encryption(trail, account_id, ""))
            findings.extend(_check_cloudwatch_logs(trail, account_id, ""))
            findings.extend(_check_s3_bucket_access(s3, trail, account_id, ""))
            findings.extend(_check_management_events(ct, trail, trail_name, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"CloudTrail run_checks failed: {e}")
    return findings


def _check_management_events(ct, trail, trail_name, account_id, account_name):
    findings = []
    try:
        selectors = ct.get_event_selectors(TrailName=trail_name)
        has_all   = any(
            s.get("ReadWriteType") == "All" and s.get("IncludeManagementEvents", False)
            for s in selectors.get("EventSelectors", [])
        )
        if not has_all:
            findings.append(build_finding(
                rule_id="SEC-CT-006", severity="HIGH",
                resource_type="AWS::CloudTrail::Trail", resource_id=trail["TrailARN"],
                title=f"Trail '{trail_name}' does not log all management events",
                description="Trail is not capturing all read and write management events.",
                recommendation="Set event selectors to include all management events.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check event selectors for {trail_name}: {e}")
    return findings
