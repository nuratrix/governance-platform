"""
Cost Agent - S3 Cost Checker (Multi-Account Edition)
Identifies S3 cost optimisation opportunities.
Rules: COST-S3-001 through COST-S3-005
Cross-account: all clients created from the injected session.
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

S3_PRICE = {
    "StandardStorage":           0.023,
    "IntelligentTieringStorage": 0.023,
    "StandardIAStorage":         0.0125,
    "OneZoneIAStorage":          0.01,
    "GlacierInstantRetrieval":   0.004,
    "GlacierFlexibleRetrieval":  0.0036,
    "DeepArchiveStorage":        0.00099,
}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    min_size_gb  = float(event.get("min_size_gb", 1.0))

    s          = session or boto3
    s3c        = s.client("s3")
    cloudwatch = s.client("cloudwatch")

    logger.info(f"S3 cost check for {account_id} — min_size_gb={min_size_gb}")

    findings         = []
    total_storage_gb = 0.0

    try:
        buckets = s3c.list_buckets()["Buckets"]
        for bucket in buckets:
            name     = bucket["Name"]
            size_gb  = _get_bucket_size_gb(s3c, cloudwatch, name)
            total_storage_gb += size_gb

            if size_gb < min_size_gb:
                continue

            findings += _check_lifecycle_policy(s3c, name, size_gb, account_id, account_name)
            findings += _check_intelligent_tiering(s3c, name, size_gb, account_id, account_name)
            findings += _check_versioning_expiry(s3c, name, size_gb, account_id, account_name)
            findings += _check_storage_class_analysis(s3c, name, size_gb, account_id, account_name)

    except Exception as e:
        logger.error(f"S3 cost check failed: {e}")

    total_saving = sum(f.get("estimated_monthly_saving", 0) for f in findings)
    for f in findings:
        f["region"] = "global"

    return {
        "findings":     findings,
        "scan_id":      scan_id,
        "account_id":   account_id,
        "account_name": account_name,
        "summary": {
            "total_findings":         len(findings),
            "total_potential_saving": round(total_saving, 2),
            "buckets_scanned":        len(s3c.list_buckets()["Buckets"]),
            "total_storage_gb":       round(total_storage_gb, 2),
        }
    }


def _get_bucket_size_gb(s3c, cloudwatch, bucket_name):
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace  = "AWS/S3",
            MetricName = "BucketSizeBytes",
            Dimensions = [
                {"Name": "BucketName",  "Value": bucket_name},
                {"Name": "StorageType", "Value": "StandardStorage"},
            ],
            StartTime  = datetime.now(timezone.utc) - timedelta(days=2),
            EndTime    = datetime.now(timezone.utc),
            Period     = 86400,
            Statistics = ["Average"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            bytes_val = sorted(datapoints, key=lambda x: x["Timestamp"])[-1]["Average"]
            return bytes_val / (1024 ** 3)
    except Exception:
        pass
    return 0.0


def _check_lifecycle_policy(s3c, bucket_name, size_gb, account_id, account_name):
    findings = []
    try:
        s3c.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    except s3c.exceptions.ClientError as e:
        if "NoSuchLifecycleConfiguration" in str(e):
            standard_monthly = size_gb * S3_PRICE["StandardStorage"]
            ia_monthly       = size_gb * S3_PRICE["StandardIAStorage"]
            saving           = (standard_monthly - ia_monthly) * 0.5

            if saving < 1.0:
                return []

            findings.append({
                **build_finding(
                    rule_id        = "COST-S3-001",
                    severity       = "MEDIUM",
                    resource_type  = "AWS::S3::Bucket",
                    resource_id    = bucket_name,
                    title          = f"S3 bucket has no lifecycle policy — {bucket_name}",
                    description    = (
                        f"Bucket {bucket_name} ({size_gb:.1f}GB) has no lifecycle policy. "
                        f"All objects remain in Standard at ${standard_monthly:.2f}/month."
                    ),
                    recommendation = (
                        "Add a lifecycle rule to transition objects to Standard-IA after 30 days "
                        "and Glacier after 90 days. "
                        f"Estimated saving: ${saving:.2f}/month."
                    ),
                    auto_remediable = False,
                    account_id=account_id, account_name=account_name,
                ),
                "estimated_monthly_saving": round(saving, 2),
                "bucket_size_gb":           round(size_gb, 2),
                "storage_class":            "Standard",
            })
    except Exception as e:
        logger.warning(f"Lifecycle check failed for {bucket_name}: {e}")
    return findings


def _check_intelligent_tiering(s3c, bucket_name, size_gb, account_id, account_name):
    findings = []
    if size_gb < 50:
        return []

    try:
        configs = s3c.list_bucket_intelligent_tiering_configurations(Bucket=bucket_name)
        if configs.get("IntelligentTieringConfigurationList"):
            return []

        standard_monthly = size_gb * S3_PRICE["StandardStorage"]
        saving           = standard_monthly * 0.30

        findings.append({
            **build_finding(
                rule_id        = "COST-S3-002",
                severity       = "LOW",
                resource_type  = "AWS::S3::Bucket",
                resource_id    = bucket_name,
                title          = f"Large S3 bucket without Intelligent-Tiering — {bucket_name}",
                description    = (
                    f"Bucket {bucket_name} ({size_gb:.1f}GB) stores all data in Standard class "
                    f"at ${standard_monthly:.2f}/month."
                ),
                recommendation = (
                    "Enable S3 Intelligent-Tiering for automatic cost optimisation. "
                    f"Estimated saving: ${saving:.2f}/month."
                ),
                auto_remediable = False,
                account_id=account_id, account_name=account_name,
            ),
            "estimated_monthly_saving": round(saving, 2),
            "bucket_size_gb":           round(size_gb, 2),
            "storage_class":            "Standard",
        })

    except Exception as e:
        logger.warning(f"Intelligent-Tiering check failed for {bucket_name}: {e}")
    return findings


def _check_versioning_expiry(s3c, bucket_name, size_gb, account_id, account_name):
    findings = []
    try:
        versioning = s3c.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") != "Enabled":
            return []

        has_expiry = False
        try:
            lifecycle = s3c.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            for rule in lifecycle.get("Rules", []):
                if rule.get("Status") == "Enabled" and (
                    "NoncurrentVersionExpiration" in rule or
                    "NoncurrentVersionTransitions" in rule
                ):
                    has_expiry = True
                    break
        except s3c.exceptions.ClientError:
            pass

        if not has_expiry:
            standard_monthly = size_gb * S3_PRICE["StandardStorage"]
            saving           = standard_monthly * 0.3

            if saving < 1.0:
                return []

            findings.append({
                **build_finding(
                    rule_id        = "COST-S3-003",
                    severity       = "MEDIUM",
                    resource_type  = "AWS::S3::Bucket",
                    resource_id    = bucket_name,
                    title          = f"Versioned bucket with no version expiry — {bucket_name}",
                    description    = (
                        f"Bucket {bucket_name} has versioning enabled but no lifecycle rule "
                        "to expire noncurrent versions. Old versions accumulate indefinitely."
                    ),
                    recommendation = (
                        "Add a lifecycle rule to expire noncurrent versions after 30-90 days. "
                        f"Estimated saving: ${saving:.2f}/month."
                    ),
                    auto_remediable = False,
                    account_id=account_id, account_name=account_name,
                ),
                "estimated_monthly_saving": round(saving, 2),
                "bucket_size_gb":           round(size_gb, 2),
                "storage_class":            "Standard (versioned)",
            })

    except Exception as e:
        logger.warning(f"Versioning expiry check failed for {bucket_name}: {e}")
    return findings


def _check_storage_class_analysis(s3c, bucket_name, size_gb, account_id, account_name):
    findings = []
    if size_gb < 100:
        return []

    try:
        analyses = s3c.list_bucket_analytics_configurations(Bucket=bucket_name)
        if not analyses.get("AnalyticsConfigurationList"):
            findings.append({
                **build_finding(
                    rule_id        = "COST-S3-004",
                    severity       = "LOW",
                    resource_type  = "AWS::S3::Bucket",
                    resource_id    = bucket_name,
                    title          = f"Large S3 bucket without Storage Class Analysis — {bucket_name}",
                    description    = (
                        f"Bucket {bucket_name} ({size_gb:.1f}GB) does not have Storage Class Analysis enabled."
                    ),
                    recommendation = (
                        "Enable S3 Storage Class Analysis to identify objects suitable for Standard-IA. "
                        "This is a free feature."
                    ),
                    auto_remediable = False,
                    account_id=account_id, account_name=account_name,
                ),
                "estimated_monthly_saving": 0,
                "bucket_size_gb":           round(size_gb, 2),
                "storage_class":            "Standard",
            })
    except Exception as e:
        logger.warning(f"Storage class analysis check failed for {bucket_name}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    s3c = session.client("s3")
    cloudwatch = session.client("cloudwatch", region_name=region)
    findings = []
    try:
        buckets = s3c.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            size_gb = _get_bucket_size_gb(s3c, cloudwatch, name)
            if size_gb < 1.0:
                continue
            findings.extend(_check_lifecycle_policy(s3c, name, size_gb, account_id, ""))
            findings.extend(_check_intelligent_tiering(s3c, name, size_gb, account_id, ""))
            findings.extend(_check_versioning_expiry(s3c, name, size_gb, account_id, ""))
            findings.extend(_check_storage_class_analysis(s3c, name, size_gb, account_id, ""))
    except Exception as e:
        logger.error(f"S3 cost run_checks failed: {e}")
    return findings
