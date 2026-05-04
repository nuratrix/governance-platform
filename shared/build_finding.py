"""
build_finding — Multi-Account Edition
account_id is now a required field in every finding.
All checkers pass the account they are scanning so findings in DynamoDB
can be filtered and grouped by account.
"""

from datetime import datetime, timezone


def build_finding(
    rule_id,
    severity,
    resource_type,
    resource_id,
    title,
    description,
    recommendation,
    account_id="",       # Multi-Account: which account this finding belongs to
    account_name="",     # Human-readable alias (optional, for alert messages)
    region="",           # Multi-Region: which region this finding is from ("global" for IAM/S3)
    auto_remediable=False,
    extra=None
):
    finding = {
        "rule_id":          rule_id,
        "severity":         severity,        # CRITICAL, HIGH, MEDIUM, LOW
        "resource_type":    resource_type,   # e.g. AWS::IAM::User
        "resource_id":      resource_id,     # e.g. johndoe or sg-0abc1234
        "title":            title,
        "description":      description,
        "recommendation":   recommendation,
        "auto_remediable":  auto_remediable,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        # ── Multi-Account fields ──────────────────────────────────────────────
        "account_id":       account_id,
        "account_name":     account_name,
        # ── Multi-Region fields ───────────────────────────────────────────────
        "region":           region,
    }
    if extra:
        finding.update(extra)
    return finding
