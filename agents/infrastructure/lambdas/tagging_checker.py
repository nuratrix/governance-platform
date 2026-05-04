"""
Infra Agent - Tag Checker — Multi-Account Edition
Audits & Identify EC2, DB and LB missing tags.
Rules: TAG-001 through TAG-003
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Required tags — customise to your organisation's standards
REQUIRED_TAGS = ["Environment", "Owner", "Project", "CostCenter"]


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"Tag check — account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        s     = session or boto3
        ec2   = s.client("ec2", region_name=region)
        rds   = s.client("rds", region_name=region)
        elbv2 = s.client("elbv2", region_name=region)
        region_findings = []
        region_findings += _check_ec2_tags(ec2, account_id, account_name)
        region_findings += _check_rds_tags(rds, account_id, account_name)
        region_findings += _check_elb_tags(elbv2, account_id, account_name)
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    return {"findings": findings, "scan_id": scan_id,
            "account_id": account_id, "account_name": account_name}


def _missing_tags(tags):
    tag_keys = {t["Key"] for t in tags}
    return [t for t in REQUIRED_TAGS if t not in tag_keys]


def _check_ec2_tags(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    )
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            missing = _missing_tags(i.get("Tags", []))
            if missing:
                name = next(
                    (t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"),
                    i["InstanceId"]
                )
                findings.append(build_finding(
                    rule_id        = "TAG-001",
                    severity       = "LOW",
                    resource_type  = "AWS::EC2::Instance",
                    resource_id    = i["InstanceId"],
                    title          = "EC2 instance missing required tags",
                    description    = f"Instance {name} is missing tags: {', '.join(missing)}",
                    recommendation  = f"Add required tags: {', '.join(missing)}",
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    return findings


def _check_rds_tags(rds, account_id, account_name):
    findings = []
    resp = rds.describe_db_instances()
    for db in resp["DBInstances"]:
        tags_resp = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])
        missing   = _missing_tags(tags_resp.get("TagList", []))
        if missing:
            findings.append(build_finding(
                rule_id        = "TAG-002",
                severity       = "LOW",
                resource_type  = "AWS::RDS::DBInstance",
                resource_id    = db["DBInstanceIdentifier"],
                title          = "RDS instance missing required tags",
                description    = (
                    f"RDS instance {db['DBInstanceIdentifier']} is missing tags: "
                    f"{', '.join(missing)}"
                ),
                recommendation  = f"Add required tags: {', '.join(missing)}",
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ec2 = session.client("ec2", region_name=region)
    rds = session.client("rds", region_name=region)
    elbv2 = session.client("elbv2", region_name=region)
    findings = []
    findings.extend(_check_ec2_tags(ec2, account_id, ""))
    findings.extend(_check_rds_tags(rds, account_id, ""))
    findings.extend(_check_elb_tags(elbv2, account_id, ""))
    return findings


def _check_elb_tags(elbv2, account_id, account_name):
    findings = []
    lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    for lb in lbs:
        tags_resp = elbv2.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])
        for td in tags_resp["TagDescriptions"]:
            missing = _missing_tags(td.get("Tags", []))
            if missing:
                findings.append(build_finding(
                    rule_id        = "TAG-003",
                    severity       = "LOW",
                    resource_type  = "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    resource_id    = lb["LoadBalancerName"],
                    title          = "Load balancer missing required tags",
                    description    = (
                        f"Load balancer {lb['LoadBalancerName']} is missing tags: "
                        f"{', '.join(missing)}"
                    ),
                    recommendation  = f"Add required tags: {', '.join(missing)}",
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    return findings
