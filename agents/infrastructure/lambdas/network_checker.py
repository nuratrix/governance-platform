"""
Infra Agent - Network Checker — Multi-Account Edition
Audits & Identify Empty and Default VPC in use and Unhealthy LB, NGW Existence.
Rules: NET-001 through NET-004
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "manual")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"Network check — account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        s     = session or boto3
        ec2   = s.client("ec2", region_name=region)
        elbv2 = s.client("elbv2", region_name=region)
        region_findings = []
        region_findings += _check_unused_nat_gateways(ec2, account_id, account_name)
        region_findings += _check_unhealthy_load_balancers(elbv2, account_id, account_name)
        region_findings += _check_empty_vpcs(ec2, account_id, account_name)
        region_findings += _check_default_vpc_in_use(ec2, account_id, account_name)
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    return {"findings": findings, "scan_id": scan_id,
            "account_id": account_id, "account_name": account_name}


def _check_unused_nat_gateways(ec2, account_id, account_name):
    findings = []
    resp = ec2.describe_nat_gateways(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    for nat in resp["NatGateways"]:
        findings.append(build_finding(
            rule_id        = "NET-001",
            severity       = "MEDIUM",
            resource_type  = "AWS::EC2::NatGateway",
            resource_id    = nat["NatGatewayId"],
            title          = "NAT Gateway exists — verify it is in use",
            description    = (
                f"NAT Gateway {nat['NatGatewayId']} in VPC {nat['VpcId']} "
                "costs ~$32/month plus data transfer"
            ),
            recommendation  = (
                "Check CloudWatch metrics — if BytesOutToDestination is near zero, "
                "consider deleting"
            ),
            auto_remediable = False,
            account_id      = account_id,
            account_name    = account_name,
        ))
    return findings


def _check_unhealthy_load_balancers(elbv2, account_id, account_name):
    findings = []
    lbs = elbv2.describe_load_balancers()["LoadBalancers"]
    for lb in lbs:
        tgs = elbv2.describe_target_groups(
            LoadBalancerArn=lb["LoadBalancerArn"]
        )["TargetGroups"]
        for tg in tgs:
            health    = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            unhealthy = [t for t in health["TargetHealthDescriptions"]
                         if t["TargetHealth"]["State"] == "unhealthy"]
            if unhealthy:
                findings.append(build_finding(
                    rule_id        = "NET-002",
                    severity       = "HIGH",
                    resource_type  = "AWS::ElasticLoadBalancingV2::TargetGroup",
                    resource_id    = tg["TargetGroupArn"],
                    title          = "Unhealthy targets in load balancer target group",
                    description    = (
                        f"{len(unhealthy)} unhealthy targets in {tg['TargetGroupName']} "
                        f"behind {lb['LoadBalancerName']}"
                    ),
                    recommendation  = (
                        "Investigate instance health — check application logs and health check config"
                    ),
                    auto_remediable = False,
                    account_id      = account_id,
                    account_name    = account_name,
                ))
    return findings


def _check_empty_vpcs(ec2, account_id, account_name):
    findings = []
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for vpc in vpcs:
        instances = ec2.describe_instances(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
        )["Reservations"]
        if not instances and not vpc.get("IsDefault"):
            findings.append(build_finding(
                rule_id        = "NET-003",
                severity       = "LOW",
                resource_type  = "AWS::EC2::VPC",
                resource_id    = vpc["VpcId"],
                title          = "Empty non-default VPC",
                description    = f"VPC {vpc['VpcId']} has no running instances",
                recommendation  = "Delete if unused to reduce configuration complexity",
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
    elbv2 = session.client("elbv2", region_name=region)
    findings = []
    findings.extend(_check_unused_nat_gateways(ec2, account_id, ""))
    findings.extend(_check_unhealthy_load_balancers(elbv2, account_id, ""))
    findings.extend(_check_empty_vpcs(ec2, account_id, ""))
    findings.extend(_check_default_vpc_in_use(ec2, account_id, ""))
    return findings


def _check_default_vpc_in_use(ec2, account_id, account_name):
    findings = []
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    )["Vpcs"]
    for vpc in vpcs:
        instances = ec2.describe_instances(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
        )["Reservations"]
        if instances:
            findings.append(build_finding(
                rule_id        = "NET-004",
                severity       = "MEDIUM",
                resource_type  = "AWS::EC2::VPC",
                resource_id    = vpc["VpcId"],
                title          = "Resources running in default VPC",
                description    = (
                    f"Default VPC {vpc['VpcId']} has {len(instances)} instance reservations. "
                    "Default VPCs lack proper network segmentation"
                ),
                recommendation  = (
                    "Migrate workloads to a custom VPC with proper subnet isolation"
                ),
                auto_remediable = False,
                account_id      = account_id,
                account_name    = account_name,
            ))
    return findings
