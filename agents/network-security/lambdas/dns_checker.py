"""
Network Security Agent - DNS & Transit Gateway Checker
Audits Route 53 Resolver DNS security (logging, firewall, query logging)
and Transit Gateway sharing/routing misconfigurations.
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

    findings = []
    for region in get_scan_regions(session):
        ec2      = session.client("ec2", region_name=region)      if session else boto3.client("ec2", region_name=region)
        route53r = session.client("route53resolver", region_name=region) if session else boto3.client("route53resolver", region_name=region)
        ram      = session.client("ram", region_name=region)      if session else boto3.client("ram", region_name=region)
        region_findings = []
        region_findings.extend(_check_dns_query_logging(route53r, account_id, account_name, ec2=ec2))
        region_findings.extend(_check_dns_firewall(route53r, account_id, account_name))
        region_findings.extend(_check_transit_gateways(ec2, ram, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"DNS/TGW Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_dns_query_logging(route53r, account_id, account_name, ec2=None):
    """Verify Route 53 Resolver query logging is enabled on all VPCs."""
    findings = []
    try:
        if ec2 is None:
            ec2 = boto3.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        vpc_ids = {v["VpcId"] for v in vpcs}

        logged_vpcs = set()
        paginator   = route53r.get_paginator("list_resolver_query_log_config_associations")
        for page in paginator.paginate():
            for assoc in page.get("ResolverQueryLogConfigAssociations", []):
                if assoc.get("Status") == "ACTIVE":
                    logged_vpcs.add(assoc.get("ResourceId", ""))

        for vpc_id in vpc_ids:
            if vpc_id not in logged_vpcs:
                findings.append(build_finding(
                    rule_id="NET-DNS-001", severity="MEDIUM",
                    resource_type="AWS::Route53Resolver::ResolverQueryLoggingConfig",
                    resource_id=vpc_id,
                    title=f"DNS query logging not enabled for VPC {vpc_id}",
                    description=(
                        f"VPC {vpc_id} does not have Route 53 Resolver DNS query logging enabled. "
                        "DNS query logs are critical for detecting data exfiltration, C2 beaconing, "
                        "and DNS-based attacks such as DNS tunnelling."
                    ),
                    recommendation=(
                        "Create a Route 53 Resolver query logging configuration and associate it with this VPC. "
                        "Send logs to CloudWatch Logs or S3 and set up alerts for suspicious domains "
                        "(e.g. newly registered domains, DGA patterns)."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"vpc_id": vpc_id}
                ))
    except Exception as e:
        logger.error(f"DNS query logging check failed: {e}")
    return findings


def _check_dns_firewall(route53r, account_id, account_name):
    """Check whether Route 53 Resolver DNS Firewall rule groups are associated with VPCs."""
    findings = []
    try:
        ec2 = boto3.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])

        protected_vpcs = set()
        paginator = route53r.get_paginator("list_firewall_rule_group_associations")
        for page in paginator.paginate():
            for assoc in page.get("FirewallRuleGroupAssociations", []):
                if assoc.get("Status") == "COMPLETE":
                    protected_vpcs.add(assoc.get("VpcId", ""))

        if not protected_vpcs and vpcs:
            findings.append(build_finding(
                rule_id="NET-DNS-002", severity="MEDIUM",
                resource_type="AWS::Route53Resolver::FirewallRuleGroupAssociation",
                resource_id="no-dns-firewall",
                title="No Route 53 Resolver DNS Firewall rule groups configured",
                description=(
                    "No Route 53 Resolver DNS Firewall rule groups are associated with any VPC. "
                    "DNS Firewall provides protection against DNS-based threats including "
                    "known malicious domains, data exfiltration, and DNS tunnelling."
                ),
                recommendation=(
                    "Create DNS Firewall rule groups with AWS-managed domain lists (AWSManagedDomainsMalwareDomainList, "
                    "AWSManagedDomainsBotnetCommandandControl) and associate them with each VPC. "
                    "Set unassociated VPCs to BLOCK or ALERT mode."
                ),
                account_id=account_id, account_name=account_name,
            ))
        else:
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                if vpc_id not in protected_vpcs:
                    findings.append(build_finding(
                        rule_id="NET-DNS-002b", severity="LOW",
                        resource_type="AWS::Route53Resolver::FirewallRuleGroupAssociation",
                        resource_id=vpc_id,
                        title=f"VPC {vpc_id} has no DNS Firewall rule group associated",
                        description=(
                            f"VPC {vpc_id} does not have a Route 53 Resolver DNS Firewall rule group associated. "
                            "Other VPCs in this account are protected but this one is not."
                        ),
                        recommendation=(
                            "Associate an existing DNS Firewall rule group with this VPC, "
                            "or create one with AWS-managed domain block lists."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"vpc_id": vpc_id}
                    ))
    except Exception as e:
        logger.error(f"DNS Firewall check failed: {e}")
    return findings


def _check_transit_gateways(ec2, ram, account_id, account_name):
    """Audit Transit Gateways for insecure sharing and routing."""
    findings = []
    try:
        for page in ec2.get_paginator("describe_transit_gateways").paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ):
            for tgw in page.get("TransitGateways", []):
                tgw_id    = tgw["TransitGatewayId"]
                tgw_owner = tgw.get("OwnerId", "")
                options   = tgw.get("Options", {})

                # Auto-accept cross-account attachments is risky
                if options.get("AutoAcceptSharedAttachments") == "enable":
                    findings.append(build_finding(
                        rule_id="NET-TGW-001", severity="HIGH",
                        resource_type="AWS::EC2::TransitGateway",
                        resource_id=tgw_id,
                        title=f"Transit Gateway {tgw_id} auto-accepts cross-account attachments",
                        description=(
                            f"Transit Gateway {tgw_id} has AutoAcceptSharedAttachments=enable. "
                            "Any account that shares a VPC attachment will be automatically accepted "
                            "without manual approval, potentially allowing unexpected network access."
                        ),
                        recommendation=(
                            "Disable AutoAcceptSharedAttachments on the Transit Gateway. "
                            "Use RAM resource shares with explicit account/OU allow-listing "
                            "and manually approve each attachment request."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"tgw_id": tgw_id, "owner": tgw_owner}
                    ))

                # Default route table association allows all attachments to see each other
                if options.get("DefaultRouteTableAssociation") == "enable":
                    findings.append(build_finding(
                        rule_id="NET-TGW-002", severity="MEDIUM",
                        resource_type="AWS::EC2::TransitGateway",
                        resource_id=tgw_id,
                        title=f"Transit Gateway {tgw_id} uses default route table association",
                        description=(
                            f"Transit Gateway {tgw_id} has DefaultRouteTableAssociation=enable. "
                            "All VPC attachments are associated with the same default route table, "
                            "meaning all connected VPCs can route traffic to each other by default. "
                            "This violates network segmentation principles."
                        ),
                        recommendation=(
                            "Disable DefaultRouteTableAssociation and create separate route tables "
                            "per network segment (e.g., prod, dev, shared-services). "
                            "Explicitly configure which attachments can communicate."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"tgw_id": tgw_id, "owner": tgw_owner}
                    ))

    except Exception as e:
        logger.error(f"Transit Gateway check failed: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    route53r = session.client("route53resolver", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    ram = session.client("ram", region_name=region)
    findings.extend(_check_dns_query_logging(route53r, account_id, ""))
    findings.extend(_check_dns_firewall(route53r, account_id, ""))
    findings.extend(_check_transit_gateways(ec2, ram, account_id, ""))
    return findings
