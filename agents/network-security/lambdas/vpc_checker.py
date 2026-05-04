"""
Network Security Agent - VPC Checker
Audits VPC configuration: flow logs, default VPC usage, public subnets,
VPC peering exposure, and dangling Internet Gateways.
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
        ec2_r = session.client("ec2", region_name=region) if session else boto3.client("ec2", region_name=region)
        region_findings = []
        region_findings.extend(_check_flow_logs(ec2_r, region, account_id, account_name))
        region_findings.extend(_check_default_vpc(ec2_r, region, account_id, account_name))
        region_findings.extend(_check_public_subnets(ec2_r, region, account_id, account_name))
        region_findings.extend(_check_vpc_peering(ec2_r, region, account_id, account_name))
        region_findings.extend(_check_unused_igw(ec2_r, region, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"VPC Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_flow_logs(ec2, region, account_id, account_name):
    findings = []
    try:
        vpcs     = ec2.describe_vpcs().get("Vpcs", [])
        flow_log_vpc_ids = set()

        for page in ec2.get_paginator("describe_flow_logs").paginate(
            Filters=[{"Name": "resource-type", "Values": ["VPC"]}]
        ):
            for fl in page.get("FlowLogs", []):
                flow_log_vpc_ids.add(fl.get("ResourceId", ""))

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            if vpc_id not in flow_log_vpc_ids:
                is_default = vpc.get("IsDefault", False)
                findings.append(build_finding(
                    rule_id="NET-VPC-001", severity="HIGH",
                    resource_type="AWS::EC2::VPC",
                    resource_id=f"{region}/{vpc_id}",
                    title=f"VPC flow logs not enabled: {vpc_id} ({region})",
                    description=(
                        f"VPC {vpc_id} in {region} has no VPC flow logs configured. "
                        f"Flow logs are essential for network traffic visibility, "
                        f"security incident investigation, and compliance."
                        + (" This is the default VPC." if is_default else "")
                    ),
                    recommendation=(
                        "Enable VPC flow logs to CloudWatch Logs or S3. "
                        "Use the REJECT filter at minimum to capture denied traffic. "
                        "Set retention to at least 90 days for security investigation purposes."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"vpc_id": vpc_id, "region": region, "is_default": is_default}
                ))
    except Exception as e:
        logger.error(f"Flow log check failed in {region}: {e}")
    return findings


def _check_default_vpc(ec2, region, account_id, account_name):
    findings = []
    try:
        for vpc in ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", []):
            vpc_id = vpc["VpcId"]

            # Check if anything is running in the default VPC
            instances = ec2.describe_instances(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                         {"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ).get("Reservations", [])

            if instances:
                findings.append(build_finding(
                    rule_id="NET-VPC-002", severity="MEDIUM",
                    resource_type="AWS::EC2::VPC",
                    resource_id=f"{region}/{vpc_id}",
                    title=f"Resources running in default VPC {vpc_id} ({region})",
                    description=(
                        f"The default VPC ({vpc_id}) in {region} has {len(instances)} reservation(s) "
                        "with running or stopped EC2 instances. The default VPC uses permissive defaults "
                        "(public subnets, internet gateway) and should not host production resources."
                    ),
                    recommendation=(
                        "Migrate resources from the default VPC to a purpose-built VPC with private subnets, "
                        "NAT gateways, and appropriate security groups. "
                        "Delete the default VPC once all resources are migrated."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"vpc_id": vpc_id, "region": region, "reservation_count": len(instances)}
                ))
    except Exception as e:
        logger.error(f"Default VPC check failed in {region}: {e}")
    return findings


def _check_public_subnets(ec2, region, account_id, account_name):
    """Flag subnets with auto-assign public IP enabled that aren't in the default VPC."""
    findings = []
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        default_vpc_ids = {v["VpcId"] for v in vpcs if v.get("IsDefault")}

        for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "mapPublicIpOnLaunch", "Values": ["true"]}]
        ):
            for subnet in page.get("Subnets", []):
                vpc_id    = subnet.get("VpcId", "")
                subnet_id = subnet["SubnetId"]

                if vpc_id in default_vpc_ids:
                    continue  # expected for default VPC

                name = next((t["Value"] for t in subnet.get("Tags", []) if t["Key"] == "Name"), "")
                # Only flag if name doesn't suggest it's intentionally public
                if any(kw in name.lower() for kw in ("public", "dmz", "ingress", "alb", "elb")):
                    continue

                findings.append(build_finding(
                    rule_id="NET-VPC-003", severity="LOW",
                    resource_type="AWS::EC2::Subnet",
                    resource_id=f"{region}/{subnet_id}",
                    title=f"Subnet {subnet_id} auto-assigns public IPs ({region})",
                    description=(
                        f"Subnet {subnet_id} ('{name}') in VPC {vpc_id} ({region}) has "
                        "'Map public IP on launch' enabled but is not named as a public/DMZ subnet. "
                        "Instances launched here receive public IPs, increasing attack surface."
                    ),
                    recommendation=(
                        "Disable 'Map public IP on launch' if this is a private subnet. "
                        "Use Elastic IPs or a NAT Gateway for outbound internet access from private subnets. "
                        "Rename the subnet to include 'public' in the name if public assignment is intentional."
                    ),
                    account_id=account_id, account_name=account_name,
                    extra={"subnet_id": subnet_id, "vpc_id": vpc_id, "region": region, "name": name}
                ))
    except Exception as e:
        logger.error(f"Public subnet check failed in {region}: {e}")
    return findings


def _check_vpc_peering(ec2, region, account_id, account_name):
    """Flag active VPC peering connections with external (non-org) accounts."""
    findings = []
    try:
        for page in ec2.get_paginator("describe_vpc_peering_connections").paginate(
            Filters=[{"Name": "status-code", "Values": ["active"]}]
        ):
            for peer in page.get("VpcPeeringConnections", []):
                peer_id     = peer["VpcPeeringConnectionId"]
                requester   = peer.get("RequesterVpcInfo", {})
                accepter    = peer.get("AccepterVpcInfo", {})
                req_account = requester.get("OwnerId", "")
                acc_account = accepter.get("OwnerId", "")

                # External if neither side is this account
                if req_account != account_id and acc_account != account_id:
                    findings.append(build_finding(
                        rule_id="NET-VPC-004", severity="MEDIUM",
                        resource_type="AWS::EC2::VPCPeeringConnection",
                        resource_id=f"{region}/{peer_id}",
                        title=f"VPC peering connection {peer_id} between external accounts ({region})",
                        description=(
                            f"Active VPC peering connection {peer_id} between account {req_account} "
                            f"and account {acc_account} — neither of which is the scanned account {account_id}. "
                            "Unexpected peering connections may indicate a misconfiguration or security risk."
                        ),
                        recommendation=(
                            "Verify this VPC peering connection is intentional. "
                            "Ensure route tables and security groups restrict traffic to only necessary CIDR ranges. "
                            "Review and document all cross-account peering connections."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"peer_id": peer_id, "requester_account": req_account,
                               "accepter_account": acc_account, "region": region}
                    ))
    except Exception as e:
        logger.error(f"VPC peering check failed in {region}: {e}")
    return findings


def _check_unused_igw(ec2, region, account_id, account_name):
    """Flag internet gateways not attached to any VPC."""
    findings = []
    try:
        for page in ec2.get_paginator("describe_internet_gateways").paginate():
            for igw in page.get("InternetGateways", []):
                igw_id      = igw["InternetGatewayId"]
                attachments = igw.get("Attachments", [])
                if not attachments:
                    findings.append(build_finding(
                        rule_id="NET-VPC-005", severity="LOW",
                        resource_type="AWS::EC2::InternetGateway",
                        resource_id=f"{region}/{igw_id}",
                        title=f"Detached Internet Gateway {igw_id} ({region})",
                        description=(
                            f"Internet Gateway {igw_id} in {region} is not attached to any VPC. "
                            "Unused gateways are a low-risk finding but indicate resource sprawl."
                        ),
                        recommendation=(
                            "Delete the Internet Gateway if it is no longer needed. "
                            "Run `aws ec2 delete-internet-gateway --internet-gateway-id " + igw_id + "`."
                        ),
                        account_id=account_id, account_name=account_name,
                        extra={"igw_id": igw_id, "region": region}
                    ))
    except Exception as e:
        logger.error(f"IGW check failed in {region}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    ec2_r = session.client("ec2", region_name=region)
    findings.extend(_check_flow_logs(ec2_r, region, account_id, ""))
    findings.extend(_check_default_vpc(ec2_r, region, account_id, ""))
    findings.extend(_check_public_subnets(ec2_r, region, account_id, ""))
    findings.extend(_check_vpc_peering(ec2_r, region, account_id, ""))
    findings.extend(_check_unused_igw(ec2_r, region, account_id, ""))
    return findings
