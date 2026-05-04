"""
Network Security Agent - NACL & Security Group Checker
Audits Network ACLs and Security Groups for overly permissive rules,
unrestricted ingress/egress, and dangerous port exposures.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Ports that should never be publicly exposed (0.0.0.0/0 or ::/0)
DANGEROUS_PORTS = {
    22:    "SSH",
    3389:  "RDP",
    23:    "Telnet",
    21:    "FTP",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    9200:  "Elasticsearch",
    2375:  "Docker daemon (unencrypted)",
    2379:  "etcd",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")

    findings = []
    for region in get_scan_regions(session):
        ec2_r = session.client("ec2", region_name=region) if session else boto3.client("ec2", region_name=region)
        region_findings = []
        region_findings.extend(_check_security_groups(ec2_r, region, account_id, account_name))
        region_findings.extend(_check_nacls(ec2_r, region, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"NACL/SG Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _is_public(cidr):
    return cidr in PUBLIC_CIDRS


def _check_security_groups(ec2, region, account_id, account_name):
    findings = []
    try:
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id   = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                vpc_id  = sg.get("VpcId", "N/A")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port   = rule.get("ToPort", 65535)
                    protocol  = rule.get("IpProtocol", "-1")

                    all_traffic = (protocol == "-1") or (from_port == 0 and to_port == 65535)
                    public_cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if _is_public(r["CidrIp"])]
                    public_cidrs += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if _is_public(r["CidrIpv6"])]

                    if not public_cidrs:
                        continue

                    if all_traffic:
                        findings.append(build_finding(
                            rule_id="NET-SG-001", severity="CRITICAL",
                            resource_type="AWS::EC2::SecurityGroup",
                            resource_id=f"{region}/{sg_id}",
                            title=f"Security group {sg_id} allows ALL inbound traffic from internet ({region})",
                            description=(
                                f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} ({region}) "
                                f"has an inbound rule allowing ALL traffic from {', '.join(public_cidrs)}. "
                                "This completely bypasses network-layer access controls."
                            ),
                            recommendation=(
                                "Remove the overly permissive rule immediately. "
                                "Replace with specific rules scoped to required ports and trusted CIDR ranges. "
                                "Use security group references instead of CIDR ranges where possible."
                            ),
                            account_id=account_id, account_name=account_name,
                            extra={"sg_id": sg_id, "sg_name": sg_name, "vpc_id": vpc_id, "region": region}
                        ))
                        continue

                    # Check for dangerous port exposure
                    for port, service in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            findings.append(build_finding(
                                rule_id="NET-SG-002", severity="HIGH",
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=f"{region}/{sg_id}",
                                title=f"Security group {sg_id} exposes {service} (port {port}) to internet ({region})",
                                description=(
                                    f"Security group '{sg_name}' ({sg_id}) allows inbound {service} (TCP/{port}) "
                                    f"from {', '.join(public_cidrs)} in {region}. "
                                    f"Publicly exposing {service} is a significant security risk."
                                ),
                                recommendation=(
                                    f"Restrict {service} access to specific trusted IP ranges or use a VPN/bastion host. "
                                    f"Remove the public CIDR from the inbound rule for port {port}. "
                                    "Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP access."
                                ),
                                account_id=account_id, account_name=account_name,
                                extra={"sg_id": sg_id, "sg_name": sg_name, "port": port,
                                       "service": service, "region": region}
                            ))

    except Exception as e:
        logger.error(f"Security group check failed in {region}: {e}")
    return findings


def _check_nacls(ec2, region, account_id, account_name):
    """Check for NACLs with overly permissive ALLOW ALL rules."""
    findings = []
    try:
        for page in ec2.get_paginator("describe_network_acls").paginate():
            for nacl in page.get("NetworkAcls", []):
                nacl_id    = nacl["NetworkAclId"]
                vpc_id     = nacl.get("VpcId", "N/A")
                is_default = nacl.get("IsDefault", False)

                for entry in nacl.get("Entries", []):
                    if entry.get("Egress"):
                        continue  # only check inbound
                    if entry.get("RuleAction") != "allow":
                        continue

                    cidr       = entry.get("CidrBlock", "") or entry.get("Ipv6CidrBlock", "")
                    protocol   = entry.get("Protocol", "-1")
                    port_range = entry.get("PortRange", {})
                    from_port  = port_range.get("From", 0)
                    to_port    = port_range.get("To", 65535)

                    if not _is_public(cidr):
                        continue

                    # All traffic ALLOW from internet
                    if protocol == "-1":
                        findings.append(build_finding(
                            rule_id="NET-NACL-001",
                            severity="HIGH" if not is_default else "MEDIUM",
                            resource_type="AWS::EC2::NetworkAcl",
                            resource_id=f"{region}/{nacl_id}",
                            title=f"NACL {nacl_id} allows ALL inbound traffic from internet ({region})",
                            description=(
                                f"Network ACL {nacl_id} (VPC: {vpc_id}, {'default' if is_default else 'custom'}) "
                                f"in {region} has an inbound ALLOW ALL rule from {cidr}. "
                                "NACLs provide a secondary defence layer — overly permissive rules negate this."
                            ),
                            recommendation=(
                                "Replace the catch-all ALLOW with specific rules for required ports only. "
                                "Add explicit DENY rules for DANGEROUS_PORTS at a higher priority. "
                                "NACLs are stateless — ensure return traffic rules are also tightened."
                            ),
                            account_id=account_id, account_name=account_name,
                            extra={"nacl_id": nacl_id, "vpc_id": vpc_id, "region": region,
                                   "is_default": is_default, "cidr": cidr}
                        ))

                    # Dangerous port in NACL allow rule
                    for port, service in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            findings.append(build_finding(
                                rule_id="NET-NACL-002", severity="MEDIUM",
                                resource_type="AWS::EC2::NetworkAcl",
                                resource_id=f"{region}/{nacl_id}",
                                title=f"NACL {nacl_id} allows {service} (port {port}) from internet ({region})",
                                description=(
                                    f"Network ACL {nacl_id} in VPC {vpc_id} ({region}) allows "
                                    f"inbound {service} (port {port}) from {cidr}. "
                                    "Even if security groups restrict this further, defence-in-depth "
                                    "requires NACLs to also deny unnecessary ports."
                                ),
                                recommendation=(
                                    f"Add a DENY rule for port {port} from 0.0.0.0/0 at a lower rule number "
                                    "than the current ALLOW rule, or remove the broad ALLOW range."
                                ),
                                account_id=account_id, account_name=account_name,
                                extra={"nacl_id": nacl_id, "vpc_id": vpc_id, "port": port,
                                       "service": service, "region": region}
                            ))

    except Exception as e:
        logger.error(f"NACL check failed in {region}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    findings = []
    ec2_r = session.client("ec2", region_name=region)
    findings.extend(_check_security_groups(ec2_r, region, account_id, ""))
    findings.extend(_check_nacls(ec2_r, region, account_id, ""))
    return findings
