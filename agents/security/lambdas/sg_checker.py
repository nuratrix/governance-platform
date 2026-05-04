"""
Security Agent - Security Groups Checker — Multi-Account Edition
Accepts an optional boto3 session for cross-account scanning.
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DANGEROUS_PORTS = {
    22: ("SSH", "CRITICAL"), 3389: ("RDP", "CRITICAL"),
    1433: ("MSSQL", "CRITICAL"), 3306: ("MySQL", "CRITICAL"),
    5432: ("PostgreSQL", "CRITICAL"), 27017: ("MongoDB", "CRITICAL"),
    6379: ("Redis", "CRITICAL"), 9200: ("Elasticsearch", "CRITICAL"),
    5601: ("Kibana", "HIGH"), 8080: ("HTTP-Alt", "MEDIUM"),
    8443: ("HTTPS-Alt", "MEDIUM"), 2181: ("Zookeeper", "HIGH"),
    9092: ("Kafka", "HIGH"), 11211: ("Memcached", "HIGH"),
    5984: ("CouchDB", "HIGH"), 2379: ("etcd", "CRITICAL"),
    4444: ("Metasploit/RAT", "CRITICAL"),
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"Security Groups Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        ec2 = (session or boto3).client("ec2", region_name=region)
        region_findings = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    region_findings.extend(_check_ingress_rules(ec2, sg, account_id, account_name))
                    region_findings.extend(_check_egress_rules(sg, account_id, account_name))
                    region_findings.extend(_check_default_sg(sg, account_id, account_name))
                    region_findings.extend(_check_unused_sg(ec2, sg, account_id, account_name))
        except Exception as e:
            logger.error(f"Security Groups check failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Security Groups Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _check_ingress_rules(ec2, sg, account_id, account_name):
    findings = []
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", -1)
        to_port   = rule.get("ToPort", -1)
        protocol  = rule.get("IpProtocol", "-1")

        public_ranges = []
        for r in rule.get("IpRanges", []):
            if r.get("CidrIp") in PUBLIC_CIDRS:
                public_ranges.append(r["CidrIp"])
        for r in rule.get("Ipv6Ranges", []):
            if r.get("CidrIpv6") in PUBLIC_CIDRS:
                public_ranges.append(r["CidrIpv6"])

        if not public_ranges:
            continue

        if protocol == "-1":
            findings.append(build_finding(
                rule_id="SEC-SG-001", severity="CRITICAL",
                resource_type="AWS::EC2::SecurityGroup", resource_id=sg_id,
                title=f"Security group '{sg_name}' allows ALL inbound traffic from internet",
                description=f"Inbound rule allows ALL protocols from {', '.join(public_ranges)}.",
                recommendation="Remove the all-traffic rule and specify only required ports.",
                account_id=account_id, account_name=account_name,
            ))
            continue

        for port, (service, severity) in DANGEROUS_PORTS.items():
            in_range = (from_port <= port <= to_port) if from_port != -1 else True
            if in_range:
                findings.append(build_finding(
                    rule_id="SEC-SG-002", severity=severity,
                    resource_type="AWS::EC2::SecurityGroup", resource_id=sg_id,
                    title=f"Security group '{sg_name}' exposes {service} (port {port}) to internet",
                    description=f"Inbound rule allows {service} from {', '.join(public_ranges)}.",
                    recommendation=f"Restrict port {port} to specific trusted IP ranges.",
                    account_id=account_id, account_name=account_name,
                ))

        if from_port not in (-1, 80, 443) and (to_port - from_port) > 100:
            findings.append(build_finding(
                rule_id="SEC-SG-003", severity="MEDIUM",
                resource_type="AWS::EC2::SecurityGroup", resource_id=sg_id,
                title=f"Security group '{sg_name}' opens large port range to internet",
                description=f"Rule opens ports {from_port}-{to_port} from internet.",
                recommendation="Replace broad port ranges with specific required ports.",
                account_id=account_id, account_name=account_name,
            ))
    return findings


def _check_egress_rules(sg, account_id, account_name):
    findings = []
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)

    for rule in sg.get("IpPermissionsEgress", []):
        if rule.get("IpProtocol", "-1") == "-1":
            for r in rule.get("IpRanges", []):
                if r.get("CidrIp") in PUBLIC_CIDRS:
                    findings.append(build_finding(
                        rule_id="SEC-SG-004", severity="LOW",
                        resource_type="AWS::EC2::SecurityGroup", resource_id=sg_id,
                        title=f"Security group '{sg_name}' allows all outbound traffic",
                        description="Unrestricted outbound access could facilitate data exfiltration.",
                        recommendation="Restrict egress to specific required destinations.",
                        account_id=account_id, account_name=account_name,
                    ))
                    break
    return findings


def _check_default_sg(sg, account_id, account_name):
    findings = []
    if sg.get("GroupName") == "default" and sg.get("IpPermissions"):
        findings.append(build_finding(
            rule_id="SEC-SG-005", severity="MEDIUM",
            resource_type="AWS::EC2::SecurityGroup", resource_id=sg["GroupId"],
            title=f"Default security group in VPC {sg.get('VpcId', 'unknown')} has inbound rules",
            description="The default security group should have no rules.",
            recommendation="Remove all rules from the default security group.",
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ec2 = session.client("ec2", region_name=region)
    findings = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                findings.extend(_check_ingress_rules(ec2, sg, account_id, ""))
                findings.extend(_check_egress_rules(sg, account_id, ""))
                findings.extend(_check_default_sg(sg, account_id, ""))
                findings.extend(_check_unused_sg(ec2, sg, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"SG run_checks failed: {e}")
    return findings


def _check_unused_sg(ec2, sg, account_id, account_name):
    findings = []
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)

    if sg_name == "default":
        return findings
    try:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )["NetworkInterfaces"]
        if not enis:
            findings.append(build_finding(
                rule_id="SEC-SG-006", severity="LOW",
                resource_type="AWS::EC2::SecurityGroup", resource_id=sg_id,
                title=f"Security group '{sg_name}' is not attached to any resource",
                description="Unused security groups add clutter and may be reused inappropriately.",
                recommendation="Delete unused security groups.",
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check ENI attachments for {sg_id}: {e}")
    return findings
