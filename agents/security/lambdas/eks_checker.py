"""
Security Agent - EKS Checker — Multi-Account Edition
Audits EKS clusters for security misconfigurations across:
  - Public endpoint exposure and IP restrictions
  - Control plane logging coverage
  - Kubernetes version currency
  - Secrets envelope encryption
  - IMDSv2 enforcement on node groups
  - OIDC provider (required for IRSA / least-privilege pod identity)
"""

import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Minimum supported Kubernetes version — update each release cycle
MIN_K8S_VERSION = (1, 29)

# All control plane log types that should be enabled
REQUIRED_LOG_TYPES = {"api", "audit", "authenticator", "controllerManager", "scheduler"}


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"EKS Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        eks = (session or boto3).client("eks", region_name=region)
        region_findings = []
        try:
            paginator = eks.get_paginator("list_clusters")
            for page in paginator.paginate():
                for cluster_name in page["clusters"]:
                    try:
                        cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                        region_findings.extend(_check_public_endpoint(cluster, account_id, account_name))
                        region_findings.extend(_check_logging(cluster, account_id, account_name))
                        region_findings.extend(_check_k8s_version(cluster, account_id, account_name))
                        region_findings.extend(_check_envelope_encryption(cluster, account_id, account_name))
                        region_findings.extend(_check_oidc_provider(cluster, account_id, account_name))
                        region_findings.extend(_check_node_groups(eks, cluster_name, account_id, account_name))
                    except Exception as e:
                        logger.warning(f"Could not describe cluster {cluster_name}: {e}")
        except Exception as e:
            logger.error(f"EKS cluster listing failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"EKS Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


# ── Per-cluster checks ────────────────────────────────────────────────────────

def _check_public_endpoint(cluster, account_id, account_name):
    findings = []
    name       = cluster["name"]
    resources  = cluster.get("resourcesVpcConfig", {})
    public     = resources.get("endpointPublicAccess", True)
    pub_cidrs  = resources.get("publicAccessCidrs", [])

    if public:
        # Public access with no IP restriction (0.0.0.0/0 or ::/0)
        unrestricted = not pub_cidrs or any(c in ("0.0.0.0/0", "::/0") for c in pub_cidrs)
        if unrestricted:
            findings.append(build_finding(
                rule_id="SEC-EKS-001", severity="HIGH",
                resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
                title=f"EKS cluster '{name}' API endpoint is publicly accessible with no IP restriction",
                description=(
                    "The Kubernetes API server endpoint is accessible from the internet "
                    f"with no CIDR restrictions (publicAccessCidrs={pub_cidrs or ['0.0.0.0/0']})."
                ),
                recommendation=(
                    "Disable public endpoint access and use a VPN/Direct Connect, or "
                    "restrict publicAccessCidrs to your corporate IP ranges only."
                ),
                account_id=account_id, account_name=account_name,
            ))
        else:
            # Public but restricted — lower severity, still worth noting
            findings.append(build_finding(
                rule_id="SEC-EKS-001b", severity="LOW",
                resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
                title=f"EKS cluster '{name}' API endpoint is public (CIDR-restricted)",
                description=f"Public access is enabled but restricted to: {pub_cidrs}.",
                recommendation="Consider disabling public endpoint entirely if VPC/VPN access is available.",
                account_id=account_id, account_name=account_name,
            ))
    return findings


def _check_logging(cluster, account_id, account_name):
    findings = []
    name     = cluster["name"]
    enabled  = set()

    for log_config in cluster.get("logging", {}).get("clusterLogging", []):
        if log_config.get("enabled"):
            enabled.update(log_config.get("types", []))

    missing = REQUIRED_LOG_TYPES - enabled
    if missing:
        severity = "HIGH" if {"audit", "api"} & missing else "MEDIUM"
        findings.append(build_finding(
            rule_id="SEC-EKS-002", severity=severity,
            resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
            title=f"EKS cluster '{name}' is missing control plane log types: {sorted(missing)}",
            description=(
                f"Control plane logging is not enabled for: {sorted(missing)}. "
                "Without audit logs, API server activity cannot be investigated."
            ),
            recommendation="Enable all five log types: api, audit, authenticator, controllerManager, scheduler.",
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _check_k8s_version(cluster, account_id, account_name):
    findings = []
    name     = cluster["name"]
    version  = cluster.get("version", "0.0")

    try:
        major, minor = (int(x) for x in version.split(".")[:2])
        if (major, minor) < MIN_K8S_VERSION:
            severity = "CRITICAL" if (major, minor) < (MIN_K8S_VERSION[0], MIN_K8S_VERSION[1] - 2) else "HIGH"
            findings.append(build_finding(
                rule_id="SEC-EKS-003", severity=severity,
                resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
                title=f"EKS cluster '{name}' is running Kubernetes {version} (below minimum {'.'.join(map(str, MIN_K8S_VERSION))})",
                description=(
                    f"Kubernetes {version} may be end-of-life or missing security patches. "
                    f"Minimum recommended version is {'.'.join(map(str, MIN_K8S_VERSION))}."
                ),
                recommendation="Upgrade the cluster to a supported Kubernetes version via the EKS managed upgrade process.",
                account_id=account_id, account_name=account_name,
            ))
    except (ValueError, AttributeError) as e:
        logger.warning(f"Could not parse K8s version '{version}' for cluster {name}: {e}")

    return findings


def _check_envelope_encryption(cluster, account_id, account_name):
    findings = []
    name            = cluster["name"]
    encrypt_configs = cluster.get("encryptionConfig", [])

    has_secret_encryption = any(
        "secrets" in cfg.get("resources", [])
        for cfg in encrypt_configs
    )

    if not has_secret_encryption:
        findings.append(build_finding(
            rule_id="SEC-EKS-004", severity="HIGH",
            resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
            title=f"EKS cluster '{name}' does not use envelope encryption for Kubernetes Secrets",
            description=(
                "Kubernetes Secrets stored in etcd are not encrypted with a KMS CMK. "
                "If etcd is compromised, Secrets (tokens, passwords, certificates) are readable."
            ),
            recommendation=(
                "Enable envelope encryption by associating a KMS CMK with the cluster's "
                "encryptionConfig for the 'secrets' resource type."
            ),
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _check_oidc_provider(cluster, account_id, account_name):
    findings = []
    name     = cluster["name"]
    oidc     = cluster.get("identity", {}).get("oidc", {})

    if not oidc.get("issuer"):
        findings.append(build_finding(
            rule_id="SEC-EKS-005", severity="MEDIUM",
            resource_type="AWS::EKS::Cluster", resource_id=cluster["arn"],
            title=f"EKS cluster '{name}' does not have an OIDC provider configured",
            description=(
                "Without an OIDC provider, pods cannot use IAM Roles for Service Accounts (IRSA). "
                "Workloads fall back to EC2 instance profile credentials, violating least privilege."
            ),
            recommendation=(
                "Associate an IAM OIDC provider with the cluster and migrate pod AWS access to IRSA."
            ),
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _check_node_groups(eks, cluster_name, account_id, account_name):
    findings = []
    try:
        paginator = eks.get_paginator("list_nodegroups")
        for page in paginator.paginate(clusterName=cluster_name):
            for ng_name in page["nodegroups"]:
                try:
                    ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)["nodegroup"]
                    findings.extend(_check_imdsv2(ng, cluster_name, account_id, account_name))
                    findings.extend(_check_node_ami_type(ng, cluster_name, account_id, account_name))
                except Exception as e:
                    logger.warning(f"Could not describe nodegroup {ng_name}: {e}")
    except Exception as e:
        logger.warning(f"Could not list nodegroups for cluster {cluster_name}: {e}")
    return findings


def _check_imdsv2(ng, cluster_name, account_id, account_name):
    """IMDSv2 (hop limit=1, HttpTokens=required) prevents SSRF-based metadata theft."""
    findings = []
    ng_name  = ng["nodegroupName"]
    lt       = ng.get("launchTemplate")

    if not lt:
        # Managed node group with no custom launch template — IMDSv2 not enforced
        findings.append(build_finding(
            rule_id="SEC-EKS-006", severity="MEDIUM",
            resource_type="AWS::EKS::Nodegroup",
            resource_id=f"{cluster_name}/{ng_name}",
            title=f"EKS node group '{ng_name}' does not use a launch template — IMDSv2 cannot be enforced",
            description=(
                "Without a custom launch template, IMDSv2 (HttpTokens=required) cannot be enforced. "
                "Pods running on these nodes can access IMDS v1 and steal instance credentials via SSRF."
            ),
            recommendation=(
                "Create a launch template with HttpTokens=required and HttpPutResponseHopLimit=1 "
                "and associate it with the node group."
            ),
            account_id=account_id, account_name=account_name,
        ))
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    eks = session.client("eks", region_name=region)
    findings = []
    try:
        paginator = eks.get_paginator("list_clusters")
        for page in paginator.paginate():
            for cluster_name in page["clusters"]:
                try:
                    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                    findings.extend(_check_public_endpoint(cluster, account_id, ""))
                    findings.extend(_check_logging(cluster, account_id, ""))
                    findings.extend(_check_k8s_version(cluster, account_id, ""))
                    findings.extend(_check_envelope_encryption(cluster, account_id, ""))
                    findings.extend(_check_oidc_provider(cluster, account_id, ""))
                    findings.extend(_check_node_groups(eks, cluster_name, account_id, ""))
                except Exception as e:
                    import logging
                    logging.getLogger().warning(f"Could not describe cluster {cluster_name}: {e}")
    except Exception as e:
        import logging
        logging.getLogger().error(f"EKS run_checks failed: {e}")
    return findings


def _check_node_ami_type(ng, cluster_name, account_id, account_name):
    """Flag AL1-based AMIs (Amazon Linux 1) — end of life."""
    findings = []
    ng_name  = ng["nodegroupName"]
    ami_type = ng.get("amiType", "")

    if "AL2023" not in ami_type and "BOTTLEROCKET" not in ami_type and ami_type:
        findings.append(build_finding(
            rule_id="SEC-EKS-007", severity="LOW",
            resource_type="AWS::EKS::Nodegroup",
            resource_id=f"{cluster_name}/{ng_name}",
            title=f"EKS node group '{ng_name}' uses AMI type '{ami_type}' instead of AL2023 or Bottlerocket",
            description=(
                f"Node group is using '{ami_type}'. AL2023 and Bottlerocket receive more frequent "
                "security patches and have a smaller attack surface."
            ),
            recommendation="Migrate node group to AL2023_x86_64 or BOTTLEROCKET_x86_64 AMI type.",
            account_id=account_id, account_name=account_name,
        ))
    return findings
