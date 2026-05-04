"""
Security Agent - ECR Checker — Multi-Account Edition
Audits Elastic Container Registry repositories for:
  - Image scanning on push not enabled
  - Repositories allowing public or cross-account access
  - Missing lifecycle policies (stale image accumulation)
  - Critical/High vulnerabilities in most recent images
  - Repositories using mutable image tags
"""

import json
import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Vulnerability severity thresholds
CRITICAL_VULN_THRESHOLD = 0   # any CRITICAL CVE = CRITICAL finding
HIGH_VULN_THRESHOLD     = 5   # >5 HIGH CVEs = HIGH finding


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"ECR Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        ecr = (session or boto3).client("ecr", region_name=region)
        region_findings = []
        try:
            paginator = ecr.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page["repositories"]:
                    region_findings.extend(_check_scan_on_push(repo, account_id, account_name))
                    region_findings.extend(_check_image_tag_mutability(repo, account_id, account_name))
                    region_findings.extend(_check_lifecycle_policy(ecr, repo, account_id, account_name))
                    region_findings.extend(_check_repository_policy(ecr, repo, account_id, account_name))
                    region_findings.extend(_check_image_vulnerabilities(ecr, repo, account_id, account_name))
        except Exception as e:
            logger.error(f"ECR repository listing failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"ECR Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


# ── Per-repository checks ─────────────────────────────────────────────────────

def _check_scan_on_push(repo, account_id, account_name):
    scan_config = repo.get("imageScanningConfiguration", {})
    if not scan_config.get("scanOnPush", False):
        return [build_finding(
            rule_id="SEC-ECR-001", severity="HIGH",
            resource_type="AWS::ECR::Repository", resource_id=repo["repositoryArn"],
            title=f"ECR repository '{repo['repositoryName']}' does not scan images on push",
            description=(
                "Image scanning on push is disabled. Vulnerabilities in pushed images "
                "will not be detected until a manual scan is triggered."
            ),
            recommendation=(
                "Enable scanOnPush on the repository. For enhanced scanning, enable "
                "ECR Enhanced Scanning with Inspector integration."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_image_tag_mutability(repo, account_id, account_name):
    if repo.get("imageTagMutability") == "MUTABLE":
        return [build_finding(
            rule_id="SEC-ECR-002", severity="MEDIUM",
            resource_type="AWS::ECR::Repository", resource_id=repo["repositoryArn"],
            title=f"ECR repository '{repo['repositoryName']}' allows mutable image tags",
            description=(
                "MUTABLE tag setting allows image tags (e.g. 'latest') to be overwritten. "
                "This enables supply chain attacks where a trusted tag is replaced with malicious content."
            ),
            recommendation=(
                "Set imageTagMutability to IMMUTABLE. Use image digests (sha256) in "
                "deployment manifests to pin exact image versions."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_lifecycle_policy(ecr, repo, account_id, account_name):
    repo_name = repo["repositoryName"]
    try:
        ecr.get_lifecycle_policy(repositoryName=repo_name)
        return []   # Policy exists
    except ecr.exceptions.LifecyclePolicyNotFoundException:
        return [build_finding(
            rule_id="SEC-ECR-003", severity="LOW",
            resource_type="AWS::ECR::Repository", resource_id=repo["repositoryArn"],
            title=f"ECR repository '{repo_name}' has no lifecycle policy",
            description=(
                "Without a lifecycle policy, old and untagged images accumulate indefinitely. "
                "This increases storage costs and means unscanned/vulnerable images persist."
            ),
            recommendation=(
                "Add a lifecycle policy to expire untagged images after 30 days and "
                "keep only the last N tagged images per prefix."
            ),
            account_id=account_id, account_name=account_name,
        )]
    except Exception as e:
        logger.warning(f"Could not check lifecycle policy for {repo_name}: {e}")
        return []


def _check_repository_policy(ecr, repo, account_id, account_name):
    findings = []
    repo_name = repo["repositoryName"]
    try:
        policy_text = ecr.get_repository_policy(repositoryName=repo_name)["policyText"]
        policy = json.loads(policy_text)
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            effect    = stmt.get("Effect", "")
            is_wildcard = (
                principal == "*" or
                (isinstance(principal, dict) and (
                    principal.get("AWS") == "*" or
                    principal.get("Service") == "*"
                ))
            )
            if effect == "Allow" and is_wildcard:
                findings.append(build_finding(
                    rule_id="SEC-ECR-004", severity="CRITICAL",
                    resource_type="AWS::ECR::Repository", resource_id=repo["repositoryArn"],
                    title=f"ECR repository '{repo_name}' policy allows public access (*)",
                    description=(
                        "The repository resource policy contains an Allow statement with "
                        "Principal: '*', making images publicly pullable without authentication."
                    ),
                    recommendation=(
                        "Remove the wildcard principal. Restrict pull access to specific "
                        "IAM roles, accounts, or use ECR public only for intentionally public images."
                    ),
                    account_id=account_id, account_name=account_name,
                ))
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        pass   # No policy = no public access, fine
    except Exception as e:
        logger.warning(f"Could not check repository policy for {repo_name}: {e}")
    return findings


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ecr = session.client("ecr", region_name=region)
    findings = []
    try:
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page["repositories"]:
                findings.extend(_check_scan_on_push(repo, account_id, ""))
                findings.extend(_check_image_tag_mutability(repo, account_id, ""))
                findings.extend(_check_lifecycle_policy(ecr, repo, account_id, ""))
                findings.extend(_check_repository_policy(ecr, repo, account_id, ""))
                findings.extend(_check_image_vulnerabilities(ecr, repo, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"ECR run_checks failed: {e}")
    return findings


def _check_image_vulnerabilities(ecr, repo, account_id, account_name):
    findings = []
    repo_name = repo["repositoryName"]
    try:
        # Get the most recent image
        images = ecr.describe_images(
            repositoryName=repo_name,
            filter={"tagStatus": "TAGGED"},
        ).get("imageDetails", [])

        if not images:
            return []

        # Sort by push date descending, check latest image
        latest = sorted(images, key=lambda x: x.get("imagePushedAt", ""), reverse=True)[0]
        digest  = latest.get("imageDigest", "")
        tag     = (latest.get("imageTags") or ["<untagged>"])[0]

        scan_findings = latest.get("imageScanFindingsSummary", {})
        counts        = scan_findings.get("findingSeverityCounts", {})

        critical_count = counts.get("CRITICAL", 0)
        high_count     = counts.get("HIGH", 0)

        if critical_count > CRITICAL_VULN_THRESHOLD:
            findings.append(build_finding(
                rule_id="SEC-ECR-005", severity="CRITICAL",
                resource_type="AWS::ECR::Image",
                resource_id=f"{repo_name}:{tag}@{digest[:19]}",
                title=f"ECR image '{repo_name}:{tag}' has {critical_count} CRITICAL vulnerabilities",
                description=(
                    f"The latest image has {critical_count} CRITICAL and {high_count} HIGH CVEs "
                    "as reported by ECR image scanning."
                ),
                recommendation=(
                    "Rebuild the image with a patched base image. Update package dependencies "
                    "and re-push. Block deployment of this image until vulnerabilities are remediated."
                ),
                account_id=account_id, account_name=account_name,
            ))
        elif high_count > HIGH_VULN_THRESHOLD:
            findings.append(build_finding(
                rule_id="SEC-ECR-005b", severity="HIGH",
                resource_type="AWS::ECR::Image",
                resource_id=f"{repo_name}:{tag}@{digest[:19]}",
                title=f"ECR image '{repo_name}:{tag}' has {high_count} HIGH vulnerabilities",
                description=(
                    f"The latest image has {high_count} HIGH CVEs as reported by ECR image scanning."
                ),
                recommendation=(
                    "Rebuild the image with updated base image and patched dependencies. "
                    "Consider using Distroless or minimal base images to reduce attack surface."
                ),
                account_id=account_id, account_name=account_name,
            ))
    except Exception as e:
        logger.warning(f"Could not check vulnerability scan results for {repo_name}: {e}")
    return findings
