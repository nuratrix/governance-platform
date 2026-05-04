"""
Security Agent - SSM Checker — Multi-Account Edition
Audits AWS Systems Manager for security issues:
  - Parameter Store parameters with secret-like names stored as String (not SecureString)
  - SSM documents shared publicly
  - EC2 instances not registered/reachable via SSM (no agent or no connectivity)
  - Patch compliance: instances with missing critical/security patches
"""

import re
import boto3
import logging
from datetime import datetime, timezone, timedelta
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Regex to identify parameters that likely contain secrets by name
_SECRET_NAME_RE = re.compile(
    r"(password|passwd|secret|token|api[_/.-]?key|access[_/.-]?key|private[_/.-]?key|"
    r"credential|cert|certificate|private|auth|bearer|webhook)",
    re.IGNORECASE,
)

# How long since last ping before an instance is considered unmanaged
STALE_PING_DAYS = 7


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"SSM Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        ssm = (session or boto3).client("ssm", region_name=region)
        ec2 = (session or boto3).client("ec2", region_name=region)
        region_findings = []
        region_findings.extend(_check_parameter_store(ssm, account_id, account_name))
        region_findings.extend(_check_public_documents(ssm, account_id, account_name))
        region_findings.extend(_check_unmanaged_instances(ssm, ec2, account_id, account_name))
        region_findings.extend(_check_patch_compliance(ssm, account_id, account_name))
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"SSM Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    ssm = session.client("ssm", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    findings = []
    findings.extend(_check_parameter_store(ssm, account_id, ""))
    findings.extend(_check_public_documents(ssm, account_id, ""))
    findings.extend(_check_unmanaged_instances(ssm, ec2, account_id, ""))
    findings.extend(_check_patch_compliance(ssm, account_id, ""))
    return findings


# ── Parameter Store ───────────────────────────────────────────────────────────

def _check_parameter_store(ssm, account_id, account_name):
    """Flag parameters with secret-like names stored as plain String (not SecureString)."""
    findings = []
    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page["Parameters"]:
                name  = param.get("Name", "")
                ptype = param.get("Type", "")
                if ptype == "String" and _SECRET_NAME_RE.search(name):
                    findings.append(build_finding(
                        rule_id="SEC-SSM-001", severity="HIGH",
                        resource_type="AWS::SSM::Parameter", resource_id=name,
                        title=f"SSM Parameter '{name}' stores a potential secret as plaintext String",
                        description=(
                            f"Parameter '{name}' appears to contain a secret or credential "
                            f"(based on its name) but is stored as type 'String' (unencrypted). "
                            "Anyone with ssm:GetParameter access can read the plaintext value."
                        ),
                        recommendation=(
                            "Change the parameter type to SecureString, encrypted with a KMS CMK. "
                            "Update any code that reads this parameter to handle SecureString decryption."
                        ),
                        account_id=account_id, account_name=account_name,
                    ))
    except Exception as e:
        logger.error(f"SSM Parameter Store check failed: {e}")
    return findings


# ── SSM Documents ─────────────────────────────────────────────────────────────

def _check_public_documents(ssm, account_id, account_name):
    """Flag SSM documents owned by this account that are shared publicly."""
    findings = []
    try:
        paginator = ssm.get_paginator("list_documents")
        for page in paginator.paginate(
            Filters=[{"Key": "Owner", "Values": [account_id]}]
        ):
            for doc in page["DocumentIdentifiers"]:
                doc_name = doc.get("Name", "")
                try:
                    perms = ssm.describe_document_permission(
                        Name=doc_name, PermissionType="Share"
                    )
                    account_ids = perms.get("AccountIds", [])
                    if "all" in account_ids:
                        findings.append(build_finding(
                            rule_id="SEC-SSM-002", severity="HIGH",
                            resource_type="AWS::SSM::Document", resource_id=doc_name,
                            title=f"SSM document '{doc_name}' is publicly shared with all AWS accounts",
                            description=(
                                f"SSM document '{doc_name}' has been shared with 'all' accounts. "
                                "Public documents expose your automation runbooks and may reveal "
                                "infrastructure details, internal resource names, or sensitive logic."
                            ),
                            recommendation=(
                                "Remove the public sharing permission. Share documents only with "
                                "specific trusted AWS account IDs."
                            ),
                            account_id=account_id, account_name=account_name,
                        ))
                except Exception as e:
                    logger.warning(f"Could not check permissions for document {doc_name}: {e}")
    except Exception as e:
        logger.error(f"SSM document listing failed: {e}")
    return findings


# ── Unmanaged EC2 Instances ───────────────────────────────────────────────────

def _check_unmanaged_instances(ssm, ec2, account_id, account_name):
    """
    Detect running EC2 instances not registered with SSM, or registered but
    not seen by the SSM agent within the past STALE_PING_DAYS days.
    Unmanaged instances cannot receive patches or run SSM automation.
    """
    findings = []
    try:
        # Get all running EC2 instance IDs
        running_ids = set()
        ec2_paginator = ec2.get_paginator("describe_instances")
        for page in ec2_paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    running_ids.add(inst["InstanceId"])

        if not running_ids:
            return []

        # Get instances visible to SSM
        managed_ids  = set()
        stale_cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_PING_DAYS)

        ssm_paginator = ssm.get_paginator("describe_instance_information")
        for page in ssm_paginator.paginate():
            for info in page["InstanceInformationList"]:
                inst_id     = info.get("InstanceId", "")
                last_ping   = info.get("LastPingDateTime")
                ping_status = info.get("PingStatus", "")

                if last_ping and last_ping.replace(tzinfo=timezone.utc) > stale_cutoff:
                    managed_ids.add(inst_id)
                else:
                    # SSM knows about the instance but agent is stale
                    if inst_id in running_ids:
                        findings.append(build_finding(
                            rule_id="SEC-SSM-003b", severity="MEDIUM",
                            resource_type="AWS::EC2::Instance", resource_id=inst_id,
                            title=f"EC2 instance '{inst_id}' SSM agent has not pinged in over {STALE_PING_DAYS} days",
                            description=(
                                f"The SSM agent on instance '{inst_id}' last pinged more than "
                                f"{STALE_PING_DAYS} days ago (status: {ping_status}). "
                                "The instance cannot receive patch baselines or run SSM automation."
                            ),
                            recommendation=(
                                "Verify the SSM agent is running and has outbound HTTPS access "
                                "to ssm.region.amazonaws.com. Restart the agent if needed."
                            ),
                            account_id=account_id, account_name=account_name,
                        ))
                    managed_ids.add(inst_id)   # Still in SSM registry

        # Instances running but completely invisible to SSM
        unmanaged = running_ids - managed_ids
        for inst_id in unmanaged:
            findings.append(build_finding(
                rule_id="SEC-SSM-003", severity="MEDIUM",
                resource_type="AWS::EC2::Instance", resource_id=inst_id,
                title=f"EC2 instance '{inst_id}' is not registered with SSM",
                description=(
                    f"Running EC2 instance '{inst_id}' is not visible in SSM. "
                    "It cannot be patched, inventoried, or accessed via Session Manager. "
                    "This creates an unmanaged, potentially unpatched machine in the environment."
                ),
                recommendation=(
                    "Install the SSM agent on the instance and attach an IAM role with "
                    "AmazonSSMManagedInstanceCore policy. Ensure VPC endpoints or internet "
                    "access to SSM endpoints is available."
                ),
                account_id=account_id, account_name=account_name,
            ))

    except Exception as e:
        logger.error(f"SSM unmanaged instance check failed: {e}")
    return findings


# ── Patch Compliance ──────────────────────────────────────────────────────────

def _check_patch_compliance(ssm, account_id, account_name):
    """Flag instances with missing CRITICAL or SECURITY patches per SSM Patch Manager."""
    findings = []
    try:
        paginator = ssm.get_paginator("describe_instance_patch_states")
        # We pass all instance IDs from SSM
        ssm_instances = []
        info_paginator = ssm.get_paginator("describe_instance_information")
        for page in info_paginator.paginate():
            ssm_instances.extend([
                i["InstanceId"] for i in page["InstanceInformationList"]
            ])

        if not ssm_instances:
            return []

        # describe_instance_patch_states takes up to 50 instance IDs per call
        for i in range(0, len(ssm_instances), 50):
            batch = ssm_instances[i:i + 50]
            try:
                resp = ssm.describe_instance_patch_states(InstanceIds=batch)
                for state in resp.get("InstancePatchStates", []):
                    inst_id       = state.get("InstanceId", "")
                    critical_miss = state.get("CriticalNonCompliantCount", 0)
                    security_miss = state.get("SecurityNonCompliantCount", 0)
                    other_miss    = state.get("OtherNonCompliantCount", 0)

                    if critical_miss > 0:
                        findings.append(build_finding(
                            rule_id="SEC-SSM-004", severity="CRITICAL",
                            resource_type="AWS::EC2::Instance", resource_id=inst_id,
                            title=f"EC2 instance '{inst_id}' is missing {critical_miss} CRITICAL patches",
                            description=(
                                f"Instance '{inst_id}' has {critical_miss} critical and "
                                f"{security_miss} security patches missing per SSM Patch Manager."
                            ),
                            recommendation=(
                                "Run 'AWS-RunPatchBaseline' SSM document with Operation=Install "
                                "on this instance immediately, or schedule a patch maintenance window."
                            ),
                            account_id=account_id, account_name=account_name,
                        ))
                    elif security_miss > 0:
                        findings.append(build_finding(
                            rule_id="SEC-SSM-004b", severity="HIGH",
                            resource_type="AWS::EC2::Instance", resource_id=inst_id,
                            title=f"EC2 instance '{inst_id}' is missing {security_miss} SECURITY patches",
                            description=(
                                f"Instance '{inst_id}' has {security_miss} security patches "
                                f"and {other_miss} other patches missing."
                            ),
                            recommendation=(
                                "Apply the security patch baseline via SSM Patch Manager. "
                                "Schedule regular patch maintenance windows."
                            ),
                            account_id=account_id, account_name=account_name,
                        ))
            except Exception as e:
                logger.warning(f"Could not get patch states for batch: {e}")
    except Exception as e:
        logger.error(f"SSM patch compliance check failed: {e}")
    return findings
