"""
Security Agent - Lambda Security Checker — Multi-Account Edition
Audits Lambda functions for security misconfigurations:
  - Resource-based policies that allow public invocation
  - Deprecated / end-of-life runtimes
  - Plaintext secrets in environment variables
  - Missing code signing configuration
  - No dead-letter queue on async-invocable functions
  - Functions with admin IAM roles attached
"""

import re
import boto3
import logging
from build_finding import build_finding
from utils import get_scan_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Runtimes that are deprecated or approaching EOL — update periodically
DEPRECATED_RUNTIMES = {
    "python3.6", "python3.7", "python3.8",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "java8",
    "dotnet6",
    "ruby2.7",
    "go1.x",           # superseded by provided.al2023
    "provided",        # generic provided (AL1 based)
}

# Patterns suggesting a plaintext secret value in env vars
_SECRET_KEY_RE   = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE,
)
_PLAINTEXT_RE    = re.compile(
    r"^(?!arn:)(?!{{).{8,}$"    # Not an ARN or template reference, at least 8 chars
)


def lambda_handler(event, context, session=None):
    scan_id      = event.get("scan_id", "unknown")
    account_id   = event.get("account_id", "")
    account_name = event.get("account_name", "")
    logger.info(f"Lambda Security Checker starting for scan_id={scan_id} account={account_id}")

    findings = []
    for region in get_scan_regions(session):
        lmb = (session or boto3).client("lambda", region_name=region)
        region_findings = []
        try:
            paginator = lmb.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    fn_name = fn["FunctionName"]
                    fn_arn  = fn["FunctionArn"]
                    region_findings.extend(_check_deprecated_runtime(fn, account_id, account_name))
                    region_findings.extend(_check_env_var_secrets(fn, account_id, account_name))
                    region_findings.extend(_check_dead_letter_queue(fn, account_id, account_name))
                    region_findings.extend(_check_public_resource_policy(lmb, fn_name, fn_arn, account_id, account_name))
                    region_findings.extend(_check_code_signing(lmb, fn_name, fn_arn, account_id, account_name))
                    region_findings.extend(_check_admin_role(fn, account_id, account_name))
        except Exception as e:
            logger.error(f"Lambda function listing failed: {e}")
        for f in region_findings:
            f["region"] = region
        findings.extend(region_findings)

    logger.info(f"Lambda Security Checker complete. {len(findings)} findings for account {account_id}.")
    return {"findings": findings}


# ── Per-function checks ───────────────────────────────────────────────────────

def _check_deprecated_runtime(fn, account_id, account_name):
    runtime = fn.get("Runtime", "")
    if runtime in DEPRECATED_RUNTIMES:
        return [build_finding(
            rule_id="SEC-LMB-001", severity="HIGH",
            resource_type="AWS::Lambda::Function", resource_id=fn["FunctionArn"],
            title=f"Lambda function '{fn['FunctionName']}' uses deprecated runtime '{runtime}'",
            description=(
                f"Runtime '{runtime}' is deprecated or end-of-life. AWS will block new deployments "
                "and eventually block invocations. Deprecated runtimes do not receive security patches."
            ),
            recommendation=(
                f"Migrate the function to a supported runtime. "
                "For Python: python3.12. For Node.js: nodejs22.x. For Java: java21. "
                "For Go: provided.al2023 with go build -tags lambda.norpc."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_env_var_secrets(fn, account_id, account_name):
    findings = []
    env_vars = fn.get("Environment", {}).get("Variables", {})
    for key, value in env_vars.items():
        if _SECRET_KEY_RE.search(key) and _PLAINTEXT_RE.match(str(value)):
            findings.append(build_finding(
                rule_id="SEC-LMB-002", severity="HIGH",
                resource_type="AWS::Lambda::Function", resource_id=fn["FunctionArn"],
                title=f"Lambda '{fn['FunctionName']}' has potential plaintext secret in env var '{key}'",
                description=(
                    f"Environment variable '{key}' appears to contain a plaintext credential or secret. "
                    "Environment variables are visible to anyone with lambda:GetFunction access and "
                    "appear in CloudTrail logs."
                ),
                recommendation=(
                    "Store the secret in AWS Secrets Manager or SSM Parameter Store (SecureString). "
                    "Fetch it at runtime using the SDK. Remove plaintext values from environment variables."
                ),
                account_id=account_id, account_name=account_name,
            ))
    return findings


def _check_dead_letter_queue(fn, account_id, account_name):
    """Flag async functions with no DLQ — failed invocations silently disappear."""
    dlq = fn.get("DeadLetterConfig", {}).get("TargetArn", "")
    if not dlq:
        return [build_finding(
            rule_id="SEC-LMB-003", severity="LOW",
            resource_type="AWS::Lambda::Function", resource_id=fn["FunctionArn"],
            title=f"Lambda function '{fn['FunctionName']}' has no Dead Letter Queue configured",
            description=(
                "Without a DLQ, asynchronous invocation failures (e.g. from SNS, EventBridge, S3) "
                "are silently discarded after Lambda's retry exhaustion. This can hide security events."
            ),
            recommendation=(
                "Configure an SQS queue or SNS topic as a Dead Letter Queue for the function "
                "so failed invocations can be inspected and replayed."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []


def _check_public_resource_policy(lmb, fn_name, fn_arn, account_id, account_name):
    """Detect resource-based policies granting invocation to * (the internet)."""
    import json
    findings = []
    try:
        policy_text = lmb.get_policy(FunctionName=fn_name)["Policy"]
        policy = json.loads(policy_text)
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            effect    = stmt.get("Effect", "")
            is_wildcard = (
                principal == "*" or
                (isinstance(principal, dict) and principal.get("AWS") == "*")
            )
            # Only flag if there is no aws:SourceArn / aws:SourceAccount condition narrowing it
            conditions = stmt.get("Condition", {})
            has_source_condition = any(
                k in ("ArnLike", "ArnEquals", "StringEquals")
                for k in conditions.keys()
            )
            if effect == "Allow" and is_wildcard and not has_source_condition:
                findings.append(build_finding(
                    rule_id="SEC-LMB-004", severity="CRITICAL",
                    resource_type="AWS::Lambda::Function", resource_id=fn_arn,
                    title=f"Lambda function '{fn_name}' allows invocation from any AWS principal (*)",
                    description=(
                        "The resource-based policy contains an Allow statement with Principal: '*' "
                        "and no source condition. Any AWS account can invoke this function."
                    ),
                    recommendation=(
                        "Restrict the resource policy to specific AWS accounts, services, or ARNs. "
                        "Add aws:SourceArn or aws:SourceAccount conditions on service-principal statements."
                    ),
                    account_id=account_id, account_name=account_name,
                ))
    except lmb.exceptions.ResourceNotFoundException:
        pass   # No resource policy — not a finding
    except Exception as e:
        logger.warning(f"Could not check policy for Lambda {fn_name}: {e}")
    return findings


def _check_code_signing(lmb, fn_name, fn_arn, account_id, account_name):
    """Flag functions that do not enforce code signing."""
    try:
        config = lmb.get_function_code_signing_config(FunctionName=fn_name)
        if not config.get("CodeSigningConfigArn"):
            raise Exception("No signing config")
        return []
    except Exception:
        return [build_finding(
            rule_id="SEC-LMB-005", severity="MEDIUM",
            resource_type="AWS::Lambda::Function", resource_id=fn_arn,
            title=f"Lambda function '{fn_name}' does not enforce code signing",
            description=(
                "Code signing is not configured. Any deployment package can be deployed "
                "to this function, including packages that bypass license or security checks."
            ),
            recommendation=(
                "Create an AWS Signer signing profile and code signing configuration, "
                "then associate it with the function."
            ),
            account_id=account_id, account_name=account_name,
        )]


def _get_session(account_id):
    from utils import assume_role_session as get_session
    return get_session(account_id)


def run_checks(account_id, region):
    """Entry point for the fan-out scheduled scanner."""
    session = _get_session(account_id)
    lmb = session.client("lambda", region_name=region)
    findings = []
    try:
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                fn_name = fn["FunctionName"]
                fn_arn = fn["FunctionArn"]
                findings.extend(_check_deprecated_runtime(fn, account_id, ""))
                findings.extend(_check_env_var_secrets(fn, account_id, ""))
                findings.extend(_check_dead_letter_queue(fn, account_id, ""))
                findings.extend(_check_public_resource_policy(lmb, fn_name, fn_arn, account_id, ""))
                findings.extend(_check_code_signing(lmb, fn_name, fn_arn, account_id, ""))
                findings.extend(_check_admin_role(fn, account_id, ""))
    except Exception as e:
        import logging
        logging.getLogger().error(f"Lambda security run_checks failed: {e}")
    return findings


def _check_admin_role(fn, account_id, account_name):
    """Flag functions whose execution role name suggests AdministratorAccess."""
    role_arn  = fn.get("Role", "")
    role_name = role_arn.split("/")[-1].lower()
    suspicious_terms = ("admin", "administrator", "root", "superuser", "fullaccess")
    if any(term in role_name for term in suspicious_terms):
        return [build_finding(
            rule_id="SEC-LMB-006", severity="HIGH",
            resource_type="AWS::Lambda::Function", resource_id=fn["FunctionArn"],
            title=f"Lambda function '{fn['FunctionName']}' uses a potentially over-privileged execution role '{role_arn.split('/')[-1]}'",
            description=(
                f"The execution role name '{role_arn.split('/')[-1]}' suggests broad administrative access. "
                "If a function is compromised, overly-permissive roles allow lateral movement across the account."
            ),
            recommendation=(
                "Review the execution role's attached policies. Apply least-privilege — "
                "the role should only allow the specific AWS actions the function actually calls."
            ),
            account_id=account_id, account_name=account_name,
        )]
    return []
