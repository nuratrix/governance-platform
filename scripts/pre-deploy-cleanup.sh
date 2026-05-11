#!/usr/bin/env bash
# scripts/pre-deploy-cleanup.sh
#
# Delete orphaned governance agent resources by prefix before terraform apply.
# Breaks the "already exists / role already exists" loop caused by resources
# left behind from previous failed deploys that are not in Terraform state.
#
# Usage: bash scripts/pre-deploy-cleanup.sh <agent-prefix> [region]
#   agent-prefix  e.g. governance-cost-anomaly, governance-security
#   region        default: us-east-1
#
# All deletions use || true so missing resources are silently ignored.
# All inner AWS calls use </dev/null to prevent stdin bleed in loops.

set -uo pipefail

PREFIX="${1:?Usage: $0 <agent-prefix> [region]}"
REGION="${2:-us-east-1}"

# Filter helper: split tab-separated AWS CLI output into one item per line,
# drop empty lines and AWS CLI "None" sentinel. grep returns 1 when no matches;
# the || true prevents that from aborting the script under set -e callers.
list() { tr '\t' '\n' | grep -Ev '^$|^None$' || true; }

echo "==> Pre-deploy cleanup: prefix='${PREFIX}' region='${REGION}'"

# ── Bedrock agents ────────────────────────────────────────────────────────────
echo "  [bedrock] scanning agents..."
while IFS= read -r agent_id; do
  echo "    Deleting aliases for agent $agent_id"
  while IFS= read -r alias_id; do
    aws bedrock-agent delete-agent-alias \
      --agent-id "$agent_id" --agent-alias-id "$alias_id" \
      --region "$REGION" </dev/null 2>&1 || true
  done < <(aws bedrock-agent list-agent-aliases \
    --agent-id "$agent_id" --region "$REGION" \
    --query "agentAliasSummaries[].agentAliasId" \
    --output text </dev/null 2>&1 | list)
  echo "    Deleting agent $agent_id"
  aws bedrock-agent delete-agent \
    --agent-id "$agent_id" --skip-resource-in-use-check \
    --region "$REGION" </dev/null 2>&1 || true
done < <(aws bedrock-agent list-agents --region "$REGION" \
  --query "agentSummaries[?starts_with(agentName,'${PREFIX}')].agentId" \
  --output text </dev/null 2>&1 | list)

# ── Lambda event source mappings ──────────────────────────────────────────────
echo "  [lambda] event source mappings..."
while IFS= read -r uuid; do
  echo "    Deleting ESM $uuid"
  aws lambda delete-event-source-mapping --uuid "$uuid" \
    --region "$REGION" </dev/null 2>&1 || true
done < <(aws lambda list-event-source-mappings --region "$REGION" \
  --query "EventSourceMappings[?contains(FunctionArn,'${PREFIX}')].UUID" \
  --output text </dev/null 2>&1 | list)

# ── Lambda functions ──────────────────────────────────────────────────────────
echo "  [lambda] functions..."
while IFS= read -r fn; do
  echo "    Deleting function $fn"
  aws lambda delete-function --function-name "$fn" \
    --region "$REGION" </dev/null 2>&1 || true
done < <(aws lambda list-functions --region "$REGION" \
  --query "Functions[?starts_with(FunctionName,'${PREFIX}')].FunctionName" \
  --output text </dev/null 2>&1 | list)

# ── IAM roles ─────────────────────────────────────────────────────────────────
echo "  [iam] roles..."
while IFS= read -r role; do
  echo "    Cleaning role $role"
  while IFS= read -r arn; do
    aws iam detach-role-policy --role-name "$role" \
      --policy-arn "$arn" </dev/null 2>&1 || true
  done < <(aws iam list-attached-role-policies --role-name "$role" \
    --query "AttachedPolicies[].PolicyArn" \
    --output text </dev/null 2>&1 | list)
  while IFS= read -r pname; do
    aws iam delete-role-policy --role-name "$role" \
      --policy-name "$pname" </dev/null 2>&1 || true
  done < <(aws iam list-role-policies --role-name "$role" \
    --query "PolicyNames[]" \
    --output text </dev/null 2>&1 | list)
  aws iam delete-role --role-name "$role" </dev/null 2>&1 || true
done < <(aws iam list-roles \
  --query "Roles[?starts_with(RoleName,'${PREFIX}')].RoleName" \
  --output text </dev/null 2>&1 | list)

echo "==> Pre-deploy cleanup complete for prefix '${PREFIX}'."
