# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/stackset.tf
#
# Deploys the governance-platform-reader IAM role to every member account in the
# target OUs via CloudFormation StackSets (SERVICE_MANAGED permission model).
#
# Auto-deployment is enabled: new accounts that join a targeted OU automatically
# receive the role. Accounts removed from the OU have the stack deleted.
#
# Prerequisites (one-time, run once in the governance / management account):
#
#   aws organizations enable-aws-service-access \
#     --service-principal stacksets.cloudformation.amazonaws.com
#
#   aws cloudformation activate-organizations-access
#
# This file is active only when stackset_target_ou_ids is non-empty.
# Leave it empty ([]) to skip StackSet deployment and manage roles manually
# or via the member_account_setup GitHub workflow instead.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  stackset_enabled = length(var.stackset_target_ou_ids) > 0
}

resource "aws_cloudformation_stack_set" "reader_role" {
  count = local.stackset_enabled ? 1 : 0

  name             = "governance-platform-reader-role"
  description      = "Cross-account reader IAM role for the AWS Governance Platform"
  permission_model = "SERVICE_MANAGED"
  call_as          = "DELEGATED_ADMIN"

  # Automatically deploy to new accounts as they join the targeted OUs.
  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  template_body = file("${path.module}/../cloudformation/member_account_role.yaml")

  parameters = {
    GovernanceAccountId = local.account_id
    RoleName            = "governance-platform-reader"
    ExternalId          = "governance-platform"
  }

  capabilities = ["CAPABILITY_NAMED_IAM"]

  tags = merge(var.tags, {
    Name      = "governance-platform-reader-stackset"
    ManagedBy = "Terraform"
  })
}

resource "aws_cloudformation_stack_set_instance" "reader_role" {
  count = local.stackset_enabled ? 1 : 0

  stack_set_name = aws_cloudformation_stack_set.reader_role[0].name
  region         = var.aws_region

  deployment_targets {
    organizational_unit_ids = var.stackset_target_ou_ids
  }

  # Tolerate individual account failures — a locked-down account should not
  # block the StackSet from deploying to all others.
  operation_preferences {
    failure_tolerance_percentage = 20
    max_concurrent_percentage    = 50
  }

  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }
}

output "stackset_id" {
  description = "CloudFormation StackSet name (empty if stackset_target_ou_ids is not set)"
  value       = local.stackset_enabled ? aws_cloudformation_stack_set.reader_role[0].id : null
}
