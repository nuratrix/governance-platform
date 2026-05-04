# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/organizations.tf  (NEW — multi-account)
# AWS Organizations integration.
#
# Two usage modes:
#
# Mode A — Static list (default, deploy_member_roles = false):
#   Define member_accounts in platform.tfvars.
#   Deploy the member_account module to each account separately.
#
# Mode B — Auto-discovery via Organizations + auto-deploy roles
#   (deploy_member_roles = true):
#   The platform reads the account list from Organizations and deploys
#   the cross-account reader role into each member account via provider
#   aliases (requires broad org-level credentials in CI/CD).
#
# For most organisations Mode A is recommended — it gives explicit control
# over which accounts are governed and avoids the need for org-root credentials
# in CI/CD.
# ─────────────────────────────────────────────────────────────────────────────

# ── Optional: read account list from Organizations ────────────────────────────
# Useful for auto-discovery. Comment out if not using AWS Organizations.
# data "aws_organizations_organization" "org" {}
#
# locals {
#   org_accounts = [
#     for a in data.aws_organizations_organization.org.accounts :
#     {
#       account_id  = a.id
#       name        = a.name
#       env         = "production"         # Override per OU tag if needed
#       reader_role = "governance-platform-reader"
#     }
#     if a.id != local.account_id         # Exclude governance account itself
#   ]
# }

# ── S3 knowledge base bucket (referenced by outputs.tf) ──────────────────────
resource "aws_s3_bucket" "knowledge_base" {
  bucket = "governance-platform-knowledge-base-${local.account_id}"
}

resource "aws_s3_bucket_versioning" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "knowledge_base" {
  bucket = aws_s3_bucket.knowledge_base.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "knowledge_base" {
  bucket                  = aws_s3_bucket.knowledge_base.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
