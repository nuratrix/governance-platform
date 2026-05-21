# ─────────────────────────────────────────────────────────────────────────────
# platform/terraform/dashboard_hosting.tf
#
# S3 + CloudFront hosting for the static governance findings dashboard.
# The HTML is uploaded with the API Gateway URL injected automatically —
# no manual edits needed after terraform apply.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  # Inject the API Gateway URL into the HTML at deploy time.
  dashboard_html = replace(
    file("${path.module}/../dashboard/index.html"),
    "YOUR_API_GATEWAY_URL_HERE",
    trimspace(aws_apigatewayv2_stage.dashboard.invoke_url)
  )
}

# ── S3 bucket (private — accessed only via CloudFront OAC) ───────────────────

resource "aws_s3_bucket" "dashboard" {
  bucket = "${local.prefix}-dashboard-${local.account_id}"
}

resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket                  = aws_s3_bucket.dashboard.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── CloudFront Origin Access Control ─────────────────────────────────────────
# Import block: brings the existing OAC into state on first apply after adding
# dashboard_hosting.tf. Safe to leave in — it becomes a no-op once imported.
import {
  to = aws_cloudfront_origin_access_control.dashboard
  id = "EHTXGJZDOMMUR"
}

resource "aws_cloudfront_origin_access_control" "dashboard" {
  name                              = "${local.prefix}-dashboard-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ── CloudFront distribution ───────────────────────────────────────────────────

resource "aws_cloudfront_distribution" "dashboard" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "Governance findings dashboard"

  origin {
    domain_name              = aws_s3_bucket.dashboard.bucket_regional_domain_name
    origin_id                = "s3-dashboard"
    origin_access_control_id = aws_cloudfront_origin_access_control.dashboard.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-dashboard"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = var.tags
}

# ── S3 bucket policy — restrict reads to CloudFront OAC only ─────────────────

resource "aws_s3_bucket_policy" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAC"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.dashboard.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.dashboard.arn
        }
      }
    }]
  })
}

# ── Upload HTML with API URL already substituted ──────────────────────────────

resource "aws_s3_object" "dashboard_html" {
  bucket       = aws_s3_bucket.dashboard.id
  key          = "index.html"
  content      = local.dashboard_html
  content_type = "text/html"
  etag         = md5(local.dashboard_html)
}

# ── Output ────────────────────────────────────────────────────────────────────

output "dashboard_url" {
  description = "CloudFront URL for the governance findings dashboard"
  value       = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}
