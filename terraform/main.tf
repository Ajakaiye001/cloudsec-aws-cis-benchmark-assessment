# =============================================================================
# CIS BENCHMARK TRAINING SANDBOX - REMEDIATED CONFIGURATION
# Target: a dedicated, isolated AWS training account (set via var.allowed_account_id)
#
# This version keeps the training resources but removes the intentionally weak
# settings from the supplied lab file. Review the Terraform plan before apply.
# The account-wide IAM password policy affects every IAM console user in this
# AWS account, so use only in the dedicated training account.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  description = "Sandbox region"
  type        = string
  default     = "eu-north-1"
}

variable "allowed_account_id" {
  description = "The only AWS account ID this configuration may deploy into"
  type        = string
}

variable "lab_bucket_name" {
  description = "Name of the existing lab bucket flagged in the Prowler baseline"
  type        = string
}

variable "create_public_bucket" {
  description = "Create a private S3 bucket for the lab"
  type        = bool
  default     = true
}

provider "aws" {
  region              = var.region
  profile             = "default"
  allowed_account_ids = [var.allowed_account_id]

  default_tags {
    tags = {
      Project = "cis-benchmark-lab"
      Warning = "TRAINING-SANDBOX"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# NETWORKING
# Keep the lab security group, but do not expose SSH or RDP to the internet.
# No inbound rules means inbound traffic is denied by the security group.
# -----------------------------------------------------------------------------
resource "aws_security_group" "wide_open" {
  name        = "cis-lab-wide-open"
  description = "CIS training security group - no public administrative ingress"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Allow outbound traffic required by the sandbox"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------------------
# IAM
# Keep a lab identity for assessment visibility, but do not grant it admin
# permissions and do not create a long-lived access key for it.
# -----------------------------------------------------------------------------
resource "aws_iam_user" "overprivileged" {
  name          = "cis-lab-overprivileged-user"
  force_destroy = true
}

# -----------------------------------------------------------------------------
# IAM ACCOUNT PASSWORD POLICY
# Account-wide control: use only because this account is dedicated to the lab.
# -----------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "strong" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# -----------------------------------------------------------------------------
# S3
# Keep the bucket private, enable versioning and default server-side encryption,
# and explicitly deny unencrypted (HTTP) transport.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "public" {
  count = var.create_public_bucket ? 1 : 0
  # This is the exact bucket identified in the uploaded Prowler baseline.
  # Import it into Terraform if it still exists before running terraform apply.
  bucket        = var.lab_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public" {
  count                   = var.create_public_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.public[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "public" {
  count  = var.create_public_bucket ? 1 : 0
  bucket = aws_s3_bucket.public[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "public" {
  count  = var.create_public_bucket ? 1 : 0
  bucket = aws_s3_bucket.public[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "require_tls" {
  count  = var.create_public_bucket ? 1 : 0
  bucket = aws_s3_bucket.public[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.public[0].arn,
        "${aws_s3_bucket.public[0].arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

# -----------------------------------------------------------------------------
# OUTPUTS
# Do not output or store any long-lived IAM secret access key.
# -----------------------------------------------------------------------------
output "lab_summary" {
  value = <<-EOT
    CIS training sandbox remediated configuration applied.
    IAM: lab user has no inline administrator policy and no access key managed here.
    Networking: no inbound SSH/RDP rules are configured on the lab security group.
    S3: Block Public Access enabled, versioning enabled, default encryption enabled,
        and insecure HTTP transport denied.

    Assessment command:
    prowler aws --profile lab --compliance cis_3.0_aws --output-formats html json-ocsf csv --output-directory ./prowler-run-2 --mutelist-file ./mutelist.yaml
  EOT
}

output "lab_bucket_name" {
  value       = try(aws_s3_bucket.public[0].bucket, null)
  description = "Name of the private training bucket"
}
