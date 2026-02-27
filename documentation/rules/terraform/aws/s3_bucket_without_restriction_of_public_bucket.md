---
title: "S3 bucket without restriction of public bucket"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_without_restriction_of_public_bucket"
  id: "1ec253ab-c220-4d63-b2de-5b40e0af9293"
  display_name: "S3 bucket without restriction of public bucket"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `1ec253ab-c220-4d63-b2de-5b40e0af9293`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block)

### Description

This check verifies whether public access to an Amazon S3 bucket is properly restricted using the `restrict_public_buckets` attribute within the `aws_s3_bucket_public_access_block` resource. If `restrict_public_buckets` is set to `false` or omitted, as shown below, the bucket may still be publicly accessible through policies, even if other public access blocks are enabled:

```
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = false
}
```

Leaving public bucket restriction disabled increases the risk of unintended data exposure, as users could still attach bucket policies that override ACLs and grant public access. To mitigate this vulnerability and ensure S3 buckets cannot be made public by any means, the `restrict_public_buckets` attribute should be explicitly set to `true`:

```
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
}
```
Failure to enforce this protection may lead to unauthorized access to sensitive data stored in S3, resulting in data breaches and compliance violations.

## Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"
  restrict_public_buckets = true

  versioning = {
    enabled = true
  }

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}

```

```terraform
resource "aws_s3_bucket" "negative1" {
  bucket = "example"
}

resource "aws_s3_bucket_public_access_block" "negative2" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  block_public_policy = true

  restrict_public_buckets = true
}

```
## Non-Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  restrict_public_buckets = false

  versioning = {
    enabled = true
  }

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning = {
    enabled = true
  }

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my_tf_test_bucket/*",
      "Condition": {
         "IpAddress": {"aws:SourceIp": "8.8.8.8/32"}
      }
    }
  ]
}
POLICY
}

```

```terraform
resource "aws_s3_bucket" "positive1" {
  bucket = "example"
}

// comment
resource "aws_s3_bucket_public_access_block" "positive2" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "positive3" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  block_public_policy = true
}

```