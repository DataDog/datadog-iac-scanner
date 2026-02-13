---
title: "S3 bucket access to any principal"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_access_to_any_principal"
  id: "7af43613-6bb9-4a0e-8c4d-1314b799425e"
  display_name: "S3 bucket access to any principal"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `7af43613-6bb9-4a0e-8c4d-1314b799425e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy)

### Description

When an S3 bucket policy allows access to all AWS principals (`*`), it creates a significant security vulnerability by potentially exposing sensitive data to anyone on the internet. Malicious actors could access, modify, or delete your data, leading to data breaches, regulatory violations, and reputational damage. To secure your S3 bucket, avoid using `*` in the `Principal` field with an `Allow` effect. Instead, explicitly specify authorized principals or use a `Deny` effect, as shown below:

```
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
```

## Compliant Code Examples
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
resource "aws_s3_bucket_policy" "negative1" {
  bucket = aws_s3_bucket.b.id

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
## Non-Compliant Code Examples
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
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
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
resource "aws_s3_bucket" "this" {
  bucket = "my_tf_test_bucket"
  tags = {
    Name = "My bucket"
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # When used directly as a Cloudfront origin.
      Effect = "Allow"
      Action = "s3:GetObject"
      Principal = {
        Service = "cloudfront.amazonaws.com"
      }
      Resource = [
        "${aws_s3_bucket.this.arn}/*",
      ]
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.this.arn
        }
      }
      },
      {
        # Admin access for policy updates, etc.
        Effect = "Allow"
        Action = "s3:*"
        Principal = {
          AWS = [
            data.aws_caller_identity.current.id,
          ]
        }
        Resource = [
          "${aws_s3_bucket.this.arn}/*",
        ]
      },
      {
        # Delegate access to the access point.
        Effect = "Allow"
        Action = "*"
        Principal = {
          AWS = [
            "*"
          ]
        }
        Resource = [
          aws_s3_bucket.this.arn,
          "${aws_s3_bucket.this.arn}/*",
        ]
        Condition = {
          "StringEquals" = {
            "s3:DataAccessPointAccount" = data.aws_caller_identity.current.account_id
          }
        }
    }]
  })
}

```

```terraform
resource "aws_s3_bucket_policy" "positive1" {
  bucket = aws_s3_bucket.b.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYBUCKETPOLICY",
  "Statement": [
    {
      "Sid": "IPAllow",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
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