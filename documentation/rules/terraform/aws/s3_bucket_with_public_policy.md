---
title: "S3 bucket allows public policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_with_public_policy"
  id: "1a4bc881-9f69-4d44-8c9a-d37d08f54c50"
  display_name: "S3 bucket allows public policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `1a4bc881-9f69-4d44-8c9a-d37d08f54c50`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block)

### Description

 S3 buckets should block public policies to prevent unauthorized access to bucket contents. When the `block_public_policy` attribute is set to false or not defined in the `aws_s3_bucket_public_access_block` resource, attackers could potentially attach public policies to the bucket, exposing sensitive data to the internet. To secure your S3 bucket, ensure that `block_public_policy` is set to `true`, as shown in the following example:

```terraform
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = false
}
```


## Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"
  restrict_public_buckets = true
  block_public_acls = true
  block_public_policy = true

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
  ignore_public_acls  = false
}
```
## Non-Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"
  restrict_public_buckets = true
  block_public_acls = true
  block_public_policy = false

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
  restrict_public_buckets = true
  block_public_acls = true

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

resource "aws_s3_bucket_public_access_block" "positive2" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  block_public_policy = false
  ignore_public_acls  = false
}

// comment
// comment
// comment
// comment
// comment
resource "aws_s3_bucket_public_access_block" "positive3" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  ignore_public_acls  = false
}
```