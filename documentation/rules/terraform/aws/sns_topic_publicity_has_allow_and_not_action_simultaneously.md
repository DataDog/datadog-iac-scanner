---
title: "SNS topic publicity has allow and NotAction simultaneously"
group_id: "Terraform / AWS"
meta:
  name: "aws/sns_topic_publicity_has_allow_and_not_action_simultaneously"
  id: "5ea624e4-c8b1-4bb3-87a4-4235a776adcc"
  display_name: "SNS topic publicity has allow and NotAction simultaneously"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{</* copyable-code */>}}5ea624e4-c8b1-4bb3-87a4-4235a776adcc{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy)

### Description

An SNS topic policy should not use both `"Effect": "Allow"` and the `"NotAction"` attribute together, as this grants permission to all actions except those explicitly denied, significantly increasing the potential attack surface. This misconfiguration can unintentionally allow broad access to the SNS topic, which may be exploited by attackers to perform unauthorized actions. To secure the policy, use the `"Action"` attribute alongside `"Effect": "Allow"`, as shown below:

```
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
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
  "Id": "MYPOLICYTEST",
  "Statement": [
    {
      "Action": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::*",
      "Sid": "MyStatementId",
      "Effect": "Allow"
    }
  ]
}
POLICY

   server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

```

```terraform
resource "aws_sns_topic" "negative1" {
  name = "my-topic-with-policy"
}

resource "aws_sns_topic_policy" "negative2" {
  arn = aws_sns_topic.test.arn

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYPOLICYTEST",
  "Statement": [
    {
      "Action": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::*",
      "Sid": "MyStatementId",
      "Effect": "Allow"
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
  "Id": "MYPOLICYTEST",
  "Statement": [
    {
      "NotAction": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::*",
      "Sid": "MyStatementId",
      "Effect": "Allow"
    }
  ]
}
POLICY

   server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

```

```terraform
resource "aws_sns_topic_policy" "multi_statement" {
  arn = aws_sns_topic.example.arn

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "SNS:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:example"
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "NotAction": "SNS:DeleteTopic",
      "Resource": "arn:aws:sns:us-east-1:123456789012:example"
    }
  ]
}
POLICY
}

resource "aws_sns_topic_policy" "jsonencoded" {
  arn = aws_sns_topic.example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        NotAction = "SNS:DeleteTopic"
        Resource  = "arn:aws:sns:us-east-1:123456789012:example"
      }
    ]
  })
}

```

```terraform
resource "aws_sns_topic" "positive1" {
  name = "my-topic-with-policy"
}

resource "aws_sns_topic_policy" "positive2" {
  arn = aws_sns_topic.test.arn

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYPOLICYTEST",
  "Statement": [
    {
      "NotAction": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::*",
      "Sid": "MyStatementId",
      "Effect": "Allow"
    }
  ]
}
POLICY
}

```