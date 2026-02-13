---
title: "CloudTrail not integrated with CloudWatch"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_not_integrated_with_cloudwatch"
  id: "17b30f8f-8dfb-4597-adf6-57600b6cf25e"
  display_name: "CloudTrail not integrated with CloudWatch"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `17b30f8f-8dfb-4597-adf6-57600b6cf25e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail)

### Description

Integrating AWS CloudTrail with CloudWatch Logs is essential for real-time monitoring and alerting on account activity. If the `cloud_watch_logs_group_arn` and `cloud_watch_logs_role_arn` attributes are not set in the `aws_cloudtrail` resource, as in the following insecure configuration, CloudTrail events will only be stored in S3 with no efficient mechanism for real-time detection or automated response to suspicious activities:

```
resource "aws_cloudtrail" "example" {
  name = "tf-trail-foobar"
  s3_bucket_name = aws_s3_bucket.foo.id
  // cloud_watch_logs_group_arn and cloud_watch_logs_role_arn not set
}
```

Without CloudWatch integration, critical security or operational issues could go unnoticed, increasing the risk of unauthorized behavior persisting undetected in your AWS environment.

A secure Terraform configuration should explicitly connect CloudTrail to CloudWatch Logs. For example:

```
resource "aws_cloudtrail" "example" {
  name                          = "tf-trail-secure"
  s3_bucket_name                = aws_s3_bucket.foo.id
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_logs.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn
}
```

## Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name = "aws-foundations-benchmark-1-4-0-terraform-3-4-remediated"
}


resource "aws_iam_role" "cloud_watch_logs_role" {
  name = "aws-foundations-benchmark-1-4-0-terraform-3-4-remediated"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloud_watch_policy" {
  name = "CloudWatch-policy"
  role = aws_iam_role.cloud_watch_logs_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream"
      ],
      "Resource": [
        "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
      ]
    }
  ]
}
EOF
}


data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "negative1" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloud_watch_logs_role.arn
}

resource "aws_s3_bucket" "negative2" {
  bucket        = "tf-test-trail"
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::tf-test-trail"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::tf-test-trail/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudtrail" "positive1" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "positive4" {
  bucket        = "tf-test-trail"
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::tf-test-trail"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::tf-test-trail/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

```