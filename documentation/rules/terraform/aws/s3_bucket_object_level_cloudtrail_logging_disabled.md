---
title: "S3 bucket object-level CloudTrail logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_object_level_cloudtrail_logging_disabled"
  id: "a8fc2180-b3ac-4c93-bd0d-a55b974e4b07"
  display_name: "S3 bucket object-level CloudTrail logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `a8fc2180-b3ac-4c93-bd0d-a55b974e4b07`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#event_selector)

### Description

S3 bucket object-level CloudTrail logging should be enabled for both read and write events by specifying `read_write_type = "All"` in the `event_selector` block. Without this, only management events are logged, leaving access or changes to individual objects unmonitored. If left unaddressed, this misconfiguration can result in undetected data exfiltration or unauthorized access, as malicious or accidental activities at the object level within the bucket would not be captured in CloudTrail logs.

## Compliant Code Examples
```terraform
data "aws_caller_identity" "current3" {}

resource "aws_cloudtrail" "example3" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo3.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_s3_bucket" "foo3" {
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
            "Resource": "arn:aws:s3:::tf-test-trail/prefix/AWSLogs/${data.aws_caller_identity.current3.account_id}/*",
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
data "aws_caller_identity" "current2" {}

resource "aws_cloudtrail" "example2" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo2.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false

  event_selector {
    read_write_type           = "ReadOnly"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_s3_bucket2" "foo" {
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
            "Resource": "arn:aws:s3:::tf-test-trail/prefix/AWSLogs/${data.aws_caller_identity.current2.account_id}/*",
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

```terraform
data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "example" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false

  event_selector {
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_s3_bucket" "foo" {
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