---
title: "CloudTrail log files S3 bucket with logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_log_files_s3_bucket_with_logging_disabled"
  id: "ee9e50e8-b2ed-4176-ad42-8fc0cf7593f4"
  display_name: "CloudTrail log files S3 bucket with logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `ee9e50e8-b2ed-4176-ad42-8fc0cf7593f4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#s3_bucket_name)

### Description

 Enabling server access logging on S3 buckets that store AWS CloudTrail log files is essential for ensuring a comprehensive audit trail. If the `logging` block is not configured in the `aws_s3_bucket` resource, for example, in `resource "aws_s3_bucket" "foo" { ... }` without a `logging` attribute, access requests to the bucket itself are not recorded. This omission means that critical activities—such as who accessed, modified, or deleted CloudTrail log files—may go undetected, undermining visibility and hindering forensic investigations. If left unaddressed, this vulnerability could enable attackers or malicious insiders to cover their tracks by accessing or deleting evidence of unauthorized activity without any trace in bucket-level access logs.


## Compliant Code Examples
```terraform
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.2.0"
    }
  }
}

provider "aws" {
  # Configuration options
}

resource "aws_cloudtrail" "foobar2" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.bbb.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "bbb" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_logging" "example" {
  bucket = aws_s3_bucket.bbb.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "0.0.1"
  bucket = "s3-tf-example-versioning"
  acl    = "private"
  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }

  versioning_inputs = [
    {
      enabled = true
      mfa_delete = null
    },
  ]
}

```

```terraform
provider "aws" {
  region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

data "aws_caller_identity" "current2" {}

resource "aws_cloudtrail" "foobar2" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo2.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-tf-log-bucket"
  acl    = "log-delivery-write"
}


resource "aws_s3_bucket" "foo2" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}

```
## Non-Compliant Code Examples
```terraform
module "foo" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "0.0.1"
  acl    = "private"
  bucket        = "foo"
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

  versioning_inputs = [
    {
      enabled = true
      mfa_delete = null
    },
  ]
}

resource "aws_cloudtrail" "foobar" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

```

```terraform
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.2.0"
    }
  }
}

provider "aws" {
  # Configuration options
}

resource "aws_cloudtrail" "foobar2" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.bb.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "bb" {
  bucket = "my-tf-example-bucket"
}

```

```terraform
provider "aws" {
  region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "foobar" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
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