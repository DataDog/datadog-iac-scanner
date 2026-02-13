---
title: "CloudTrail log files S3 bucket is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_log_files_s3_bucket_is_publicly_accessible"
  id: "bd0088a5-c133-4b20-b129-ec9968b16ef3"
  display_name: "CloudTrail log files S3 bucket is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Observability"
---
## Metadata

**Id:** `bd0088a5-c133-4b20-b129-ec9968b16ef3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#s3_bucket_name)

### Description

This check identifies when CloudTrail logs are stored in an S3 bucket that is publicly accessible, creating a significant security risk. CloudTrail logs contain sensitive information about API calls and activities in your AWS environment that could be exposed to unauthorized parties if stored in a public bucket. To remediate this issue, ensure your S3 bucket has its ACL set to `private` instead of `public-read`, as shown in the example below:

```
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"
  acl    = "private"  // Correct setting instead of "public-read"
}
```

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

resource "aws_cloudtrail" "foobar4" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.bbb.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "bb" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl2" {
  bucket = aws_s3_bucket.bbb.id
  acl    = "private"
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
  s3_bucket_name                = aws_s3_bucket.b2.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "b2" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

```
## Non-Compliant Code Examples
```terraform
variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "private_key_path" {}
variable "key_name" {}
variable "region" {
  default = "us-west-2"
}
provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = var.region
}

module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  versioning = {
    enabled = true
  }

  bucket = "my_bucket"
  acl    = "public-read"
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


module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  versioning = {
    enabled = true
  }

  bucket = "my_bucket"
  acl    = "public-read"
}

resource "aws_cloudtrail" "foobar2" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.bb.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "bb" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl" {
  bucket = aws_s3_bucket.bb.id
  acl    = "public-read"
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
  s3_bucket_name                = aws_s3_bucket.b.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"
  acl    = "public-read"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

```