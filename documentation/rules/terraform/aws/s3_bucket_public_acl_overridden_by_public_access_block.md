---
title: "S3 bucket public ACL overridden by public access block"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_public_acl_overridden_by_public_access_block"
  id: "bf878b1a-7418-4de3-b13c-3a86cf894920"
  display_name: "S3 bucket public ACL overridden by public access block"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `bf878b1a-7418-4de3-b13c-3a86cf894920`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket)

### Description

This check identifies S3 buckets that have been configured with public ACLs but are simultaneously protected by bucket-level public access block settings that override those ACLs. This configuration creates a security risk through misleading access controls, where developers might assume the bucket is public (based on ACL settings) when it's actually restricted by the public access block. To properly secure S3 buckets, ensure consistency between your ACL settings and public access block configuration. For example, an insecure configuration might include a public ACL with restrictive public access block settings: ```acl = "public-read-write"
block_public_acls = true
ignore_public_acls = true```. A more transparent configuration would align these settings: ```acl = "public-read-write"
block_public_acls = false
ignore_public_acls = false```.

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

resource "aws_s3_bucket" "bu2" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl2" {
  bucket = aws_s3_bucket.bu2.id
  acl = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "block_public_bucket_322" {
  bucket = aws_s3_bucket.bu2.id
  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = false
  restrict_public_buckets = true
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "public-read-write"

  versioning = {
    enabled = true
  }

  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = false
  restrict_public_buckets = true

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
resource "aws_s3_bucket" "public-bucket2" {
  bucket = "bucket-with-public-acl-32"
  acl = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "block_public_bucket_32" {
  bucket = aws_s3_bucket.public-bucket2.id
  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = false
  restrict_public_buckets = true
}

```
## Non-Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "public-read-write"

  versioning = {
    enabled = true
  }

  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true

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

resource "aws_s3_bucket" "bu" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl" {
  bucket = aws_s3_bucket.bu.id
  acl = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "block_public_bucket_3" {
  bucket = aws_s3_bucket.bu.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
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

resource "aws_s3_bucket" "public-bucket" {
  bucket = "bucket-with-public-acl-3"
  acl = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "block_public_bucket_3" {
  bucket = aws_s3_bucket.public-bucket.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

```