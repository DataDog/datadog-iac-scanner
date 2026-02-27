---
title: "S3 bucket ACL allows read or write to all users"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_or_write_to_all_users"
  id: "38c5ee0d-7f22-4260-ab72-5073048df100"
  display_name: "S3 bucket ACL allows read or write to all users"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `38c5ee0d-7f22-4260-ab72-5073048df100`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

### Description

This check identifies AWS S3 buckets that have ACLs allowing read or write access to all users, creating a significant security risk. When S3 buckets are configured with public access (using ACLs such as `public-read` or `public-read-write`), sensitive data can be exposed to unauthorized users, potentially leading to data breaches, intellectual property theft, or compliance violations. To secure your S3 buckets, always use private ACLs, as shown in the example below:

```terraform
resource "aws_s3_bucket" "secure_example" {
  bucket = "my-tf-test-bucket"
  acl    = "private"
}
```

## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.2.0"
    }
  }
}

resource "aws_s3_bucket" "example0" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl" {
  bucket = aws_s3_bucket.example0.id
  acl    = "private"
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

resource "aws_s3_bucket" "negative1" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }

  versioning {
    enabled = true
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "4.2.0"
    }
  }
}

resource "aws_s3_bucket" "example000" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_acl" "example_bucket_acl" {
  bucket = aws_s3_bucket.example000.id
  acl    = "public-read-write"
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

resource "aws_s3_bucket" "positive2" {
  bucket = "my-tf-test-bucket"
  acl    = "public-read-write"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }

  versioning {
    enabled = true
  }
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "public-read"

  versioning = {
    enabled = true
  }
}

```