---
title: "S3 bucket without enabled MFA delete"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_without_enabled_mfa_delete"
  id: "c5b31ab9-0f26-4a49-b8aa-4cc064392f4d"
  display_name: "S3 bucket without enabled MFA delete"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `c5b31ab9-0f26-4a49-b8aa-4cc064392f4d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#mfa_delete)

### Description

An Amazon S3 bucket without Multi-Factor Authentication (MFA) delete enabled is vulnerable to accidental or malicious deletion of objects, even if bucket versioning is turned on. MFA delete adds an extra layer of security by requiring a time-based one-time password from a hardware or virtual MFA device before allowing delete operations on objects or bucket versions. If this protection is not enabled, anyone with appropriate credentials can permanently delete data, increasing the risk of data loss due to stolen credentials or misconfigured permissions. Terraform does not currently support enabling `mfa_delete` in the `versioning` block of the `aws_s3_bucket` resource, so this must be configured manually using the AWS CLI after applying Terraform, as shown in the command: `aws s3api put-bucket-versioning --versioning-configuration Status=Enabled,MFADelete=Enabled --bucket=<BUCKET_NAME> --mfa=<MFA_SERIAL_NUMBER>`.

## Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  lifecycle_rule {
    id      = "tmp"
    prefix  = "tmp/"
    enabled = true

    expiration {
      date = "2016-01-12"
    }
  }
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning {
    enabled = true
    mfa_delete = true
  }
}

```
## Non-Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning {
    enabled = false
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

resource "aws_s3_bucket" "positive2" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }

  versioning {
    enabled = true
    mfa_delete = false
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

resource "aws_s3_bucket" "positive3" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }

  versioning {
    enabled = false
  }
}

```