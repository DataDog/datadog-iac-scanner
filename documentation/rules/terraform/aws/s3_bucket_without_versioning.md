---
title: "S3 bucket without versioning"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_without_versioning"
  id: "568a4d22-3517-44a6-a7ad-6a7eed88722c"
  display_name: "S3 bucket without versioning"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `568a4d22-3517-44a6-a7ad-6a7eed88722c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#versioning)

### Description

 Amazon S3 buckets should have versioning enabled to protect against accidental or malicious deletion and overwriting of objects. Without versioning (`versioning { enabled = false }`), deleted or overwritten files cannot be recovered, potentially leading to permanent data loss or loss of critical information. Enabling versioning (`versioning { enabled = true }`) allows you to preserve, retrieve, and restore every version of every object stored in the bucket, significantly improving data resiliency.


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

resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.b.id

  versioning_configuration {
    status = "Enabled"
  }
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
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  version = "3.7.0"

  bucket = "my-s3-bucket"
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

resource "aws_s3_bucket" "positive2" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
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
    mfa_delete = true
  }
}

```