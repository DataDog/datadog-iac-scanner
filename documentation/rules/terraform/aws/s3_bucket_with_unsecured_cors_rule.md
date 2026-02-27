---
title: "S3 bucket with unsecured CORS rule"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_with_unsecured_cors_rule"
  id: "98a8f708-121b-455b-ae2f-da3fb59d17e1"
  display_name: "S3 bucket with unsecured CORS rule"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `98a8f708-121b-455b-ae2f-da3fb59d17e1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#cors_rule)

### Description

When defining a Cross-Origin Resource Sharing (CORS) rule in an S3 bucket, it is important to ensure that the `allowed_headers` attribute is not overly permissive, for example, by setting `allowed_headers = ["*"]`. Allowing all headers to be accepted from any origin can expose the bucket to potential cross-origin attacks, enabling malicious sites to interact with S3 resources in unintended ways. This misconfiguration increases the risk of data exfiltration or manipulation by allowing arbitrary clients to send any HTTP headers, which can compromise sensitive data and security controls. To mitigate this vulnerability, it is recommended to specify only the necessary headers in `allowed_headers` and restrict origins to trusted domains.

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

resource "aws_s3_bucket_cors_configuration" "example" {
  bucket = aws_s3_bucket.b.bucket

  cors_rule {
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://s3-website-test.hashicorp.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "s3-tf-example-versioning"
  acl    = "private"
  version = "0.0.1"

  versioning = [
    {
      enabled = true
      mfa_delete = null
    },
  ]

  cors_rule = [
   {
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://s3-website-test.hashicorp.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
   }
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

resource "aws_s3_bucket" "negative1" {
  bucket = "s3-website-test.hashicorp.com"
  acl    = "public-read"

  cors_rule {
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://s3-website-test.hashicorp.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
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
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

resource "aws_s3_bucket" "positive2" {
  bucket = "my-tf-test-bucket"
  acl    = "public-read"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }

  versioning {
    enabled = false
  }

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
   }
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "s3-tf-example-versioning"
  acl    = "private"
  version = "0.0.1"
  
  versioning = [
    {
      enabled = true
      mfa_delete = null
    },
  ]

  cors_rule = [
   {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://s3-website-test.hashicorp.com"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
   }
  ]
}

```

```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "s3-tf-example-versioning"
  acl    = "private"
  version = "0.0.1"

  versioning = [
    {
      enabled = true
      mfa_delete = null
    },
  ]

  cors_rule = [
   {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
   }
  ]
}

```