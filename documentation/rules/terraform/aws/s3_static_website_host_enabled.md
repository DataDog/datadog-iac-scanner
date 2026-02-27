---
title: "S3 static website host enabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_static_website_host_enabled"
  id: "42bb6b7f-6d54-4428-b707-666f669d94fb"
  display_name: "S3 static website host enabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `42bb6b7f-6d54-4428-b707-666f669d94fb`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#website)

### Description

AWS S3 static website hosting allows serving content directly from buckets without additional authentication, potentially exposing sensitive data to the internet. When enabled via the `website` block, the bucket content becomes accessible through the website endpoint, bypassing S3's access controls and increasing the attack surface. Attackers could access unintended data if bucket policies are misconfigured or files are incorrectly permissioned.

Secure configuration example:
```
resource "aws_s3_bucket" "secure_example" {
  bucket = "s3-website-test.hashicorp.com"
  acl    = "public-read"
  // No website configuration block
}
```

Instead, consider using CloudFront distribution with proper access controls and HTTPS to securely serve website content.

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


resource "aws_s3_bucket" "bu" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
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
  bucket = "s3-website-test.hashicorp.com"
  acl    = "public-read"
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

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
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


resource "aws_s3_bucket" "buc" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_website_configuration" "example" {
  bucket = aws_s3_bucket.buc.bucket

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }

  routing_rule {
    condition {
      key_prefix_equals = "docs/"
    }
    redirect {
      replace_key_prefix_with = "documents/"
    }
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

resource "aws_s3_bucket" "positive1" {
  bucket = "s3-website-test.hashicorp.com"
  acl    = "public-read"

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}

```