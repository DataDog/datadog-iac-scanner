---
title: "S3 bucket ACL grants WRITE_ACP permission"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_acl_grants_write_acp_permission"
  id: "64a222aa-7793-4e40-915f-4b302c76e4d4"
  display_name: "S3 bucket ACL grants WRITE_ACP permission"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `64a222aa-7793-4e40-915f-4b302c76e4d4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl)

### Description

 The `WRITE_ACP` permission on an S3 bucket allows external entities to modify the bucket's Access Control Lists, which could lead to unauthorized access to your data. If exploited, an attacker could grant themselves or others full access to your bucket contents, potentially resulting in data leaks or tampering with critical information. Instead of using `WRITE_ACP` permissions, you should use `READ` or `READ_ACP`, as shown in the secure example: `permission = "READ"` or `permission = "READ_ACP"`, avoiding the insecure pattern: `permission = "WRITE_ACP"`.


## Compliant Code Examples
```terraform
data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "example" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  access_control_policy {
    grant {
      grantee {
        id   = data.aws_canonical_user_id.current.id
        type = "CanonicalUser"
      }
      permission = "READ"
    }

    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery"
      }
      permission = "READ_ACP"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "example" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  access_control_policy {
    grant {
      grantee {
        id   = data.aws_canonical_user_id.current.id
        type = "CanonicalUser"
      }
      permission = "READ"
    }

    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery"
      }
      permission = "WRITE_ACP"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

```

```terraform
data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "example" {
  bucket = "my-tf-example-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  access_control_policy {

    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery"
      }
      permission = "WRITE_ACP"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

```