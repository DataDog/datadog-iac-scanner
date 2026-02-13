---
title: "S3 bucket allows authenticated users access"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_allows_access_to_all_authenticated_users"
  id: "d4e5f6g7-h8i9-0jkl-1234-mn567opq8901"
  display_name: "S3 bucket allows authenticated users access"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `d4e5f6g7-h8i9-0jkl-1234-mn567opq8901`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl)

### Description

This check verifies if AWS S3 bucket ACLs are configured to prevent access from all authenticated AWS users. When an S3 bucket grants access to the `AuthenticatedUsers` group, it allows any AWS account holder worldwide to access your data, not just users within your organization. This significantly increases the risk of unauthorized data access, potential data breaches, and violation of data governance policies.

To secure your S3 bucket, use specific canonical user IDs rather than the global authenticated users group. For example, instead of using:
```
grantee {
  type = "Group"
  uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
}
```

Use a specific user configuration:
```
grantee {
  type = "CanonicalUser"
  id   = "1234567890abcdef1234567890abcdef12345678"
}
```

## Compliant Code Examples
```terraform
resource "aws_s3_bucket_acl" "good_example" {
  bucket = aws_s3_bucket.example.id

  access_control_policy {
    grant {
      grantee {
        type = "CanonicalUser"
        id   = "1234567890abcdef1234567890abcdef12345678" # ✅ Restricted access
      }
      permission = "READ"
    }
    owner {
      id = aws_s3_bucket.example.owner_id
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_s3_bucket_acl" "bad_example" {
  bucket = aws_s3_bucket.example.id

  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" # ❌ Allows access to all authenticated users
      }
      permission = "READ"
    }
    owner {
      id = aws_s3_bucket.example.owner_id
    }
  }
}

```