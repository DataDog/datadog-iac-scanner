---
title: "OSS bucket encryption using CMK disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_cmk_encryption_disabled"
  id: "terraform-alicloud-oss-bucket-cmk-encryption-disabled"
  display_name: "OSS bucket encryption using CMK disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `terraform-alicloud-oss-bucket-cmk-encryption-disabled`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#server_side_encryption_rule)

### Description

`alicloud_oss_bucket` resources must have server-side encryption enabled and configured to use a customer-managed KMS key. The `server_side_encryption_rule` block must be present, and the `kms_master_key_id` attribute must be set. Absence of either is considered a policy violation.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_cmk_encryption1" {
  bucket = "bucket-170309-sserule"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm     = "KMS"
    kms_master_key_id = "your kms key id"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_cmk_encryption3" {
  bucket = "bucket-170309-sserule"
  acl    = "private"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_cmk_encryption2" {
  bucket = "bucket-170309-sserule"
  acl    = "private"

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }
}

```