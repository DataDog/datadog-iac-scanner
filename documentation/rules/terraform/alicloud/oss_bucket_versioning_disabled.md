---
title: "OSS bucket versioning disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_versioning_disabled"
  id: "terraform-alicloud-oss-bucket-versioning-disabled"
  display_name: "OSS bucket versioning disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `terraform-alicloud-oss-bucket-versioning-disabled`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#versioning)

### Description

OSS bucket resources (`alicloud_oss_bucket`) should have `versioning.status` set to `Enabled`. This rule flags buckets where `versioning.status` is `Suspended`, or where the `versioning` block is missing. To remediate, add or update the `versioning` block so that `status = "Enabled"`.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-versioning1" {
  bucket = "bucket-170309-versioning"
  acl    = "private"

  versioning {
    status = "Enabled"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-versioning3" {
  bucket = "bucket-170309-versioning"
  acl    = "private"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket-versioning2" {
  bucket = "bucket-170309-versioning"
  acl    = "private"

  versioning {
    status = "Suspended"
  }
}

```