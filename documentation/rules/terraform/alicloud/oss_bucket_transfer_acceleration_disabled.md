---
title: "OSS bucket transfer acceleration disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_transfer_acceleration_disabled"
  id: "8f98334a-99aa-4d85-b72a-1399ca010413"
  display_name: "OSS bucket transfer acceleration disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `8f98334a-99aa-4d85-b72a-1399ca010413`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#transfer_acceleration)

### Description

An OSS bucket should have `transfer_acceleration.enabled` set to `true`. This rule inspects `alicloud_oss_bucket` resources and reports when the `transfer_acceleration` block is missing or when `transfer_acceleration.enabled` is `false`. It recommends adding a `transfer_acceleration` block with `enabled = true` or updating the existing value to `true`.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-accelerate3" {
  bucket = "bucket_name"

  transfer_acceleration {
    enabled = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-accelerate2" {
  bucket = "bucket_name"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket-accelerate" {
  bucket = "bucket_name"

  transfer_acceleration {
    enabled = false
  }
}

```